import logging
import os
import re
from concurrent.futures import ThreadPoolExecutor
from typing import List, Dict, Any, Optional
from pydantic import ValidationError
from vibeharness.core.models import CodeSymbol, ReviewFinding, FindingSeverity, text_or
from vibeharness.core.llm_gateway import LLMGateway, LLMGatewayError, UNCONFIGURED_ALIAS
from vibeharness.core.i18n import bi, en_only
from vibeharness.core.codecontext import render_symbols, batch_symbols
from vibeharness.core.sanitize import UNTRUSTED_CODE_POLICY, untrusted_block
from vibeharness.agents.whitebox.common import cancel_pending

logger = logging.getLogger("VibeHarness.MultiReviewer")

# 模型輸出的嚴重度字串若與列舉不符（大小寫怪異、拼錯）就落到這裡
# Model-emitted severity strings that do not match the enum (odd casing, typos) land here
_DEFAULT_SEVERITY = FindingSeverity.MEDIUM
# 模型常用的嚴重度同義詞（比對前已去除空白與標點並轉大寫）
# Severity synonyms models commonly emit (matched after stripping whitespace / punctuation and upper-casing)
_SEVERITY_SYNONYMS = {
    "CRIT": FindingSeverity.CRITICAL, "BLOCKER": FindingSeverity.CRITICAL, "SEVERE": FindingSeverity.HIGH,
    "MAJOR": FindingSeverity.HIGH, "MED": FindingSeverity.MEDIUM, "MODERATE": FindingSeverity.MEDIUM,
    "MINOR": FindingSeverity.LOW, "INFORMATIONAL": FindingSeverity.INFO, "INFORMATION": FindingSeverity.INFO,
    "NOTE": FindingSeverity.INFO,
}


def parse_severity(value: Any) -> Optional[FindingSeverity]:
    """把模型輸出的嚴重度轉成列舉：去除空白、引號與標點、不分大小寫，並接受常見同義詞（"critical "、"Severe"、"P1" 除外）；
    無法辨識時回傳 None。
    Converts a model-emitted severity to the enum: whitespace, quotes and punctuation stripped, case-insensitive,
    common synonyms accepted ("critical ", "Severe"; not "P1"); None when it cannot be recognized."""
    text = re.sub(r"[^A-Z]", "", str(value).upper())
    if text in FindingSeverity.__members__:
        return FindingSeverity(text)
    return _SEVERITY_SYNONYMS.get(text)


REVIEWER_PREFIX = "whitebox_reviewer_"


class HeterogeneousReviewerEnsemble:
    """
    協調白箱多模型審查集合。審查者來自設定：每個 `whitebox_reviewer_*` 代理都以自己的模型、
    名稱與專注領域參與。預設陣容是 Claude（邏輯與狀態）、DeepSeek（防禦與資源）、
    GLM（規格與契約）以及 Gemini（依 OWASP Top 10 for LLM Applications 2026 的 AI/LLM 整合與供應鏈安全）。
    Orchestrates the white-box multi-model review ensemble. Reviewers come from config: every
    `whitebox_reviewer_*` agent is used with its own model, name and focus. The default lineup is
    Claude (logic & state), DeepSeek (defensive & resource), GLM (spec & contract) and Gemini
    (AI/LLM-integration & supply-chain security per the OWASP Top 10 for LLM Applications 2026).
    """

    # 每個符號都會被審查，需要幾個批次就分幾個；一個批次的程式碼清單必須放得進 token 預算
    # Every symbol is reviewed, in as many batches as needed; a batch's code listing fits the token budget
    BATCH_MAX_TOKENS = 10000
    BATCH_MAX_SYMBOLS = 15

    def __init__(self, gateway: LLMGateway):
        self.gateway = gateway
        self.reviewer_agents: List[Dict[str, str]] = []
        for agent_id, meta in gateway.agents_config.items():
            if not agent_id.startswith(REVIEWER_PREFIX):
                continue
            meta = meta if isinstance(meta, dict) else {}
            # 與閘道相同的解析方式：沒有 model_alias 的審查者就是 `unconfigured`
            # （hybrid 模式下模擬、live 模式下報錯），報告才能顯示它的呼叫實際去了哪裡
            # Same resolution as the gateway: a reviewer without a model_alias is `unconfigured`
            # (simulated in hybrid, an error in live), so the report shows where its calls really went
            alias = meta.get("model_alias") or UNCONFIGURED_ALIAS
            self.reviewer_agents.append({
                "agent_id": agent_id,
                "model_alias": str(alias),
                "name": text_or(meta.get("name"), bi(f"審查者（{alias}）", f"Reviewer ({alias})")),
                "focus": text_or(meta.get("focus"), bi("一般正確性與安全缺陷", "General correctness and security defects")),
            })
        if not self.reviewer_agents:
            logger.warning(bi("未設定任何 whitebox_reviewer_* 代理；略過白箱審查。",
                              "No whitebox_reviewer_* agents are configured; the white-box review is skipped."))

    @property
    def distinct_models(self) -> List[str]:
        """集合中的模型別名；少於兩個就無法進行跨模型驗證。
        Model aliases in the ensemble; fewer than two means no cross-model verification is possible."""
        return sorted({r["model_alias"] for r in self.reviewer_agents})

    def review_symbols(self, symbols: List[CodeSymbol], root_dir: Optional[str] = None) -> List[ReviewFinding]:
        if not symbols or not self.reviewer_agents:
            return []
        root = root_dir or os.path.dirname(os.path.abspath(symbols[0].file_path))
        batches = batch_symbols(symbols, root, self.BATCH_MAX_TOKENS, self.BATCH_MAX_SYMBOLS)
        jobs = [(reviewer, batch) for reviewer in self.reviewer_agents for batch in batches]

        # 審查者是彼此獨立的模型，所以它們的呼叫並行執行。一個當掉的批次
        # 不能丟掉其他所有批次（已經付費的）結果；live 模式的失敗
        # 仍會往上傳遞，讓執行大聲地失敗。
        # Reviewers are independent models, so their calls run concurrently. A crashed batch
        # must not discard every other batch's (already paid-for) results; live-mode failures
        # still propagate so the run fails loudly.
        with ThreadPoolExecutor(max_workers=min(self.gateway.max_concurrent_calls, len(jobs))) as pool:
            futures = [pool.submit(self._review_batch, job[0], job[1], root) for job in jobs]
            responses = []
            try:
                for job, future in zip(jobs, futures, strict=True):
                    try:
                        responses.append(future.result())
                    except LLMGatewayError:
                        raise
                    except Exception as e:
                        logger.error(bi(f"{job[0]['name']} 的審查批次失敗：{type(e).__name__}: {e}",
                                        f"Reviewer batch for {job[0]['name']} failed: {type(e).__name__}: {e}"))
                        # 記為一次無效呼叫：該批次的發現是缺漏，而不是不存在
                        # Booked as an invalid call: the batch's findings are missing, not absent
                        self.gateway.record_failure(job[0]["agent_id"], f"{type(e).__name__}: {e}")
                        responses.append(({}, False))
            except BaseException:
                # live 失敗或 Ctrl-C：取消尚未開始的呼叫，不再為一次注定失敗的執行付費
                # A live failure or Ctrl-C: cancel the calls not started yet instead of paying for a run that already failed
                cancel_pending(futures)
                raise

        all_findings: List[ReviewFinding] = []
        counters: Dict[str, int] = {}
        for (reviewer, batch), (resp, simulated) in zip(jobs, responses, strict=True):
            model_alias = reviewer["model_alias"]
            raw_findings = resp.get("findings")
            if not isinstance(raw_findings, list):
                logger.warning(bi(f"略過 {reviewer['name']} 無法使用的發現清單（收到 {type(raw_findings).__name__}）",
                                  f"Ignoring unusable findings list from {reviewer['name']} (got {type(raw_findings).__name__})"))
                raw_findings = []
            for item in raw_findings:
                if not isinstance(item, dict):
                    continue
                if not text_or(item.get("title"), "") and not text_or(item.get("description"), ""):
                    # 沒有驗證者或測試產生器可據以行動的內容
                    # Nothing a verifier or test generator could act on
                    logger.warning(bi(f"略過 {reviewer['name']} 沒有可用標題或描述的發現",
                                      f"Skipping finding without a usable title or description from {reviewer['name']}"))
                    continue
                raw_severity = item.get("severity", "MEDIUM")
                parsed = parse_severity(raw_severity)
                if parsed is None:
                    shown = str(raw_severity).strip()[:40]
                    logger.warning(bi(f"{reviewer['name']} 回傳未知的嚴重度 '{shown}'；改用 MEDIUM",
                                      f"Unknown severity '{shown}' from {reviewer['name']}; using MEDIUM"))
                severity = parsed or _DEFAULT_SEVERITY

                reported_symbol = item.get("symbol_name") if isinstance(item.get("symbol_name"), str) else None
                symbol = self._match_symbol(reported_symbol, batch)
                # 計數器以審查者代理為鍵，因此兩個共用同一 model_alias 的代理
                # 仍會產生不同的發現 id
                # Counters are keyed per reviewer agent, so two agents sharing a model_alias
                # still generate distinct finding ids
                counters[reviewer["agent_id"]] = counters.get(reviewer["agent_id"], 0) + 1
                try:
                    all_findings.append(ReviewFinding(
                        finding_id=f"WB-{model_alias[:3].upper()}-{counters[reviewer['agent_id']]:02d}",
                        reviewer_name=reviewer["name"],
                        model_alias=model_alias,
                        file_path=symbol.file_path if symbol else "unknown",
                        symbol_name=symbol.name if symbol else reported_symbol,
                        line_number=symbol.line_start if symbol else None,
                        severity=severity,
                        title=text_or(item.get("title"), bi("潛在缺陷", "Potential Defect")),
                        description=text_or(item.get("description"), ""),
                        root_cause=text_or(item.get("root_cause"), ""),
                        suspected_vibe_flaw=text_or(item.get("suspected_vibe_flaw"), ""),
                        suggested_test_scenario=text_or(item.get("suggested_test_scenario"), ""),
                        owasp_mapping=text_or(item.get("owasp_mapping"), "") or None,
                        is_simulated=simulated
                    ))
                except ValidationError as e:
                    logger.warning(bi(f"略過 {reviewer['name']} 無法使用的發現：{e}",
                                      f"Skipping unusable finding from {reviewer['name']}: {e}"))

        return self._unique_finding_ids(all_findings)

    @staticmethod
    def _unique_finding_ids(findings: List[ReviewFinding]) -> List[ReviewFinding]:
        """消除重複的 id（例如兩個審查者代理設定了相同的 model_alias）。
        Disambiguates duplicate ids (e.g. two reviewer agents configured with the same model_alias)."""
        seen: Dict[str, int] = {}
        unique = []
        for f in findings:
            count = seen.get(f.finding_id, 0) + 1
            seen[f.finding_id] = count
            unique.append(f if count == 1 else f.model_copy(update={"finding_id": f"{f.finding_id}-{count}"}))
        return unique

    def _review_batch(self, reviewer: Dict[str, str], batch: List[CodeSymbol], root: str):
        name = reviewer["name"]
        # 模型提示詞：維持英文（雙語的預設名稱／專注領域只貢獻其英文半）
        # Model prompt: stays English (a bilingual default name / focus contributes its English half only)
        system_prompt = (
            f"You are {en_only(name)}, a specialized white-box AI code auditor.\n"
            f"Your primary focus: {en_only(reviewer['focus'])}.\n"
            f"The target codebase was produced via 'vibe coding' (rapid conversational AI generation), "
            f"which frequently passes superficial tests but hides critical logic gaps, lack of defensive boundaries, "
            f"and unhandled exceptions.\n\n"
            f"Only report defects you can point to in the provided code. Return a JSON object with this schema:\n"
            f"{{\n"
            f'  "findings": [\n'
            f'    {{\n'
            f'      "symbol_name": "Exact Symbol name from the listing where the defect lives",\n'
            f'      "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW",\n'
            f'      "title": "Brief title",\n'
            f'      "description": "Detailed observation",\n'
            f'      "root_cause": "Underlying mechanism",\n'
            f'      "suspected_vibe_flaw": "Why vibe coding caused this",\n'
            f'      "suggested_test_scenario": "Concrete test condition to expose this flaw",\n'
            f'      "owasp_mapping": "Optional taxonomy id, e.g. LLM01:2026 or API1:2023"\n'
            f'    }}\n'
            f'  ]\n'
            f"}}\n"
            f'Return {{"findings": []}} if you find no defect.'
            f"{UNTRUSTED_CODE_POLICY}"
        )
        user_prompt = (
            f"Target Codebase Extract:\n\n"
            f"{untrusted_block(render_symbols(batch, root, max_tokens=self.BATCH_MAX_TOKENS))}\n\n"
            f"Please audit against your specialty."
        )
        logger.info(bi(f"以審查者 {name} 執行白箱稽核（{len(batch)} 個符號）",
                       f"Running white-box audit with reviewer: {name} ({len(batch)} symbols)"))
        resp = self.gateway.generate(
            reviewer["agent_id"], system_prompt, user_prompt, json_output=True, required_keys=["findings"]
        )
        return resp, self.gateway.is_simulated(resp)

    @staticmethod
    def _match_symbol(name: Any, batch: List[CodeSymbol]) -> Optional[CodeSymbol]:
        """解析模型回報的符號名稱：完全相符優先於短名稱字尾相符。

        沒有指名任何符號的發現刻意保持未解析（None）—— 若默默地把它附到批次的第一個符號，
        泛泛的發現就會得到具體的檔案／符號，進而把目標式測試產生導向錯誤的地方。
        Resolves the model-reported symbol name: exact matches win over short-name suffix matches.

        A finding that names no symbol is deliberately left unresolved (None) — silently attaching
        it to the batch's first symbol gave generic findings a concrete file/symbol that then drove
        targeted test generation at the wrong place.
        """
        if isinstance(name, str) and name:
            for sym in batch:
                if sym.name == name:
                    return sym
            for sym in batch:
                if sym.name.split(".")[-1] == name:
                    return sym
        return None
