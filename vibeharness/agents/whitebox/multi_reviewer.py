import functools
import logging
import os
import re
from typing import List, Dict, Any, Optional
from pydantic import ValidationError
from vibeharness.core.models import CodeSymbol, ReviewFinding, FindingSeverity, text_or
from vibeharness.core.llm_gateway import LLMGateway
from vibeharness.core.i18n import bi, en_only
from vibeharness.core.codecontext import estimate_tokens, render_symbols, batch_symbols
from vibeharness.core.sanitize import UNTRUSTED_CODE_POLICY, untrusted_block
from vibeharness.core.fanout import Call, CallKind, PlannedCalls, fan_out
from vibeharness.core.identity import UNKNOWN_FILE
from vibeharness.core.model_output import LIST_OF_OBJECTS, OutputSchema

logger = logging.getLogger("VibeHarness.MultiReviewer")


def is_usable_finding(item: Dict[str, Any]) -> bool:
    """模型回報的一項發現可以使用：有非空的 title 或 description（驗證者與測試生成器才有內容可據以行動）。
    審查者略過其他項目；閘道的形狀檢查也用同一個判斷，所以兩者不會不一致。
    A reported finding item is usable: it has a non-empty title or description (something the verifiers and the
    test generator can act on). The reviewer skips the others, and the gateway's shape check uses the same rule, so
    the two cannot disagree."""
    return bool(text_or(item.get("title"), "") or text_or(item.get("description"), ""))


# 審查者回答的形狀（core/model_output.py）：`findings` 是物件清單，不為空時至少要有一項可用的發現
# The shape of a reviewer's answer (core/model_output.py): `findings` is a list of objects, with at least one usable
# finding when it is not empty
FINDINGS_SCHEMA = OutputSchema(required={"findings": LIST_OF_OBJECTS(
    usable=is_usable_finding,
    requirement=bi("每一項都要有非空的 title 或 description", "each item needs a non-empty title or description"),
)})

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
            alias = gateway.settings.alias_for(agent_id)
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

    def plan(self, symbols: List[CodeSymbol], root: str) -> List[PlannedCalls]:
        """review_symbols 對這些符號會發出的呼叫：每個審查者、每個白箱批次一次，執行前就已知。
        The calls review_symbols would make for these symbols: one per reviewer and white-box batch, known before
        the run."""
        if not symbols or not self.reviewer_agents:
            return []
        listing_tokens = [estimate_tokens(self._listing(batch, root)) for batch in self._batches(symbols, root)]
        return [
            PlannedCalls(agent_id=reviewer["agent_id"], model_alias=reviewer["model_alias"],
                         kind=CallKind.REVIEWER, calls=1, json_output=True, code_tokens=tokens, exact=True)
            for reviewer in self.reviewer_agents for tokens in listing_tokens
        ]

    def batch_count(self, symbols: List[CodeSymbol], root: str) -> int:
        """review_symbols 對這些符號會審幾個白箱批次（每個審查者都審同樣的批次）；沒有符號或沒有審查者時是 0。
        How many white-box batches review_symbols would review for these symbols (every reviewer reviews the same
        batches); 0 without symbols or without reviewers."""
        if not symbols or not self.reviewer_agents:
            return 0
        return len(self._batches(symbols, root))

    def _batches(self, symbols: List[CodeSymbol], root: str) -> List[List[CodeSymbol]]:
        return batch_symbols(symbols, root, self.BATCH_MAX_TOKENS, self.BATCH_MAX_SYMBOLS)

    def _listing(self, batch: List[CodeSymbol], root: str) -> str:
        return render_symbols(batch, root, max_tokens=self.BATCH_MAX_TOKENS)

    def review_symbols(self, symbols: List[CodeSymbol], root_dir: Optional[str] = None) -> List[ReviewFinding]:
        if not symbols or not self.reviewer_agents:
            return []
        root = root_dir or os.path.dirname(os.path.abspath(symbols[0].file_path))
        batches = self._batches(symbols, root)
        jobs = [(reviewer, batch) for reviewer in self.reviewer_agents for batch in batches]

        # 審查者是彼此獨立的模型，所以它們的呼叫並行執行。一個當掉的批次不能丟掉其他所有批次（已經付費的）結果：
        # fan_out 把它記成無效呼叫（該批次的發現是缺漏，而不是不存在）；live 模式的失敗仍會往上傳遞，讓執行大聲地失敗。
        # Reviewers are independent models, so their calls run concurrently. A crashed batch must not discard every
        # other batch's (already paid-for) results: fan_out books it as an invalid call (the batch's findings are
        # missing, not absent); live-mode failures still propagate so the run fails loudly.
        calls = [
            Call(reviewer["agent_id"], (f"{reviewer['name']} 的審查批次", f"Reviewer batch for {reviewer['name']}"),
                 functools.partial(self._review_batch, reviewer, batch, root))
            for reviewer, batch in jobs
        ]
        responses = fan_out(self.gateway, calls, fallback=({}, False), logger=logger)

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
                if not is_usable_finding(item):
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
                        file_path=symbol.file_path if symbol else UNKNOWN_FILE,
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
            f"{untrusted_block(self._listing(batch, root))}\n\n"
            f"Please audit against your specialty."
        )
        logger.info(bi(f"以審查者 {name} 執行白箱稽核（{len(batch)} 個符號）",
                       f"Running white-box audit with reviewer: {name} ({len(batch)} symbols)"))
        agent_id = reviewer["agent_id"]
        answer = self.gateway.generate(
            agent_id, system_prompt, user_prompt, json_output=True, schema=FINDINGS_SCHEMA,
            simulated=lambda alias: _simulated_review(agent_id, alias),
        )
        return answer.data, answer.simulated

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


# 逐模型別名的固定離線審查樣板：審查者的模擬輸出（見 _simulated_review）
# Fixed offline review templates per model alias: the reviewers' Simulated output (see _simulated_review)
_SIMULATED_REVIEWS: Dict[str, Dict[str, str]] = {
    "claude": {
        "severity": "HIGH",
        "title": bi("處理函式中未檢查的空值／隱含的狀態假設", "Unchecked Null / Implicit State Assumption in Handler"),
        "description": bi("Vibe coding 產出的邏輯假設實體存在且狀態轉換有效，卻未驗證資料庫查詢結果，導致未處理的 NoneType / NullPointer 例外。",
                          "The vibe-coded logic assumes entities exist and state transitions are valid without verifying database fetch outcomes, leading to unhandled NoneType / NullPointer exceptions."),
        "root_cause": bi("存取屬性前缺少防禦性的空值檢查。", "Absence of defensive null-check before property traversal."),
        "suspected_vibe_flaw": bi("Vibe coding 常假設一定找得到紀錄的「理想路徑」。",
                                  "Vibe coding commonly assumes the 'happy path' where records are always found."),
        "suggested_test_scenario": bi("以不存在的 ID 或空酬載呼叫端點／函式，並斷言回傳正確的錯誤狀態（404/400）而不是 500 當機。",
                                      "Invoke the endpoint/function with a non-existent ID or empty payload and assert proper error status (404/400) instead of a 500 crash."),
    },
    "deepseek": {
        "severity": "CRITICAL",
        "title": bi("缺少輸入清理與無上限的資源配置", "Missing Input Sanitization & Unbounded Resource Allocation"),
        "description": bi("邏輯未對查詢或資料陣列限制輸入長度與數值範圍，可能造成記憶體耗盡、ReDoS 或未驗證的大量酬載。",
                          "The logic lacks input length and numerical range clamping on queries or data arrays, allowing memory exhaustion and ReDoS or unvalidated bulk payloads."),
        "root_cause": bi("直接把不可信的輸入餵入下游的迭代與記憶體結構。",
                         "Directly feeding untrusted input into downstream iteration and memory structures."),
        "suspected_vibe_flaw": bi("AI 程式助理常略過明確的大小檢查與分頁上限。",
                                  "AI coding assistants frequently skip explicit size checks and pagination limits."),
        "suggested_test_scenario": bi("提供 10MB 的酬載或超過 1,000,000 的整數值，確認以 HTTP 413 或 422 妥善拒絕。",
                                      "Supply a 10MB payload or integer values exceeding 1,000,000 and verify graceful rejection with HTTP 413 or 422."),
    },
    "glm": {
        "severity": "MEDIUM",
        "title": bi("API 契約規格漂移與結構描述不一致", "API Contract Specification Drift & Schema Inconsistency"),
        "description": bi("缺少參數型別強制檢查，且預期的回應結構描述與實際序列化的字典欄位不一致。",
                          "Missing parameter type enforcement and inconsistency between expected response schema and actual serialized dictionary fields."),
        "root_cause": bi("隱含的結構描述轉型，沒有嚴格的 Pydantic/dataclass 結構描述驗證。",
                         "Implicit schema casting without strict Pydantic/dataclass schema validation."),
        "suspected_vibe_flaw": bi("Vibe coding 的快速原型常臨時更改回應結構，卻未更新契約定義。",
                                  "Quick prototyping in vibe coding often changes response structures on the fly without updating contract definitions."),
        "suggested_test_scenario": bi("斷言回應結構描述在所有欄位型別上都與預期的 OpenAPI/JSON 契約完全一致。",
                                      "Assert response schema matches the expected OpenAPI/JSON contract exactly across all field types."),
    },
    "gemini": {
        "severity": "HIGH",
        "title": bi("不可信的輸入進入提示詞，且模型輸出未經驗證就被使用",
                    "Untrusted Input Reaches the Prompt and Model Output Is Used Unvalidated"),
        "description": bi("使用者控制或擷取的文字被串接進模型提示詞，而模型輸出未經嚴格的結構描述檢查就驅動決策或下游呼叫。",
                          "User-controlled or retrieved text is concatenated into model prompts, and model output drives decisions or downstream calls without a strict schema check."),
        "root_cause": bi("指令與資料之間沒有信任邊界，模型輸出也沒有確定性的驗證（OWASP LLM01:2026 / LLM10:2026）。",
                         "No trust boundary between instructions and data, and no deterministic validation of model output (OWASP LLM01:2026 / LLM10:2026)."),
        "suspected_vibe_flaw": bi("Vibe coding 產出的 AI 功能因為示範提示詞看起來正常，就把模型直接接進業務邏輯。",
                                  "Vibe-coded AI features wire the model straight into business logic because the demo prompt behaved."),
        "suggested_test_scenario": bi("餵入含有指令覆寫與不可見 Unicode 的輸入，並斷言輸出經過結構描述驗證，絕不會進入 eval/SQL/HTML 或特權操作。",
                                      "Feed input containing an instruction override and invisible Unicode, and assert the output is schema-validated and never reaches eval/SQL/HTML or a privileged action."),
        "owasp_mapping": "LLM01:2026",
    },
}


def _simulated_review(agent_id: str, model_alias: str) -> Dict[str, Any]:
    """審查者的模擬輸出：反映各審查者關注重點的固定樣板，依模型別名選取，退而以代理 id 的字尾選取。
    樣板與目標程式碼無關；它們讓流程能離線演練，且在報告中一律標示為 simulated。
    - Claude：狀態轉換、缺少的 null 檢查、邊界情況邏輯。
    - DeepSeek：邊界限制、輸入消毒、防禦性守衛。
    - GLM：合約規格、API 合規性、參數驗證。
    - Gemini：AI/LLM 整合（OWASP Top 10 for LLM Applications 2026）。
    A reviewer's Simulated output: a fixed template reflecting each reviewer's focus, chosen by model alias, falling
    back to the agent id's suffix. The templates are independent of the target code; they let the pipeline be
    exercised offline and are always flagged as simulated in reports.
    - Claude: state transitions, missing null checks, edge-case logic.
    - DeepSeek: boundary limits, input sanitization, defensive guards.
    - GLM: contract specifications, API compliance, parameter validation.
    - Gemini: AI/LLM integration (OWASP Top 10 for LLM Applications 2026)."""
    template = _SIMULATED_REVIEWS.get(model_alias) or _SIMULATED_REVIEWS.get(agent_id.rsplit("_", 1)[-1])
    return {"findings": [dict(template)] if template else []}
