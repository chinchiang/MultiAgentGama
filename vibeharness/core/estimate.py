"""`--estimate`：一次執行大約需要多少模型呼叫與 token，而不實際發出任何呼叫。

執行前只有兩個數字是精確的：審查者呼叫數（審查者 × 白箱批次）與
威脅建模呼叫數（批次）。下游的一切都取決於審查者回報多少發現以及
建模者產出多少威脅，因此那些部分是依所述假設（每批次發現數、每批次威脅數）
計算出的情境數字，並如實標示。無法使用的回答重新詢問（`retry_invalid_output`）
在最壞情況下會使每次 JSON 呼叫成倍；回應快取命中會讓重新執行更便宜，
但不在預測之內。
`--estimate`: how many model calls and roughly how many tokens a run would need, without making any.

Only two numbers are exact before the run: reviewer calls (reviewers × white-box batches) and
threat-modeling calls (batches). Everything downstream depends on how many findings the reviewers
report and how many threats the modeler produces, so those parts are scenario figures computed from
stated assumptions (findings per batch, threats per batch) and shown as such. Re-asks of unusable
answers (`retry_invalid_output`) multiply every JSON call in the worst case; response-cache hits
would make a re-run cheaper and are not predicted.
"""
import math
from typing import Dict, List, Optional

from pydantic import BaseModel, Field

from vibeharness.agents.blackbox.threat_modeler import BATCH_MAX_SYMBOLS as TM_BATCH_SYMBOLS
from vibeharness.agents.blackbox.threat_modeler import BATCH_MAX_TOKENS as TM_BATCH_TOKENS
from vibeharness.agents.whitebox.debater import MultiModelDebater
from vibeharness.agents.whitebox.multi_reviewer import HeterogeneousReviewerEnsemble
from vibeharness.core.codecontext import batch_symbols, estimate_tokens, render_symbols
from vibeharness.core.i18n import bi
from vibeharness.core.models import CodeSymbol

# 程式碼清單以外的提示額外負擔（系統提示、結構描述、指引）與典型回答大小，
# 以估計的 token 計。回答大小是線上執行的平均產出；真正的上限是
# max_output_tokens，它是天花板而非花費。
# Prompt overhead beyond the code listing (system prompt, schema, guidance) and typical answer sizes,
# in estimated tokens. Answer sizes are what live runs produced on average; the real cap is
# max_output_tokens, which is a ceiling, not a spend.
_OVERHEAD = {"reviewer": 450, "verifier": 350, "test_generator": 700, "heal": 300, "threat_modeler": 2200, "synthesizer": 900}
_TYPICAL_OUTPUT = {"reviewer": 1500, "verifier": 600, "test_generator": 1500, "heal": 1200, "threat_modeler": 2500, "synthesizer": 1500}
_VERIFIER_LISTING_TOKENS = MultiModelDebater.LISTING_MAX_TOKENS
_VERIFIER_CODE_TOKENS = MultiModelDebater.CODE_CONTEXT_TOKENS
_PER_FINDING_CODE_TOKENS = 4000  # test_generator / scenario_builder 的 CODE_CONTEXT_TOKENS ／ test_generator / scenario_builder CODE_CONTEXT_TOKENS
_HEAL_ATTEMPTS_MAX = 2


class CallEstimate(BaseModel):
    """一種代理在本次執行中所佔的份額。
    One agent kind's share of the run."""
    agent: str
    model_alias: str
    calls_exact: Optional[int] = None  # 執行前已知（審查者、威脅建模） ／ known before the run (reviewers, threat modeling)
    calls_typical: int = 0  # 在所述假設之下 ／ under the stated assumptions
    calls_max: int = 0  # 假設之下的最壞情況（修復、重新詢問） ／ worst case under the assumptions (heals, re-asks)
    prompt_tokens_typical: int = 0
    output_tokens_typical: int = 0
    basis: str = ""  # 數字是如何推導出來的 ／ how the number was derived


class RunEstimate(BaseModel):
    target_path: str
    files_analyzed: int
    symbols: int
    whitebox_batches: int
    threat_batches: int
    assumptions: Dict[str, float] = Field(default_factory=dict)
    retry_invalid_output: int = 0
    max_model_calls: Optional[int] = None
    # --cache-only：呼叫數照樣估算（快取命中與否要等執行時才知道），但不會有任何供應商呼叫或花費
    # --cache-only: the calls are still estimated (hits are only known at run time), but no provider call or spend happens
    cache_only: bool = False
    by_agent: List[CallEstimate] = Field(default_factory=list)
    calls_exact: int = 0
    calls_typical: int = 0
    calls_max: int = 0
    prompt_tokens_typical: int = 0
    output_tokens_typical: int = 0
    # 逐模型別名：呼叫數／token／成本（只有別名具備價格欄位時才有成本）
    # Per model alias: calls / tokens / cost (cost only when the alias has price fields)
    by_model: Dict[str, Dict[str, float]] = Field(default_factory=dict)
    estimated_cost_usd: Optional[float] = None
    # 突變測試（只有開啟時）：每個變異體一個沙盒批次，不呼叫模型；上限 = mutation_max_mutants
    # Mutation testing (only when on): one sandbox batch per mutant, no model call; the ceiling is mutation_max_mutants
    mutation_sandbox_runs_max: Optional[int] = None
    warnings: List[str] = Field(default_factory=list)


def _alias(gateway, agent_id: str) -> str:
    meta = gateway.agents_config.get(agent_id) or {}
    return str(meta.get("model_alias") or "unconfigured")


def estimate_run(
    commander, target_dir: str, findings_per_batch: float = 3.0, threats_per_batch: float = 4.0
) -> RunEstimate:
    """第 1 階段（符號擷取，不涉及模型）加上對代理設定的算術運算。
    Phase 1 (symbol extraction, no model) plus arithmetic on the agent configuration."""
    symbols, filters = commander.select_symbols(target_dir)
    gateway = commander.gateway
    work_dir = commander.work_dir_for(target_dir)
    reviewers = commander.multi_reviewer.reviewer_agents
    verifiers = commander.debater.verifiers
    retry = int(gateway.retry_invalid_output)
    reask = 1 + retry

    wb_batches = batch_symbols(
        symbols, work_dir, HeterogeneousReviewerEnsemble.BATCH_MAX_TOKENS, HeterogeneousReviewerEnsemble.BATCH_MAX_SYMBOLS
    ) if symbols and reviewers else []
    ordered = sorted(symbols, key=lambda s: s.symbol_type != "route")
    tm_batches: List[List[CodeSymbol]] = batch_symbols(ordered, work_dir, TM_BATCH_TOKENS, TM_BATCH_SYMBOLS) or [[]]

    est = RunEstimate(
        target_path=target_dir, files_analyzed=len(commander.ast_extractor.analyzed_files), symbols=len(symbols),
        whitebox_batches=len(wb_batches), threat_batches=len(tm_batches),
        assumptions={"findings_per_reviewer_batch": findings_per_batch, "threats_per_batch": threats_per_batch,
                     "confirmed_share": 0.7, "tests_per_finding": 1.0, "heal_rate": 0.3},
        retry_invalid_output=retry, max_model_calls=gateway.max_model_calls, cache_only=gateway.cache_only,
        mutation_sandbox_runs_max=commander._mutation_cfg["max_mutants"] if commander.mutation_testing else None,
    )
    if filters:
        est.warnings.append(bi("已套用檔案篩選", "File selection applied") + ": " + "; ".join(filters))
    if not symbols:
        est.warnings.append(bi("沒有可分析的符號：審查者與測試產生器不會發出任何呼叫",
                               "No analyzable symbols: the reviewers and the test generator would make no calls"))

    # 1. 審查者：精確值
    # 1. Reviewers: exact
    wb_listing_tokens = [estimate_tokens(render_symbols(b, work_dir, max_tokens=HeterogeneousReviewerEnsemble.BATCH_MAX_TOKENS)) for b in wb_batches]
    for reviewer in reviewers:
        calls = len(wb_batches)
        est.by_agent.append(CallEstimate(
            agent=reviewer["agent_id"], model_alias=reviewer["model_alias"], calls_exact=calls, calls_typical=calls,
            calls_max=calls * reask, prompt_tokens_typical=sum(wb_listing_tokens) + calls * _OVERHEAD["reviewer"],
            output_tokens_typical=calls * _TYPICAL_OUTPUT["reviewer"],
            basis=bi(f"{len(wb_batches)} 個白箱批次 × 1 次呼叫", f"{len(wb_batches)} white-box batch(es) × 1 call"),
        ))

    # 2. 發現情境 -> 驗證者
    # 2. Findings scenario -> verifiers
    raw_findings = findings_per_batch * len(wb_batches) * len(reviewers)
    distinct = raw_findings * 0.8  # 部分重複項會合併 ／ some duplicates merge
    for agent_id, alias in verifiers.items():
        # 驗證者絕不裁決自家模型的發現：它只看到其他模型回報的那一份
        # A verifier never rules on its own model's findings: it sees the share reported by other models
        own_share = sum(1 for r in reviewers if r["model_alias"] == alias) / max(len(reviewers), 1)
        assigned = distinct * (1 - own_share)
        calls = math.ceil(assigned / MultiModelDebater.FINDINGS_PER_CALL) if assigned > 0 else 0
        est.by_agent.append(CallEstimate(
            agent=agent_id, model_alias=alias, calls_typical=calls, calls_max=calls * reask,
            prompt_tokens_typical=calls * (_VERIFIER_LISTING_TOKENS + _VERIFIER_CODE_TOKENS + _OVERHEAD["verifier"]),
            output_tokens_typical=calls * _TYPICAL_OUTPUT["verifier"],
            basis=bi(f"來自其他模型的 ~{assigned:.0f} 筆發現 / 每次呼叫 {MultiModelDebater.FINDINGS_PER_CALL} 筆",
                     f"~{assigned:.0f} finding(s) from other models / {MultiModelDebater.FINDINGS_PER_CALL} per call"),
        ))

    # 3. 每筆已確認發現的測試產生（+ 修復）
    # 3. Test generation per confirmed finding (+ heals)
    confirmed = distinct * est.assumptions["confirmed_share"]
    gen_calls = math.ceil(confirmed * est.assumptions["tests_per_finding"])
    heal_typical = math.ceil(gen_calls * est.assumptions["heal_rate"])
    tg_alias = _alias(gateway, "whitebox_test_generator")
    est.by_agent.append(CallEstimate(
        agent="whitebox_test_generator", model_alias=tg_alias, calls_typical=gen_calls + heal_typical,
        calls_max=gen_calls * reask + gen_calls * _HEAL_ATTEMPTS_MAX,
        prompt_tokens_typical=gen_calls * (_PER_FINDING_CODE_TOKENS + _OVERHEAD["test_generator"]) + heal_typical * (_OVERHEAD["heal"] + 1200),
        output_tokens_typical=gen_calls * _TYPICAL_OUTPUT["test_generator"] + heal_typical * _TYPICAL_OUTPUT["heal"],
        basis=bi(f"~{confirmed:.0f} 筆已確認的發現 × 1 次呼叫，+ 修復（典型 {heal_typical}，每個測試最多 {_HEAL_ATTEMPTS_MAX}）",
                 f"~{confirmed:.0f} confirmed finding(s) × 1 call, + heals (typical {heal_typical}, max {_HEAL_ATTEMPTS_MAX} per test)"),
    ))

    # 4. 威脅建模：精確值
    # 4. Threat modeling: exact
    tm_alias = _alias(gateway, "blackbox_threat_modeler")
    tm_listing = [estimate_tokens(render_symbols(b, work_dir, max_tokens=TM_BATCH_TOKENS)) if b else 0 for b in tm_batches]
    est.by_agent.append(CallEstimate(
        agent="blackbox_threat_modeler", model_alias=tm_alias, calls_exact=len(tm_batches), calls_typical=len(tm_batches),
        calls_max=len(tm_batches) * reask, prompt_tokens_typical=sum(tm_listing) + len(tm_batches) * _OVERHEAD["threat_modeler"],
        output_tokens_typical=len(tm_batches) * _TYPICAL_OUTPUT["threat_modeler"],
        basis=bi(f"{len(tm_batches)} 個威脅模型批次 × 1 次呼叫", f"{len(tm_batches)} threat-model batch(es) × 1 call"),
    ))

    # 5. 每個威脅的攻擊合成
    # 5. Attack synthesis per threat
    threats = math.ceil(threats_per_batch * len(tm_batches))
    sy_alias = _alias(gateway, "blackbox_test_synthesizer")
    est.by_agent.append(CallEstimate(
        agent="blackbox_test_synthesizer", model_alias=sy_alias, calls_typical=threats, calls_max=threats * reask,
        prompt_tokens_typical=threats * (_PER_FINDING_CODE_TOKENS + _OVERHEAD["synthesizer"]),
        output_tokens_typical=threats * _TYPICAL_OUTPUT["synthesizer"],
        basis=bi(f"~{threats} 個威脅 × 1 次呼叫", f"~{threats} threat(s) × 1 call"),
    ))

    est.calls_exact = sum(c.calls_exact or 0 for c in est.by_agent)
    est.calls_typical = sum(c.calls_typical for c in est.by_agent)
    est.calls_max = sum(c.calls_max for c in est.by_agent)
    est.prompt_tokens_typical = sum(c.prompt_tokens_typical for c in est.by_agent)
    est.output_tokens_typical = sum(c.output_tokens_typical for c in est.by_agent)

    # 逐模型，設定了價格時附成本
    # Per model, with cost when prices are configured
    total_cost = 0.0
    priced = False
    for c in est.by_agent:
        row = est.by_model.setdefault(c.model_alias, {"calls_typical": 0, "calls_max": 0, "prompt_tokens": 0, "output_tokens": 0})
        row["calls_typical"] += c.calls_typical
        row["calls_max"] += c.calls_max
        row["prompt_tokens"] += c.prompt_tokens_typical
        row["output_tokens"] += c.output_tokens_typical
    for alias, row in est.by_model.items():
        info = gateway.models_config.get(alias) or {}
        p_in, p_out = info.get("price_per_million_input"), info.get("price_per_million_output")
        if isinstance(p_in, (int, float)) and isinstance(p_out, (int, float)):
            row["cost_usd"] = round(row["prompt_tokens"] / 1e6 * p_in + row["output_tokens"] / 1e6 * p_out, 4)
            total_cost += row["cost_usd"]
            priced = True
        elif alias != "unconfigured":
            est.warnings.append(bi(
                f"模型別名 '{alias}' 沒有設定價格（models.{alias}.price_per_million_input/_output）：只列 token",
                f"No price configured for model alias '{alias}' (models.{alias}.price_per_million_input/_output): tokens only"
            ))
    if priced:
        est.estimated_cost_usd = round(total_cost, 4)
    if est.cache_only:
        # 只讀快取：預算與費用都不適用，因此不提出預算警告
        # Cache only: neither the budget nor the cost applies, so no budget warning is raised
        est.warnings.append(bi(
            "--cache-only：不會呼叫任何供應商，也沒有花費；上列呼叫都只從回應快取取用，快取沒有的會改用模擬（hybrid）或失敗（live），"
            "費用與 token 只代表當初建立快取的花費",
            "--cache-only: no provider is called and nothing is spent; the calls above are served from the response cache "
            "only, and those it cannot answer are simulated (hybrid) or fail (live). Cost and tokens only describe what "
            "filling the cache cost"
        ))
    elif est.max_model_calls is not None and est.calls_typical > est.max_model_calls:
        est.warnings.append(bi(
            f"max_model_calls={est.max_model_calls} 低於典型呼叫數（{est.calls_typical}）：之後的代理會退回模擬（hybrid）或失敗（live）",
            f"max_model_calls={est.max_model_calls} is below the typical call count ({est.calls_typical}): later agents "
            "would fall back to simulation (hybrid) or fail (live)"
        ))
    return est


# `estimate_lines` 表格的雙語欄位標題 ／ Bilingual column headers of the `estimate_lines` table
ESTIMATE_COLUMNS = (
    bi("代理", "agent"), bi("模型", "model"), bi("精確", "exact"), bi("典型", "typical"), bi("最大", "max"),
    bi("提示 token", "prompt tok"), bi("輸出 token", "output tok"), bi("依據", "basis"),
)
# 每欄寬度：原本的寬度或雙語標題的長度，取較大者 ／ Column widths: the original width or the bilingual header, whichever is wider
_COLUMN_WIDTHS = tuple(max(w, len(h)) for w, h in zip((28, 12, 6, 8, 6, 11, 11), ESTIMATE_COLUMNS[:-1], strict=True))


def estimate_lines(est: RunEstimate) -> List[str]:
    """純文字呈現（CLI 會印出它；JSON 輸出直接使用模型）。
    Plain-text rendering (the CLI prints it; JSON output uses the model directly)."""
    w_agent, w_model, w_exact, w_typ, w_max, w_prompt, w_output = _COLUMN_WIDTHS
    h_agent, h_model, h_exact, h_typ, h_max, h_prompt, h_output, h_basis = ESTIMATE_COLUMNS
    assumptions = ', '.join(f'{k}={v:g}' for k, v in est.assumptions.items())
    lines = [
        f"{bi('目標', 'Target')}: {est.target_path}",
        f"{bi('分析的檔案', 'Files analyzed')}: {est.files_analyzed} | {bi('符號', 'symbols')}: {est.symbols} | "
        f"{bi('白箱批次', 'white-box batches')}: {est.whitebox_batches} | {bi('威脅批次', 'threat batches')}: {est.threat_batches}",
        f"{bi('假設', 'Assumptions')}: {assumptions}; retry_invalid_output={est.retry_invalid_output}",
        "",
        f"{h_agent:<{w_agent}} {h_model:<{w_model}} {h_exact:>{w_exact}} {h_typ:>{w_typ}} {h_max:>{w_max}} "
        f"{h_prompt:>{w_prompt}} {h_output:>{w_output}}  {h_basis}",
    ]
    for c in est.by_agent:
        exact = str(c.calls_exact) if c.calls_exact is not None else "-"
        lines.append(f"{c.agent:<{w_agent}} {c.model_alias:<{w_model}} {exact:>{w_exact}} {c.calls_typical:>{w_typ}} {c.calls_max:>{w_max}} "
                     f"{c.prompt_tokens_typical:>{w_prompt},} {c.output_tokens_typical:>{w_output},}  {c.basis}")
    lines.append("")
    if est.max_model_calls is not None:
        cap = f" (max_model_calls={est.max_model_calls})"
    else:
        cap = f" ({bi('沒有 max_model_calls', 'no max_model_calls')})"
    lines.append(f"{bi('模型呼叫', 'Model calls')}: "
                 + bi(f"精確 {est.calls_exact} + 情境 → 典型 {est.calls_typical}，最大 {est.calls_max}",
                      f"exact {est.calls_exact} + scenario → typical {est.calls_typical}, max {est.calls_max}") + cap)
    lines.append(f"{bi('Token（典型）', 'Tokens (typical)')}: "
                 + bi(f"提示 {est.prompt_tokens_typical:,}，輸出 {est.output_tokens_typical:,}",
                      f"prompt {est.prompt_tokens_typical:,}, output {est.output_tokens_typical:,}"))
    for alias, row in est.by_model.items():
        cost = f", ~${row['cost_usd']:.4f}" if "cost_usd" in row else ""
        calls_t, calls_m = int(row['calls_typical']), int(row['calls_max'])
        prompt_t, output_t = int(row['prompt_tokens']), int(row['output_tokens'])
        lines.append(f"  {alias:<12} "
                     + bi(f"呼叫 {calls_t}（最大 {calls_m}），提示 {prompt_t:,}，輸出 {output_t:,}",
                          f"calls {calls_t} (max {calls_m}), prompt {prompt_t:,}, output {output_t:,}") + cost)
    if est.estimated_cost_usd is not None:
        lines.append(f"{bi('預估費用（僅計有定價的模型）', 'Estimated cost (priced models only)')}: ~${est.estimated_cost_usd:.4f}")
    if est.mutation_sandbox_runs_max is not None:
        lines.append(f"{bi('突變測試', 'Mutation testing')}: "
                     + bi(f"最多 {est.mutation_sandbox_runs_max} 個變異體，每個一次沙盒批次（不呼叫模型）；實際數量要等第 3 階段有通過的測試才知道",
                          f"up to {est.mutation_sandbox_runs_max} mutant(s), one sandbox batch each (no model call); the real number is known only after Phase 3 has passing tests"))
    for w in est.warnings:
        lines.append(f"[!] {w}")
    lines.append(bi("沒有呼叫任何模型。典型／最大數字是情境推估；精確數字是第 2 與第 4 階段實際會花費的。",
                    "No model was called. Typical/max figures are scenarios; exact figures are what Phase 2 and Phase 4 will spend."))
    return lines
