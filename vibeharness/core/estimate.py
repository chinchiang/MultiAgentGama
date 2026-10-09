"""`--estimate`: how many model calls and roughly how many tokens a run would need, without making any.

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
from vibeharness.core.models import CodeSymbol

# Prompt overhead beyond the code listing (system prompt, schema, guidance) and typical answer sizes,
# in estimated tokens. Answer sizes are what live runs produced on average; the real cap is
# max_output_tokens, which is a ceiling, not a spend.
_OVERHEAD = {"reviewer": 450, "verifier": 350, "test_generator": 700, "heal": 300, "threat_modeler": 2200, "synthesizer": 900}
_TYPICAL_OUTPUT = {"reviewer": 1500, "verifier": 600, "test_generator": 1500, "heal": 1200, "threat_modeler": 2500, "synthesizer": 1500}
_VERIFIER_LISTING_TOKENS = MultiModelDebater.LISTING_MAX_TOKENS
_VERIFIER_CODE_TOKENS = MultiModelDebater.CODE_CONTEXT_TOKENS
_PER_FINDING_CODE_TOKENS = 4000  # test_generator / scenario_builder CODE_CONTEXT_TOKENS
_HEAL_ATTEMPTS_MAX = 2


class CallEstimate(BaseModel):
    """One agent kind's share of the run."""
    agent: str
    model_alias: str
    calls_exact: Optional[int] = None  # known before the run (reviewers, threat modeling)
    calls_typical: int = 0  # under the stated assumptions
    calls_max: int = 0  # worst case under the assumptions (heals, re-asks)
    prompt_tokens_typical: int = 0
    output_tokens_typical: int = 0
    basis: str = ""  # how the number was derived


class RunEstimate(BaseModel):
    target_path: str
    files_analyzed: int
    symbols: int
    whitebox_batches: int
    threat_batches: int
    assumptions: Dict[str, float] = Field(default_factory=dict)
    retry_invalid_output: int = 0
    max_model_calls: Optional[int] = None
    by_agent: List[CallEstimate] = Field(default_factory=list)
    calls_exact: int = 0
    calls_typical: int = 0
    calls_max: int = 0
    prompt_tokens_typical: int = 0
    output_tokens_typical: int = 0
    # Per model alias: calls / tokens / cost (cost only when the alias has price fields)
    by_model: Dict[str, Dict[str, float]] = Field(default_factory=dict)
    estimated_cost_usd: Optional[float] = None
    warnings: List[str] = Field(default_factory=list)


def _alias(gateway, agent_id: str) -> str:
    meta = gateway.agents_config.get(agent_id) or {}
    return str(meta.get("model_alias") or "unconfigured")


def estimate_run(
    commander, target_dir: str, findings_per_batch: float = 3.0, threats_per_batch: float = 4.0
) -> RunEstimate:
    """Phase 1 (symbol extraction, no model) plus arithmetic on the agent configuration."""
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
        retry_invalid_output=retry, max_model_calls=gateway.max_model_calls,
    )
    if filters:
        est.warnings.append("File selection applied: " + "; ".join(filters))
    if not symbols:
        est.warnings.append("No analyzable symbols: the reviewers and the test generator would make no calls")

    # 1. Reviewers: exact
    wb_listing_tokens = [estimate_tokens(render_symbols(b, work_dir, max_tokens=HeterogeneousReviewerEnsemble.BATCH_MAX_TOKENS)) for b in wb_batches]
    for reviewer in reviewers:
        calls = len(wb_batches)
        est.by_agent.append(CallEstimate(
            agent=reviewer["agent_id"], model_alias=reviewer["model_alias"], calls_exact=calls, calls_typical=calls,
            calls_max=calls * reask, prompt_tokens_typical=sum(wb_listing_tokens) + calls * _OVERHEAD["reviewer"],
            output_tokens_typical=calls * _TYPICAL_OUTPUT["reviewer"],
            basis=f"{len(wb_batches)} white-box batch(es) × 1 call",
        ))

    # 2. Findings scenario -> verifiers
    raw_findings = findings_per_batch * len(wb_batches) * len(reviewers)
    distinct = raw_findings * 0.8  # some duplicates merge
    for agent_id, alias in verifiers.items():
        # A verifier never rules on its own model's findings: it sees the share reported by other models
        own_share = sum(1 for r in reviewers if r["model_alias"] == alias) / max(len(reviewers), 1)
        assigned = distinct * (1 - own_share)
        calls = math.ceil(assigned / MultiModelDebater.FINDINGS_PER_CALL) if assigned > 0 else 0
        est.by_agent.append(CallEstimate(
            agent=agent_id, model_alias=alias, calls_typical=calls, calls_max=calls * reask,
            prompt_tokens_typical=calls * (_VERIFIER_LISTING_TOKENS + _VERIFIER_CODE_TOKENS + _OVERHEAD["verifier"]),
            output_tokens_typical=calls * _TYPICAL_OUTPUT["verifier"],
            basis=f"~{assigned:.0f} finding(s) from other models / {MultiModelDebater.FINDINGS_PER_CALL} per call",
        ))

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
        basis=f"~{confirmed:.0f} confirmed finding(s) × 1 call, + heals (typical {heal_typical}, max {_HEAL_ATTEMPTS_MAX} per test)",
    ))

    # 4. Threat modeling: exact
    tm_alias = _alias(gateway, "blackbox_threat_modeler")
    tm_listing = [estimate_tokens(render_symbols(b, work_dir, max_tokens=TM_BATCH_TOKENS)) if b else 0 for b in tm_batches]
    est.by_agent.append(CallEstimate(
        agent="blackbox_threat_modeler", model_alias=tm_alias, calls_exact=len(tm_batches), calls_typical=len(tm_batches),
        calls_max=len(tm_batches) * reask, prompt_tokens_typical=sum(tm_listing) + len(tm_batches) * _OVERHEAD["threat_modeler"],
        output_tokens_typical=len(tm_batches) * _TYPICAL_OUTPUT["threat_modeler"],
        basis=f"{len(tm_batches)} threat-model batch(es) × 1 call",
    ))

    # 5. Attack synthesis per threat
    threats = math.ceil(threats_per_batch * len(tm_batches))
    sy_alias = _alias(gateway, "blackbox_test_synthesizer")
    est.by_agent.append(CallEstimate(
        agent="blackbox_test_synthesizer", model_alias=sy_alias, calls_typical=threats, calls_max=threats * reask,
        prompt_tokens_typical=threats * (_PER_FINDING_CODE_TOKENS + _OVERHEAD["synthesizer"]),
        output_tokens_typical=threats * _TYPICAL_OUTPUT["synthesizer"],
        basis=f"~{threats} threat(s) × 1 call",
    ))

    est.calls_exact = sum(c.calls_exact or 0 for c in est.by_agent)
    est.calls_typical = sum(c.calls_typical for c in est.by_agent)
    est.calls_max = sum(c.calls_max for c in est.by_agent)
    est.prompt_tokens_typical = sum(c.prompt_tokens_typical for c in est.by_agent)
    est.output_tokens_typical = sum(c.output_tokens_typical for c in est.by_agent)

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
            est.warnings.append(f"No price configured for model alias '{alias}' (models.{alias}.price_per_million_input/_output): tokens only")
    if priced:
        est.estimated_cost_usd = round(total_cost, 4)
    if est.max_model_calls is not None and est.calls_typical > est.max_model_calls:
        est.warnings.append(
            f"max_model_calls={est.max_model_calls} is below the typical call count ({est.calls_typical}): later agents "
            "would fall back to simulation (hybrid) or fail (live)"
        )
    return est


def estimate_lines(est: RunEstimate) -> List[str]:
    """Plain-text rendering (the CLI prints it; JSON output uses the model directly)."""
    lines = [
        f"Target: {est.target_path}",
        f"Files analyzed: {est.files_analyzed} | symbols: {est.symbols} | white-box batches: {est.whitebox_batches} | threat batches: {est.threat_batches}",
        f"Assumptions: {', '.join(f'{k}={v:g}' for k, v in est.assumptions.items())}; retry_invalid_output={est.retry_invalid_output}",
        "",
        f"{'agent':<28} {'model':<12} {'exact':>6} {'typical':>8} {'max':>6} {'prompt tok':>11} {'output tok':>11}  basis",
    ]
    for c in est.by_agent:
        exact = str(c.calls_exact) if c.calls_exact is not None else "-"
        lines.append(f"{c.agent:<28} {c.model_alias:<12} {exact:>6} {c.calls_typical:>8} {c.calls_max:>6} "
                     f"{c.prompt_tokens_typical:>11,} {c.output_tokens_typical:>11,}  {c.basis}")
    lines.append("")
    lines.append(f"Model calls: exact {est.calls_exact} + scenario → typical {est.calls_typical}, max {est.calls_max}"
                 + (f" (max_model_calls={est.max_model_calls})" if est.max_model_calls is not None else " (no max_model_calls)"))
    lines.append(f"Tokens (typical): prompt {est.prompt_tokens_typical:,}, output {est.output_tokens_typical:,}")
    for alias, row in est.by_model.items():
        cost = f", ~${row['cost_usd']:.4f}" if "cost_usd" in row else ""
        lines.append(f"  {alias:<12} calls {int(row['calls_typical'])} (max {int(row['calls_max'])}), prompt {int(row['prompt_tokens']):,}, output {int(row['output_tokens']):,}{cost}")
    if est.estimated_cost_usd is not None:
        lines.append(f"Estimated cost (priced models only): ~${est.estimated_cost_usd:.4f}")
    for w in est.warnings:
        lines.append(f"[!] {w}")
    lines.append("No model was called. Typical/max figures are scenarios; exact figures are what Phase 2 and Phase 4 will spend.")
    return lines
