"""品質閘門：由一次執行的證據決定判定結果、證據缺口與建議。

只有已執行的證據（實際執行的測試、確定性規則命中）能讓判定結果成為 NEEDS_FIXES 或
BLOCKED_CRITICAL_RISK；模型發現與建模出的威脅在測試確認之前都只是假設。證據缺口使
READY_TO_SHIP 不成立。`evaluate` 是純函式：不做 I/O、不印出任何東西、不拋出例外。
The quality gate: decides a run's verdict, evidence gaps and recommendations from that run's evidence.

Only executed evidence (tests that actually ran, deterministic rule hits) can make the verdict NEEDS_FIXES or
BLOCKED_CRITICAL_RISK; model findings and modeled threats are hypotheses until a test confirms them. Evidence
gaps forbid READY_TO_SHIP. `evaluate` is pure: no I/O, no printing, no exceptions."""
import os
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Sequence

from vibeharness.core.baseline import Baseline, compare_with_baseline
from vibeharness.core.i18n import bi
from vibeharness.core.llm_gateway import budget_exhausted_calls, cache_miss_calls, invalid_calls, simulated_calls
from vibeharness.core.models import (
    AgentCallRecord, BaselineSuppressedItem, FindingSeverity, MutationReport, ReviewFinding, StaticFinding,
    GeneratedTest, TestExecutionResult, ThreatModelReport,
)
from vibeharness.core.verdict import Verdict


class GapCode(str, Enum):
    """證據缺口的穩定代碼。宣告順序就是缺口在報告與 --summary-json 中的順序。
    Stable evidence-gap codes. The declaration order is the order of the gaps in the reports and --summary-json."""
    BUDGET_EXHAUSTED = "budget_exhausted"
    CACHE_MISS = "cache_miss"
    SIMULATED = "simulated"
    INVALID_OUTPUT = "invalid_output"
    FINDINGS_WITHOUT_MODEL_TESTS = "findings_without_model_tests"
    REVIEW_INTEGRITY = "review_integrity"
    NO_REVIEWERS = "no_reviewers"
    SINGLE_REVIEWER_MODEL = "single_reviewer_model"
    NO_SYMBOLS = "no_symbols"
    PARSE_FAILURES = "parse_failures"
    INCOMPLETE_SCAN = "incomplete_scan"
    OVERSIZED_FILES = "oversized_files"
    MAX_FILES_SKIPPED = "max_files_skipped"
    TESTS_NOT_RUN = "tests_not_run"
    MUTATION_NO_CONCLUSION = "mutation_no_conclusion"
    MUTATION_BELOW_THRESHOLD = "mutation_below_threshold"
    MUTATION_TRUNCATED = "mutation_truncated"
    JS_NO_TESTS = "js_no_tests"
    JS_TESTS_NOT_RUN = "js_tests_not_run"
    TS_TESTS_NOT_RUN = "ts_tests_not_run"
    UNSUPPORTED_LANGUAGES = "unsupported_languages"
    CONFIG_FILES_NOT_SCANNED = "config_files_not_scanned"
    UNCLASSIFIED_BLACKBOX_FAILURES = "unclassified_blackbox_failures"
    NO_WHITEBOX_TESTS = "no_whitebox_tests"
    NO_THREATS = "no_threats"
    UNTESTED_THREATS = "untested_threats"


_GAP_ORDER = {code: i for i, code in enumerate(GapCode)}


@dataclass(frozen=True)
class EvidenceGap:
    """使 READY_TO_SHIP 不成立、但本身不證明有缺陷的理由。
    A reason that forbids READY_TO_SHIP without itself proving a defect."""
    code: GapCode
    message: str  # 雙語 ／ bilingual


@dataclass(frozen=True)
class GateLimits:
    """閘門訊息引用的設定值；mutation_min_score 也決定突變分數是否構成缺口。
    Settings the gate's messages quote; mutation_min_score also decides whether a mutation score is a gap."""
    max_model_calls: Optional[int] = None
    max_files: int = 0
    max_file_bytes: int = 0
    mutation_min_score: float = 0.0


@dataclass(frozen=True)
class ReviewEvidence:
    """白箱模型審查留下的事實。
    What the white-box model review left behind."""
    reviewers_configured: bool = True
    reviewer_models: Sequence[str] = ()
    arbitration_applied: bool = False
    confirmed_findings: Sequence[ReviewFinding] = ()
    findings_without_model_tests: Sequence[str] = ()


@dataclass(frozen=True)
class ScopeDisclosure:
    """哪些檔案沒有被完整分析，以及為什麼。
    Which files were not fully analyzed, and why."""
    symbols_found: bool = True
    detected_langs: Sequence[str] = ()
    parse_failures: Sequence[str] = ()
    oversized_files: Sequence[str] = ()
    skipped_files: Sequence[str] = ()
    unsupported_count: int = 0
    unsupported_languages: Dict[str, int] = field(default_factory=dict)
    unsupported_files: Sequence[str] = ()  # 樣本 ／ a sample
    incomplete_files: Sequence[str] = ()
    config_files_not_fully_scanned: Sequence[str] = ()


@dataclass(frozen=True)
class ExecutionEvidence:
    """產生並執行的測試，以及使它們無法執行的執行環境問題。
    The generated and executed tests, and the runtime problems that kept them from running."""
    wb_tests: Sequence[GeneratedTest] = ()
    bb_tests: Sequence[GeneratedTest] = ()
    wb_results: Sequence[TestExecutionResult] = ()
    bb_results: Sequence[TestExecutionResult] = ()
    js_runner_problem: Optional[str] = None
    ts_problem: Optional[str] = None
    mutation_report: Optional[MutationReport] = None


@dataclass(frozen=True)
class GateEvidence:
    target_dir: str
    threat_report: ThreatModelReport
    baseline: Optional[Baseline] = None
    limits: GateLimits = GateLimits()
    call_log: Sequence[AgentCallRecord] = ()
    review: ReviewEvidence = ReviewEvidence()
    scope: ScopeDisclosure = ScopeDisclosure()
    static_findings: Sequence[StaticFinding] = ()
    execution: ExecutionEvidence = ExecutionEvidence()
    untested_threats: Sequence[str] = ()


@dataclass(frozen=True)
class GateResult:
    verdict: Verdict
    gaps: List[EvidenceGap]
    recommendations: List[str]
    # 計入判定結果的數字：有 --baseline 時只算新的 ／ What counts toward the verdict: only new ones with --baseline
    whitebox_failed: int
    breaches: int
    blocking_rule_hits: List[StaticFinding]
    suppressed: List[BaselineSuppressedItem]

    @property
    def reasons(self) -> List[str]:
        return [gap.message for gap in self.gaps]


def evaluate(evidence: GateEvidence) -> GateResult:
    gaps = sorted(_evidence_gaps(evidence), key=lambda gap: _GAP_ORDER[gap.code])
    ex = evidence.execution
    wb_results, bb_results = list(ex.wb_results), list(ex.bb_results)

    blocking_rule_hits = [
        f for f in evidence.static_findings if f.severity in (FindingSeverity.CRITICAL, FindingSeverity.HIGH)
    ]
    whitebox_failed = sum(1 for r in wb_results if r.is_failure)
    breaches = sum(1 for r in bb_results if r.is_security_exploit_confirmed)
    # --baseline：只有先前報告未包含的問題才決定判定結果；已知的
    # 問題仍留在表格中，並列於「Known from baseline」之下
    # --baseline: only problems the previous report did not contain decide the verdict; the known
    # ones stay in the tables and are listed under "Known from baseline"
    gate_wb_results, gate_bb_results = wb_results, bb_results
    suppressed: List[BaselineSuppressedItem] = []
    if evidence.baseline is not None:
        comparison = compare_with_baseline(
            evidence.baseline, evidence.target_dir, blocking_rule_hits, wb_results,
            list(evidence.review.confirmed_findings), bb_results, evidence.threat_report.threats
        )
        suppressed = comparison.suppressed
        blocking_rule_hits = comparison.new_static_blocking
        known_ids = {s.id for s in suppressed if s.kind != "static"}
        gate_wb_results = [r for r in wb_results if not (r.is_failure and r.test_id in known_ids)]
        gate_bb_results = [r for r in bb_results if not (r.is_security_exploit_confirmed and r.test_id in known_ids)]
        whitebox_failed = len(comparison.new_whitebox_failures)
        breaches = len(comparison.new_breaches)

    if breaches > 0:
        verdict = Verdict.BLOCKED_CRITICAL_RISK
    elif whitebox_failed > 0 or blocking_rule_hits:
        verdict = Verdict.NEEDS_FIXES
    elif gaps:
        verdict = Verdict.INCONCLUSIVE
    else:
        verdict = Verdict.READY_TO_SHIP

    recommendations = _recommendations(
        gate_wb_results, gate_bb_results, evidence.threat_report, list(evidence.untested_threats), bool(gaps),
        blocking_rule_hits
    )
    survivors = [m for m in (ex.mutation_report.mutants if ex.mutation_report else []) if m.status == "survived"]
    if survivors:
        where = ", ".join(f"{m.file}:{m.line}" for m in survivors[:3])
        recommendations.append(bi(
            f"在 {where} 等位置補強斷言，讓測試抓得到這 {len(survivors)} 個存活的變異（把運算子或常數改掉測試仍通過）",
            f"Strengthen the assertions around {where} so the tests catch these {len(survivors)} surviving mutant(s) "
            "(the tests still pass when an operator or constant is changed)"
        ))
    if suppressed:
        recommendations.append(
            bi(f"基準中已有的 {len(suppressed)} 個問題不計入；它們仍然存在",
               f"{len(suppressed)} problem(s) already in the baseline were not counted; they are still present")
            + ": " + ", ".join(f"`{s.id}`" for s in suppressed)
        )
    return GateResult(
        verdict=verdict, gaps=gaps, recommendations=recommendations, whitebox_failed=whitebox_failed,
        breaches=breaches, blocking_rule_hits=blocking_rule_hits, suppressed=suppressed,
    )


def _evidence_gaps(evidence: GateEvidence) -> List[EvidenceGap]:
    """使 READY_TO_SHIP 判定結果不成立的證據缺口。
    Evidence gaps that forbid a READY_TO_SHIP verdict."""
    gaps: List[EvidenceGap] = []

    def gap(code: GapCode, message: str) -> None:
        gaps.append(EvidenceGap(code, message))

    call_log = list(evidence.call_log)
    limits, review, scope, ex = evidence.limits, evidence.review, evidence.scope, evidence.execution

    budget_hits = budget_exhausted_calls(call_log)
    if budget_hits:
        gap(GapCode.BUDGET_EXHAUSTED, bi(
            f"max_model_calls 預算（{limits.max_model_calls}）已用盡；之後的 {len(budget_hits)} 次代理呼叫改用模擬引擎而非真實模型",
            f"The max_model_calls budget ({limits.max_model_calls}) was exhausted; "
            f"{len(budget_hits)} later agent call(s) used the simulation engine instead of a real model"
        ))
    cache_misses = cache_miss_calls(call_log)
    if cache_misses:
        gap(GapCode.CACHE_MISS, bi(
            f"--cache-only：{len(cache_misses)} 次代理呼叫在回應快取中沒有答案，未呼叫任何模型，改用模擬引擎",
            f"--cache-only: {len(cache_misses)} agent call(s) had no answer in the response cache; no model "
            "was called and the simulation engine was used instead"
        ))
    simulated = simulated_calls(call_log)
    if simulated:
        simulated_agents = sorted({rec.agent_id for rec in simulated})
        gap(GapCode.SIMULATED,
            bi("以下代理使用了模擬引擎（非真實模型）", "Simulation engine (not real models) was used for")
            + f": {', '.join(simulated_agents)}")
    invalid = invalid_calls(call_log)
    if invalid:
        # 每個代理與原因各一筆：當機的批次與格式錯誤的回答讀起來不同
        # One entry per agent and reason: a crashed batch reads differently from a malformed answer
        invalid_details = sorted({f"{rec.agent_id} ({rec.reason})" if rec.reason else rec.agent_id for rec in invalid})
        gap(GapCode.INVALID_OUTPUT, bi(
            f"{len(invalid)} 次模型呼叫回傳了無法使用的輸出，或在回答前就崩潰（無效的 JSON／欄位缺漏，或批次中發生例外）",
            f"{len(invalid)} model call(s) returned unusable output or crashed before answering "
            f"(invalid JSON / missing fields, or an exception in the batch)"
        ) + f": {'; '.join(invalid_details)}")
    unmodeled_findings = list(review.findings_without_model_tests)
    if unmodeled_findings:
        # 沒有套用跨模型驗證時，這些發現只是未經驗證的假設，不能稱為「已確認」
        # Without cross-model verification these findings are unverified hypotheses and must not be called "confirmed"
        kind_zh, kind_en = ("已確認", "confirmed") if review.arbitration_applied else ("未經驗證", "unverified")
        gap(GapCode.FINDINGS_WITHOUT_MODEL_TESTS, bi(
            f"{len(unmodeled_findings)} 筆{kind_zh}的發現沒有可用的模型產生測試，只由確定性探針涵蓋，而非針對該缺陷的測試",
            f"{len(unmodeled_findings)} {kind_en} finding(s) had no usable model-generated test and were only "
            f"covered by deterministic probes, not by a test targeting the defect"
        ) + f": {', '.join(unmodeled_findings)}")
    integrity_hits = [f for f in evidence.static_findings if f.affects_review_integrity]
    if integrity_hits:
        integrity_rules = ', '.join(sorted({f.rule_id for f in integrity_hits}))
        gap(GapCode.REVIEW_INTEGRITY, bi(
            f"目標中發現 {len(integrity_hits)} 處針對審查者的指示或不可見字元序列（{integrity_rules}）；"
            "以模型為基礎的審查、驗證與威脅建模可能遭到操弄（OWASP LLM01:2026），請人工檢視那些位置",
            f"{len(integrity_hits)} reviewer-directed instruction(s) or invisible-character sequence(s) were found in "
            f"the target ({integrity_rules}); model-based review, verification "
            "and threat modeling may have been manipulated (OWASP LLM01:2026), so review those locations manually"
        ))
    if not review.reviewers_configured:
        gap(GapCode.NO_REVIEWERS, bi("沒有設定任何 whitebox_reviewer_* 代理，因此沒有執行白箱模型審查",
                                     "No whitebox_reviewer_* agents are configured, so no white-box model review ran"))
    elif len(review.reviewer_models) < 2:
        # 同一模型的副本意見一致只是一致性，而非交叉佐證（OWASP LLM07:2026）
        # Copies of one model agreeing is consistency, not corroboration (OWASP LLM07:2026)
        gap(GapCode.SINGLE_REVIEWER_MODEL, bi(
            f"只設定了一個不同的審查模型（{review.reviewer_models[0]}），因此跨模型驗證無法執行；這些發現是未經過濾的單一模型假設",
            f"Only one distinct reviewer model ({review.reviewer_models[0]}) is configured, so cross-model verification "
            "could not run; the findings are unfiltered single-model hypotheses"
        ))
    if not scope.symbols_found:
        gap(GapCode.NO_SYMBOLS, bi("目標中找不到可分析的原始碼符號", "No analyzable source symbols were found in the target"))
    if scope.parse_failures:
        n_fail = len(scope.parse_failures)
        gap(GapCode.PARSE_FAILURES, bi(
            f"{n_fail} 個原始碼檔案無法解析，未納入分析",
            f"{n_fail} source file(s) could not be parsed and were not analyzed"
        ))
    if scope.incomplete_files:
        # 確定性規則在這些檔案上超時或出錯而提前停止：缺的命中不能當成「乾淨」
        # The deterministic rules stopped early on these files (time cap or error): missing hits are not "clean"
        n_inc = len(scope.incomplete_files)
        gap(GapCode.INCOMPLETE_SCAN, bi(
            f"{n_inc} 個原始碼檔案的確定性 AI 安全規則未能完整掃描（逾時或出錯）",
            f"The deterministic AI security rules could not fully scan {n_inc} source file(s) (time cap or error)"
        ))
    if scope.oversized_files:
        n_big = len(scope.oversized_files)
        gap(GapCode.OVERSIZED_FILES, bi(
            f"{n_big} 個原始碼檔案超過 max_file_bytes（{limits.max_file_bytes}），未納入分析",
            f"{n_big} source file(s) exceed max_file_bytes ({limits.max_file_bytes}) and were not analyzed"
        ) + f": {', '.join(os.path.basename(p) for p in list(scope.oversized_files)[:5])}")
    if scope.skipped_files:
        n_skip = len(scope.skipped_files)
        gap(GapCode.MAX_FILES_SKIPPED, bi(
            f"{n_skip} 個原始碼檔案因 max_files 上限（{limits.max_files}）而被略過",
            f"{n_skip} source file(s) were skipped by the max_files limit ({limits.max_files})"
        ))
    errored = sum(1 for r in list(ex.wb_results) + list(ex.bb_results) if r.is_not_run)
    if errored:
        gap(GapCode.TESTS_NOT_RUN, bi(
            f"{errored} 個產生的測試發生錯誤、被略過或從未執行；它們涵蓋的邊界在這次執行中仍未驗證",
            f"{errored} generated test(s) errored, were skipped, or never ran; "
            "the boundaries they cover remain unverified by this run"
        ))
    mutation_report = ex.mutation_report
    if mutation_report is not None:
        min_score = limits.mutation_min_score
        if mutation_report.skipped_reason and mutation_report.score is None:
            gap(GapCode.MUTATION_NO_CONCLUSION, bi(
                "已要求突變測試但沒有結論，通過的測試是否抓得到行為改變仍未驗證",
                "Mutation testing was requested but has no conclusion, so whether the passing tests catch behaviour changes is unverified"
            ) + f": {mutation_report.skipped_reason}")
        elif mutation_report.score is not None and mutation_report.score < min_score:
            gap(GapCode.MUTATION_BELOW_THRESHOLD, bi(
                f"突變測試分數 {mutation_report.score:.1f}% 低於門檻 {min_score:g}%：{mutation_report.survived} 個存活的變異體表示通過的測試可能抓不到行為改變",
                f"Mutation score {mutation_report.score:.1f}% is below the {min_score:g}% threshold: {mutation_report.survived} surviving mutant(s) "
                "mean the passing tests may not catch behaviour changes"
            ))
        if mutation_report.truncated:
            gap(GapCode.MUTATION_TRUNCATED, bi(
                f"突變測試只涵蓋 {mutation_report.total} 個變異體（候選 {mutation_report.candidate_sites} 個，受 mutation_max_mutants 限制），分數只是樣本",
                f"Mutation testing covered {mutation_report.total} mutant(s) of {mutation_report.candidate_sites} candidates "
                "(limited by mutation_max_mutants), so the score is a sample"
            ))
    js_tests = [t for t in list(ex.wb_tests) + list(ex.bb_tests) if t.language != "python"]
    if "TypeScript/JavaScript" in scope.detected_langs:
        if not js_tests:
            gap(GapCode.JS_NO_TESTS, bi(
                "TypeScript/JavaScript 程式碼只做了靜態審查：沒有為它產生任何 JS/TS 測試",
                "TypeScript/JavaScript code was reviewed statically only: no JS/TS test was generated for it"
            ))
        elif ex.js_runner_problem:
            gap(GapCode.JS_TESTS_NOT_RUN, bi(
                f"已產生 {len(js_tests)} 個 JS/TS 測試但無法執行：{ex.js_runner_problem}；TypeScript/JavaScript 程式碼只做了靜態審查",
                f"{len(js_tests)} JS/TS test(s) were generated but could not run: {ex.js_runner_problem}; "
                "TypeScript/JavaScript code was reviewed statically only"
            ))
        elif ex.ts_problem and any(t.language == "typescript" for t in js_tests):
            gap(GapCode.TS_TESTS_NOT_RUN,
                bi("已產生 TypeScript 測試但未執行", "TypeScript tests were generated but not run")
                + f": {ex.ts_problem}")
    if scope.unsupported_count:
        # 擷取器只支援 Python 與 JS/TS：其他語言的原始碼完全沒有被審查或測試，不能當成「乾淨」
        # The extractor only supports Python and JS/TS: source in other languages was neither reviewed nor
        # tested, so it cannot count as "clean"
        n_uns = scope.unsupported_count
        langs = ", ".join(f"{lang}: {n}" for lang, n in sorted(scope.unsupported_languages.items()))
        gap(GapCode.UNSUPPORTED_LANGUAGES, bi(
            f"{n_uns} 個不支援語言的原始碼檔案（{langs}）未納入分析",
            f"{n_uns} source file(s) in unsupported languages ({langs}) were not analyzed"
        ) + f": {', '.join(os.path.basename(p) for p in list(scope.unsupported_files)[:5])}")
    n_cfg = len(scope.config_files_not_fully_scanned)
    if n_cfg:
        gap(GapCode.CONFIG_FILES_NOT_SCANNED, bi(
            f"{n_cfg} 個設定類檔案未完整做密鑰掃描（超過數量上限、max_file_bytes 或時間上限）",
            f"{n_cfg} configuration-like file(s) were not fully secret-scanned "
            "(file-count cap, max_file_bytes or time cap)"
        ))
    # 不符合嚴格利用判定條件的 FAILED 攻擊測試屬於模糊證據，不可悄悄地從閘門中消失
    # A FAILED attack test that does not match the strict exploit predicate is ambiguous evidence and must not
    # silently disappear from the gate
    unclassified = [r for r in ex.bb_results if r.is_unclassified_failure]
    if unclassified:
        gap(GapCode.UNCLASSIFIED_BLACKBOX_FAILURES, bi(
            f"{len(unclassified)} 個黑箱攻擊測試失敗，但沒有確認的利用分類；證據不明確，需要人工調查",
            f"{len(unclassified)} black-box attack test(s) failed without a confirmed exploit "
            f"classification; the evidence is ambiguous and needs manual investigation"
        ) + f": {', '.join(r.test_id for r in unclassified)}")
    if not ex.wb_results:
        gap(GapCode.NO_WHITEBOX_TESTS, bi("沒有執行任何白箱測試", "No white-box tests were executed"))
    if not evidence.threat_report.threats:
        gap(GapCode.NO_THREATS, bi("威脅建模沒有產生任何威脅，因此黑箱涵蓋範圍未知",
                                   "Threat modeling produced no threats, so black-box coverage is unknown"))
    if evidence.untested_threats:
        gap(GapCode.UNTESTED_THREATS, bi(
            f"{len(evidence.untested_threats)} 個已建模的威脅沒有可執行的測試",
            f"{len(evidence.untested_threats)} modeled threat(s) have no executable test"
        ) + f": {', '.join(evidence.untested_threats)}")
    return gaps


def _recommendations(
    wb_results: List[TestExecutionResult],
    bb_results: List[TestExecutionResult],
    threat_report: ThreatModelReport,
    untested_threats: List[str],
    has_gaps: bool,
    blocking_rule_hits: List[StaticFinding],
) -> List[str]:
    """由本次執行的證據推導出的建議，最緊急者優先。
    Recommendations derived from this run's evidence, most urgent first."""
    recs: List[str] = []
    threats_by_id = {t.threat_id: t for t in threat_report.threats}
    for r in bb_results:
        if r.is_security_exploit_confirmed:
            threat = threats_by_id.get(r.source_ref or "")
            label = f"{threat.threat_id} {threat.title}" if threat else r.test_id
            recs.append(bi(f"修正已確認的資安突破 `{r.test_id}`（{label}）",
                           f"Fix confirmed security breach `{r.test_id}` ({label})") + f": {r.failure_reason}")
    for f in blocking_rule_hits:
        location = f"`{os.path.basename(f.file_path)}:{f.line_number}`"
        recs.append(bi(f"修正 `{f.rule_id}` {f.title}，位於 {location}（{f.owasp_mapping}）",
                       f"Fix `{f.rule_id}` {f.title} at {location} ({f.owasp_mapping})") + f": {f.remediation}")
    for r in wb_results:
        if r.is_failure:
            recs.append(bi(f"修正 `{r.test_id}` 暴露的缺陷（來自 `{r.source_ref or '-'}`）",
                           f"Fix defect exposed by `{r.test_id}` (from `{r.source_ref or '-'}`)") + f": {r.failure_reason}")
    for r in bb_results:
        if r.is_unclassified_failure:
            recs.append(bi(f"調查 `{r.test_id}` 中的黑箱崩潰", f"Investigate black-box crash in `{r.test_id}`") + f": {r.failure_reason}")
    if untested_threats:
        recs.append(bi("為未測試的威脅撰寫或合成測試", "Write or synthesize tests for untested threats") + f": {', '.join(untested_threats)}")
    if has_gaps:
        recs.append(bi("在信任通過判定之前，先補上上方列出的證據缺口（例如以 `--mode live` 與有效的 API 金鑰執行）。",
                       "Close the evidence gaps listed above (e.g. run with `--mode live` and valid API keys) before trusting a pass verdict."))
    if not recs:
        recs.append(bi("已執行的測試未暴露任何缺陷；請把這些測試留在 CI 中作為回歸防護。",
                       "No defects were exposed by the executed tests; keep these tests in CI as regression guards."))
    return recs
