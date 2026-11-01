"""證據計數（GLOSSARY：Evidence tally）：一次執行裡決定判定結果的項目，依種類只算一次，每一種都分成全部、新的與已知問題。
品質閘門、console 與 summary 都讀這一份，不再各自計數。
The Evidence tally (GLOSSARY): what decides one run's Verdict, counted once by kind, each kind split into all, new and
Known problems. The Quality Gate, the console and the summary all read this one instead of counting for themselves."""
from dataclasses import dataclass
from typing import Generic, Optional, Sequence, Tuple, TypeVar

from vibeharness.core.baseline import Baseline, compare_with_baseline
from vibeharness.core.models import (
    BaselineSuppressedItem, FindingSeverity, GeneratedTest, ReviewFinding, StaticFinding, TestExecutionResult, ThreatItem,
)

T = TypeVar("T")
# 這些嚴重度的確定性規則命中會阻擋 ／ Deterministic rule hits of these severities block
_BLOCKING_SEVERITIES = (FindingSeverity.CRITICAL, FindingSeverity.HIGH)


@dataclass(frozen=True)
class Split(Generic[T]):
    """一種計數的三份清單，都保持輸入時的順序：全部、新的（決定判定結果）、已知問題（沒有基準時是空的）。
    One kind's three lists, each in input order: all, new (these decide the Verdict) and Known problems (empty without
    a Baseline)."""
    all: Tuple[T, ...]
    new: Tuple[T, ...]
    known: Tuple[T, ...]


@dataclass(frozen=True)
class EvidenceTally:
    """一次執行的證據計數。
    One run's Evidence tally."""
    breaches: Split[TestExecutionResult]
    whitebox_failures: Split[TestExecutionResult]
    unclassified_failures: Split[TestExecutionResult]
    whitebox_not_run: Split[TestExecutionResult]
    blackbox_not_run: Split[TestExecutionResult]
    blocking_rule_hits: Split[StaticFinding]
    untested_threats: Split[str]  # 威脅 id ／ threat ids
    # 報告列出的已知問題，順序與 compare_with_baseline 相同 ／ The Known problems as the reports list them, in compare_with_baseline's order
    suppressed: Tuple[BaselineSuppressedItem, ...] = ()


def _unsplit(items: Sequence[T]) -> Split[T]:
    # 基準不記錄這一種：全部都是新的 ／ The Baseline does not record this kind: all of it is new
    return Split(all=tuple(items), new=tuple(items), known=())


def _split(items: Sequence[T], new: Sequence[T]) -> Split[T]:
    # 依物件本身比對，保持輸入順序 ／ Compared by identity, keeping input order
    new_ids = {id(x) for x in new}
    return Split(all=tuple(items), new=tuple(x for x in items if id(x) in new_ids),
                 known=tuple(x for x in items if id(x) not in new_ids))


def tally_evidence(*, wb_results: Sequence[TestExecutionResult] = (),
                   bb_results: Sequence[TestExecutionResult] = (),
                   static_findings: Sequence[StaticFinding] = (),
                   bb_tests: Sequence[GeneratedTest] = (),
                   threats: Sequence[ThreatItem] = (),
                   confirmed_findings: Sequence[ReviewFinding] = (),
                   target_dir: str = "",
                   baseline: Optional[Baseline] = None) -> EvidenceTally:
    """由目前已有的結果建出證據計數；沒傳入的結果當作還沒有。
    Build the Evidence tally from the results available so far; results not passed in count as not there yet."""
    breaches = [r for r in bb_results if r.is_security_exploit_confirmed]
    wb_failures = [r for r in wb_results if r.is_failure]
    blocking = [f for f in static_findings if f.severity in _BLOCKING_SEVERITIES]
    tested_threat_ids = {t.source_ref for t in bb_tests}
    if baseline is None:
        new_breaches, new_wb_failures, new_blocking = breaches, wb_failures, blocking
        suppressed: Tuple[BaselineSuppressedItem, ...] = ()
    else:
        # 只有這裡呼叫基準比對 ／ The only caller of the baseline comparison
        comparison = compare_with_baseline(baseline, target_dir, blocking, list(wb_results), list(confirmed_findings),
                                           list(bb_results), list(threats))
        new_breaches, new_wb_failures = comparison.new_breaches, comparison.new_whitebox_failures
        new_blocking, suppressed = comparison.new_static_blocking, tuple(comparison.suppressed)
    return EvidenceTally(
        breaches=_split(breaches, new_breaches),
        whitebox_failures=_split(wb_failures, new_wb_failures),
        unclassified_failures=_unsplit([r for r in bb_results if r.is_unclassified_failure]),
        whitebox_not_run=_unsplit([r for r in wb_results if r.is_not_run]),
        blackbox_not_run=_unsplit([r for r in bb_results if r.is_not_run]),
        blocking_rule_hits=_split(blocking, new_blocking),
        untested_threats=_unsplit([t.threat_id for t in threats if t.threat_id not in tested_threat_ids]),
        suppressed=suppressed,
    )
