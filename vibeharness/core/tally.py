"""證據計數（GLOSSARY：Evidence tally）：一次執行裡決定判定結果的項目，依種類只算一次，每一種都分成全部、新的與已知問題。
品質閘門與 summary 讀一次執行的完整計數；console 在第 3、5 階段讀只含當時結果的部分計數。
The Evidence tally (GLOSSARY): what decides one run's Verdict, counted once by kind, each kind split into all, new and
Known problems. The Quality Gate and the summary read the run's full tally; the console reads partial tallies of the
results available in phases 3 and 5."""
import os
from dataclasses import dataclass
from typing import AbstractSet, Callable, Dict, Generic, List, Optional, Sequence, Tuple, TypeVar

from vibeharness.core.baseline import Baseline
from vibeharness.core.identity import breach_key, static_key, whitebox_failure_key
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
    # 報告列出的已知問題（規則命中、白箱失敗、資安突破） ／ The Known problems as the reports list them (rule hits, white-box failures, Breaches)
    known_problems: Tuple[BaselineSuppressedItem, ...] = ()


def _unsplit(items: Sequence[T]) -> Split[T]:
    # 基準不記錄這一種（或沒有基準）：全部都是新的 ／ The Baseline does not record this kind (or no Baseline): all of it is new
    return Split(all=tuple(items), new=tuple(items), known=())


def _partition(
    items: Sequence[T],
    known_keys: AbstractSet[str],
    kind: str,
    describe: Callable[[T], Tuple[Optional[str], str, str]],
    suppressed: List[BaselineSuppressedItem],
) -> Split[T]:
    """依基準鍵集將一組證據拆成 `Split(all, new, known)`，並將命中的已知項目加入 `suppressed`。
    Partitions `items` into `Split(all, new, known)` against `known_keys`, appending matched items to `suppressed`."""
    new_items: List[T] = []
    known_items: List[T] = []
    for item in items:
        key, item_id, title = describe(item)
        if key is not None and key in known_keys:
            known_items.append(item)
            suppressed.append(BaselineSuppressedItem(kind=kind, id=item_id, title=title, fingerprint=key))
        else:
            new_items.append(item)
    return Split(all=tuple(items), new=tuple(new_items), known=tuple(known_items))


def _split_blocking(
    baseline: Baseline,
    target_dir: str,
    blocking: Sequence[StaticFinding],
    wb_failures: Sequence[TestExecutionResult],
    confirmed_findings: Sequence[ReviewFinding],
    breaches: Sequence[TestExecutionResult],
    threats: Sequence[ThreatItem],
) -> Tuple[Split[StaticFinding], Split[TestExecutionResult], Split[TestExecutionResult], Tuple[BaselineSuppressedItem, ...]]:
    """依基準線一次分開規則命中、白箱失敗與資安突破的新舊項目，並建出已知問題清單。
    Splits blocking rule hits, white-box failures and Breaches into new and known against the Baseline in one pass,
    and builds the Known problems list."""
    suppressed: List[BaselineSuppressedItem] = []
    findings_by_id: Dict[str, ReviewFinding] = {f.finding_id: f for f in confirmed_findings}
    threats_by_id: Dict[str, ThreatItem] = {t.threat_id: t for t in threats}

    def _wb_desc(r: TestExecutionResult) -> Tuple[Optional[str], str, str]:
        finding = findings_by_id.get(r.source_ref or "")
        title = finding.title if finding else (r.failure_reason or r.test_id)
        return whitebox_failure_key(r, finding, target_dir), r.test_id, title

    def _bb_desc(r: TestExecutionResult) -> Tuple[Optional[str], str, str]:
        threat = threats_by_id.get(r.source_ref or "")
        return breach_key(r, threat), r.test_id, (threat.title if threat else r.test_id)

    return (
        _partition(blocking, baseline.static, "static",
                   lambda sf: (static_key(sf, target_dir),
                               f"{sf.rule_id}@{os.path.basename(sf.file_path)}:{sf.line_number}", sf.title),
                   suppressed),
        _partition(wb_failures, baseline.findings, "whitebox_failure", _wb_desc, suppressed),
        _partition(breaches, baseline.breaches, "breach", _bb_desc, suppressed),
        tuple(suppressed),
    )


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
        blocking_split = _unsplit(blocking)
        wb_split = _unsplit(wb_failures)
        breaches_split = _unsplit(breaches)
        known_problems: Tuple[BaselineSuppressedItem, ...] = ()
    else:
        blocking_split, wb_split, breaches_split, known_problems = _split_blocking(
            baseline, target_dir, blocking, wb_failures, confirmed_findings, breaches, threats,
        )
    return EvidenceTally(
        breaches=breaches_split,
        whitebox_failures=wb_split,
        unclassified_failures=_unsplit([r for r in bb_results if r.is_unclassified_failure]),
        whitebox_not_run=_unsplit([r for r in wb_results if r.is_not_run]),
        blackbox_not_run=_unsplit([r for r in bb_results if r.is_not_run]),
        blocking_rule_hits=blocking_split,
        untested_threats=_unsplit([t.threat_id for t in threats if t.threat_id not in tested_threat_ids]),
        known_problems=known_problems,
    )
