"""證據計數（GLOSSARY：Evidence tally）：一次執行裡決定判定結果的項目，依種類只算一次，每一種都分成全部、新的與已知問題。
品質閘門與 summary 讀一次執行的完整計數；console 在第 3、5 階段讀只含當時結果的部分計數。
The Evidence tally (GLOSSARY): what decides one run's Verdict, counted once by kind, each kind split into all, new and
Known problems. The Quality Gate and the summary read the run's full tally; the console reads partial tallies of the
results available in phases 3 and 5."""
import os
from dataclasses import dataclass
from typing import Dict, Generic, List, Optional, Sequence, Tuple, TypeVar

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
    new_static: List[StaticFinding] = []
    known_static: List[StaticFinding] = []
    for sf in blocking:
        key = static_key(sf, target_dir)
        if key in baseline.static:
            known_static.append(sf)
            suppressed.append(BaselineSuppressedItem(
                kind="static", id=f"{sf.rule_id}@{os.path.basename(sf.file_path)}:{sf.line_number}",
                title=sf.title, fingerprint=key,
            ))
        else:
            new_static.append(sf)

    findings_by_id: Dict[str, ReviewFinding] = {f.finding_id: f for f in confirmed_findings}
    new_wb: List[TestExecutionResult] = []
    known_wb: List[TestExecutionResult] = []
    for r in wb_failures:
        finding = findings_by_id.get(r.source_ref or "")
        wb_key = whitebox_failure_key(r, finding, target_dir)
        if wb_key is not None and wb_key in baseline.findings:
            known_wb.append(r)
            title = finding.title if finding else (r.failure_reason or r.test_id)
            suppressed.append(BaselineSuppressedItem(kind="whitebox_failure", id=r.test_id, title=title, fingerprint=wb_key))
        else:
            new_wb.append(r)

    threats_by_id: Dict[str, ThreatItem] = {t.threat_id: t for t in threats}
    new_bb: List[TestExecutionResult] = []
    known_bb: List[TestExecutionResult] = []
    for r in breaches:
        threat = threats_by_id.get(r.source_ref or "")
        bb_key = breach_key(r, threat)
        if bb_key in baseline.breaches:
            known_bb.append(r)
            suppressed.append(BaselineSuppressedItem(
                kind="breach", id=r.test_id, title=threat.title if threat else r.test_id, fingerprint=bb_key,
            ))
        else:
            new_bb.append(r)

    return (
        Split(all=tuple(blocking), new=tuple(new_static), known=tuple(known_static)),
        Split(all=tuple(wb_failures), new=tuple(new_wb), known=tuple(known_wb)),
        Split(all=tuple(breaches), new=tuple(new_bb), known=tuple(known_bb)),
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
