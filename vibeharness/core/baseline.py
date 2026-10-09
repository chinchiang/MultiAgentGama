"""Cross-run identity of findings, breaches and static hits, and the `--baseline` comparison.

Per-run ids (``WB-CLA-01``, ``THREAT-03``, ``BB-TEST-THREAT-03``) change whenever a model numbers its
answers differently, so a CI gate that must react only to *new* problems needs keys that survive
re-numbering, cosmetic rewording and unrelated line shifts. The keys here are built from the
file path relative to the audited target (a string operation, so a report produced on another
machine still compares), the rule / symbol / threat identity and a case- and punctuation-insensitive
form of the model's title. They are stored in the JSON report (``fingerprint`` fields) and recomputed
from older reports that lack them.
"""
import hashlib
import json
import os
import re
from typing import Any, Dict, Iterable, List, Optional, Set

from pydantic import BaseModel, Field

from vibeharness.core.i18n import bi
from vibeharness.core.models import (
    BaselineSuppressedItem, ReviewFinding, StaticFinding, TestExecutionResult, ThreatItem,
)

TOOL_NAME = "vibeharness-mas"


def normalize(text: Optional[str]) -> str:
    """Case/punctuation-insensitive form of model text, so keys survive cosmetic rewording."""
    return " ".join(re.findall(r"[a-z0-9]+", (text or "").lower()))


def fingerprint(*parts: str) -> str:
    return hashlib.sha1("|".join(parts).encode("utf-8")).hexdigest()


def target_relative(file_path: Optional[str], target_path: str) -> str:
    """`file_path` relative to the audited target as a forward-slash string, or the bare name when it
    cannot be related (an "unknown" placeholder, a different drive). Pure string work: a baseline from
    another checkout or machine must yield the same key for the same file."""
    if not file_path or file_path.strip() == "unknown":
        return ""
    base = os.path.abspath(target_path)
    if not os.path.isdir(base) and os.path.splitext(base)[1]:
        base = os.path.dirname(base)
    try:
        rel = os.path.relpath(os.path.abspath(file_path), base)
    except ValueError:
        return os.path.basename(file_path)
    if rel.startswith(".."):
        return os.path.basename(file_path)
    return rel.replace(os.sep, "/")


def static_key(sf: StaticFinding, target_path: str) -> str:
    """Rule + file + evidence, without the line number (an unrelated edit above the hit must not
    turn a known hit into a new one; the SARIF fingerprint keeps the line for Code Scanning)."""
    return fingerprint("static", target_relative(sf.file_path, target_path), sf.rule_id, normalize(sf.evidence))


def finding_key(f: ReviewFinding, target_path: str) -> str:
    return fingerprint("finding", target_relative(f.file_path, target_path), f.symbol_name or "", normalize(f.title))


def probe_key(result: TestExecutionResult) -> str:
    """A deterministic probe is identified by the symbol it exercised (its source_ref)."""
    return fingerprint("probe", result.source_ref or result.test_id)


def whitebox_failure_key(result: TestExecutionResult, finding: Optional[ReviewFinding], target_path: str) -> Optional[str]:
    """Key of a FAILED white-box result: the finding it was generated for, or the probe's symbol;
    None when the result's finding cannot be resolved (then it is always new)."""
    if result.test_type == "whitebox_probe":
        return probe_key(result)
    return finding_key(finding, target_path) if finding else None


def breach_key(result: TestExecutionResult, threat: Optional[ThreatItem]) -> str:
    """A confirmed breach is identified by its threat (category, title, attack vector), not by the
    per-run test id; without a resolvable threat the test id is all there is."""
    if threat is not None:
        return fingerprint("breach", threat.stride_category.value, normalize(threat.title), normalize(threat.attack_vector))
    return fingerprint("breach", result.test_id, result.source_ref or "")


class Baseline(BaseModel):
    """The keys loaded from a previous JSON report."""
    path: str
    generated_at: Optional[str] = None
    static: Set[str] = Field(default_factory=set)
    findings: Set[str] = Field(default_factory=set)
    breaches: Set[str] = Field(default_factory=set)

    @property
    def size(self) -> int:
        return len(self.static) + len(self.findings) + len(self.breaches)


def _dicts(value: Any) -> List[Dict[str, Any]]:
    return [v for v in value if isinstance(v, dict)] if isinstance(value, list) else []


def _keys_from_report(payload: Dict[str, Any]) -> Baseline:
    """Keys of a report: the stored ``fingerprint`` fields, or the same keys recomputed from the
    fields for reports written before they existed (0.3.0)."""
    target = str(payload.get("target_path") or "")
    raw_summary = payload.get("summary")
    summary: Dict[str, Any] = raw_summary if isinstance(raw_summary, dict) else {}
    run = summary.get("run")
    baseline = Baseline(path="", generated_at=run.get("generated_at") if isinstance(run, dict) else None)
    for item in _dicts(summary.get("static_findings")):
        key = item.get("fingerprint")
        if not isinstance(key, str):
            try:
                key = static_key(StaticFinding(**item), target)
            except Exception:
                continue
        baseline.static.add(key)
    debate = (payload.get("whitebox") or {}).get("debate") if isinstance(payload.get("whitebox"), dict) else {}
    for item in _dicts((debate or {}).get("confirmed_findings")):
        key = item.get("fingerprint")
        if not isinstance(key, str):
            try:
                key = finding_key(ReviewFinding(**item), target)
            except Exception:
                continue
        baseline.findings.add(key)
    findings_by_id: Dict[str, ReviewFinding] = {}
    for item in _dicts((debate or {}).get("confirmed_findings")):
        try:
            finding = ReviewFinding(**item)
        except Exception:
            continue
        findings_by_id[finding.finding_id] = finding
    whitebox = payload.get("whitebox") if isinstance(payload.get("whitebox"), dict) else {}
    for item in _dicts((whitebox or {}).get("test_results")):
        if item.get("status") != "FAILED":
            continue
        key = item.get("fingerprint")
        if not isinstance(key, str):
            try:
                result = TestExecutionResult(**item)
            except Exception:
                continue
            key = whitebox_failure_key(result, findings_by_id.get(result.source_ref or ""), target)
        if key:
            baseline.findings.add(key)
    threats: Dict[str, ThreatItem] = {}
    for item in _dicts((payload.get("threat_model") or {}).get("threats") if isinstance(payload.get("threat_model"), dict) else []):
        try:
            threat = ThreatItem(**item)
        except Exception:
            continue
        threats[threat.threat_id] = threat
    for item in _dicts(payload.get("blackbox_test_results")):
        if not item.get("is_security_exploit_confirmed"):
            continue
        key = item.get("fingerprint")
        if not isinstance(key, str):
            try:
                result = TestExecutionResult(**item)
            except Exception:
                continue
            key = breach_key(result, threats.get(result.source_ref or ""))
        baseline.breaches.add(key)
    return baseline


def load_baseline(path: str) -> Baseline:
    """Reads a previous JSON report. A partial report (written by a crashed run) or a file from
    another tool is refused: comparing against an incomplete set of findings would hide new ones."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            payload = json.load(f)
    except OSError as e:
        raise ValueError(bi(f"基準 {path!r} 無法讀取", f"baseline {path!r} cannot be read") + f": {e}") from e
    except ValueError as e:
        raise ValueError(bi(f"基準 {path!r} 不是有效的 JSON", f"baseline {path!r} is not valid JSON") + f": {e}") from e
    if not isinstance(payload, dict) or payload.get("tool") != TOOL_NAME:
        raise ValueError(bi(f"基準 {path!r} 不是 VibeHarness 的 JSON 報告（需要 --format json 的輸出）",
                            f"baseline {path!r} is not a VibeHarness JSON report (expected --format json output)"))
    if payload.get("partial"):
        raise ValueError(bi(f"基準 {path!r} 是崩潰執行留下的部分報告；請使用完整的 JSON 報告",
                            f"baseline {path!r} is a partial report from a crashed run; use a complete JSON report"))
    baseline = _keys_from_report(payload)
    baseline.path = os.path.abspath(path)
    return baseline


def annotate_report_payload(
    payload: Dict[str, Any],
    target_path: str,
    static_findings: Iterable[StaticFinding],
    confirmed_findings: Iterable[ReviewFinding],
    whitebox_results: Iterable[TestExecutionResult],
    blackbox_results: Iterable[TestExecutionResult],
    threats: Iterable[ThreatItem],
) -> None:
    """Adds the ``fingerprint`` field to the JSON report's static findings, confirmed findings and
    confirmed breaches (in place). An addition only: the schema version is unchanged."""
    for item, sf in zip(_dicts(payload["summary"].get("static_findings")), list(static_findings), strict=True):
        item["fingerprint"] = static_key(sf, target_path)
    confirmed = list(confirmed_findings)
    for item, f in zip(_dicts(payload["whitebox"]["debate"].get("confirmed_findings")), confirmed, strict=True):
        item["fingerprint"] = finding_key(f, target_path)
    findings_by_id = {f.finding_id: f for f in confirmed}
    for item, r in zip(_dicts(payload["whitebox"].get("test_results")), list(whitebox_results), strict=True):
        if r.status.value == "FAILED":
            key = whitebox_failure_key(r, findings_by_id.get(r.source_ref or ""), target_path)
            if key:
                item["fingerprint"] = key
    threats_by_id = {t.threat_id: t for t in threats}
    for item, r in zip(_dicts(payload.get("blackbox_test_results")), list(blackbox_results), strict=True):
        if r.is_security_exploit_confirmed:
            item["fingerprint"] = breach_key(r, threats_by_id.get(r.source_ref or ""))


class BaselineComparison(BaseModel):
    """What the gate may count (new) and what it must only report (known)."""
    new_breaches: List[TestExecutionResult] = Field(default_factory=list)
    new_whitebox_failures: List[TestExecutionResult] = Field(default_factory=list)
    new_static_blocking: List[StaticFinding] = Field(default_factory=list)
    suppressed: List[BaselineSuppressedItem] = Field(default_factory=list)


def compare_with_baseline(
    baseline: Baseline,
    target_path: str,
    static_blocking: List[StaticFinding],
    whitebox_results: List[TestExecutionResult],
    confirmed_findings: List[ReviewFinding],
    blackbox_results: List[TestExecutionResult],
    threats: List[ThreatItem],
) -> BaselineComparison:
    """Splits this run's blocking evidence into new and already-known. A white-box failure is known
    through the finding its test was generated for (its own id is per run); a probe or a result whose
    finding cannot be resolved is always new."""
    out = BaselineComparison()
    key: Optional[str]
    for sf in static_blocking:
        key = static_key(sf, target_path)
        if key in baseline.static:
            out.suppressed.append(BaselineSuppressedItem(
                kind="static", id=f"{sf.rule_id}@{os.path.basename(sf.file_path)}:{sf.line_number}", title=sf.title, fingerprint=key
            ))
        else:
            out.new_static_blocking.append(sf)
    findings_by_id = {f.finding_id: f for f in confirmed_findings}
    for r in whitebox_results:
        if r.status.value != "FAILED":
            continue
        finding = findings_by_id.get(r.source_ref or "")
        key = whitebox_failure_key(r, finding, target_path)
        if key is not None and key in baseline.findings:
            title = finding.title if finding else (r.failure_reason or r.test_id)
            out.suppressed.append(BaselineSuppressedItem(kind="whitebox_failure", id=r.test_id, title=title, fingerprint=key))
        else:
            out.new_whitebox_failures.append(r)
    threats_by_id = {t.threat_id: t for t in threats}
    for r in blackbox_results:
        if not r.is_security_exploit_confirmed:
            continue
        threat = threats_by_id.get(r.source_ref or "")
        key = breach_key(r, threat)
        if key in baseline.breaches:
            out.suppressed.append(BaselineSuppressedItem(kind="breach", id=r.test_id, title=threat.title if threat else r.test_id, fingerprint=key))
        else:
            out.new_breaches.append(r)
    return out
