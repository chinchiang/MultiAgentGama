"""跨執行的發現、突破與靜態命中身分識別，以及 `--baseline` 比較。

逐次執行的 id（``WB-CLA-01``、``THREAT-03``、``BB-TEST-THREAT-03``）會在模型以不同方式為
回答編號時改變，因此只對*新*問題反應的 CI 閘門需要能在重新編號、
表面措辭改寫與無關的行數位移之後仍存活的鍵。這裡的鍵由
相對於受稽核目標的檔案路徑（純字串運算，因此在另一台機器產生的報告
仍可比較）、規則／符號／威脅身分識別，以及模型標題的不分大小寫與標點的
形式組成。它們儲存在 JSON 報告中（``fingerprint`` 欄位），並從缺少這些欄位的
較舊報告重新計算。
Cross-run identity of findings, breaches and static hits, and the `--baseline` comparison.

Per-run ids (``WB-CLA-01``, ``THREAT-03``, ``BB-TEST-THREAT-03``) change whenever a model numbers its
answers differently, so a CI gate that must react only to *new* problems needs keys that survive
re-numbering, cosmetic rewording and unrelated line shifts. The keys here are built from the
file path relative to the audited target (a string operation, so a report produced on another
machine still compares), the rule / symbol / threat identity and a case- and punctuation-insensitive
form of the model's title. They are stored in the JSON report (``fingerprint`` fields) and recomputed
from older reports that lack them.
"""
import json
import os
from typing import Any, Dict, Iterable, List, Optional, Set

from pydantic import BaseModel, Field

from vibeharness.core.i18n import bi
# 鍵與其組成（正規化、位置、雜湊）在 core/identity.py；以舊名稱重新匯出
# The keys and their parts (normalization, location, hash) live in core/identity.py; re-exported under the old names
from vibeharness.core.identity import (  # noqa: F401
    breach_key, finding_key, fingerprint, key_text, normalize, probe_key, static_key, target_relative,
    whitebox_failure_key,
)
from vibeharness.core.models import (
    BaselineSuppressedItem, ReviewFinding, StaticFinding, TestExecutionResult, ThreatItem,
)

TOOL_NAME = "vibeharness-mas"


class Baseline(BaseModel):
    """從先前 JSON 報告載入的鍵。
    The keys loaded from a previous JSON report."""
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
    """報告的鍵：儲存的 ``fingerprint`` 欄位，或對於這些欄位出現之前（0.3.0）寫出的報告，
    由各欄位重新計算出的相同鍵。
    Keys of a report: the stored ``fingerprint`` fields, or the same keys recomputed from the
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
    # 已確認的發現本身不會決定判定，只有「其測試失敗」才會：所以只有 FAILED 的白箱結果（經其發現識別）
    # 進基準線；上次通過（防線守住）的發現這次失敗就是新問題，不能被壓下
    # A confirmed finding never decides the verdict on its own, only a FAILED test for it does: so only FAILED
    # white-box results (keyed by their finding) seed the baseline; a finding whose test passed last time and
    # fails now is a new problem and must not be suppressed
    debate = (payload.get("whitebox") or {}).get("debate") if isinstance(payload.get("whitebox"), dict) else {}
    # 較舊的報告只在 debate／threat_model 層級標 is_simulated：項目本身沒有該欄位時才補上（有的話以項目為準，
    # 混合執行裡 live 的項目不會被誤標），重算的 key 才與這一輪一致
    # Older reports flag is_simulated only at the debate / threat_model level: it is propagated only to items that
    # lack the field (an item's own flag wins, so live items of a mixed run are never mis-flagged), so the recomputed
    # keys match this run's
    debate_simulated = bool(isinstance(debate, dict) and debate.get("is_simulated"))
    findings_by_id: Dict[str, ReviewFinding] = {}
    for item in _dicts((debate or {}).get("confirmed_findings")):
        try:
            finding = ReviewFinding(**item)
        except Exception:
            continue
        if debate_simulated and "is_simulated" not in item:
            finding.is_simulated = True
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
    threat_model = payload.get("threat_model") if isinstance(payload.get("threat_model"), dict) else {}
    model_simulated = bool((threat_model or {}).get("is_simulated"))
    for item in _dicts((threat_model or {}).get("threats")):
        try:
            threat = ThreatItem(**item)
        except Exception:
            continue
        if model_simulated and "is_simulated" not in item:
            threat.is_simulated = True
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
    """讀取先前的 JSON 報告。部分報告（由當掉的執行寫出）或來自
    其他工具的檔案會被拒絕：與不完整的發現集合比較會隱藏新的發現。
    Reads a previous JSON report. A partial report (written by a crashed run) or a file from
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
    """為 JSON 報告的靜態發現、已確認發現與已確認突破加入 ``fingerprint`` 欄位
    （就地修改）。純粹新增：結構描述版本不變。
    Adds the ``fingerprint`` field to the JSON report's static findings, confirmed findings and
    confirmed breaches (in place). An addition only: the schema version is unchanged."""
    for item, sf in zip(_dicts(payload["summary"].get("static_findings")), list(static_findings), strict=True):
        item["fingerprint"] = static_key(sf, target_path)
    confirmed = list(confirmed_findings)
    for item, f in zip(_dicts(payload["whitebox"]["debate"].get("confirmed_findings")), confirmed, strict=True):
        item["fingerprint"] = finding_key(f, target_path)
    findings_by_id = {f.finding_id: f for f in confirmed}
    for item, r in zip(_dicts(payload["whitebox"].get("test_results")), list(whitebox_results), strict=True):
        if r.is_failure:
            key = whitebox_failure_key(r, findings_by_id.get(r.source_ref or ""), target_path)
            if key:
                item["fingerprint"] = key
    threats_by_id = {t.threat_id: t for t in threats}
    for item, r in zip(_dicts(payload.get("blackbox_test_results")), list(blackbox_results), strict=True):
        if r.is_security_exploit_confirmed:
            item["fingerprint"] = breach_key(r, threats_by_id.get(r.source_ref or ""))


class BaselineComparison(BaseModel):
    """閘門可計入的（新的）與只能列出的（已知的）。
    What the gate may count (new) and what it must only report (known)."""
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
    """把本次執行的阻擋證據分成新的與已知的。白箱失敗是透過其測試所對應產生的
    發現而為已知（其自身的 id 是逐次執行的）；探測或發現無法解析的結果
    一律是新的。
    Splits this run's blocking evidence into new and already-known. A white-box failure is known
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
        if not r.is_failure:
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
