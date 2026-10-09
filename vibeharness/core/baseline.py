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
import hashlib
import json
import os
import re
from typing import Any, Dict, Iterable, List, Optional, Set

from pydantic import BaseModel, Field

from vibeharness.core.i18n import bi, en_only
from vibeharness.core.models import (
    BaselineSuppressedItem, ReviewFinding, StaticFinding, TestExecutionResult, ThreatItem,
)

TOOL_NAME = "vibeharness-mas"


def normalize(text: Optional[str]) -> str:
    """模型文字的不分大小寫與標點形式，讓鍵在表面措辭改寫後仍存活。任何文字的字母與數字都算
    （中文標題各自不同，不會塌成空字串）；純 ASCII 文字的結果與 0.3.0 相同。
    Case/punctuation-insensitive form of model text, so keys survive cosmetic rewording. Letters and digits of
    any script count (Chinese titles stay distinct instead of collapsing to ""); ASCII text keys exactly as in 0.3.0."""
    return " ".join(re.findall(r"[^\W_]+", (text or "").lower()))


def key_text(text: Optional[str], simulated: bool) -> str:
    """進鍵的文字：模擬引擎的項目是 `bi()` 雙語字串，只取英文半（鍵與 0.3.0 相同）；真實模型的文字原樣使用，
    即使含有全形斜線。
    The text that enters a key: simulated items are bilingual `bi()` strings and contribute their English half
    only (keys as in 0.3.0); real model text is used as is, even when it contains a full-width slash."""
    return en_only(text or "") if simulated else (text or "")


def fingerprint(*parts: str) -> str:
    """SARIF partialFingerprints 與基準線鍵共用的雜湊 ／ The hash shared by SARIF partialFingerprints and baseline keys."""
    return hashlib.sha1("|".join(parts).encode("utf-8")).hexdigest()


def target_relative(file_path: Optional[str], target_path: str) -> str:
    """`file_path` 相對於受稽核目標的正斜線字串形式；無法關聯時（「unknown」佔位字、
    不同磁碟機）則為純檔名。純字串運算：來自另一個簽出或機器的基準線
    對同一檔案必須產生相同的鍵。
    `file_path` relative to the audited target as a forward-slash string, or the bare name when it
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
    """規則 + 檔案 + 證據，不含行號（命中處上方無關的編輯不得
    把已知命中變成新命中；SARIF 指紋則保留行號供 Code Scanning 使用）。
    Rule + file + evidence, without the line number (an unrelated edit above the hit must not
    turn a known hit into a new one; the SARIF fingerprint keeps the line for Code Scanning)."""
    return fingerprint("static", target_relative(sf.file_path, target_path), sf.rule_id, normalize(sf.evidence))


def finding_key(f: ReviewFinding, target_path: str) -> str:
    return fingerprint("finding", target_relative(f.file_path, target_path), f.symbol_name or "",
                       normalize(key_text(f.title, f.is_simulated)))


def probe_key(result: TestExecutionResult) -> str:
    """確定性探測以它所演練的符號（其 source_ref）識別。
    A deterministic probe is identified by the symbol it exercised (its source_ref)."""
    return fingerprint("probe", result.source_ref or result.test_id)


def whitebox_failure_key(result: TestExecutionResult, finding: Optional[ReviewFinding], target_path: str) -> Optional[str]:
    """FAILED 白箱結果的鍵：它所對應產生的發現，或探測的符號；
    當結果的發現無法解析時為 None（此時它一律是新的）。
    Key of a FAILED white-box result: the finding it was generated for, or the probe's symbol;
    None when the result's finding cannot be resolved (then it is always new)."""
    if result.test_type == "whitebox_probe":
        return probe_key(result)
    return finding_key(finding, target_path) if finding else None


def breach_key(result: TestExecutionResult, threat: Optional[ThreatItem]) -> str:
    """已確認的突破以其威脅（類別、標題、攻擊向量）識別，而非
    逐次執行的測試 id；沒有可解析的威脅時，測試 id 就是僅有的依據。
    A confirmed breach is identified by its threat (category, title, attack vector), not by the
    per-run test id; without a resolvable threat the test id is all there is."""
    if threat is not None:
        return fingerprint("breach", threat.stride_category.value, normalize(key_text(threat.title, threat.is_simulated)),
                           normalize(key_text(threat.attack_vector, threat.is_simulated)))
    return fingerprint("breach", result.test_id, result.source_ref or "")


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
        if r.status.value == "FAILED":
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
