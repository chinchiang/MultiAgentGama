"""發現、威脅與靜態命中的身分識別：模型文字的正規化、位置規則、嚴重度順序，以及跨執行的鍵。

`--baseline` 的鍵（JSON 報告的 ``fingerprint`` 欄位）與 SARIF 的 ``partialFingerprints`` 是同一組組成的兩種呈現，兩者都定義
在這裡、並排放置。兩者都已寫進使用者既有的報告或 GitHub Code Scanning 的警示裡：任何一個位元組改變，既有基準中的已知問題就會
變成「新的」，Code Scanning 的警示也會全部關閉後重開，所以這裡的改動必須保持每個雜湊不變。威脅合併（同一威脅出現在多個批次）與
`breach_key` 用同一個威脅身分；去重的相似度是另一種（模糊的）判斷，留在 deduplicator。
Identity of findings, threats and static hits: normalization of model text, the location rule, the severity order, and
the cross-run keys.

The `--baseline` keys (the JSON report's ``fingerprint`` fields) and SARIF ``partialFingerprints`` are two renderings of
the same parts, both defined here, side by side. Both are already stored in users' existing reports and GitHub Code
Scanning alerts: change one byte and every known problem in an existing baseline becomes "new" and every Code Scanning
alert is closed and reopened, so any change here must keep every hash as it is. The threat merge (the same threat
reported by several batches) and `breach_key` share one threat identity; dedup similarity is a different (fuzzy)
judgement and stays in the deduplicator."""
import hashlib
import os
import re
from typing import Optional, Tuple

from vibeharness.core.i18n import en_only
from vibeharness.core.models import FindingSeverity, ReviewFinding, StaticFinding, TestExecutionResult, ThreatItem

# 審查者無法把發現歸屬到任何符號時的檔案佔位字，不是檔案
# The file placeholder for a finding the reviewer could not tie to any symbol; not a file
UNKNOWN_FILE = "unknown"



def is_unknown_location(file_path: Optional[str]) -> bool:
    """發現沒有可用的檔案位置：None、空字串、只有空白，或（前後空白不計的）`UNKNOWN_FILE` 佔位字。
    去重、測試生成、基準線鍵與 SARIF 都以這一個判斷為準。
    The finding has no usable file location: None, empty, whitespace only, or the `UNKNOWN_FILE` placeholder
    (surrounding whitespace ignored). Dedup, test generation, the baseline keys and SARIF all go by this one rule."""
    return not file_path or not file_path.strip() or file_path.strip() == UNKNOWN_FILE


_SEVERITY_RANK = {
    FindingSeverity.CRITICAL: 0, FindingSeverity.HIGH: 1, FindingSeverity.MEDIUM: 2,
    FindingSeverity.LOW: 3, FindingSeverity.INFO: 4,
}


def severity_rank(severity: FindingSeverity) -> int:
    """越嚴重越小（CRITICAL 為 0）；未知的嚴重度排在最後。
    Smaller is more severe (CRITICAL is 0); an unknown severity sorts last."""
    return _SEVERITY_RANK.get(severity, len(_SEVERITY_RANK))


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
    if file_path is None or is_unknown_location(file_path):
        return ""
    base = os.path.abspath(target_path)
    path = os.path.abspath(file_path)
    try:
        rel = os.path.relpath(path, base)
        # 檔案位於目標之下時目標必定是目錄，即使它在這台機器上不存在且名稱含點（另一台機器的 app.v2）；
        # 只有不在其下時，存在的檔案或帶副檔名的不存在路徑才改以其所在目錄為基準
        # A file under the target means the target is a directory, even one that does not exist on this machine and
        # has a dot in its name (another machine's app.v2); only when it is not under it is an existing file, or a
        # missing path with an extension, related to its directory instead
        if rel.startswith("..") and (os.path.isfile(base) or (not os.path.isdir(base) and os.path.splitext(base)[1])):
            rel = os.path.relpath(path, os.path.dirname(base))
    except ValueError:
        return os.path.basename(file_path)
    if rel == "." or rel.startswith(".."):
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


def threat_identity(threat: ThreatItem) -> Tuple[str, str, str]:
    """同一威脅的判斷依據：STRIDE 類別、正規化的標題與攻擊向量（模擬的項目只取英文半）。威脅合併以它為鍵，`breach_key`
    與 SARIF 突破指紋則雜湊它。
    What makes two threats the same: the STRIDE category and the normalized title and attack vector (the English half
    of a simulated item). The threat merge keys on it; `breach_key` and the SARIF breach fingerprint hash it."""
    return (threat.stride_category.value, normalize(key_text(threat.title, threat.is_simulated)),
            normalize(key_text(threat.attack_vector, threat.is_simulated)))


def breach_key(result: TestExecutionResult, threat: Optional[ThreatItem]) -> str:
    """已確認的突破以其威脅（類別、標題、攻擊向量）識別，而非
    逐次執行的測試 id；沒有可解析的威脅時，測試 id 就是僅有的依據。
    A confirmed breach is identified by its threat (category, title, attack vector), not by the
    per-run test id; without a resolvable threat the test id is all there is."""
    if threat is not None:
        return fingerprint("breach", *threat_identity(threat))
    return fingerprint("breach", result.test_id, result.source_ref or "")


# --- SARIF partialFingerprints（Code Scanning 以 ruleId + 指紋追蹤警示）-----------------------------------------
# --- SARIF partialFingerprints (Code Scanning tracks alerts by ruleId + fingerprint) ---------------------------

def sarif_static_fingerprint(sf: StaticFinding, uri: Optional[str]) -> str:
    """與 `static_key` 不同，保留行號而不含證據：Code Scanning 的警示綁在那一行上。
    Unlike `static_key`, keeps the line and leaves out the evidence: a Code Scanning alert sits on that line."""
    return fingerprint(uri or "", sf.rule_id, str(sf.line_number))


def sarif_finding_fingerprint(f: ReviewFinding, uri: Optional[str]) -> str:
    """與 `finding_key` 相同的組成，但用 SARIF 的 uri 而不是相對於目標的路徑，也沒有種類字首。
    The same parts as `finding_key`, but with the SARIF uri instead of the target-relative path and no kind prefix."""
    return fingerprint(uri or "", f.symbol_name or "", normalize(key_text(f.title, f.is_simulated)))


def sarif_breach_fingerprint(result: TestExecutionResult, threat: Optional[ThreatItem]) -> str:
    """與 `breach_key` 相同的組成，沒有種類字首。
    The same parts as `breach_key`, without the kind prefix."""
    return fingerprint(*(threat_identity(threat) if threat is not None else (result.test_id, result.source_ref or "")))
