import logging
import re
from typing import List, Set

from vibeharness.core.models import ReviewFinding
from vibeharness.core.i18n import bi
from vibeharness.core.identity import is_unknown_location, severity_rank

logger = logging.getLogger("VibeHarness.Deduplicator")

_STOPWORDS = {
    "the", "and", "for", "with", "without", "from", "that", "this", "when", "into", "can", "may", "are",
    "not", "missing", "lack", "lacks", "potential", "possible", "issue", "bug", "defect", "function",
    "method", "handler", "code", "value", "values", "has", "via", "does",
}
# 較小那個發現的關鍵詞中，必須也出現在另一個發現裡的比例。
# 刻意嚴格：合併兩個不同的缺陷會失去其中一個，而殘留的重複只多花一個測試。
# Share of the smaller finding's key terms that must also appear in the other one.
# Deliberately strict: merging two distinct defects loses one of them, a leftover duplicate only costs a test.
SIMILARITY_THRESHOLD = 0.6
# 關鍵詞少於這個數量時，「較小集合比例」沒有意義：像 "Missing input validation"
# （{input, validation}）這種泛用發現幾乎會被任何其他發現「包含」。
# 這類短發現改用 Jaccard（共有詞 / 合併詞）比較。
# Below this many key terms the smaller-set ratio is meaningless: a generic finding such as
# "Missing input validation" ({input, validation}) would be fully "contained" in almost any other
# finding. Such short findings are compared by Jaccard (shared / combined terms) instead.
MIN_TERMS_FOR_CONTAINMENT = 3
# 不指名任何特定缺陷的泛用詞：只由這些詞構成的短發現（"Missing input validation"）不能靠子集規則併入具體發現
# Generic words that name no specific defect: a short finding made only of these ("Missing input validation")
# cannot be absorbed into a specific finding by the subset rule
_GENERIC_TERMS = {
    "input", "validation", "validate", "validated", "unvalidated", "sanitization", "sanitize", "sanitized",
    "unsanitized", "check", "checking", "error", "handling", "exception", "improper", "insecure", "unsafe",
    "weak", "security", "vulnerability", "vulnerable", "risk", "data", "user", "incorrect", "invalid", "bad",
    "logic", "edge", "case", "unchecked", "untrusted", "parameter", "argument", "output", "control",
}
# 中日韓文字的連續段（漢字、假名、諺文）：這些文字不以空格分詞
# Runs of CJK script (Han, kana, Hangul): these scripts do not separate words with spaces
_CJK_RUN = re.compile(r"[\u3040-\u30ff\u3400-\u4dbf\u4e00-\u9fff\uf900-\ufaff\uac00-\ud7af]+")


def _stem(word: str) -> str:
    """輕量的複數詞幹還原，不會弄壞 'classes' 或 'address' 這類字。
    Light plural stemming that does not mangle words like 'classes' or 'address'."""
    if len(word) <= 4:
        return word
    if word.endswith("ies"):
        return word[:-3] + "y"      # 例：vulnerabilities -> vulnerability ／ vulnerabilities -> vulnerability
    if word.endswith("sses"):
        return word[:-2]            # 例：classes -> class ／ classes -> class
    if word.endswith("s") and not word.endswith(("ss", "us", "is")):
        return word[:-1]            # keys -> key、cases -> case；'address'/'virus' 保持原樣 ／ keys -> key, cases -> case; 'address'/'virus' stay whole
    return word


def _words(text: str) -> Set[str]:
    """ASCII 詞（至少 3 個字元、去掉停用詞並還原詞幹），加上每個 CJK 字元連續段的相鄰二字詞
    （中文沒有空格，單字太泛，整段又太難重疊）；只有一個字的段落整段算一個詞。
    ASCII words (3+ characters, stop words dropped, stemmed), plus the adjacent character pairs of every CJK run
    (Chinese has no spaces; single characters are too generic and whole runs rarely overlap); a one-character
    run counts whole."""
    lowered = text.lower()
    words = re.findall(r"[a-z0-9_]+", lowered)
    terms = {w for w in (_stem(w) for w in words if len(w) >= 3 and w not in _STOPWORDS)}
    for run in _CJK_RUN.findall(lowered):
        terms.update({run} if len(run) == 1 else {run[i:i + 2] for i in range(len(run) - 1)})
    return terms


def _terms(finding: ReviewFinding) -> Set[str]:
    return _words(f"{finding.title} {finding.root_cause}")


def _similar(a: ReviewFinding, b: ReviewFinding) -> bool:
    ta, tb = _terms(a), _terms(b)
    if not ta or not tb:
        return a.title.strip().lower() == b.title.strip().lower()
    shared = len(ta & tb)
    if min(len(ta), len(tb)) < MIN_TERMS_FOR_CONTAINMENT:
        return shared / len(ta | tb) >= SIMILARITY_THRESHOLD or _terse_subset(a, b, ta, tb)
    return shared / min(len(ta), len(tb)) >= SIMILARITY_THRESHOLD


def _terse_subset(a: ReviewFinding, b: ReviewFinding, ta: Set[str], tb: Set[str]) -> bool:
    """簡短發現（"SQL injection"，沒有根因）的關鍵詞全部出現在詳細發現的「標題」中，且至少含一個
    具體（非泛用）詞時，視為同一缺陷；兩者若都填了 OWASP 分類則必須相同。泛用的 "Missing input validation"
    只有泛用詞，因此無法藉此併入 "SQL injection via search term"。
    A terse finding ("SQL injection", no root cause) is the same defect as a detailed one when all of its
    key terms appear in the detailed finding's *title* and at least one of them is specific (not generic);
    when both carry an OWASP mapping it must be the same. The generic "Missing input validation" has only
    generic terms, so it cannot be absorbed into "SQL injection via search term" this way."""
    terse, detailed, terse_terms = (a, b, ta) if len(ta) <= len(tb) else (b, a, tb)
    if not terse_terms - _GENERIC_TERMS or not terse_terms <= _words(detailed.title):
        return False
    return not (terse.owasp_mapping and detailed.owasp_mapping and terse.owasp_mapping != detailed.owasp_mapping)


def _same_location(a: ReviewFinding, b: ReviewFinding) -> bool:
    # 無法對應到檔案或符號的發現只在標題完全相同時合併；兩個未知位置（不論佔位字怎麼寫）算同一位置
    # Findings that could not be tied to a file or a symbol only merge on an identical title; two unknown locations
    # (however the placeholder is spelled) count as the same location
    unknown_a, unknown_b = is_unknown_location(a.file_path), is_unknown_location(b.file_path)
    if unknown_a or unknown_b or not a.symbol_name or not b.symbol_name:
        same_file = (unknown_a and unknown_b) or a.file_path == b.file_path
        return same_file and a.title.strip().lower() == b.title.strip().lower()
    return a.file_path == b.file_path and a.symbol_name == b.symbol_name


def deduplicate_findings(findings: List[ReviewFinding]) -> List[ReviewFinding]:
    """
    把同一缺陷的多份回報（相同檔案與符號、標題／根因詞彙重疊）合併成一個發現。
    保留最嚴重的那份；其餘記錄在 corroborated_by / merged_finding_ids 中，
    讓跨模型的一致性對仲裁者與報告仍然可見。維持首次出現的順序。

    叢集採完全連結（complete-linkage）：發現只有在與叢集每個成員都相符時才加入，
    因此泛用發現無法把兩個不同缺陷串在一起（A~C 且 B~C 不再合併 A 與 B）。
    發現依嚴重度由高到低處理、finding_id 打破平手，因此結果不取決於哪個模型先回報。
    Merges reports of the same defect (same file and symbol, overlapping title/root-cause terms) into one
    finding. The most severe report is kept; the others are recorded in corroborated_by / merged_finding_ids,
    so cross-model agreement stays visible to the arbiter and the report. Order of first appearance is kept.

    Clustering is complete-linkage: a finding joins a cluster only if it matches every member, so a
    generic finding cannot chain two distinct defects together (A~C and B~C no longer merge A and B).
    Findings are considered most severe first, finding_id breaking ties, so the result does not depend
    on which model reported first.
    """
    order = sorted(
        range(len(findings)),
        key=lambda i: (severity_rank(findings[i].severity), findings[i].finding_id),
    )
    groups: List[List[int]] = []
    for i in order:
        f = findings[i]
        home = next((
            g for g in groups
            if all(_same_location(findings[j], f) and _similar(findings[j], f) for j in g)
        ), None)
        if home is None:
            groups.append([i])
        else:
            home.append(i)

    # 叢集依首次出現的順序回報，成員維持輸入順序
    # Report clusters in order of first appearance, members in input order
    clusters: List[List[ReviewFinding]] = [
        [findings[j] for j in sorted(g)] for g in sorted(groups, key=min)
    ]

    merged: List[ReviewFinding] = []
    for cluster in clusters:
        # 最嚴重者勝出；finding_id 用來確定地打破平手，而不是依輸入順序
        # Most severe wins; finding_id breaks ties deterministically instead of input order
        primary = min(cluster, key=lambda f: (severity_rank(f.severity), f.finding_id))
        others = [f for f in cluster if f is not primary]
        if not others:
            merged.append(primary)
            continue
        corroborators: Set[str] = set()
        corroborating_models: Set[str] = set()
        for f in others:
            if f.reviewer_name != primary.reviewer_name:
                corroborators.add(f.reviewer_name)
            if f.model_alias != primary.model_alias:
                corroborating_models.add(f.model_alias)
        merged.append(primary.model_copy(update={
            # 已排序：合併後的紀錄是確定的，與回報順序無關
            # Sorted: the merged record is deterministic and independent of reporting order
            "corroborated_by": sorted(corroborators),
            "corroborating_models": sorted(corroborating_models),
            "merged_finding_ids": sorted(f.finding_id for f in others),
        }))

    if len(merged) < len(findings):
        logger.info(bi(f"已將 {len(findings)} 個審查者發現合併為 {len(merged)} 個不重複的發現。",
                       f"Merged {len(findings)} reviewer findings into {len(merged)} distinct findings."))
    return merged
