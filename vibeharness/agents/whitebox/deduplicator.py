import logging
import re
from typing import Dict, List, Set

from vibeharness.core.models import ReviewFinding, FindingSeverity
from vibeharness.core.i18n import bi

logger = logging.getLogger("VibeHarness.Deduplicator")

_SEVERITY_RANK = {
    FindingSeverity.CRITICAL: 0, FindingSeverity.HIGH: 1, FindingSeverity.MEDIUM: 2,
    FindingSeverity.LOW: 3, FindingSeverity.INFO: 4,
}
_STOPWORDS = {
    "the", "and", "for", "with", "without", "from", "that", "this", "when", "into", "can", "may", "are",
    "not", "missing", "lack", "lacks", "potential", "possible", "issue", "bug", "defect", "function",
    "method", "handler", "code", "value", "values",
}
# 較小那個發現的關鍵詞中，必須也出現在另一個發現裡的比例。
# 刻意嚴格：合併兩個不同的缺陷會失去其中一個，而殘留的重複只多花一個測試。
# Share of the smaller finding's key terms that must also appear in the other one.
# Deliberately strict: merging two distinct defects loses one of them, a leftover duplicate only costs a test.
SIMILARITY_THRESHOLD = 0.6


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


def _terms(finding: ReviewFinding) -> Set[str]:
    words = re.findall(r"[a-z0-9_]+", f"{finding.title} {finding.root_cause}".lower())
    return {w for w in (_stem(w) for w in words if len(w) >= 3 and w not in _STOPWORDS)}


def _similar(a: ReviewFinding, b: ReviewFinding) -> bool:
    ta, tb = _terms(a), _terms(b)
    if not ta or not tb:
        return a.title.strip().lower() == b.title.strip().lower()
    return len(ta & tb) / min(len(ta), len(tb)) >= SIMILARITY_THRESHOLD


def _same_location(a: ReviewFinding, b: ReviewFinding) -> bool:
    # 無法對應到符號的發現只在標題完全相同時合併
    # Findings that could not be tied to a symbol only merge on an identical title
    if a.file_path == "unknown" or b.file_path == "unknown" or not a.symbol_name or not b.symbol_name:
        return a.file_path == b.file_path and a.title.strip().lower() == b.title.strip().lower()
    return a.file_path == b.file_path and a.symbol_name == b.symbol_name


def deduplicate_findings(findings: List[ReviewFinding]) -> List[ReviewFinding]:
    """
    把同一缺陷的多份回報（相同檔案與符號、標題／根因詞彙重疊）合併成一個發現。
    保留最嚴重的那份；其餘記錄在 corroborated_by / merged_finding_ids 中，
    讓跨模型的一致性對仲裁者與報告仍然可見。維持首次出現的順序。

    叢集具遞移性（union-find）：A~B 且 B~C 不論輸入順序都落在同一叢集，
    因此結果不取決於哪個模型先回報。
    Merges reports of the same defect (same file and symbol, overlapping title/root-cause terms) into one
    finding. The most severe report is kept; the others are recorded in corroborated_by / merged_finding_ids,
    so cross-model agreement stays visible to the arbiter and the report. Order of first appearance is kept.

    Clustering is transitive (union-find): A~B and B~C land in one cluster regardless of input order,
    so the result does not depend on which model reported first.
    """
    n = len(findings)
    parent = list(range(n))

    def find(i: int) -> int:
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    for i in range(n):
        for j in range(i + 1, n):
            if _same_location(findings[i], findings[j]) and _similar(findings[i], findings[j]):
                parent[find(j)] = find(i)

    clusters: Dict[int, List[ReviewFinding]] = {}
    for i in range(n):
        clusters.setdefault(find(i), []).append(findings[i])

    merged: List[ReviewFinding] = []
    for cluster in clusters.values():
        # 最嚴重者勝出；finding_id 用來確定地打破平手，而不是依輸入順序
        # Most severe wins; finding_id breaks ties deterministically instead of input order
        primary = min(cluster, key=lambda f: (_SEVERITY_RANK.get(f.severity, len(_SEVERITY_RANK)), f.finding_id))
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
