import logging
import re
from typing import List, Set

from core.models import ReviewFinding, FindingSeverity

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
# Share of the smaller finding's key terms that must also appear in the other one.
# Deliberately strict: merging two distinct defects loses one of them, a leftover duplicate only costs a test.
SIMILARITY_THRESHOLD = 0.6


def _terms(finding: ReviewFinding) -> Set[str]:
    words = re.findall(r"[a-z0-9_]+", f"{finding.title} {finding.root_cause}".lower())
    return {w.rstrip("s") if len(w) > 4 else w for w in words if len(w) >= 3 and w not in _STOPWORDS}


def _similar(a: ReviewFinding, b: ReviewFinding) -> bool:
    ta, tb = _terms(a), _terms(b)
    if not ta or not tb:
        return a.title.strip().lower() == b.title.strip().lower()
    return len(ta & tb) / min(len(ta), len(tb)) >= SIMILARITY_THRESHOLD


def _same_location(a: ReviewFinding, b: ReviewFinding) -> bool:
    # Findings that could not be tied to a symbol only merge on an identical title
    if a.file_path == "unknown" or b.file_path == "unknown" or not a.symbol_name or not b.symbol_name:
        return a.file_path == b.file_path and a.title.strip().lower() == b.title.strip().lower()
    return a.file_path == b.file_path and a.symbol_name == b.symbol_name


def deduplicate_findings(findings: List[ReviewFinding]) -> List[ReviewFinding]:
    """
    Merges reports of the same defect (same file and symbol, overlapping title/root-cause terms) into one
    finding. The most severe report is kept; the others are recorded in corroborated_by / merged_finding_ids,
    so cross-model agreement stays visible to the arbiter and the report. Order of first appearance is kept.
    """
    clusters: List[List[ReviewFinding]] = []
    for finding in findings:
        target = next(
            (c for c in clusters if any(_same_location(finding, m) and _similar(finding, m) for m in c)), None
        )
        if target is None:
            clusters.append([finding])
        else:
            target.append(finding)

    merged: List[ReviewFinding] = []
    for cluster in clusters:
        primary = min(cluster, key=lambda f: _SEVERITY_RANK.get(f.severity, len(_SEVERITY_RANK)))
        others = [f for f in cluster if f is not primary]
        if not others:
            merged.append(primary)
            continue
        corroborators: List[str] = []
        corroborating_models: List[str] = []
        for f in others:
            if f.reviewer_name != primary.reviewer_name and f.reviewer_name not in corroborators:
                corroborators.append(f.reviewer_name)
            if f.model_alias != primary.model_alias and f.model_alias not in corroborating_models:
                corroborating_models.append(f.model_alias)
        merged.append(primary.model_copy(update={
            "corroborated_by": corroborators,
            "corroborating_models": corroborating_models,
            "merged_finding_ids": [f.finding_id for f in others],
        }))

    if len(merged) < len(findings):
        logger.info(f"Merged {len(findings)} reviewer findings into {len(merged)} distinct findings.")
    return merged
