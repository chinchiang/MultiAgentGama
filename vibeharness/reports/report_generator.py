import hashlib
import html
import json
import os
import re
from typing import Dict, List, Optional, Tuple
from vibeharness.core.models import (
    CodeSymbol,
    MultiModelDebateResult,
    ReviewFinding,
    ThreatItem,
    ThreatModelReport,
    TestExecutionResult,
    GeneratedTest,
    VibeHarnessSummary,
    TestStatus,
    FindingSeverity,
    StaticFinding
)
from vibeharness.core.sanitize import clean_model_text, markdown_safe

# Windows drive paths ("C:\...") count as absolute even on POSIX hosts, so a SARIF produced
# on Windows relativizes identically when re-processed by a Linux CI runner.
_WINDOWS_DRIVE_RE = re.compile(r"^[A-Za-z]:[\\/]")

# Stable SARIF rule ids: GitHub Code Scanning tracks alerts by ruleId + fingerprint, so a per-run
# finding id (WB-CLA-01 is just "Claude's first finding this run") would close and reopen alerts
# whenever the numbering shifted. The run-specific ids are kept in each result's properties.
SARIF_RULE_WHITEBOX = "vibeharness/whitebox-finding"
SARIF_RULE_BLACKBOX = "vibeharness/blackbox-breach"
# Deterministic AI-security rules keep their own stable ids: vibeharness/VH-AI-001, ...
SARIF_RULE_STATIC_PREFIX = "vibeharness/"
# Version of the JSON report layout (summary / whitebox / threat_model / blackbox_* keys)
JSON_SCHEMA_VERSION = "1"


class ReportGenerator:
    """
    Generates a structured, audit-grade Markdown report detailing the complete
    multi-agent white-box and black-box verification lifecycle.
    """

    def generate_markdown_report(
        self,
        summary: VibeHarnessSummary,
        debate_result: MultiModelDebateResult,
        threat_model: ThreatModelReport,
        whitebox_results: List[TestExecutionResult],
        blackbox_results: List[TestExecutionResult],
        target_path: str,
        whitebox_tests: Optional[List[GeneratedTest]] = None,
        blackbox_tests: Optional[List[GeneratedTest]] = None
    ) -> str:
        md = []

        # Header
        md.append("# 🛡️ VibeHarness-MAS Multi-Agent Quality & Security Report")
        md.append(f"**Target System Path**: `{os.path.abspath(target_path)}`  ")
        md.append("**Orchestrator**: Commander Harness Agent  ")
        md.append(f"**Overall Status**: `{summary.overall_status}`  ")
        if summary.run:
            run = summary.run
            revision = run.target_git_commit or "not a git repository"
            if run.target_git_commit and run.target_git_dirty:
                revision += " (uncommitted changes)"
            md.append(f"**Generated**: {run.generated_at} by VibeHarness-MAS {run.harness_version} "
                      f"(mode `{run.execution_mode}`, sandbox `{run.sandbox_provider}`)  ")
            md.append(f"**Target revision**: `{self._cell(revision)}`  ")
            md.append(f"**Config**: `{self._cell(run.config_path)}`  ")
            if run.file_filters:
                md.append(f"**File selection**: {self._code_span('; '.join(run.file_filters))}  ")
        md.append("\n---\n")

        simulated_calls = [c for c in summary.agent_calls if c.mode == "simulated"]
        if simulated_calls:
            scope = "ALL" if len(simulated_calls) == len(summary.agent_calls) else "SOME"
            md.append(
                f"> ⚠️ **SIMULATED RESULTS — {scope} agent outputs in this report come from the offline simulation engine**, "
                "which returns fixed template responses independent of the target code. "
                "Findings, consensus ratio and threat model marked `[SIMULATED]` are NOT a real model audit. "
                "Only executed test outcomes reflect the actual target behaviour.\n"
            )

        # 1. Executive Summary
        md.append("## 1. 📊 Executive Summary & Quality Gate")
        status_badge = {
            "READY_TO_SHIP": "🟢 **PASS: READY TO SHIP**",
            "NEEDS_FIXES": "🟠 **FAIL: NEEDS FIXES**",
            "INCONCLUSIVE": "🟡 **INCONCLUSIVE: INSUFFICIENT EVIDENCE**",
            "BLOCKED_CRITICAL_RISK": "🔴 **FAIL: BLOCKED BY CRITICAL RISKS**",
        }.get(summary.overall_status, f"⚠️ **UNKNOWN STATUS: `{summary.overall_status}`**")
        md.append(f"### Verdict: {status_badge}\n")
        if summary.inconclusive_reasons:
            md.append("**Evidence gaps:**")
            for reason in summary.inconclusive_reasons:
                md.append(f"- {markdown_safe(reason)}")  # reasons quote model-chosen ids and failure text
            md.append("")

        sim_tag = " `[SIMULATED]`" if debate_result.is_simulated else ""
        md.append("| Metric | Value | Target |")
        md.append("| :--- | :--- | :--- |")
        md.append(f"| **Primary Target Language** | `{summary.detected_language}` | Supported Stack |")
        ratio = debate_result.model_agreement_ratio
        if not debate_result.arbitration_applied:
            ratio_str = "N/A (verification not applied)"
        else:
            ratio_str = f"{ratio * 100:.1f}%" if ratio is not None else "N/A (no decisive votes)"
        md.append(f"| **Cross-Model Agreement** | `{ratio_str}`{sim_tag} | ≥ 70% Agreement |")
        cov_str = f"{summary.line_coverage_pct:.1f}%" if summary.line_coverage_pct is not None else "N/A"
        md.append(f"| **Code Line Coverage** | `{cov_str}` | ≥ 80% Baseline |")
        if summary.distinct_whitebox_findings is not None:
            md.append(f"| **Reviewer Findings (raw → distinct)** | `{summary.total_whitebox_findings} → {summary.distinct_whitebox_findings}` | - |")
        md.append(f"| **Confirmed White-Box Logic Flaws** | `{summary.confirmed_whitebox_bugs}` | 0 Critical |")
        md.append(f"| **White-Box Tests Passed** | `{summary.whitebox_tests_passed} / {len(whitebox_results)}` ({summary.whitebox_tests_errored} errored / not run) | 100% Pass Rate |")
        md.append(f"| **STRIDE Threat Scenarios Modeled** | `{summary.total_threats_modeled}` | Full Asset Coverage |")
        md.append(f"| **Threats Without Executable Test** | `{len(summary.untested_threat_ids)}` | 0 Untested |")
        md.append(f"| **Confirmed Black-Box Security Breaches** | `{summary.blackbox_security_breaches}` | 0 Breaches Tolerated |")
        md.append(f"| **Black-Box Tests Failed (unclassified)** | `{summary.blackbox_tests_failed}` | 0 — failing attack scripts need manual review |")
        blocking = sum(1 for f in summary.static_findings if f.severity in (FindingSeverity.CRITICAL, FindingSeverity.HIGH))
        md.append(f"| **Deterministic AI-Security Rule Hits** | `{len(summary.static_findings)}` ({blocking} HIGH+) | 0 HIGH+ |")
        md.append("\n")
        if summary.reviewer_models:
            md.append(f"**Reviewer models** ({len(summary.reviewer_models)} distinct): `{', '.join(summary.reviewer_models)}`  ")
        if summary.ai_components:
            md.append(f"**AI/LLM components detected**: `{', '.join(summary.ai_components)}` — OWASP Top 10 for LLM Applications 2026 applied to threat modeling  ")
        md.append("")
        md.extend(self._static_section(summary.static_findings))

        # Provenance
        md.append("### Execution Provenance")
        if summary.agent_calls:
            md.append("| Agent | Model | Mode | Calls | Reason |")
            md.append("| :--- | :--- | :--- | :--- | :--- |")
            grouped: Dict[Tuple[str, str, str, str], int] = {}
            for c in summary.agent_calls:
                key = (c.agent_id, c.model_name, c.mode, c.reason or "")
                grouped[key] = grouped.get(key, 0) + 1
            for (agent_id, model_name, mode, reason), count in grouped.items():
                mode_label = {"live": "🟢 live", "simulated": "🟡 simulated",
                              "retried": "🟠 unusable, re-asked"}.get(mode, "🔴 invalid output")
                md.append(f"| `{self._cell(agent_id)}` | `{self._cell(model_name)}` | {mode_label} | {count} | {self._cell(reason) or '-'} |")
        else:
            md.append("No agent invocations were recorded.")
        md.append("\n")

        # 2. White-Box Multi-Model Review Findings
        md.append("## 2. 🔬 Phases 2–3: Heterogeneous White-Box Code Review, Verification & Tests")
        models = " / ".join(summary.reviewer_models) or "the configured reviewer models"
        if debate_result.is_simulated or any(f.is_simulated for f in debate_result.confirmed_findings):
            md.append(f"> **De-biasing Architecture (SIMULATED)**: Reviewer and verifier outputs below are simulation templates, not real {models} audits.\n")
        else:
            md.append(f"> **De-biasing Architecture**: Findings cross-audited across {models}; no model rules on its own finding.\n")
        md.append(f"**Debate Consensus Summary**{sim_tag}: {markdown_safe(debate_result.consensus_summary)}\n")

        if debate_result.confirmed_findings:
            kept = f" ({debate_result.undecided_count} undecided tie(s) kept for testing)" if debate_result.undecided_count else ""
            md.append(f"### Confirmed Logic & Defensive Blindspots{kept}:")
            for f in debate_result.confirmed_findings:
                tag = " `[SIMULATED]`" if f.is_simulated else ""
                also = f"; also reported by {', '.join(f.corroborated_by)}" if f.corroborated_by else ""
                mapping = f" `{self._cell(f.owasp_mapping)}`" if f.owasp_mapping else ""
                md.append(f"- **[{f.severity.value}] {markdown_safe(f.title)}**{mapping}{tag} (Identified by {f.reviewer_name}{also})")
                md.append(f"  - **Root Cause**: {markdown_safe(f.root_cause)}")
                md.append(f"  - **Vibe-Coding Flaw**: {markdown_safe(f.suspected_vibe_flaw)}")
                md.append(f"  - **Suggested Scenario**: {self._code_span(f.suggested_test_scenario)}")
                if f.verification_votes:
                    md.append(f"  - **Verification**: {self._votes(f)}")
        else:
            md.append("✅ No critical white-box defects identified.")

        if debate_result.disputed_findings:
            md.append("\n### Disputed Findings (rejected by a cross-model majority, not tested):")
            for f in debate_result.disputed_findings:
                md.append(f"- [{f.severity.value}] {markdown_safe(f.title)} (Identified by {f.reviewer_name}) — {self._votes(f)}")

        md.append("\n### White-Box Test Execution Results")
        if whitebox_results:
            md.append("| Test ID | Type | Derived From | Status | Duration | Outcome |")
            md.append("| :--- | :--- | :--- | :--- | :--- | :--- |")
            for r in whitebox_results:
                md.append(f"| `{self._cell(r.test_id)}` | {r.test_type} | `{self._cell(r.source_ref) or '-'}` | {self._status_label(r.status, 'FAILED')} | `{r.duration_seconds}s` | {self._cell(r.failure_reason) or 'Passed'} |")
        else:
            md.append("No white-box tests executed.")

        md.append("\n")

        # 3. Black-Box Threat Modeling Matrix
        md.append("## 3. 🎯 Phase 4: Black-Box Threat Modeling (STRIDE & OWASP)" + (" `[SIMULATED]`" if threat_model.is_simulated else ""))
        md.append(f"**System Description**: {markdown_safe(threat_model.system_description)}  ")
        md.append(f"**Entrypoints Audited**: {self._code_span(self._join_list(threat_model.entrypoints))}  ")
        md.append(f"**Trust Boundaries**: {self._code_span(self._join_list(threat_model.trust_boundaries))}\n")

        md.append("| Threat ID | STRIDE Category | OWASP Mapping | MITRE ATLAS | Severity | Threat Title & Attack Vector |")
        md.append("| :--- | :--- | :--- | :--- | :--- | :--- |")
        for t in threat_model.threats:
            owasp = self._cell(t.owasp_mapping) or "N/A"
            atlas = self._cell(t.atlas_mapping) or "-"
            md.append(f"| `{self._cell(t.threat_id)}` | **{t.stride_category.value}** | {owasp} | {atlas} | `{t.severity.value}` | **{self._cell(t.title)}**<br>*{self._cell(t.attack_vector)}* |")

        md.append("\n")

        # 4. Black-Box Dynamic Security Execution Results
        md.append("## 4. ⚡ Phase 5: Threat-Derived Black-Box Dynamic Test Execution")
        if blackbox_results:
            md.append("| Test ID | Type | Status | Latency | Outcome / Exploitation |")
            md.append("| :--- | :--- | :--- | :--- | :--- |")
            for r in blackbox_results:
                status_icon = "❌ VULNERABLE" if r.is_security_exploit_confirmed else self._status_label(r.status, "FAILED")
                md.append(f"| `{self._cell(r.test_id)}` | {r.test_type} | {status_icon} | `{r.duration_seconds}s` | {self._cell(r.failure_reason) or 'Boundary defended'} |")

            # Check for reproduction PoCs
            pocs = [r for r in blackbox_results if r.reproduction_poc and r.is_security_exploit_confirmed]
            if pocs:
                md.append("\n### 🚨 Confirmed Vulnerability Proof of Concepts (PoCs):")
                for p in pocs:
                    md.append(f"#### PoC for `{p.test_id}`")
                    poc_text = p.reproduction_poc or ""
                    fence = self._fence(poc_text)
                    md.append(f"{fence}python\n{poc_text}\n{fence}")
        else:
            md.append("No black-box tests executed.")

        if summary.untested_threat_ids:
            md.append("\n### ⚪ Threats Not Tested")
            md.append("No executable test was synthesized for these threats; they are neither confirmed nor ruled out:")
            for threat_id in summary.untested_threat_ids:
                md.append(f"- {self._code_span(threat_id)}")  # a model-chosen id cannot break out of the span

        md.append("\n")

        # 5. Key Recommendations for Vibe Coder
        md.append("## 5. 💡 Actionable Next Steps for Vibe Coder")
        for rec in summary.key_recommendations:
            md.append(f"- {markdown_safe(rec)}")

        md.extend(self._generated_tests_section(whitebox_tests, whitebox_results, blackbox_tests, blackbox_results))

        md.append("\n---\n*Generated automatically by VibeHarness-MAS Harness Commander.*")

        return "\n".join(md)

    def generate_json_report(
        self,
        summary: VibeHarnessSummary,
        debate_result: MultiModelDebateResult,
        threat_model: ThreatModelReport,
        whitebox_results: List[TestExecutionResult],
        blackbox_results: List[TestExecutionResult],
        target_path: str,
        whitebox_tests: Optional[List[GeneratedTest]] = None,
        blackbox_tests: Optional[List[GeneratedTest]] = None
    ) -> str:
        """Machine-readable report with the same content as the Markdown one (provenance included).
        Generated test code is stored verbatim, so a run can be audited and its tests re-executed."""
        payload = {
            "tool": "vibeharness-mas",
            # Bump when a field is renamed/removed or its meaning changes; additions keep the version
            "schema_version": JSON_SCHEMA_VERSION,
            "target_path": os.path.abspath(target_path),
            "summary": summary.model_dump(),
            "whitebox": {
                "debate": debate_result.model_dump(),
                "test_results": [r.model_dump() for r in whitebox_results],
                "generated_tests": [t.model_dump() for t in whitebox_tests or []],
            },
            "threat_model": threat_model.model_dump(),
            "blackbox_test_results": [r.model_dump() for r in blackbox_results],
            "blackbox_generated_tests": [t.model_dump() for t in blackbox_tests or []],
        }
        return json.dumps(payload, indent=2, ensure_ascii=False, default=str)

    def generate_sarif_report(
        self,
        summary: VibeHarnessSummary,
        debate_result: MultiModelDebateResult,
        threat_model: ThreatModelReport,
        whitebox_results: List[TestExecutionResult],
        blackbox_results: List[TestExecutionResult],
        target_path: str,
        symbols: Optional[List[CodeSymbol]] = None
    ) -> str:
        """
        SARIF 2.1.0 output for GitHub Code Scanning: confirmed white-box findings with
        best-effort file/line locations, plus confirmed black-box breaches (located at the
        symbol their threat's attack vector names, when one can be resolved).
        URIs are relative to the enclosing git repository (%SRCROOT%), else to the target.
        """
        from vibeharness import __version__
        root = self._sarif_root(target_path)

        rules: List[Dict[str, object]] = []
        rule_index: Dict[str, int] = {}
        results: List[Dict[str, object]] = []

        def add_rule(rule_id: str, short: str, full: str, level: str) -> int:
            if rule_id not in rule_index:
                rule_index[rule_id] = len(rules)
                rules.append({
                    "id": rule_id,
                    "name": rule_id,
                    "shortDescription": {"text": short},
                    "fullDescription": {"text": full},
                    "defaultConfiguration": {"level": level},
                })
            return rule_index[rule_id]

        # 0. Deterministic AI-security rule hits (no model involved)
        for sf in summary.static_findings:
            rule_id = SARIF_RULE_STATIC_PREFIX + sf.rule_id
            idx = add_rule(rule_id, sf.title, sf.remediation, self._sarif_level(sf.severity))
            tags = [t for t in (sf.owasp_mapping, sf.atlas_mapping, sf.cwe) if t]
            rules[idx].setdefault("properties", {"tags": ["security", *tags]})
            uri = self._sarif_uri(sf.file_path, root)
            static_result: Dict[str, object] = {
                "ruleId": rule_id,
                "ruleIndex": idx,
                "level": self._sarif_level(sf.severity),
                "message": {"text": f"{sf.title}: {clean_model_text(sf.evidence)}" if sf.evidence else sf.title},
                "partialFingerprints": {"vibeharness/v1": self._fingerprint(uri or "", sf.rule_id, str(sf.line_number))},
                "properties": {"severity": sf.severity.value, "owasp": sf.owasp_mapping or "",
                               "atlas": sf.atlas_mapping or "", "cwe": sf.cwe or "", "deterministic": True},
            }
            if uri:
                static_result["locations"] = [self._location(uri, sf.line_number)]
            results.append(static_result)

        add_rule(
            SARIF_RULE_WHITEBOX, "Confirmed white-box defect hypothesis",
            "A defect reported by a reviewer model and confirmed (or left undecided) by cross-model verification.",
            "warning",
        )
        # 1. Confirmed white-box findings (file locations resolved from line_number or the symbol table)
        for f in debate_result.confirmed_findings:
            level = self._sarif_level(f.severity)
            desc = f.title
            if f.description:
                desc += f"\n\n{f.description}"
            if f.root_cause:
                desc += f"\n\nRoot cause: {f.root_cause}"
            if f.suggested_test_scenario:
                desc += f"\n\nSuggested test: {f.suggested_test_scenario}"
            desc = clean_model_text(desc)
            uri = self._sarif_uri(f.file_path, root)
            result: Dict[str, object] = {
                "ruleId": SARIF_RULE_WHITEBOX,
                "ruleIndex": rule_index[SARIF_RULE_WHITEBOX],
                "level": level,
                "message": {"text": desc},
                "partialFingerprints": {"vibeharness/v1": self._fingerprint(
                    uri or "", f.symbol_name or "", self._normalize(f.title)
                )},
                "properties": {
                    "findingId": f.finding_id,
                    "severity": f.severity.value,
                    "reviewer": f.reviewer_name,
                    "symbol": f.symbol_name or "",
                    "corroboratedBy": f.corroborated_by,
                    "simulated": f.is_simulated,
                },
            }
            if uri:
                # Omitted (never null) when unknown: SARIF requires an array if present
                result["locations"] = [self._location(uri, self._resolve_line(f, symbols))]
            results.append(result)

        # 2. Confirmed black-box security breaches, located at the symbol the threat targets if known
        threats_by_id = {t.threat_id: t for t in threat_model.threats}
        for r in blackbox_results:
            if not r.is_security_exploit_confirmed:
                continue
            if SARIF_RULE_BLACKBOX not in rule_index:
                add_rule(
                    SARIF_RULE_BLACKBOX, "Confirmed black-box security breach",
                    "A threat-model-derived attack test whose defensive assertion failed against the target.",
                    "error",
                )
            threat = threats_by_id.get(r.source_ref or "")
            derived = f" (derived from {r.source_ref}{': ' + threat.title if threat else ''})" if r.source_ref else ""
            text = f"Confirmed security breach {r.test_id}{derived}: {r.failure_reason or 'the attack test succeeded'}"
            breach: Dict[str, object] = {
                "ruleId": SARIF_RULE_BLACKBOX,
                "ruleIndex": rule_index[SARIF_RULE_BLACKBOX],
                "level": "error",
                "message": {"text": clean_model_text(text)},
                "partialFingerprints": {"vibeharness/v1": self._fingerprint(
                    *((threat.stride_category.value, self._normalize(threat.title), self._normalize(threat.attack_vector))
                      if threat else (r.test_id, r.source_ref or ""))
                )},
                "properties": {"testId": r.test_id, "threatId": r.source_ref or "", "security_breach": True,
                               "simulated": False},
            }
            target_symbol = self._threat_symbol(threat, symbols) if threat else None
            if target_symbol:
                uri = self._sarif_uri(target_symbol.file_path, root)
                if uri:
                    breach["locations"] = [self._location(uri, max(1, target_symbol.line_start))]
            results.append(breach)

        payload = {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "VibeHarness-MAS",
                        "version": __version__,
                        "informationUri": "https://github.com/chinchiang/MultiAgentGama",
                        "rules": rules,
                    }
                },
                "results": results,
                "properties": {
                    "overall_status": summary.overall_status,
                    "target": os.path.abspath(target_path),
                    **({"generated_at": summary.run.generated_at, "execution_mode": summary.run.execution_mode,
                        "target_git_commit": summary.run.target_git_commit or ""} if summary.run else {}),
                },
            }],
        }
        return json.dumps(payload, indent=2, ensure_ascii=False)

    @staticmethod
    def _location(uri: str, line: int) -> Dict[str, object]:
        return {
            "physicalLocation": {
                "artifactLocation": {"uri": uri, "uriBaseId": "%SRCROOT%"},
                "region": {"startLine": line},
            }
        }

    @staticmethod
    def _normalize(text: str) -> str:
        """Case/punctuation-insensitive form of model text, so fingerprints survive cosmetic rewording."""
        return " ".join(re.findall(r"[a-z0-9]+", (text or "").lower()))

    @staticmethod
    def _threat_symbol(threat: ThreatItem, symbols: Optional[List[CodeSymbol]]) -> Optional[CodeSymbol]:
        """The extracted symbol the threat's attack vector names (whole-word match, routes first)."""
        text = f"{threat.attack_vector} {threat.attack_scenario}"
        for sym in sorted(symbols or [], key=lambda s: s.symbol_type != "route"):
            short = sym.name.split(".")[-1]
            if sym.name in text or re.search(rf"\b{re.escape(short)}\b", text):
                return sym
        return None

    @staticmethod
    def _sarif_root(target_path: str) -> str:
        """%SRCROOT% for URIs: the git repository containing the target (Code Scanning resolves
        URIs against the repo root), else the target directory itself."""
        start = os.path.abspath(target_path)
        if not os.path.isdir(start):
            start = os.path.dirname(start)
        home = os.path.expanduser("~")
        current = start
        while True:
            # A git repository at the home directory is almost always a dotfiles/config repo,
            # never the code repo the SARIF will be uploaded against; a throwaway run directory
            # under such a home must not inherit it as %SRCROOT%.
            if not ReportGenerator._same_path(current, home) and os.path.exists(os.path.join(current, ".git")):
                return current
            parent = os.path.dirname(current)
            if parent == current or ReportGenerator._same_path(current, home):
                # No repository: the target directory (a file target's own directory)
                return start if os.path.isdir(start) else target_path
            current = parent

    @staticmethod
    def _same_path(a: str, b: str) -> bool:
        """Path identity that survives Windows 8.3 short names, case differences and symlinks."""
        try:
            return os.path.samefile(a, b)
        except OSError:
            return os.path.normcase(os.path.abspath(a)) == os.path.normcase(os.path.abspath(b))

    @staticmethod
    def _sarif_level(severity: FindingSeverity) -> str:
        return {
            FindingSeverity.CRITICAL: "error",
            FindingSeverity.HIGH: "error",
            FindingSeverity.MEDIUM: "warning",
            FindingSeverity.LOW: "note",
            FindingSeverity.INFO: "note",
        }[severity]

    @staticmethod
    def _sarif_uri(file_path: str, target_path: str) -> Optional[str]:
        """Best-effort repo-root-relative URI with forward slashes; None when unknown."""
        # "unknown" is the reviewer's placeholder for a finding it could not attribute, not a file
        if not file_path or not file_path.strip() or file_path.strip() == "unknown":
            return None
        p = file_path.strip().replace("\\", "/").removeprefix("./")
        drive = _WINDOWS_DRIVE_RE.match(file_path)
        if os.path.isabs(file_path) or drive:
            if os.path.isdir(target_path) or os.path.isabs(target_path) or _WINDOWS_DRIVE_RE.match(target_path or ""):
                base = target_path
            else:
                base = os.path.dirname(os.path.abspath(target_path))
            base_drive = _WINDOWS_DRIVE_RE.match(base or "")
            if drive and (base_drive is None or file_path[:2].lower() != base[:2].lower()):
                return os.path.basename(p)
            try:
                rel = os.path.relpath(file_path, base).replace("\\", "/")
            except ValueError:  # different drive on Windows
                return os.path.basename(p)
            if rel.startswith(".."):
                return os.path.basename(p)
            return rel
        return p

    @staticmethod
    def _resolve_line(finding: ReviewFinding, symbols: Optional[List[CodeSymbol]]) -> int:
        if finding.line_number:
            return max(1, int(finding.line_number))
        if finding.symbol_name:
            candidates = [s for s in (symbols or []) if s.name == finding.symbol_name]
            if candidates:
                if finding.file_path:
                    stem = os.path.basename(finding.file_path)
                    same_file = [s for s in candidates if os.path.basename(s.file_path) == stem]
                    candidates = same_file or candidates
                return max(1, candidates[0].line_start)
        return 1

    @staticmethod
    def _fingerprint(*parts: str) -> str:
        return hashlib.sha1("|".join(parts).encode("utf-8")).hexdigest()

    @staticmethod
    def _status_label(status: TestStatus, failed_label: str) -> str:
        return {
            TestStatus.PASSED: "✅ PASSED",
            TestStatus.FAILED: f"❌ {failed_label}",
            TestStatus.ERROR: "⚠️ ERROR (not a finding)",
            TestStatus.SKIPPED: "⏭️ SKIPPED",
        }[status]

    @staticmethod
    def _votes(finding: ReviewFinding) -> str:
        """e.g. `deepseek: reject (checked before use); glm: corroborated`"""
        if not finding.verification_votes:
            return "no usable verifier votes"
        return "; ".join(
            f"{v.model_alias}: {v.verdict}" + (f" ({markdown_safe(v.reason)})" if v.reason else "")
            for v in finding.verification_votes
        )

    @staticmethod
    def _join_list(value: object) -> str:
        """Joins a list field for display; a stray string from a model response renders as one item
        instead of being exploded character by character by ', '.join."""
        items = value if isinstance(value, list) else [value]
        return ", ".join(str(v) for v in items if str(v).strip())

    @staticmethod
    def _cell(text: Optional[str]) -> str:
        """Makes free text safe for a single Markdown table cell (and defangs images / raw HTML)."""
        return markdown_safe(text or "").replace("|", "\\|").replace("\n", " ")

    @staticmethod
    def _code_span(text: Optional[str]) -> str:
        """Inline code for model text: control characters removed and the fence widened past any
        backtick run inside, so the text cannot break out of the span."""
        body = clean_model_text(text or "").replace("\n", " ")
        if not body.strip():
            return "`-`"
        longest = max((len(run) for run in re.findall(r"`+", body)), default=0)
        fence = "`" * (longest + 1)
        pad = " " if body.startswith("`") or body.endswith("`") else ""
        return f"{fence}{pad}{body}{pad}{fence}"

    @staticmethod
    def _fence(text: str) -> str:
        """A code fence longer than any backtick run in the text, so model-written code cannot close it early."""
        longest = max((len(run) for run in re.findall(r"`+", text or "")), default=0)
        return "`" * max(3, longest + 1)

    def _generated_tests_section(
        self,
        whitebox_tests: Optional[List[GeneratedTest]],
        whitebox_results: List[TestExecutionResult],
        blackbox_tests: Optional[List[GeneratedTest]],
        blackbox_results: List[TestExecutionResult],
    ) -> List[str]:
        """Appendix with every executed test's code next to its outcome. A model-written test that "passes"
        may be asserting the defect itself (e.g. `pytest.raises(KeyError)`), so the code must be reviewable;
        the JSON report keeps it verbatim, here control characters are removed for safe rendering."""
        from vibeharness.runners.test_executor import TestSuiteExecutor
        if not whitebox_tests and not blackbox_tests:
            return []
        md = ["\n## 6. 🧪 Generated Test Code (audit trail)",
              "Model-written tests are hypotheses too: check that each assertion encodes the *correct* behaviour, "
              "not the defect. Outcomes refer to the tables above.\n"]
        for label, tests, results in (
            ("White-box tests", whitebox_tests or [], whitebox_results),
            ("Black-box attack tests", blackbox_tests or [], blackbox_results),
        ):
            if not tests:
                continue
            md.append(f"### {label} ({len(tests)})")
            by_id = {r.test_id: r for r in results}
            for test_id, t in zip(TestSuiteExecutor._unique_test_ids(tests), tests, strict=True):
                result = by_id.get(test_id)
                if result is None:
                    outcome = "not run"
                elif result.is_security_exploit_confirmed:
                    outcome = "❌ VULNERABLE"
                else:
                    outcome = self._status_label(result.status, "FAILED")
                # <summary> is an HTML block (Markdown is not rendered there): escape ids as HTML
                source = f" — from <code>{html.escape(clean_model_text(t.source_ref))}</code>" if t.source_ref else ""
                code = clean_model_text(t.code)
                fence = self._fence(code)
                md.append("<details>")
                md.append(f"<summary><code>{html.escape(clean_model_text(test_id))}</code> — {outcome}{source}</summary>\n")
                md.append(f"- **Title**: {markdown_safe(t.title)}")
                md.append(f"- **Rationale**: {markdown_safe(t.rationale)}")
                md.append(f"- **Expected outcome**: {markdown_safe(t.expected_outcome)}\n")
                md.append(f"{fence}python\n{code}\n{fence}\n")
                md.append("</details>\n")
        return md

    def _static_section(self, findings: List[StaticFinding]) -> List[str]:
        """Deterministic AI-security rule hits (OWASP LLM Top 10 2026 / MITRE ATLAS mapped)."""
        md = ["### Deterministic AI-Security Rules (no model involved)"]
        if not findings:
            md.append("No rule hits. Rules cover unsafe model loading and unpinned model downloads (LLM04), model output "
                      "reaching exec/shell/SQL sinks (LLM10), uncapped model calls (LLM06), hard-coded credentials "
                      "(LLM02) and reviewer-directed prompt injection or invisible characters (LLM01).\n")
            return md
        md.append("HIGH+ hits fail the gate (`NEEDS_FIXES`); prompt-injection and invisible-character hits also mark "
                  "the model-driven phases as possibly manipulated.\n")
        md.append("| Rule | Severity | Location | Finding | OWASP | MITRE ATLAS | CWE |")
        md.append("| :--- | :--- | :--- | :--- | :--- | :--- | :--- |")
        for f in findings:
            evidence = f"<br>*{self._cell(f.evidence)}*" if f.evidence else ""
            md.append(
                f"| `{f.rule_id}` | `{f.severity.value}` | `{self._cell(os.path.basename(f.file_path))}:{f.line_number}` | "
                f"**{self._cell(f.title)}**{evidence} | {self._cell(f.owasp_mapping) or '-'} | "
                f"{self._cell(f.atlas_mapping) or '-'} | {self._cell(f.cwe) or '-'} |"
            )
        md.append("")
        return md
