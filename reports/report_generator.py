import hashlib
import json
import os
import re
from typing import List, Optional
from core.models import (
    CodeSymbol,
    MultiModelDebateResult,
    ReviewFinding,
    ThreatModelReport,
    TestExecutionResult,
    VibeHarnessSummary,
    TestStatus,
    FindingSeverity
)

# Windows drive paths ("C:\...") count as absolute even on POSIX hosts, so a SARIF produced
# on Windows relativizes identically when re-processed by a Linux CI runner.
_WINDOWS_DRIVE_RE = re.compile(r"^[A-Za-z]:[\\/]")


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
        target_path: str
    ) -> str:
        md = []

        # Header
        md.append("# 🛡️ VibeHarness-MAS Multi-Agent Quality & Security Report")
        md.append(f"**Target System Path**: `{os.path.abspath(target_path)}`  ")
        md.append("**Orchestrator**: Commander Harness Agent  ")
        md.append(f"**Overall Status**: `{summary.overall_status}`  ")
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
        }.get(summary.overall_status, "🔴 **FAIL: BLOCKED BY CRITICAL RISKS**")
        md.append(f"### Verdict: {status_badge}\n")
        if summary.inconclusive_reasons:
            md.append("**Evidence gaps:**")
            for reason in summary.inconclusive_reasons:
                md.append(f"- {reason}")
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
        md.append("\n")

        # Provenance
        md.append("### Execution Provenance")
        if summary.agent_calls:
            md.append("| Agent | Model | Mode | Calls | Reason |")
            md.append("| :--- | :--- | :--- | :--- | :--- |")
            grouped = {}
            for c in summary.agent_calls:
                key = (c.agent_id, c.model_name, c.mode, c.reason or "")
                grouped[key] = grouped.get(key, 0) + 1
            for (agent_id, model_name, mode, reason), count in grouped.items():
                mode_label = {"live": "🟢 live", "simulated": "🟡 simulated"}.get(mode, "🔴 invalid output")
                md.append(f"| `{self._cell(agent_id)}` | `{self._cell(model_name)}` | {mode_label} | {count} | {self._cell(reason) or '-'} |")
        else:
            md.append("No agent invocations were recorded.")
        md.append("\n")

        # 2. White-Box Multi-Model Review Findings
        md.append("## 2. 🔬 Phase 1: Heterogeneous White-Box Code Review & Debate")
        if debate_result.is_simulated or any(f.is_simulated for f in debate_result.confirmed_findings):
            md.append("> **De-biasing Architecture (SIMULATED)**: Reviewer and verifier outputs below are simulation templates, not real Claude / Nemotron / ChatGPT audits.\n")
        else:
            md.append("> **De-biasing Architecture**: Findings cross-audited across Claude (Logic/Edge-cases), Nemotron (Defensive/Guardrails), and ChatGPT (Spec/Contracts).\n")
        md.append(f"**Debate Consensus Summary**{sim_tag}: {debate_result.consensus_summary}\n")

        if debate_result.confirmed_findings:
            kept = f" ({debate_result.undecided_count} undecided tie(s) kept for testing)" if debate_result.undecided_count else ""
            md.append(f"### Confirmed Logic & Defensive Blindspots{kept}:")
            for f in debate_result.confirmed_findings:
                tag = " `[SIMULATED]`" if f.is_simulated else ""
                also = f"; also reported by {', '.join(f.corroborated_by)}" if f.corroborated_by else ""
                md.append(f"- **[{f.severity.value}] {f.title}**{tag} (Identified by {f.reviewer_name}{also})")
                md.append(f"  - **Root Cause**: {f.root_cause}")
                md.append(f"  - **Vibe-Coding Flaw**: {f.suspected_vibe_flaw}")
                md.append(f"  - **Suggested Scenario**: `{f.suggested_test_scenario}`")
                if f.verification_votes:
                    md.append(f"  - **Verification**: {self._votes(f)}")
        else:
            md.append("✅ No critical white-box defects identified.")

        if debate_result.disputed_findings:
            md.append("\n### Disputed Findings (rejected by a cross-model majority, not tested):")
            for f in debate_result.disputed_findings:
                md.append(f"- [{f.severity.value}] {f.title} (Identified by {f.reviewer_name}) — {self._votes(f)}")

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
        md.append("## 3. 🎯 Phase 2: Black-Box Threat Modeling (STRIDE & OWASP)" + (" `[SIMULATED]`" if threat_model.is_simulated else ""))
        md.append(f"**System Description**: {threat_model.system_description}  ")
        md.append(f"**Entrypoints Audited**: `{', '.join(threat_model.entrypoints)}`  ")
        md.append(f"**Trust Boundaries**: `{', '.join(threat_model.trust_boundaries)}`\n")

        md.append("| Threat ID | STRIDE Category | OWASP Mapping | Severity | Threat Title & Attack Vector |")
        md.append("| :--- | :--- | :--- | :--- | :--- |")
        for t in threat_model.threats:
            owasp = self._cell(t.owasp_mapping) or "N/A"
            md.append(f"| `{self._cell(t.threat_id)}` | **{t.stride_category.value}** | {owasp} | `{t.severity.value}` | **{self._cell(t.title)}**<br>*{self._cell(t.attack_vector)}* |")

        md.append("\n")

        # 4. Black-Box Dynamic Security Execution Results
        md.append("## 4. ⚡ Phase 3: Threat-Derived Black-Box Dynamic Test Execution")
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
                    md.append(f"```python\n{p.reproduction_poc}\n```")
        else:
            md.append("No black-box tests executed.")

        if summary.untested_threat_ids:
            md.append("\n### ⚪ Threats Not Tested")
            md.append("No executable test was synthesized for these threats; they are neither confirmed nor ruled out:")
            for threat_id in summary.untested_threat_ids:
                md.append(f"- `{threat_id}`")

        md.append("\n")

        # 5. Key Recommendations for Vibe Coder
        md.append("## 5. 💡 Actionable Next Steps for Vibe Coder")
        for rec in summary.key_recommendations:
            md.append(f"- {rec}")

        md.append("\n---\n*Generated automatically by VibeHarness-MAS Harness Commander.*")

        return "\n".join(md)

    def generate_json_report(
        self,
        summary: VibeHarnessSummary,
        debate_result: MultiModelDebateResult,
        threat_model: ThreatModelReport,
        whitebox_results: List[TestExecutionResult],
        blackbox_results: List[TestExecutionResult],
        target_path: str
    ) -> str:
        """Machine-readable report with the same content as the Markdown one (provenance included)."""
        payload = {
            "tool": "vibeharness-mas",
            "target_path": os.path.abspath(target_path),
            "summary": summary.model_dump(),
            "whitebox": {
                "debate": debate_result.model_dump(),
                "test_results": [r.model_dump() for r in whitebox_results],
            },
            "threat_model": threat_model.model_dump(),
            "blackbox_test_results": [r.model_dump() for r in blackbox_results],
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
        best-effort file/line locations, plus confirmed black-box breaches.
        """
        from core import __version__

        rules = []
        rule_index = {}
        results = []

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
            uri = self._sarif_uri(f.file_path, target_path)
            line = self._resolve_line(f, symbols)
            location = None
            if uri:
                location = [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": uri, "uriBaseId": "%SRCROOT%"},
                        "region": {"startLine": line},
                    }
                }]
            results.append({
                "ruleId": f.finding_id,
                "ruleIndex": add_rule(
                    f.finding_id,
                    f"[{f.severity.value}] {f.title}",
                    desc.split("\n\n")[0],
                    level
                ),
                "level": level,
                "message": {"text": desc},
                "locations": location,
                "partialFingerprints": {"vibeharness/v1": self._fingerprint(
                    uri or "", f.symbol_name or "", f.title
                )},
                "properties": {
                    "severity": f.severity.value,
                    "reviewer": f.reviewer_name,
                    "symbol": f.symbol_name or "",
                    "corroboratedBy": f.corroborated_by,
                    "simulated": f.is_simulated,
                },
            })

        # 2. Confirmed black-box security breaches (no file location: threats are system-level)
        for r in blackbox_results:
            if not r.is_security_exploit_confirmed:
                continue
            derived = f" (derived from {r.source_ref})" if r.source_ref else ""
            text = f"Confirmed security breach {r.test_id}{derived}: {r.failure_reason or 'the attack test succeeded'}"
            results.append({
                "ruleId": r.test_id,
                "ruleIndex": add_rule(
                    r.test_id,
                    f"Black-box breach: {r.test_id}",
                    text,
                    "error"
                ),
                "level": "error",
                "message": {"text": text},
                "partialFingerprints": {"vibeharness/v1": self._fingerprint(
                    r.test_id, r.source_ref or "", r.failure_reason or ""
                )},
                "properties": {"security_breach": True, "simulated": False},
            })

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
                },
            }],
        }
        return json.dumps(payload, indent=2, ensure_ascii=False)

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
        if not file_path or not file_path.strip():
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
        """e.g. `nemotron: reject (checked before use); chatgpt: corroborated`"""
        if not finding.verification_votes:
            return "no usable verifier votes"
        return "; ".join(
            f"{v.model_alias}: {v.verdict}" + (f" ({v.reason})" if v.reason else "")
            for v in finding.verification_votes
        )

    @staticmethod
    def _cell(text: str) -> str:
        """Makes free text safe for a single Markdown table cell."""
        return (text or "").replace("|", "\\|").replace("\n", " ")
