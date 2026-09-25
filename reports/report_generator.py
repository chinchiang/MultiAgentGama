import os
from typing import List, Optional
from core.models import (
    MultiModelDebateResult,
    ThreatModelReport,
    TestExecutionResult,
    VibeHarnessSummary,
    FindingSeverity,
    TestStatus
)


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
        md.append(f"**Orchestrator**: Commander Harness Agent  ")
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
        md.append(f"| **Heterogeneous Model Consensus Ratio** | `{debate_result.model_agreement_ratio * 100:.1f}%`{sim_tag} | ≥ 70% Agreement |")
        cov_str = f"{summary.line_coverage_pct:.1f}%" if summary.line_coverage_pct is not None else "N/A"
        md.append(f"| **Code Line Coverage** | `{cov_str}` | ≥ 80% Baseline |")
        md.append(f"| **Confirmed White-Box Logic Flaws** | `{summary.confirmed_whitebox_bugs}` | 0 Critical |")
        md.append(f"| **White-Box Tests Passed** | `{summary.whitebox_tests_passed} / {len(whitebox_results)}` ({summary.whitebox_tests_errored} errored / not run) | 100% Pass Rate |")
        md.append(f"| **STRIDE Threat Scenarios Modeled** | `{summary.total_threats_modeled}` | Full Asset Coverage |")
        md.append(f"| **Threats Without Executable Test** | `{len(summary.untested_threat_ids)}` | 0 Untested |")
        md.append(f"| **Confirmed Black-Box Security Breaches** | `{summary.blackbox_security_breaches}` | 0 Breaches Tolerated |")
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
                mode_label = "🟢 live" if mode == "live" else "🟡 simulated"
                md.append(f"| `{agent_id}` | `{model_name}` | {mode_label} | {count} | {self._cell(reason) or '-'} |")
        else:
            md.append("No agent invocations were recorded.")
        md.append("\n")

        # 2. White-Box Multi-Model Review Findings
        md.append("## 2. 🔬 Phase 1: Heterogeneous White-Box Code Review & Debate")
        if debate_result.is_simulated or any(f.is_simulated for f in debate_result.confirmed_findings):
            md.append("> **De-biasing Architecture (SIMULATED)**: Reviewer and arbiter outputs below are simulation templates, not real Claude / Nemotron / ChatGPT audits.\n")
        else:
            md.append("> **De-biasing Architecture**: Findings cross-audited across Claude (Logic/Edge-cases), Nemotron (Defensive/Guardrails), and ChatGPT (Spec/Contracts).\n")
        md.append(f"**Debate Consensus Summary**{sim_tag}: {debate_result.consensus_summary}\n")

        if debate_result.confirmed_findings:
            md.append("### Confirmed Logic & Defensive Blindspots:")
            for f in debate_result.confirmed_findings:
                tag = " `[SIMULATED]`" if f.is_simulated else ""
                md.append(f"- **[{f.severity.value}] {f.title}**{tag} (Identified by {f.reviewer_name})")
                md.append(f"  - **Root Cause**: {f.root_cause}")
                md.append(f"  - **Vibe-Coding Flaw**: {f.suspected_vibe_flaw}")
                md.append(f"  - **Suggested Scenario**: `{f.suggested_test_scenario}`")
        else:
            md.append("✅ No critical white-box defects identified.")

        md.append("\n### White-Box Test Execution Results")
        if whitebox_results:
            md.append("| Test ID | Type | Derived From | Status | Duration | Outcome |")
            md.append("| :--- | :--- | :--- | :--- | :--- | :--- |")
            for r in whitebox_results:
                md.append(f"| `{r.test_id}` | {r.test_type} | `{r.source_ref or '-'}` | {self._status_label(r.status, 'FAILED')} | `{r.duration_seconds}s` | {self._cell(r.failure_reason) or 'Passed'} |")
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
            md.append(f"| `{t.threat_id}` | **{t.stride_category.value}** | {t.owasp_mapping or 'N/A'} | `{t.severity.value}` | **{t.title}**<br>*{t.attack_vector}* |")

        md.append("\n")

        # 4. Black-Box Dynamic Security Execution Results
        md.append("## 4. ⚡ Phase 3: Threat-Derived Black-Box Dynamic Test Execution")
        if blackbox_results:
            md.append("| Test ID | Type | Status | Latency | Outcome / Exploitation |")
            md.append("| :--- | :--- | :--- | :--- | :--- |")
            for r in blackbox_results:
                status_icon = "❌ VULNERABLE" if r.is_security_exploit_confirmed else self._status_label(r.status, "FAILED")
                md.append(f"| `{r.test_id}` | {r.test_type} | {status_icon} | `{r.duration_seconds}s` | {self._cell(r.failure_reason) or 'Boundary defended'} |")

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

    @staticmethod
    def _status_label(status: TestStatus, failed_label: str) -> str:
        return {
            TestStatus.PASSED: "✅ PASSED",
            TestStatus.FAILED: f"❌ {failed_label}",
            TestStatus.ERROR: "⚠️ ERROR (not a finding)",
            TestStatus.SKIPPED: "⏭️ SKIPPED",
        }[status]

    @staticmethod
    def _cell(text: str) -> str:
        """Makes free text safe for a single Markdown table cell."""
        return (text or "").replace("|", "\\|").replace("\n", " ")
