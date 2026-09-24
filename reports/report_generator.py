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

        # 1. Executive Summary
        md.append("## 1. 📊 Executive Summary & Quality Gate")
        status_badge = "🟢 **PASS: READY TO SHIP**" if summary.overall_status == "READY_TO_SHIP" else "🔴 **FAIL: BLOCKED BY CRITICAL RISKS**"
        md.append(f"### Verdict: {status_badge}\n")

        md.append(f"| **Primary Target Language** | `{summary.detected_language}` | Supported Stack |")
        md.append(f"| **Heterogeneous Model Consensus Ratio** | `{debate_result.model_agreement_ratio * 100:.1f}%` | ≥ 70% Agreement |")
        cov_str = f"{summary.line_coverage_pct:.1f}%" if summary.line_coverage_pct is not None else "N/A"
        md.append(f"| **Code Line Coverage** | `{cov_str}` | ≥ 80% Baseline |")
        md.append(f"| **Confirmed White-Box Logic Flaws** | `{summary.confirmed_whitebox_bugs}` | 0 Critical |")
        md.append(f"| **White-Box Unit/Property Tests Passed** | `{summary.whitebox_tests_passed} / {len(whitebox_results)}` | 100% Pass Rate |")
        md.append(f"| **STRIDE Threat Scenarios Modeled** | `{summary.total_threats_modeled}` | Full Asset Coverage |")
        md.append(f"| **Confirmed Black-Box Security Breaches** | `{summary.blackbox_security_breaches}` | 0 Breaches Tolerated |")
        md.append("\n")

        # 2. White-Box Multi-Model Review Findings
        md.append("## 2. 🔬 Phase 1: Heterogeneous White-Box Code Review & Debate")
        md.append("> **De-biasing Architecture**: Findings cross-audited across Claude (Logic/Edge-cases), Nemotron (Defensive/Guardrails), and ChatGPT (Spec/Contracts).\n")
        md.append(f"**Debate Consensus Summary**: {debate_result.consensus_summary}\n")

        if debate_result.confirmed_findings:
            md.append("### Confirmed Logic & Defensive Blindspots:")
            for f in debate_result.confirmed_findings:
                md.append(f"- **[{f.severity.value}] {f.title}** (Identified by {f.reviewer_name})")
                md.append(f"  - **Root Cause**: {f.root_cause}")
                md.append(f"  - **Vibe-Coding Flaw**: {f.suspected_vibe_flaw}")
                md.append(f"  - **Suggested Scenario**: `{f.suggested_test_scenario}`")
        else:
            md.append("✅ No critical white-box defects identified.")

        md.append("\n")

        # 3. Black-Box Threat Modeling Matrix
        md.append("## 3. 🎯 Phase 2: Black-Box Threat Modeling (STRIDE & OWASP)")
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
                status_icon = "✅ PASSED" if r.status == TestStatus.PASSED else "❌ VULNERABLE"
                md.append(f"| `{r.test_id}` | {r.test_type} | {status_icon} | `{r.duration_seconds}s` | {r.failure_reason or 'Boundary defended'} |")

            # Check for reproduction PoCs
            pocs = [r for r in blackbox_results if r.reproduction_poc]
            if pocs:
                md.append("\n### 🚨 Confirmed Vulnerability Proof of Concepts (PoCs):")
                for p in pocs:
                    md.append(f"#### PoC for `{p.test_id}`")
                    md.append(f"```python\n{p.reproduction_poc}\n```")
        else:
            md.append("No black-box tests executed.")

        md.append("\n")

        # 5. Key Recommendations for Vibe Coder
        md.append("## 5. 💡 Actionable Next Steps for Vibe Coder")
        for rec in summary.key_recommendations:
            md.append(f"- {rec}")

        md.append("\n---\n*Generated automatically by VibeHarness-MAS Harness Commander.*")

        return "\n".join(md)
