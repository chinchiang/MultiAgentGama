import logging
import os
import sys
from typing import Any, Dict, Optional, List
from rich.console import Console
from rich.markup import escape
from rich.panel import Panel

from core.models import (
    VibeHarnessSummary,
    FindingSeverity,
    TestStatus,
    MultiModelDebateResult,
    ThreatModelReport,
    TestExecutionResult,
    StaticFinding
)
from core.llm_gateway import LLMGateway, DEFAULT_CONFIG_PATH
from core.sandbox import LocalSubprocessSandbox, DockerSandbox, DEFAULT_DOCKER_IMAGE
from agents.whitebox.ast_extractor import ASTExtractor, DEFAULT_MAX_FILES
from agents.whitebox.ai_static_scanner import AISecurityStaticScanner
from agents.whitebox.multi_reviewer import HeterogeneousReviewerEnsemble
from agents.whitebox.debater import MultiModelDebater
from agents.whitebox.deduplicator import deduplicate_findings
from agents.whitebox.test_generator import WhiteboxTestGenerator
from agents.blackbox.threat_modeler import AutomatedThreatModeler
from agents.blackbox.scenario_builder import ThreatScenarioBuilder
from runners.test_executor import TestSuiteExecutor
from reports.report_generator import ReportGenerator

logger = logging.getLogger("VibeHarness.Commander")


def force_utf8_stdio() -> None:
    """
    Makes stdout/stderr UTF-8 (replacing unrenderable characters) so emoji, box-drawing and
    CJK output never crashes or garbles when redirected on Windows (e.g. a cp950 codepage).
    Idempotent, and a no-op where streams already handle Unicode or cannot be reconfigured.
    """
    if sys.platform != "win32":
        return
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            reconfigure(encoding="utf-8", errors="replace")
        except (OSError, ValueError):
            pass


class VibeHarnessCommander:
    """
    Commander Harness: Primary AI Orchestrator that directs, schedules,
    and synchronizes sub-agents across White-Box and Black-Box testing phases.
    """

    def __init__(self, config_path: str = DEFAULT_CONFIG_PATH, execution_mode: Optional[str] = None):
        # Protect console output even when the harness is used as a library (main.py does this too)
        force_utf8_stdio()
        self.console = Console(force_terminal=False)
        self.gateway = LLMGateway(config_path, execution_mode=execution_mode)
        global_cfg = self.gateway.config.get("global") or {}
        self.sandbox = self._build_sandbox(global_cfg)
        self.ast_extractor = ASTExtractor()
        self.static_scanner = AISecurityStaticScanner()
        self.multi_reviewer = HeterogeneousReviewerEnsemble(self.gateway)
        self.debater = MultiModelDebater(self.gateway)
        self.whitebox_test_gen = WhiteboxTestGenerator(self.gateway)
        self.threat_modeler = AutomatedThreatModeler(self.gateway)
        self.scenario_builder = ThreatScenarioBuilder(self.gateway)
        self.executor = TestSuiteExecutor(
            self.sandbox, per_test_timeout_seconds=int(global_cfg.get("per_test_timeout_seconds", 30))
        )
        self.reporter = ReportGenerator()
        # Validated like the other limits (a negative or non-integer value is a ConfigError); 0/null keep the default
        self.max_files = LLMGateway._positive_int(global_cfg.get("max_files"), "max_files") or DEFAULT_MAX_FILES

    @staticmethod
    def _build_sandbox(global_cfg: dict) -> LocalSubprocessSandbox:
        provider = global_cfg.get("sandbox_provider", "local_subprocess")
        timeout = int(global_cfg.get("sandbox_timeout_seconds", 120))
        if provider == "local_subprocess":
            return LocalSubprocessSandbox(timeout_seconds=timeout)
        if provider == "docker":
            return DockerSandbox(
                timeout_seconds=timeout,
                image=global_cfg.get("docker_image", DEFAULT_DOCKER_IMAGE),
                network=global_cfg.get("docker_network", "none"),
                memory=str(global_cfg.get("docker_memory", "1g")),
                cpus=str(global_cfg.get("docker_cpus", "2")),
                pids_limit=int(global_cfg.get("docker_pids_limit", 256)),
            )
        raise ValueError(
            f"sandbox_provider '{provider}' is not implemented; supported: 'local_subprocess', 'docker'"
        )

    def run_full_pipeline(
        self,
        target_dir: str,
        system_description: Optional[str] = None,
        base_url: Optional[str] = None,
        output_report_path: str = "vibe_harness_report.md",
        output_format: str = "md",
        output_sarif_path: Optional[str] = None
    ) -> VibeHarnessSummary:
        """
        Executes the complete dual-engine testing workflow:
        Phase 1: Code Ingestion, AST Extraction & deterministic AI-security rules
        Phase 2: Heterogeneous Multi-Model White-Box Review & Debate
        Phase 3: White-Box Unit Test Generation & Sandbox Execution
        Phase 4: Mandatory STRIDE/OWASP Threat Modeling
        Phase 5: Threat-Derived Black-Box Dynamic Test Execution
        Phase 6: Quality Gate Synthesis & Report Generation
        """
        if output_format not in ("md", "json"):
            raise ValueError(f"Unknown output_format '{output_format}' (expected 'md' or 'json')")
        reviewer_models = self.multi_reviewer.distinct_models
        ensemble_label = " | ".join(r["model_alias"] for r in self.multi_reviewer.reviewer_agents) or "none configured"
        self.console.print(Panel.fit(
            "[bold cyan][VibeHarness-MAS] Commander Harness Active[/bold cyan]\n"
            f"[yellow]Target Codebase:[/yellow] {escape(os.path.abspath(target_dir))}\n"
            f"[green]Multi-Model Ensemble:[/green] {escape(ensemble_label)}\n"
            f"[magenta]Execution Mode:[/magenta] {self.gateway.execution_mode}",
            title="AI Test Orchestration Engine",
            border_style="cyan"
        ))

        # -------------------------------------------------------------
        # Phase 1: AST Extraction
        # -------------------------------------------------------------
        self.console.print("\n[bold blue]=== Phase 1: AST Ingestion & Semantic Extraction ===[/bold blue]")
        # A single-file target runs its tests from the containing directory
        work_dir = target_dir if os.path.isdir(target_dir) else os.path.dirname(os.path.abspath(target_dir))
        symbols = self.ast_extractor.parse_directory(target_dir, max_files=self.max_files)
        routes = [s.name for s in symbols if s.symbol_type == "route"]
        # Sorted so the reported stack is deterministic regardless of set iteration order
        detected_langs = sorted(self.ast_extractor.detected_languages) or ["Python"]
        lang_str = ", ".join(detected_langs)
        self.console.print(f"[+] Detected Target Stack: [bold green]{lang_str}[/bold green]")
        self.console.print(f"[+] Extracted [bold]{len(symbols)}[/bold] code symbols across target files.")
        if routes:
            self.console.print(f"[+] Detected [bold]{len(routes)}[/bold] API route handlers: {escape(', '.join(routes[:5]))}")

        # Deterministic rules run before any model sees the code: they cannot be prompt-injected
        static_findings = self.static_scanner.scan_files(self.ast_extractor.analyzed_files)
        ai_components = self.static_scanner.ai_components
        if ai_components:
            self.console.print(
                f"[+] AI/LLM components detected: [bold]{escape(', '.join(ai_components))}[/bold] "
                "(OWASP LLM Top 10 2026 threat modeling enabled)"
            )
        self.console.print(f"[+] Deterministic AI-security rules: [bold]{len(static_findings)}[/bold] hit(s)")
        for sf in static_findings:
            self.console.print(
                f"   - [{sf.severity.value}] {sf.rule_id} {escape(sf.title)} "
                f"({escape(os.path.basename(sf.file_path))}:{sf.line_number})"
            )

        # -------------------------------------------------------------
        # Phase 2: Heterogeneous White-Box Review & Multi-Model Debate
        # -------------------------------------------------------------
        self.console.print("\n[bold blue]=== Phase 2: Heterogeneous Multi-Model White-Box Review ===[/bold blue]")
        raw_findings = self.multi_reviewer.review_symbols(symbols, root_dir=work_dir)
        self.console.print(f"[+] Received [bold]{len(raw_findings)}[/bold] raw review findings from {escape(ensemble_label)}.")
        if len(reviewer_models) < 2:
            # Agreement among copies of one model is consistency, not corroboration (OWASP LLM07:2026)
            self.console.print("[yellow][!] Fewer than two distinct reviewer models: cross-model verification cannot run.[/yellow]")
        findings = deduplicate_findings(raw_findings)
        corroborated = sum(1 for f in findings if f.corroborated_by)
        if len(findings) < len(raw_findings):
            self.console.print(f"[+] Merged duplicates into [bold]{len(findings)}[/bold] distinct findings ({corroborated} reported by more than one model).")

        self.console.print("[yellow]Cross-verifying findings: each is ruled on by the models that did not report it...[/yellow]")
        debate_result: MultiModelDebateResult = self.debater.arbitrate(findings, symbols=symbols, root_dir=work_dir)
        if debate_result.arbitration_applied:
            ratio = debate_result.model_agreement_ratio
            ratio_display = f"{ratio * 100:.1f}%" if ratio is not None else "N/A (no decisive votes)"
            self.console.print(f"[+] Cross-Model Agreement: [bold green]{ratio_display}[/bold green] | {len(debate_result.disputed_findings)} disputed")
        else:
            self.console.print("[yellow][!] Cross-model verification not applied; findings are unfiltered reviewer hypotheses.[/yellow]")
        confirmed_majority = len(debate_result.confirmed_findings) - debate_result.undecided_count
        tie_note = f" (+{debate_result.undecided_count} undecided tie(s) kept for testing)" if debate_result.undecided_count else ""
        self.console.print(f"[+] Confirmed Defect Hypotheses: [bold red]{confirmed_majority}[/bold red]{tie_note}")

        # -------------------------------------------------------------
        # Phase 3: White-Box Test Generation & Sandbox Execution
        # -------------------------------------------------------------
        self.console.print("\n[bold blue]=== Phase 3: White-Box Test Generation & Sandbox Execution ===[/bold blue]")
        wb_tests = self.whitebox_test_gen.generate_tests_for_findings(
            debate_result.confirmed_findings, symbols, root_dir=work_dir
        )
        self.console.print(f"[+] Generated [bold]{len(wb_tests)}[/bold] targeted Pytest unit/boundary tests (with self-healing validation).")

        wb_results, cov_pct = self.executor.execute_test_suite(
            wb_tests,
            working_dir=work_dir,
            collect_coverage=True
        )
        wb_passed = sum(1 for r in wb_results if r.status == TestStatus.PASSED)
        wb_failed = sum(1 for r in wb_results if r.status == TestStatus.FAILED)
        wb_errored = sum(1 for r in wb_results if r.status in (TestStatus.ERROR, TestStatus.SKIPPED))
        cov_display = f"{cov_pct:.1f}%" if cov_pct is not None else "N/A"
        self.console.print(f"[+] White-Box Execution Outcome: [green]{wb_passed} Passed[/green] | [red]{wb_failed} Failed/Exposed[/red] | [yellow]{wb_errored} Error/Not Run[/yellow] | Line Coverage: [bold cyan]{cov_display}[/bold cyan]")

        # -------------------------------------------------------------
        # Phase 4: Mandatory Black-Box Threat Modeling (STRIDE & OWASP)
        # -------------------------------------------------------------
        self.console.print("\n[bold blue]=== Phase 4: Mandatory Black-Box Threat Modeling ===[/bold blue]")
        sys_desc = system_description or f"Vibe-coded application in {os.path.basename(target_dir)}"
        threat_report: ThreatModelReport = self.threat_modeler.model_system(
            system_description=sys_desc,
            entrypoints=routes or ["HTTP/REST Endpoints"],
            detected_routes=routes,
            symbols=symbols,
            root_dir=work_dir,
            ai_components=ai_components
        )
        self.console.print(f"[+] STRIDE Matrix Constructed: [bold yellow]{len(threat_report.threats)}[/bold yellow] attack scenarios identified.")
        for t in threat_report.threats:
            self.console.print(f"   - [[bold magenta]{t.stride_category.value}[/bold magenta]] ({t.severity.value}) {escape(t.title)}")

        # -------------------------------------------------------------
        # Phase 5: Threat-Derived Black-Box Dynamic Test Execution
        # -------------------------------------------------------------
        self.console.print("\n[bold blue]=== Phase 5: Threat-Derived Black-Box Test Execution ===[/bold blue]")
        bb_tests = self.scenario_builder.build_test_cases_from_threats(
            threat_report.threats, base_url=base_url, symbols=symbols, root_dir=work_dir
        )
        self.console.print(f"[+] Synthesized [bold]{len(bb_tests)}[/bold] black-box attack scripts targeting identified threats.")

        bb_results, _ = self.executor.execute_test_suite(
            bb_tests,
            working_dir=work_dir,
            collect_coverage=False
        )
        bb_passed = sum(1 for r in bb_results if r.status == TestStatus.PASSED)
        bb_breaches = sum(1 for r in bb_results if r.is_security_exploit_confirmed)
        # A FAILED attack test that does not match the strict exploit predicate is ambiguous
        # evidence: it must not silently disappear from the gate (it used to, letting the run
        # pass as READY_TO_SHIP while an attack script was actually failing against the target)
        bb_failed_unclassified = [
            r for r in bb_results if r.status == TestStatus.FAILED and not r.is_security_exploit_confirmed
        ]
        bb_errored = sum(1 for r in bb_results if r.status in (TestStatus.ERROR, TestStatus.SKIPPED))
        tested_threat_ids = {t.source_ref for t in bb_tests}
        untested_threats = [t.threat_id for t in threat_report.threats if t.threat_id not in tested_threat_ids]
        self.console.print(
            f"[+] Dynamic Black-Box Outcome: [green]{bb_passed} Defended[/green] | "
            f"[red]{bb_breaches} Confirmed Breaches[/red] | "
            f"[yellow]{len(bb_failed_unclassified)} Failed (unclassified)[/yellow] | "
            f"[yellow]{bb_errored} Error/Not Run[/yellow] | {len(untested_threats)} Threats Not Tested"
        )

        # -------------------------------------------------------------
        # Phase 6: Quality Gate Synthesis & Reporting
        # -------------------------------------------------------------
        self.console.print("\n[bold blue]=== Phase 6: Commander Quality Gate Synthesis ===[/bold blue]")
        critical_threats = sum(1 for t in threat_report.threats if t.severity == FindingSeverity.CRITICAL)

        # Evidence gaps that forbid a READY_TO_SHIP verdict
        inconclusive_reasons: List[str] = []
        budget_hits = self.gateway.budget_exhausted_calls
        if budget_hits:
            inconclusive_reasons.append(
                f"The max_model_calls budget ({self.gateway.max_model_calls}) was exhausted; "
                f"{len(budget_hits)} later agent call(s) used the simulation engine instead of a real model"
            )
        if self.gateway.used_simulation:
            simulated_agents = sorted({rec.agent_id for rec in self.gateway.call_log if rec.mode == "simulated"})
            inconclusive_reasons.append(f"Simulation engine (not real models) was used for: {', '.join(simulated_agents)}")
        invalid_calls = self.gateway.invalid_calls
        if invalid_calls:
            # One entry per agent and reason: a crashed batch reads differently from a malformed answer
            invalid_details = sorted({f"{rec.agent_id} ({rec.reason})" if rec.reason else rec.agent_id for rec in invalid_calls})
            inconclusive_reasons.append(
                f"{len(invalid_calls)} model call(s) returned unusable output or crashed before answering "
                f"(invalid JSON / missing fields, or an exception in the batch): {'; '.join(invalid_details)}"
            )
        unmodeled_findings = self.whitebox_test_gen.findings_without_model_tests
        if unmodeled_findings:
            inconclusive_reasons.append(
                f"{len(unmodeled_findings)} confirmed finding(s) had no usable model-generated test and were only "
                f"covered by deterministic probes, not by a test targeting the defect: {', '.join(unmodeled_findings)}"
            )
        integrity_hits = [f for f in static_findings if f.affects_review_integrity]
        if integrity_hits:
            inconclusive_reasons.append(
                f"{len(integrity_hits)} reviewer-directed instruction(s) or invisible-character sequence(s) were found in "
                f"the target ({', '.join(sorted({f.rule_id for f in integrity_hits}))}); model-based review, verification "
                "and threat modeling may have been manipulated (OWASP LLM01:2026), so review those locations manually"
            )
        if not self.multi_reviewer.reviewer_agents:
            inconclusive_reasons.append("No whitebox_reviewer_* agents are configured, so no white-box model review ran")
        elif len(reviewer_models) < 2:
            # Copies of one model agreeing is consistency, not corroboration (OWASP LLM07:2026)
            inconclusive_reasons.append(
                f"Only one distinct reviewer model ({reviewer_models[0]}) is configured, so cross-model verification "
                "could not run; the findings are unfiltered single-model hypotheses"
            )
        if not symbols:
            inconclusive_reasons.append("No analyzable source symbols were found in the target")
        if self.ast_extractor.parse_failures:
            inconclusive_reasons.append(
                f"{len(self.ast_extractor.parse_failures)} source file(s) could not be parsed and were not analyzed"
            )
        if self.ast_extractor.skipped_files:
            inconclusive_reasons.append(
                f"{len(self.ast_extractor.skipped_files)} source file(s) were skipped by the max_files limit ({self.max_files})"
            )
        if wb_errored or bb_errored:
            inconclusive_reasons.append(
                f"{wb_errored + bb_errored} generated test(s) errored, were skipped, or never ran; "
                "the boundaries they cover remain unverified by this run"
            )
        non_python_langs = [lang for lang in detected_langs if lang != "Python"]
        if non_python_langs:
            inconclusive_reasons.append(
                f"{', '.join(non_python_langs)} code was reviewed statically only: the test sandbox "
                "executes Python, so no dynamic verification covers it"
            )
        if bb_failed_unclassified:
            inconclusive_reasons.append(
                f"{len(bb_failed_unclassified)} black-box attack test(s) failed without a confirmed exploit "
                f"classification; the evidence is ambiguous and needs manual investigation: "
                f"{', '.join(r.test_id for r in bb_failed_unclassified)}"
            )
        if not wb_results:
            inconclusive_reasons.append("No white-box tests were executed")
        if not threat_report.threats:
            inconclusive_reasons.append("Threat modeling produced no threats, so black-box coverage is unknown")
        if untested_threats:
            inconclusive_reasons.append(f"{len(untested_threats)} modeled threat(s) have no executable test: {', '.join(untested_threats)}")

        # Only executed evidence or deterministic rule hits can block or fail the gate; model findings and
        # modeled threats are hypotheses until a test confirms them
        static_blocking = [
            f for f in static_findings if f.severity in (FindingSeverity.CRITICAL, FindingSeverity.HIGH)
        ]
        if bb_breaches > 0:
            overall_status = "BLOCKED_CRITICAL_RISK"
        elif wb_failed > 0 or static_blocking:
            overall_status = "NEEDS_FIXES"
        elif inconclusive_reasons:
            overall_status = "INCONCLUSIVE"
        else:
            overall_status = "READY_TO_SHIP"
        for reason in inconclusive_reasons:
            self.console.print(f"[yellow][!] Evidence gap: {reason}[/yellow]")

        recommendations = self._build_recommendations(
            wb_results, bb_results, threat_report, untested_threats, inconclusive_reasons, static_blocking
        )

        summary = VibeHarnessSummary(
            overall_status=overall_status,
            total_whitebox_findings=len(raw_findings),
            distinct_whitebox_findings=len(findings),
            confirmed_whitebox_bugs=len(debate_result.confirmed_findings) - debate_result.undecided_count,
            whitebox_tests_passed=wb_passed,
            whitebox_tests_failed=wb_failed,
            whitebox_tests_errored=wb_errored,
            total_threats_modeled=len(threat_report.threats),
            critical_threats_count=critical_threats,
            blackbox_tests_passed=bb_passed,
            blackbox_security_breaches=bb_breaches,
            blackbox_tests_failed=len(bb_failed_unclassified),
            blackbox_tests_errored=bb_errored,
            untested_threat_ids=untested_threats,
            agent_calls=list(self.gateway.call_log),
            inconclusive_reasons=inconclusive_reasons,
            line_coverage_pct=cov_pct,
            detected_language=lang_str,
            key_recommendations=recommendations,
            static_findings=static_findings,
            ai_components=ai_components,
            reviewer_models=reviewer_models
        )

        # Output report
        report_args: Dict[str, Any] = dict(
            summary=summary,
            debate_result=debate_result,
            threat_model=threat_report,
            whitebox_results=wb_results,
            blackbox_results=bb_results,
            target_path=target_dir
        )
        # The tests' code is part of the audit trail (md / json); SARIF carries findings only
        test_args: Dict[str, Any] = dict(whitebox_tests=wb_tests, blackbox_tests=bb_tests)
        if output_format == "json":
            md_content = self.reporter.generate_json_report(**report_args, **test_args)
        else:
            md_content = self.reporter.generate_markdown_report(**report_args, **test_args)

        with open(output_report_path, "w", encoding="utf-8") as f:
            f.write(md_content)

        self.console.print(f"[+] Final audit report written to: [bold green]{output_report_path}[/bold green]")

        if output_sarif_path:
            sarif_content = self.reporter.generate_sarif_report(symbols=symbols, **report_args)
            with open(output_sarif_path, "w", encoding="utf-8") as f:
                f.write(sarif_content)
            self.console.print(f"[+] SARIF report written to: [bold green]{output_sarif_path}[/bold green] (for GitHub Code Scanning)")
        verdict_color = {"READY_TO_SHIP": "green", "INCONCLUSIVE": "yellow"}.get(overall_status, "red")
        self.console.print(Panel.fit(
            f"[bold]Quality Gate Verdict:[/bold] [{verdict_color} bold]{overall_status}[/{verdict_color} bold]\n"
            f"White-Box Passed: {wb_passed} | Black-Box Breaches: {bb_breaches}\n"
            f"Report: {output_report_path}",
            title="Verification Summary",
            border_style=verdict_color
        ))

        return summary

    @staticmethod
    def _build_recommendations(
        wb_results: List[TestExecutionResult],
        bb_results: List[TestExecutionResult],
        threat_report: ThreatModelReport,
        untested_threats: List[str],
        inconclusive_reasons: List[str],
        static_blocking: Optional[List[StaticFinding]] = None
    ) -> List[str]:
        """Recommendations derived from this run's evidence, most urgent first."""
        recs: List[str] = []
        threats_by_id = {t.threat_id: t for t in threat_report.threats}
        for r in bb_results:
            if r.is_security_exploit_confirmed:
                threat = threats_by_id.get(r.source_ref or "")
                label = f"{threat.threat_id} {threat.title}" if threat else r.test_id
                recs.append(f"Fix confirmed security breach `{r.test_id}` ({label}): {r.failure_reason}")
        for f in static_blocking or []:
            recs.append(
                f"Fix `{f.rule_id}` {f.title} at `{os.path.basename(f.file_path)}:{f.line_number}` "
                f"({f.owasp_mapping}): {f.remediation}"
            )
        for r in wb_results:
            if r.status == TestStatus.FAILED:
                recs.append(f"Fix defect exposed by `{r.test_id}` (from `{r.source_ref or '-'}`): {r.failure_reason}")
        for r in bb_results:
            if r.status == TestStatus.FAILED and not r.is_security_exploit_confirmed:
                recs.append(f"Investigate black-box crash in `{r.test_id}`: {r.failure_reason}")
        if untested_threats:
            recs.append(f"Write or synthesize tests for untested threats: {', '.join(untested_threats)}")
        if inconclusive_reasons:
            recs.append("Close the evidence gaps listed above (e.g. run with `--mode live` and valid API keys) before trusting a pass verdict.")
        if not recs:
            recs.append("No defects were exposed by the executed tests; keep these tests in CI as regression guards.")
        return recs
