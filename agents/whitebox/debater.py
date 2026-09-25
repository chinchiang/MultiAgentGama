import logging
from typing import List
from core.models import ReviewFinding, MultiModelDebateResult
from core.llm_gateway import LLMGateway

logger = logging.getLogger("VibeHarness.Debater")


class MultiModelDebater:
    """
    Synthesizes findings from distinct LLM reviewers (Claude, Nemotron, ChatGPT),
    resolves disputes, detects cross-model consensus, and filters out model-specific hallucinations.
    """

    def __init__(self, gateway: LLMGateway):
        self.gateway = gateway

    def arbitrate(self, findings: List[ReviewFinding]) -> MultiModelDebateResult:
        if not findings:
            return MultiModelDebateResult(
                confirmed_findings=[],
                disputed_findings=[],
                consensus_summary="No findings submitted for arbitration."
            )

        findings_summary = "\n".join([
            f"[{idx}] Source: {f.reviewer_name} ({f.model_alias}) | Severity: {f.severity.value}\n"
            f"    Title: {f.title}\n"
            f"    Cause: {f.root_cause}\n"
            f"    Scenario: {f.suggested_test_scenario}"
            for idx, f in enumerate(findings)
        ])

        system_prompt = (
            "You are the Chief Multi-Model Arbiter Agent.\n"
            "Your duty is to critically evaluate code review findings submitted by different AI models "
            "(Claude, Nemotron, ChatGPT) to eliminate false positives and identify genuine high-priority issues.\n\n"
            "Output a JSON object with this schema:\n"
            "{\n"
            '  "consensus_summary": "High-level synthesis of verified vulnerabilities",\n'
            '  "model_agreement_ratio": 0.85,\n'
            '  "confirmed_findings_indices": [0, 1, 2],\n'
            '  "disputed_findings_indices": []\n'
            "}"
        )

        user_prompt = f"Review Findings to Arbitrate:\n\n{findings_summary}"
        resp = self.gateway.generate(
            "whitebox_debater", system_prompt, user_prompt, json_output=True,
            required_keys=["confirmed_findings_indices"]
        )
        simulated = self.gateway.is_simulated(resp)

        if simulated or not self.gateway.is_usable(resp):
            # A simulated arbiter returns a fixed template unrelated to these findings, and an unusable
            # answer carries no decision: keep every finding (tests decide) and report no consensus figure.
            reason = "simulated" if simulated else "unusable arbiter output"
            logger.warning(f"Arbitration not applied ({reason}); all {len(findings)} findings kept unfiltered.")
            return MultiModelDebateResult(
                confirmed_findings=list(findings),
                disputed_findings=[],
                consensus_summary=f"Arbitration not applied ({reason}); findings are unfiltered reviewer hypotheses.",
                model_agreement_ratio=None,
                arbitration_applied=False,
                is_simulated=simulated
            )

        valid_idx = range(len(findings))
        confirmed_indices = {i for i in resp.get("confirmed_findings_indices") or [] if isinstance(i, int) and i in valid_idx}
        disputed_indices = {i for i in resp.get("disputed_findings_indices") or [] if isinstance(i, int) and i in valid_idx}

        confirmed: List[ReviewFinding] = []
        disputed: List[ReviewFinding] = []

        for idx, f in enumerate(findings):
            # Findings the arbiter did not rule on are kept rather than silently dropped
            if idx in confirmed_indices or idx not in disputed_indices:
                confirmed.append(f)
            else:
                disputed.append(f)

        agreement = resp.get("model_agreement_ratio")
        if not isinstance(agreement, (int, float)) or not 0.0 <= agreement <= 1.0:
            agreement = None
        summary = resp.get("consensus_summary") or "Arbiter returned no summary."

        return MultiModelDebateResult(
            confirmed_findings=confirmed,
            disputed_findings=disputed,
            consensus_summary=summary,
            model_agreement_ratio=float(agreement) if agreement is not None else None,
            arbitration_applied=True,
            is_simulated=False
        )
