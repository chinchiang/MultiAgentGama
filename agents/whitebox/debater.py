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
                consensus_summary="No findings submitted for arbitration.",
                model_agreement_ratio=1.0
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
        resp = self.gateway.generate("whitebox_debater", system_prompt, user_prompt, json_output=True)

        confirmed_indices = set(resp.get("confirmed_findings_indices", []))
        disputed_indices = set(resp.get("disputed_findings_indices", []))

        confirmed: List[ReviewFinding] = []
        disputed: List[ReviewFinding] = []

        for idx, f in enumerate(findings):
            if idx in confirmed_indices or (idx not in disputed_indices and not confirmed_indices):
                confirmed.append(f)
            else:
                disputed.append(f)

        agreement = float(resp.get("model_agreement_ratio", 0.85))
        summary = resp.get("consensus_summary", "Consensus reached across heterogeneous models.")

        return MultiModelDebateResult(
            confirmed_findings=confirmed,
            disputed_findings=disputed,
            consensus_summary=summary,
            model_agreement_ratio=agreement
        )
