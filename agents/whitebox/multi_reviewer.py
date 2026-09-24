import logging
from typing import List, Dict, Any
from core.models import CodeSymbol, ReviewFinding, FindingSeverity
from core.llm_gateway import LLMGateway

logger = logging.getLogger("VibeHarness.MultiReviewer")


class HeterogeneousReviewerEnsemble:
    """
    Orchestrates the white-box multi-model review ensemble:
    - Claude: Deep logic & unhandled edge-case state analysis.
    - Nemotron: Defensive sanitization, resource boundaries & guardrails.
    - ChatGPT: Specification compliance & API contract adherence.
    """

    def __init__(self, gateway: LLMGateway):
        self.gateway = gateway
        self.reviewer_agents = [
            {
                "agent_id": "whitebox_reviewer_claude",
                "model_alias": "claude",
                "name": "Claude 3.7 Logic Reviewer",
                "focus": "Logic state consistency, null-pointer assumptions, unhandled exception paths"
            },
            {
                "agent_id": "whitebox_reviewer_nemotron",
                "model_alias": "nemotron",
                "name": "Nemotron Safety & Guardrails Reviewer",
                "focus": "Input sanitization, memory/array limits, ReDoS, defensive error suppression"
            },
            {
                "agent_id": "whitebox_reviewer_chatgpt",
                "model_alias": "chatgpt",
                "name": "ChatGPT Spec & Contract Reviewer",
                "focus": "API contract adherence, parameter type checking, schema consistency"
            }
        ]

    def review_symbols(self, symbols: List[CodeSymbol]) -> List[ReviewFinding]:
        all_findings: List[ReviewFinding] = []
        if not symbols:
            return all_findings

        # Prepare code representation
        code_overview = "\n\n".join([
            f"File: {sym.file_path} (Lines {sym.line_start}-{sym.line_end})\n"
            f"Symbol: {sym.name} [{sym.symbol_type}]\n"
            f"Code:\n```python\n{sym.source_code}\n```"
            for sym in symbols[:15]  # Limit batch per prompt
        ])

        for reviewer in self.reviewer_agents:
            agent_id = reviewer["agent_id"]
            name = reviewer["name"]
            model_alias = reviewer["model_alias"]
            focus = reviewer["focus"]

            system_prompt = (
                f"You are {name}, a specialized white-box AI code auditor.\n"
                f"Your primary focus: {focus}.\n"
                f"The target codebase was produced via 'vibe coding' (rapid conversational AI generation), "
                f"which frequently passes superficial tests but hides critical logic gaps, lack of defensive boundaries, "
                f"and unhandled exceptions.\n\n"
                f"Analyze the provided code and return a JSON object with this schema:\n"
                f"{{\n"
                f'  "findings": [\n'
                f'    {{\n'
                f'      "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW",\n'
                f'      "title": "Brief title",\n'
                f'      "description": "Detailed observation",\n'
                f'      "root_cause": "Underlying mechanism",\n'
                f'      "suspected_vibe_flaw": "Why vibe coding caused this",\n'
                f'      "suggested_test_scenario": "Concrete test condition to expose this flaw"\n'
                f'    }}\n'
                f'  ]\n'
                f"}}"
            )

            user_prompt = f"Target Codebase Extract:\n\n{code_overview}\n\nPlease audit against your specialty."

            logger.info(f"Running white-box audit with reviewer: {name}")
            resp = self.gateway.generate(agent_id, system_prompt, user_prompt, json_output=True)

            raw_findings = resp.get("findings", [])
            for idx, item in enumerate(raw_findings):
                severity_str = item.get("severity", "MEDIUM").upper()
                try:
                    severity = FindingSeverity(severity_str)
                except ValueError:
                    severity = FindingSeverity.MEDIUM

                finding = ReviewFinding(
                    finding_id=f"WB-{model_alias[:3].upper()}-{idx+1:02d}",
                    reviewer_name=name,
                    model_alias=model_alias,
                    file_path=symbols[0].file_path if symbols else "unknown",
                    symbol_name=symbols[0].name if symbols else None,
                    line_number=symbols[0].line_start if symbols else None,
                    severity=severity,
                    title=item.get("title", "Potential Defect"),
                    description=item.get("description", ""),
                    root_cause=item.get("root_cause", ""),
                    suspected_vibe_flaw=item.get("suspected_vibe_flaw", ""),
                    suggested_test_scenario=item.get("suggested_test_scenario", "")
                )
                all_findings.append(finding)

        return all_findings
