import logging
import os
from concurrent.futures import ThreadPoolExecutor
from typing import List, Dict, Any, Optional
from pydantic import ValidationError
from core.models import CodeSymbol, ReviewFinding, FindingSeverity
from core.llm_gateway import LLMGateway
from core.codecontext import render_symbols, batch_symbols

logger = logging.getLogger("VibeHarness.MultiReviewer")


class HeterogeneousReviewerEnsemble:
    """
    Orchestrates the white-box multi-model review ensemble:
    - Claude: Deep logic & unhandled edge-case state analysis.
    - Nemotron: Defensive sanitization, resource boundaries & guardrails.
    - ChatGPT: Specification compliance & API contract adherence.
    """

    # Every symbol is reviewed, in as many batches as needed; a batch's code listing fits the token budget
    BATCH_MAX_TOKENS = 10000
    BATCH_MAX_SYMBOLS = 15
    MAX_WORKERS = 6

    def __init__(self, gateway: LLMGateway):
        self.gateway = gateway
        self.reviewer_agents = [
            {
                "agent_id": "whitebox_reviewer_claude",
                "model_alias": "claude",
                "name": "Claude Logic Reviewer",
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

    def review_symbols(self, symbols: List[CodeSymbol], root_dir: Optional[str] = None) -> List[ReviewFinding]:
        if not symbols:
            return []
        root = root_dir or os.path.dirname(os.path.abspath(symbols[0].file_path))
        batches = batch_symbols(symbols, root, self.BATCH_MAX_TOKENS, self.BATCH_MAX_SYMBOLS)
        jobs = [(reviewer, batch) for reviewer in self.reviewer_agents for batch in batches]

        # Reviewers are independent models, so their calls run concurrently
        with ThreadPoolExecutor(max_workers=min(self.MAX_WORKERS, len(jobs))) as pool:
            responses = list(pool.map(lambda job: self._review_batch(job[0], job[1], root), jobs))

        all_findings: List[ReviewFinding] = []
        counters: Dict[str, int] = {}
        for (reviewer, batch), (resp, simulated) in zip(jobs, responses, strict=True):
            model_alias = reviewer["model_alias"]
            raw_findings = resp.get("findings")
            if not isinstance(raw_findings, list):
                logger.warning(f"Ignoring unusable findings list from {reviewer['name']} (got {type(raw_findings).__name__})")
                raw_findings = []
            for item in raw_findings:
                if not isinstance(item, dict):
                    continue
                severity_str = str(item.get("severity", "MEDIUM")).upper()
                try:
                    severity = FindingSeverity(severity_str)
                except ValueError:
                    severity = FindingSeverity.MEDIUM

                symbol = self._match_symbol(item.get("symbol_name"), batch)
                counters[model_alias] = counters.get(model_alias, 0) + 1
                try:
                    all_findings.append(ReviewFinding(
                        finding_id=f"WB-{model_alias[:3].upper()}-{counters[model_alias]:02d}",
                        reviewer_name=reviewer["name"],
                        model_alias=model_alias,
                        file_path=symbol.file_path if symbol else "unknown",
                        symbol_name=symbol.name if symbol else item.get("symbol_name"),
                        line_number=symbol.line_start if symbol else None,
                        severity=severity,
                        title=item.get("title", "Potential Defect"),
                        description=item.get("description", ""),
                        root_cause=item.get("root_cause", ""),
                        suspected_vibe_flaw=item.get("suspected_vibe_flaw", ""),
                        suggested_test_scenario=item.get("suggested_test_scenario", ""),
                        is_simulated=simulated
                    ))
                except ValidationError as e:
                    logger.warning(f"Skipping unusable finding from {reviewer['name']}: {e}")

        return all_findings

    def _review_batch(self, reviewer: Dict[str, str], batch: List[CodeSymbol], root: str):
        name = reviewer["name"]
        system_prompt = (
            f"You are {name}, a specialized white-box AI code auditor.\n"
            f"Your primary focus: {reviewer['focus']}.\n"
            f"The target codebase was produced via 'vibe coding' (rapid conversational AI generation), "
            f"which frequently passes superficial tests but hides critical logic gaps, lack of defensive boundaries, "
            f"and unhandled exceptions.\n\n"
            f"Only report defects you can point to in the provided code. Return a JSON object with this schema:\n"
            f"{{\n"
            f'  "findings": [\n'
            f'    {{\n'
            f'      "symbol_name": "Exact Symbol name from the listing where the defect lives",\n'
            f'      "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW",\n'
            f'      "title": "Brief title",\n'
            f'      "description": "Detailed observation",\n'
            f'      "root_cause": "Underlying mechanism",\n'
            f'      "suspected_vibe_flaw": "Why vibe coding caused this",\n'
            f'      "suggested_test_scenario": "Concrete test condition to expose this flaw"\n'
            f'    }}\n'
            f'  ]\n'
            f"}}\n"
            f'Return {{"findings": []}} if you find no defect.'
        )
        user_prompt = (
            f"Target Codebase Extract:\n\n{render_symbols(batch, root, max_tokens=self.BATCH_MAX_TOKENS)}\n\n"
            f"Please audit against your specialty."
        )
        logger.info(f"Running white-box audit with reviewer: {name} ({len(batch)} symbols)")
        resp = self.gateway.generate(
            reviewer["agent_id"], system_prompt, user_prompt, json_output=True, required_keys=["findings"]
        )
        return resp, self.gateway.is_simulated(resp)

    @staticmethod
    def _match_symbol(name: Any, batch: List[CodeSymbol]) -> Optional[CodeSymbol]:
        """Resolves the model-reported symbol name; findings that name no symbol fall back to the batch's first one."""
        if isinstance(name, str) and name:
            for sym in batch:
                if sym.name == name or sym.name.split(".")[-1] == name:
                    return sym
            return None
        return batch[0] if batch else None
