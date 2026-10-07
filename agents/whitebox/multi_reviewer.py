import logging
import os
from concurrent.futures import ThreadPoolExecutor
from typing import List, Dict, Any, Optional
from pydantic import ValidationError
from core.models import CodeSymbol, ReviewFinding, FindingSeverity, text_or
from core.llm_gateway import LLMGateway, LLMGatewayError
from core.codecontext import render_symbols, batch_symbols

logger = logging.getLogger("VibeHarness.MultiReviewer")

# Model-emitted severity strings that do not match the enum (odd casing, typos) land here
_DEFAULT_SEVERITY = FindingSeverity.MEDIUM


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

        # Reviewers are independent models, so their calls run concurrently. A crashed batch
        # must not discard every other batch's (already paid-for) results; live-mode failures
        # still propagate so the run fails loudly.
        with ThreadPoolExecutor(max_workers=min(self.gateway.max_concurrent_calls, len(jobs))) as pool:
            futures = [pool.submit(self._review_batch, job[0], job[1], root) for job in jobs]
            responses = []
            for job, future in zip(jobs, futures, strict=True):
                try:
                    responses.append(future.result())
                except LLMGatewayError:
                    raise
                except Exception as e:
                    logger.error(f"Reviewer batch for {job[0]['name']} failed: {type(e).__name__}: {e}")
                    responses.append(({}, False))

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
                if not text_or(item.get("title"), "") and not text_or(item.get("description"), ""):
                    # Nothing a verifier or test generator could act on
                    logger.warning(f"Skipping finding without a usable title or description from {reviewer['name']}")
                    continue
                severity_str = str(item.get("severity", "MEDIUM")).upper()
                try:
                    severity = FindingSeverity(severity_str)
                except ValueError:
                    logger.warning(f"Unknown severity '{severity_str.strip()}' from {reviewer['name']}; using MEDIUM")
                    severity = _DEFAULT_SEVERITY

                reported_symbol = item.get("symbol_name") if isinstance(item.get("symbol_name"), str) else None
                symbol = self._match_symbol(reported_symbol, batch)
                # Counters are keyed per reviewer agent, so two agents sharing a model_alias
                # still generate distinct finding ids
                counters[reviewer["agent_id"]] = counters.get(reviewer["agent_id"], 0) + 1
                try:
                    all_findings.append(ReviewFinding(
                        finding_id=f"WB-{model_alias[:3].upper()}-{counters[reviewer['agent_id']]:02d}",
                        reviewer_name=reviewer["name"],
                        model_alias=model_alias,
                        file_path=symbol.file_path if symbol else "unknown",
                        symbol_name=symbol.name if symbol else reported_symbol,
                        line_number=symbol.line_start if symbol else None,
                        severity=severity,
                        title=text_or(item.get("title"), "Potential Defect"),
                        description=text_or(item.get("description"), ""),
                        root_cause=text_or(item.get("root_cause"), ""),
                        suspected_vibe_flaw=text_or(item.get("suspected_vibe_flaw"), ""),
                        suggested_test_scenario=text_or(item.get("suggested_test_scenario"), ""),
                        is_simulated=simulated
                    ))
                except ValidationError as e:
                    logger.warning(f"Skipping unusable finding from {reviewer['name']}: {e}")

        return self._unique_finding_ids(all_findings)

    @staticmethod
    def _unique_finding_ids(findings: List[ReviewFinding]) -> List[ReviewFinding]:
        """Disambiguates duplicate ids (e.g. two reviewer agents configured with the same model_alias)."""
        seen: Dict[str, int] = {}
        unique = []
        for f in findings:
            count = seen.get(f.finding_id, 0) + 1
            seen[f.finding_id] = count
            unique.append(f if count == 1 else f.model_copy(update={"finding_id": f"{f.finding_id}-{count}"}))
        return unique

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
        """Resolves the model-reported symbol name: exact matches win over short-name suffix matches.

        A finding that names no symbol is deliberately left unresolved (None) — silently attaching
        it to the batch's first symbol gave generic findings a concrete file/symbol that then drove
        targeted test generation at the wrong place.
        """
        if isinstance(name, str) and name:
            for sym in batch:
                if sym.name == name:
                    return sym
            for sym in batch:
                if sym.name.split(".")[-1] == name:
                    return sym
        return None
