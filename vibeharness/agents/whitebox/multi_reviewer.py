import logging
import os
from concurrent.futures import ThreadPoolExecutor
from typing import List, Dict, Any, Optional
from pydantic import ValidationError
from vibeharness.core.models import CodeSymbol, ReviewFinding, FindingSeverity, text_or
from vibeharness.core.llm_gateway import LLMGateway, LLMGatewayError, UNCONFIGURED_ALIAS
from vibeharness.core.codecontext import render_symbols, batch_symbols
from vibeharness.core.sanitize import UNTRUSTED_CODE_POLICY, untrusted_block

logger = logging.getLogger("VibeHarness.MultiReviewer")

# Model-emitted severity strings that do not match the enum (odd casing, typos) land here
_DEFAULT_SEVERITY = FindingSeverity.MEDIUM


REVIEWER_PREFIX = "whitebox_reviewer_"


class HeterogeneousReviewerEnsemble:
    """
    Orchestrates the white-box multi-model review ensemble. Reviewers come from config: every
    `whitebox_reviewer_*` agent is used with its own model, name and focus. The default lineup is
    Claude (logic & state), DeepSeek (defensive & resource), GLM (spec & contract) and Gemini
    (AI/LLM-integration & supply-chain security per the OWASP Top 10 for LLM Applications 2026).
    """

    # Every symbol is reviewed, in as many batches as needed; a batch's code listing fits the token budget
    BATCH_MAX_TOKENS = 10000
    BATCH_MAX_SYMBOLS = 15

    def __init__(self, gateway: LLMGateway):
        self.gateway = gateway
        self.reviewer_agents: List[Dict[str, str]] = []
        for agent_id, meta in gateway.agents_config.items():
            if not agent_id.startswith(REVIEWER_PREFIX):
                continue
            meta = meta if isinstance(meta, dict) else {}
            # Same resolution as the gateway: a reviewer without a model_alias is `unconfigured`
            # (simulated in hybrid, an error in live), so the report shows where its calls really went
            alias = meta.get("model_alias") or UNCONFIGURED_ALIAS
            self.reviewer_agents.append({
                "agent_id": agent_id,
                "model_alias": str(alias),
                "name": text_or(meta.get("name"), f"Reviewer ({alias})"),
                "focus": text_or(meta.get("focus"), "General correctness and security defects"),
            })
        if not self.reviewer_agents:
            logger.warning("No whitebox_reviewer_* agents are configured; the white-box review is skipped.")

    @property
    def distinct_models(self) -> List[str]:
        """Model aliases in the ensemble; fewer than two means no cross-model verification is possible."""
        return sorted({r["model_alias"] for r in self.reviewer_agents})

    def review_symbols(self, symbols: List[CodeSymbol], root_dir: Optional[str] = None) -> List[ReviewFinding]:
        if not symbols or not self.reviewer_agents:
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
                    # Booked as an invalid call: the batch's findings are missing, not absent
                    self.gateway.record_failure(job[0]["agent_id"], f"{type(e).__name__}: {e}")
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
                        owasp_mapping=text_or(item.get("owasp_mapping"), "") or None,
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
            f'      "suggested_test_scenario": "Concrete test condition to expose this flaw",\n'
            f'      "owasp_mapping": "Optional taxonomy id, e.g. LLM01:2026 or API1:2023"\n'
            f'    }}\n'
            f'  ]\n'
            f"}}\n"
            f'Return {{"findings": []}} if you find no defect.'
            f"{UNTRUSTED_CODE_POLICY}"
        )
        user_prompt = (
            f"Target Codebase Extract:\n\n"
            f"{untrusted_block(render_symbols(batch, root, max_tokens=self.BATCH_MAX_TOKENS))}\n\n"
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
