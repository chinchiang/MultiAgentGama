import logging
import os
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Optional, Tuple
from core.models import ReviewFinding, MultiModelDebateResult, VerificationVote, CodeSymbol
from core.llm_gateway import LLMGateway
from core.codecontext import render_symbols, truncate_to_tokens

logger = logging.getLogger("VibeHarness.Debater")

VERIFIER_PREFIX = "whitebox_verifier_"
_VERDICTS = {"confirm", "reject", "unsure"}


class MultiModelDebater:
    """
    Cross-model verification instead of a single arbiter model:
    every finding is ruled on independently by each configured verifier model that did NOT report it
    (the reporting model never judges its own finding). A model that reported the same defect
    (merged as a duplicate) counts as a confirming vote without being asked.

    Decision per finding: more confirms than rejects -> confirmed; more rejects -> disputed;
    a tie (including no usable votes) -> kept, so the generated tests decide.
    """

    FINDINGS_PER_CALL = 15
    CODE_CONTEXT_TOKENS = 8000
    # Finding text is free-form model output; clip the listing so a verbose finding cannot
    # blow up the prompt. Worst case is about LISTING_MAX_TOKENS plus per-finding metadata.
    LISTING_MAX_TOKENS = 6000
    MAX_WORKERS = 6

    def __init__(self, gateway: LLMGateway):
        self.gateway = gateway
        # Verifier agents come from config, e.g. whitebox_verifier_claude -> model alias "claude"
        self.verifiers: Dict[str, str] = {
            agent_id: meta.get("model_alias", agent_id[len(VERIFIER_PREFIX):])
            for agent_id, meta in gateway.agents_config.items()
            if agent_id.startswith(VERIFIER_PREFIX)
        }

    def arbitrate(
        self,
        findings: List[ReviewFinding],
        symbols: Optional[List[CodeSymbol]] = None,
        root_dir: Optional[str] = None
    ) -> MultiModelDebateResult:
        if not findings:
            return MultiModelDebateResult(
                confirmed_findings=[],
                disputed_findings=[],
                consensus_summary="No findings submitted for verification."
            )

        # Which findings each verifier must rule on: never its own, never ones it already corroborated
        assignments: Dict[str, List[int]] = {}
        for agent_id, alias in self.verifiers.items():
            idxs = [i for i, f in enumerate(findings) if alias != f.model_alias and alias not in f.corroborating_models]
            if idxs:
                assignments[agent_id] = idxs
        jobs = [
            (agent_id, idxs[i:i + self.FINDINGS_PER_CALL])
            for agent_id, idxs in assignments.items()
            for i in range(0, len(idxs), self.FINDINGS_PER_CALL)
        ]

        votes: Dict[int, List[VerificationVote]] = {
            # Simulated reviewers agreeing with each other is not evidence
            i: [] if f.is_simulated else [VerificationVote(model_alias=m, verdict="corroborated") for m in f.corroborating_models]
            for i, f in enumerate(findings)
        }
        any_simulated = False
        if jobs:
            with ThreadPoolExecutor(max_workers=min(self.MAX_WORKERS, len(jobs))) as pool:
                results = list(pool.map(lambda job: self._verify(job[0], findings, job[1], symbols, root_dir), jobs))
            for job_votes, simulated in results:
                any_simulated = any_simulated or simulated
                for idx, vote in job_votes:
                    votes[idx].append(vote)

        # Only real, usable rulings (or real corroborations) count as verification
        real_votes = sum(1 for vs in votes.values() for v in vs if v.verdict != "unsure")
        if real_votes == 0:
            reason = "simulated" if any_simulated or all(f.is_simulated for f in findings) else "no usable verifier output"
            logger.warning(f"Verification not applied ({reason}); all {len(findings)} findings kept unfiltered.")
            return MultiModelDebateResult(
                confirmed_findings=list(findings),
                disputed_findings=[],
                consensus_summary=f"Cross-model verification not applied ({reason}); findings are unfiltered reviewer hypotheses.",
                model_agreement_ratio=None,
                arbitration_applied=False,
                is_simulated=reason == "simulated"
            )

        confirmed: List[ReviewFinding] = []
        disputed: List[ReviewFinding] = []
        agreeing = decisive = undecided = 0
        for idx, f in enumerate(findings):
            vs = votes[idx]
            yes = sum(1 for v in vs if v.verdict in ("confirm", "corroborated"))
            no = sum(1 for v in vs if v.verdict == "reject")
            ruled = f.model_copy(update={"verification_votes": vs})
            if no > yes:
                disputed.append(ruled)
                agreeing += no
            else:
                confirmed.append(ruled)
                if yes > no:
                    agreeing += yes
                else:
                    undecided += 1
            decisive += yes + no

        # Agreement counts only findings that were actually decided; ties agree with nothing
        ratio = agreeing / decisive if decisive else None
        summary = (
            f"{len(confirmed) - undecided} confirmed and {len(disputed)} disputed by cross-model majority; "
            f"{undecided} undecided (kept for testing). Verifiers: {', '.join(sorted(set(self.verifiers.values())))}; "
            f"no model ruled on its own finding."
        )
        return MultiModelDebateResult(
            confirmed_findings=confirmed,
            disputed_findings=disputed,
            consensus_summary=summary,
            model_agreement_ratio=ratio,
            arbitration_applied=True,
            is_simulated=False
        )

    def _verify(
        self,
        agent_id: str,
        findings: List[ReviewFinding],
        idxs: List[int],
        symbols: Optional[List[CodeSymbol]],
        root_dir: Optional[str]
    ) -> Tuple[List[Tuple[int, VerificationVote]], bool]:
        alias = self.verifiers[agent_id]
        listing = self._build_listing(findings, idxs)
        system_prompt = (
            f"You are an independent code-review verifier (model: {alias}).\n"
            "Other AI reviewers reported the findings below. You did not write them. For each one, decide from the "
            "code whether the defect is real: 'confirm' (the code really has it), 'reject' (the code does not have it, "
            "or the claim is not supported by the code shown), or 'unsure' (the code shown is insufficient).\n\n"
            "Output a JSON object:\n"
            "{\n"
            '  "verdicts": [{"index": 0, "verdict": "confirm" | "reject" | "unsure", "reason": "one sentence"}]\n'
            "}"
        )
        user_prompt = f"{self._code_context(findings, idxs, symbols, root_dir)}Findings to verify:\n\n{listing}"
        resp = self.gateway.generate(agent_id, system_prompt, user_prompt, json_output=True, required_keys=["verdicts"])
        simulated = self.gateway.is_simulated(resp)
        if simulated or not self.gateway.is_usable(resp):
            return [], simulated

        votes: List[Tuple[int, VerificationVote]] = []
        seen = set()
        raw_verdicts = resp.get("verdicts")
        if not isinstance(raw_verdicts, list):
            logger.warning(f"Ignoring unusable verdict list from {alias} (got {type(raw_verdicts).__name__})")
            raw_verdicts = []
        for item in raw_verdicts:
            if not isinstance(item, dict):
                continue
            local, verdict = item.get("index"), str(item.get("verdict", "")).lower()
            # Out-of-range, duplicate or unknown rulings are ignored rather than guessed at
            if not isinstance(local, int) or not 0 <= local < len(idxs) or local in seen or verdict not in _VERDICTS:
                continue
            seen.add(local)
            votes.append((idxs[local], VerificationVote(
                model_alias=alias, verdict=verdict, reason=str(item.get("reason") or "")
            )))
        return votes, False

    def _build_listing(self, findings: List[ReviewFinding], idxs: List[int]) -> str:
        """
        One block per finding to verify, with every [local] index kept so verdicts still map back.
        The per-field budget shrinks as the batch grows, keeping the listing within the token budget.
        """
        per_field = max(40, self.LISTING_MAX_TOKENS // max(len(idxs) * 4, 1))
        blocks = []
        for local, i in enumerate(idxs):
            f = findings[i]
            blocks.append(
                f"[{local}] {f.severity.value} | {f.file_path} :: {f.symbol_name or '-'}\n"
                f"    Title: {truncate_to_tokens(f.title or '', per_field, marker=' (truncated)')}\n"
                f"    Description: {truncate_to_tokens(f.description or '', per_field, marker=' (truncated)')}\n"
                f"    Cause: {truncate_to_tokens(f.root_cause or '', per_field, marker=' (truncated)')}\n"
                f"    Scenario: {truncate_to_tokens(f.suggested_test_scenario or '', per_field, marker=' (truncated)')}"
            )
        return "\n".join(blocks)

    def _code_context(
        self,
        findings: List[ReviewFinding],
        idxs: List[int],
        symbols: Optional[List[CodeSymbol]],
        root_dir: Optional[str]
    ) -> str:
        if not symbols:
            return ""
        wanted = {(findings[i].file_path, findings[i].symbol_name) for i in idxs}
        relevant = [s for s in symbols if (s.file_path, s.name) in wanted]
        if not relevant:
            return ""
        root = root_dir or os.path.dirname(os.path.abspath(relevant[0].file_path))
        return f"Code the findings refer to:\n{render_symbols(relevant, root, max_tokens=self.CODE_CONTEXT_TOKENS)}\n\n"
