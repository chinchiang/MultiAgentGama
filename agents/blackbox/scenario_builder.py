import logging
import urllib.error
import urllib.request
from typing import List, Optional
import os
from core.models import ThreatItem, GeneratedTest, CodeSymbol
from core.llm_gateway import LLMGateway
from core.codecheck import check_test_code, strip_code_fences
from core.codecontext import render_symbols, import_instructions

logger = logging.getLogger("VibeHarness.ScenarioBuilder")


class ThreatScenarioBuilder:
    """
    Synthesizes executable black-box security test suites directly derived from
    the Threat Modeling matrix (STRIDE & OWASP findings).
    Supports Dual-Mode: Live Server HTTP penetration or In-Process Contract verification.
    """

    def __init__(self, gateway: LLMGateway):
        self.gateway = gateway

    def check_server_live(self, base_url: str, timeout_sec: float = 1.0) -> bool:
        """Probes whether the target HTTP server is reachable."""
        try:
            req = urllib.request.Request(base_url, headers={"User-Agent": "VibeHarness-HealthCheck"})
            with urllib.request.urlopen(req, timeout=timeout_sec):
                return True
        except urllib.error.HTTPError:
            return True  # Any HTTP status (404 on '/', 500, ...) means the server answered
        except Exception:
            return False

    @staticmethod
    def _code_context(threat: ThreatItem, symbols: Optional[List[CodeSymbol]], root_dir: Optional[str]) -> str:
        """Import paths and source for the symbols the threat's attack vector names (else all entry points)."""
        if not symbols:
            return ""
        root = root_dir or os.path.dirname(os.path.abspath(symbols[0].file_path))
        text = f"{threat.attack_vector} {threat.attack_scenario}"
        relevant = [s for s in symbols if s.name.split(".")[-1] in text]
        if not relevant:
            relevant = sorted(symbols, key=lambda s: s.symbol_type != "route")
        files = sorted({s.file_path for s in relevant if s.file_path.endswith(".py")})
        imports = "\n".join(import_instructions(f, root) for f in files)
        return f"How to import the target:\n{imports}\n\nRelevant target code:\n{render_symbols(relevant, root, max_chars=15000)}\n\n"

    def build_test_cases_from_threats(
        self,
        threats: List[ThreatItem],
        base_url: str = "http://localhost:8000",
        symbols: Optional[List[CodeSymbol]] = None,
        root_dir: Optional[str] = None
    ) -> List[GeneratedTest]:
        if not threats:
            return []

        server_is_live = self.check_server_live(base_url)
        mode_label = "Live HTTP" if server_is_live else "In-Process Contract"
        logger.info(f"Synthesizing threat test cases in [{mode_label}] mode against: {base_url}")
        if server_is_live:
            mode_rules = (
                f"Send real HTTP requests to {base_url} using only the standard library (urllib.request) "
                "or `requests`. Never target any other host.\n"
            )
        else:
            mode_rules = (
                "No server is running: import the target module in-process exactly as instructed below and call "
                "its functions/handlers directly with attacker-controlled arguments. Do not start servers or use the network.\n"
            )

        tests: List[GeneratedTest] = []

        for threat in threats:
            logger.info(f"Synthesizing black-box exploit test for: [{threat.threat_id}] {threat.title}")

            system_prompt = (
                "You are an Elite Offensive Security & AppSec Test Automation Engineer.\n"
                f"Execution Mode: {mode_label}.\n"
                f"{mode_rules}"
                "Your task is to translate a specific STRIDE/OWASP threat model item into a concrete, "
                "executable Python pytest module.\n\n"
                "The test must assert that defensive boundaries hold (e.g. status code is 401/403/422, "
                "or sensitive fields are uncompromised), so that an assertion failure means the attack succeeded. "
                "If the attack cannot be expressed against the given code, return an empty code string instead of guessing.\n\n"
                "Output JSON:\n"
                "{\n"
                f'  "test_id": "BB-TEST-{threat.threat_id}",\n'
                '  "title": "Clear test name",\n'
                '  "rationale": "Why this test proves or disproves the threat",\n'
                '  "expected_outcome": "Defensive condition that must be met",\n'
                '  "code": "from module import handler\\n\\ndef test_security_case():\\n    result = handler(...)\\n    assert result[\\"status\\"] == \\"error\\""\n'
                "}"
            )

            user_prompt = (
                f"Target Base URL: {base_url}\n"
                f"Server Live Status: {server_is_live}\n"
                f"Threat ID: {threat.threat_id}\n"
                f"STRIDE Category: {threat.stride_category.value}\n"
                f"OWASP Mapping: {threat.owasp_mapping}\n"
                f"Attack Vector: {threat.attack_vector}\n"
                f"Attack Scenario: {threat.attack_scenario}\n"
                f"Defense Verification Goal: {threat.test_verification_goal}\n\n"
                f"{self._code_context(threat, symbols, root_dir)}"
                f"Generate the executable Python test function."
            )

            resp = self.gateway.generate(
                "blackbox_test_synthesizer", system_prompt, user_prompt, json_output=True, required_keys=["code"]
            )

            code_str = strip_code_fences(resp.get("code") or "")
            if not code_str:
                # No fabricated fallback: a threat without a synthesized test is reported as NOT TESTED
                logger.warning(f"No executable test synthesized for [{threat.threat_id}]; threat remains untested.")
                continue
            is_valid, problem = check_test_code(code_str)
            if not is_valid:
                # Kept so the executor reports it as ERROR rather than silently dropping it
                logger.warning(f"Synthesized test for [{threat.threat_id}] is not executable: {problem}")

            tests.append(GeneratedTest(
                test_id=f"BB-TEST-{threat.threat_id}",
                test_type="blackbox_security",
                target_component=threat.attack_vector,
                title=resp.get("title", f"Security test for {threat.title}"),
                code=code_str,
                rationale=resp.get("rationale", threat.attack_scenario),
                expected_outcome=resp.get("expected_outcome", threat.test_verification_goal),
                source_ref=threat.threat_id
            ))

        return tests
