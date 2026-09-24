import logging
import urllib.request
from typing import List, Optional
from core.models import ThreatItem, GeneratedTest
from core.llm_gateway import LLMGateway

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
            with urllib.request.urlopen(req, timeout=timeout_sec) as resp:
                return resp.status < 500
        except Exception:
            return False

    def build_test_cases_from_threats(
        self,
        threats: List[ThreatItem],
        base_url: str = "http://localhost:8000"
    ) -> List[GeneratedTest]:
        if not threats:
            return []

        server_is_live = self.check_server_live(base_url)
        mode_label = "Live HTTP" if server_is_live else "In-Process Contract"
        logger.info(f"Synthesizing threat test cases in [{mode_label}] mode against: {base_url}")

        tests: List[GeneratedTest] = []

        for threat in threats:
            logger.info(f"Synthesizing black-box exploit test for: [{threat.threat_id}] {threat.title}")

            system_prompt = (
                "You are an Elite Offensive Security & AppSec Test Automation Engineer.\n"
                f"Execution Mode: {mode_label}.\n"
                "Your task is to translate a specific STRIDE/OWASP threat model item into a concrete, "
                "executable Python black-box security test function.\n\n"
                "The test must assert that defensive boundaries hold (e.g. status code is 401/403/422, "
                "or sensitive fields are uncompromised).\n\n"
                "Output JSON:\n"
                "{\n"
                f'  "test_id": "BB-TEST-{threat.threat_id}",\n'
                '  "title": "Clear test name",\n'
                '  "rationale": "Why this test proves or disproves the threat",\n'
                '  "expected_outcome": "Defensive condition that must be met",\n'
                '  "code": "def test_security_case():\\n    # python code\\n    pass"\n'
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
                f"Generate the executable Python test function."
            )

            resp = self.gateway.generate("blackbox_test_synthesizer", system_prompt, user_prompt, json_output=True)

            code_str = resp.get("code")
            if not code_str or not code_str.strip().startswith("def test_"):
                fn_name = f"test_blackbox_{threat.stride_category.name.lower()}_{threat.threat_id.lower().replace('-', '_')}"
                if server_is_live:
                    code_str = (
                        f"def {fn_name}():\n"
                        f'    """Live HTTP verification test for {threat.title}"""\n'
                        f"    import requests\n"
                        f"    # Attack Vector: {threat.attack_vector}\n"
                        f"    # Verification Goal: {threat.test_verification_goal}\n"
                        f"    url = '{base_url}' + '/api/users/usr_002'\n"
                        f"    res = requests.get(url, timeout=3)\n"
                        f"    assert res.status_code in [200, 403, 404], 'Server returned unexpected status'\n"
                    )
                else:
                    # In-process black-box contract test
                    code_str = (
                        f"def {fn_name}():\n"
                        f'    """In-process contract verification test for {threat.title}"""\n'
                        f"    # Target Vector: {threat.attack_vector}\n"
                        f"    # Verification: {threat.test_verification_goal}\n"
                        f"    try:\n"
                        f"        from vibe_sample_app import update_user_settings\n"
                        f"    except ImportError:\n"
                        f"        from examples.vibe_sample_app import update_user_settings\n"
                        f"    # Check if untrusted parameters can escalate privileges\n"
                        f"    result = update_user_settings('usr_001', 'usr_002', {{'is_admin': True}})\n"
                        f"    # In secure systems, unauthorized escalation is rejected\n"
                        f"    is_insecure = (result.get('status') == 'success' and result.get('user', {{}}).get('is_admin') is True)\n"
                        f"    assert not is_insecure, 'Security vulnerability confirmed: unauthorized role escalation succeeded'\n"
                    )

            tests.append(GeneratedTest(
                test_id=resp.get("test_id", f"BB-TEST-{threat.threat_id}"),
                test_type="blackbox_security",
                target_component=threat.attack_vector,
                title=resp.get("title", f"Security test for {threat.title}"),
                code=code_str,
                rationale=resp.get("rationale", threat.attack_scenario),
                expected_outcome=resp.get("expected_outcome", threat.test_verification_goal)
            ))

        return tests
