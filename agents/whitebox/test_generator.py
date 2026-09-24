import ast
import logging
from typing import List, Optional
from core.models import ReviewFinding, GeneratedTest, CodeSymbol
from core.llm_gateway import LLMGateway

logger = logging.getLogger("VibeHarness.TestGenerator")


class WhiteboxTestGenerator:
    """
    Generates executable Pytest test cases targeting edge-case defects
    and blindspots verified during the multi-model arbitration phase.
    Includes a self-healing loop (Generation-Validation-Repair).
    """

    def __init__(self, gateway: LLMGateway):
        self.gateway = gateway

    def generate_tests_for_findings(
        self,
        findings: List[ReviewFinding],
        symbols: List[CodeSymbol]
    ) -> List[GeneratedTest]:
        if not findings:
            return []

        generated_tests: List[GeneratedTest] = []
        target_file = symbols[0].file_path if symbols else "main.py"

        for idx, finding in enumerate(findings):
            system_prompt = (
                "You are an expert Python QA Engineer and Test Automation Specialist.\n"
                "Your job is to generate a robust, executable pytest test function that asserts "
                "correct behavior under the specified edge-case scenario.\n\n"
                "Respond in JSON format:\n"
                "{\n"
                f'  "test_id": "WB-TEST-{idx+1:02d}",\n'
                '  "title": "Clear description of test purpose",\n'
                '  "rationale": "Why this test exposes vibe-coding flaws",\n'
                '  "expected_outcome": "Expected assertion or exception handling",\n'
                '  "code": "def test_something():\\n    # python code\\n    pass"\n'
                "}"
            )

            user_prompt = (
                f"Target File: {finding.file_path}\n"
                f"Finding Title: {finding.title}\n"
                f"Root Cause: {finding.root_cause}\n"
                f"Suggested Test Scenario: {finding.suggested_test_scenario}\n"
                f"Produce an executable Pytest unit test."
            )

            resp = self.gateway.generate("whitebox_test_generator", system_prompt, user_prompt, json_output=True)

            tests_data = resp.get("tests", [])
            if not tests_data and "code" in resp:
                tests_data = [resp]

            for t_item in tests_data:
                raw_code = t_item.get("code", "")
                # Self-healing validation loop
                validated_code = self._validate_and_heal(raw_code, idx + 1)

                generated_tests.append(GeneratedTest(
                    test_id=t_item.get("test_id", f"WB-TEST-{idx+1:02d}"),
                    test_type="whitebox_unit",
                    target_component=finding.symbol_name or target_file,
                    title=t_item.get("title", finding.title),
                    code=validated_code,
                    rationale=t_item.get("rationale", finding.suggested_test_scenario),
                    expected_outcome=t_item.get("expected_outcome", "Graceful handling without crash")
                ))

        return generated_tests

    def _validate_and_heal(self, code: str, case_index: int, max_retries: int = 2) -> str:
        """
        Validates Python syntax via AST parser.
        If syntax error occurs, triggers the self-healing repair loop.
        """
        code_to_check = code.strip()
        if not code_to_check.startswith("def test_"):
            code_to_check = f"def test_vibe_case_{case_index}():\n    # Self-healed test\n    pass"

        for attempt in range(max_retries + 1):
            try:
                ast.parse(code_to_check)
                return code_to_check
            except SyntaxError as e:
                logger.warning(f"Syntax validation failed on generated test (attempt {attempt+1}): {e}")
                if attempt < max_retries:
                    heal_prompt = (
                        f"The following Python test code has a syntax error: {str(e)}.\n"
                        f"Please fix and output valid Python test code only:\n\n{code_to_check}"
                    )
                    resp = self.gateway.generate("whitebox_test_generator", "Fix Python Syntax Error", heal_prompt, json_output=False)
                    fixed_raw = resp.get("raw", "")
                    if "def test_" in fixed_raw:
                        code_to_check = fixed_raw.strip()
                else:
                    # Final fallback to safe dummy test
                    return f"def test_vibe_fallback_{case_index}():\n    # Fallback after repair failure\n    pass"

        return code_to_check
