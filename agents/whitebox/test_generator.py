import logging
import os
import re
from typing import List, Optional, Set
from core.models import ReviewFinding, GeneratedTest, CodeSymbol
from core.llm_gateway import LLMGateway
from core.codecheck import check_test_code, strip_code_fences

logger = logging.getLogger("VibeHarness.TestGenerator")


class WhiteboxTestGenerator:
    """
    Generates executable Pytest test cases targeting edge-case defects
    and blindspots verified during the multi-model arbitration phase.
    Includes a self-healing loop (Generation-Validation-Repair).
    When no usable model-generated test exists for a finding (e.g. offline simulation),
    falls back to deterministic None-input robustness probes derived from the target's own functions.
    """

    MAX_PROBES = 10

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
        needs_probes = False

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
            tests_data = [t for t in tests_data if (t.get("code") or "").strip()]

            has_valid_test = False
            for t_idx, t_item in enumerate(tests_data):
                # Self-healing validation loop; code that stays invalid is kept so it is reported as ERROR
                validated_code = self._validate_and_heal(t_item["code"], idx + 1)
                has_valid_test = has_valid_test or check_test_code(validated_code)[0]

                test_id = f"WB-TEST-{idx+1:02d}" + (f"-{t_idx+1}" if len(tests_data) > 1 else "")
                generated_tests.append(GeneratedTest(
                    test_id=test_id,
                    test_type="whitebox_unit",
                    target_component=finding.symbol_name or target_file,
                    title=t_item.get("title", finding.title),
                    code=validated_code,
                    rationale=t_item.get("rationale", finding.suggested_test_scenario),
                    expected_outcome=t_item.get("expected_outcome", "Graceful handling without crash"),
                    source_ref=finding.finding_id
                ))

            if not has_valid_test:
                logger.warning(f"No executable model-generated test for finding {finding.finding_id}; will use target-derived probes.")
                needs_probes = True

        if needs_probes:
            generated_tests.extend(self.build_offline_probes(symbols))

        return generated_tests

    def _validate_and_heal(self, code: str, case_index: int, max_retries: int = 2) -> str:
        """
        Validates that the code parses and defines a module-level test_ function.
        On failure, asks the model to repair it. Returns the best available code;
        code that could not be repaired is returned unchanged so the executor reports it as ERROR
        (never silently replaced by a no-op test that would pass).
        """
        code_to_check = strip_code_fences(code)

        for attempt in range(max_retries + 1):
            is_valid, problem = check_test_code(code_to_check)
            if is_valid:
                return code_to_check
            logger.warning(f"Generated test for case {case_index} is invalid (attempt {attempt+1}): {problem}")
            if attempt == max_retries:
                break
            heal_prompt = (
                f"The following Python pytest code is invalid: {problem}.\n"
                f"Fix it so it parses and defines at least one module-level test_ function. "
                f"Output the corrected Python code only:\n\n{code_to_check}"
            )
            resp = self.gateway.generate("whitebox_test_generator", "Fix Python Test Code", heal_prompt, json_output=False)
            fixed = strip_code_fences(resp.get("raw", ""))
            if not fixed:
                break  # Nothing to repair with (e.g. simulation engine)
            code_to_check = fixed

        return code_to_check

    @staticmethod
    def _is_async_def(source: str) -> bool:
        """Checks the symbol's own def line (decorators may precede it)."""
        match = re.search(r"^\s*(async\s+)?def\s", source, re.MULTILINE)
        return bool(match and match.group(1))

    def build_offline_probes(self, symbols: List[CodeSymbol]) -> List[GeneratedTest]:
        """
        Deterministic None-input robustness probes for module-level synchronous Python functions.
        An unhandled TypeError/KeyError/AttributeError/IndexError on None inputs is reported as a failure;
        explicit rejection via other exceptions (ValueError, custom errors) counts as a defended boundary.
        """
        probes: List[GeneratedTest] = []
        seen: Set[str] = set()
        for sym in symbols:
            if len(probes) >= self.MAX_PROBES:
                break
            if sym.symbol_type != "function" or not sym.file_path.endswith(".py"):
                continue
            if sym.name.startswith("__") or self._is_async_def(sym.source_code):
                continue
            key = f"{sym.file_path}::{sym.name}"
            if key in seen:
                continue
            seen.add(key)

            probe_no = len(probes) + 1
            safe_name = re.sub(r"[^a-zA-Z0-9_]", "_", sym.name)
            code = (
                "import importlib.util\n"
                "import inspect\n\n"
                f"_spec = importlib.util.spec_from_file_location('vh_probe_target_{probe_no}', {os.path.abspath(sym.file_path)!r})\n"
                "_target = importlib.util.module_from_spec(_spec)\n"
                "_spec.loader.exec_module(_target)\n\n\n"
                f"def test_probe_{safe_name}_none_inputs():\n"
                f"    fn = getattr(_target, {sym.name!r})\n"
                "    params = [p for p in inspect.signature(fn).parameters.values() if p.default is p.empty]\n"
                "    positional = [p for p in params if p.kind in (p.POSITIONAL_ONLY, p.POSITIONAL_OR_KEYWORD)]\n"
                "    keyword = {p.name: None for p in params if p.kind is p.KEYWORD_ONLY}\n"
                "    try:\n"
                "        fn(*[None] * len(positional), **keyword)\n"
                "    except (TypeError, KeyError, AttributeError, IndexError) as exc:\n"
                f"        raise AssertionError(f'{sym.name}() crashed with unhandled {{type(exc).__name__}} on None inputs: {{exc}}')\n"
                "    except Exception:\n"
                "        pass  # Explicit rejection is treated as a defended boundary\n"
            )
            probes.append(GeneratedTest(
                test_id=f"WB-PROBE-{probe_no:02d}",
                test_type="whitebox_probe",
                target_component=sym.name,
                title=f"Offline None-input robustness probe: {sym.name}()",
                code=code,
                rationale="Target-derived deterministic probe (no model-generated test available).",
                expected_outcome="Function rejects or handles None inputs without an unhandled TypeError/KeyError/AttributeError/IndexError.",
                source_ref=sym.name
            ))
        return probes
