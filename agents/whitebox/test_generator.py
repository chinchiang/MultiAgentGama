import ast
import logging
import os
import re
import textwrap
from concurrent.futures import ThreadPoolExecutor
from typing import List, Optional, Set, Tuple
from core.models import ReviewFinding, GeneratedTest, CodeSymbol, text_or
from core.llm_gateway import LLMGateway, LLMGatewayError
from core.codecheck import check_test_code, strip_code_fences
from core.codecontext import file_source, fence_language, import_instructions, truncate_to_tokens

logger = logging.getLogger("VibeHarness.TestGenerator")

# Estimated-token budget for the target source shown per finding
CODE_CONTEXT_TOKENS = 4000


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
        # Findings from the last run for which no usable model-generated test was produced
        self.findings_without_model_tests: List[str] = []

    def generate_tests_for_findings(
        self,
        findings: List[ReviewFinding],
        symbols: List[CodeSymbol],
        root_dir: Optional[str] = None
    ) -> List[GeneratedTest]:
        self.findings_without_model_tests = []
        if not findings:
            return []

        target_file = symbols[0].file_path if symbols else "main.py"
        root = root_dir or os.path.dirname(os.path.abspath(target_file))

        # Findings are independent, so their generate-validate-heal loops run concurrently;
        # results are collected in finding order so ids, reports and probes stay deterministic.
        with ThreadPoolExecutor(max_workers=min(self.gateway.max_concurrent_calls, len(findings))) as pool:
            futures = [
                pool.submit(self._tests_for_finding, idx, finding, symbols, root, target_file)
                for idx, finding in enumerate(findings)
            ]
            outcomes = []
            for finding, future in zip(findings, futures, strict=True):
                try:
                    outcomes.append(future.result())
                except LLMGatewayError:
                    raise  # strict live mode fails loudly
                except Exception as e:
                    logger.error(f"Test generation for {finding.finding_id} failed: {type(e).__name__}: {e}")
                    outcomes.append(([], False))

        generated_tests: List[GeneratedTest] = []
        for finding, (tests, has_valid_test) in zip(findings, outcomes, strict=True):
            generated_tests.extend(tests)
            if not has_valid_test:
                logger.warning(f"No executable model-generated test for finding {finding.finding_id}; will use target-derived probes.")
                self.findings_without_model_tests.append(finding.finding_id)

        if self.findings_without_model_tests:
            generated_tests.extend(self.build_offline_probes(symbols))

        return generated_tests

    def _tests_for_finding(
        self, idx: int, finding: ReviewFinding, symbols: List[CodeSymbol], root: str, target_file: str
    ) -> Tuple[List[GeneratedTest], bool]:
        """Model-generated (and healed) tests for one finding, and whether any of them is executable."""
        system_prompt = (
            "You are an expert Python QA Engineer and Test Automation Specialist.\n"
            "Your job is to generate a robust, executable pytest test module that imports the real "
            "code under test and asserts correct behavior under the specified edge-case scenario.\n"
            "Rules: import the target exactly as instructed; every test_ function must assert on the "
            "target's behavior (assert / pytest.raises); a failing assertion must mean the target is defective; "
            "do not use the network, do not write files outside tmp_path, do not mock the function under test.\n\n"
            "Respond in JSON format:\n"
            "{\n"
            f'  "test_id": "WB-TEST-{idx+1:02d}",\n'
            '  "title": "Clear description of test purpose",\n'
            '  "rationale": "Why this test exposes vibe-coding flaws",\n'
            '  "expected_outcome": "Expected assertion or exception handling",\n'
            '  "code": "import pytest\\nfrom module import func\\n\\ndef test_something():\\n    with pytest.raises(ValueError):\\n        func(None)"\n'
            "}"
        )

        user_prompt = (
            f"{self._code_context(finding, symbols, root, target_file)}\n\n"
            f"Finding Title: {finding.title}\n"
            f"Description: {finding.description}\n"
            f"Root Cause: {finding.root_cause}\n"
            f"Suggested Test Scenario: {finding.suggested_test_scenario}\n"
            f"Produce an executable Pytest unit test."
        )

        # The model may answer with a batch ({"tests": [...]}) or a single object ({"code": ...});
        # anything else is recorded as an invalid call instead of silently producing zero tests.
        resp = self.gateway.generate(
            "whitebox_test_generator", system_prompt, user_prompt,
            json_output=True, required_keys_any=["tests", "code"]
        )

        raw_tests = resp.get("tests")
        tests_data = raw_tests if isinstance(raw_tests, list) else []
        if not tests_data and isinstance(resp.get("code"), str) and resp["code"].strip():
            tests_data = [resp]
        tests_data = [t for t in tests_data if isinstance(t, dict) and text_or(t.get("code"), "")]

        tests: List[GeneratedTest] = []
        has_valid_test = False
        for t_idx, t_item in enumerate(tests_data):
            # Self-healing validation loop; code that stays invalid is kept so it is reported as ERROR
            validated_code = self._validate_and_heal(t_item["code"], idx + 1)
            has_valid_test = has_valid_test or check_test_code(validated_code)[0]

            test_id = f"WB-TEST-{idx+1:02d}" + (f"-{t_idx+1}" if len(tests_data) > 1 else "")
            tests.append(GeneratedTest(
                test_id=test_id,
                test_type="whitebox_unit",
                target_component=finding.symbol_name or target_file,
                title=text_or(t_item.get("title"), finding.title),
                code=validated_code,
                rationale=text_or(t_item.get("rationale"), finding.suggested_test_scenario),
                expected_outcome=text_or(t_item.get("expected_outcome"), "Graceful handling without crash"),
                source_ref=finding.finding_id
            ))
        return tests, has_valid_test

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
                f"Fix it so it parses and defines at least one module-level test_ function, "
                f"and every test_ function asserts on the target's behavior. "
                f"Output the corrected Python code only:\n\n{code_to_check}"
            )
            resp = self.gateway.generate("whitebox_test_generator", "Fix Python Test Code", heal_prompt, json_output=False)
            fixed = strip_code_fences(text_or(resp.get("raw"), ""))
            if not fixed:
                break  # Nothing to repair with (e.g. simulation engine)
            code_to_check = fixed

        return code_to_check

    @staticmethod
    def _code_context(finding: ReviewFinding, symbols: List[CodeSymbol], root: str, default_file: str) -> str:
        """Import instructions plus the source the finding refers to (its symbol, else its whole file)."""
        file_path = finding.file_path if finding.file_path not in ("", "unknown") else default_file
        symbol = next((s for s in symbols if s.name == finding.symbol_name and s.file_path == file_path), None)
        if symbol:
            source = truncate_to_tokens(symbol.source_code, CODE_CONTEXT_TOKENS)
            label = f"Source of `{symbol.name}` (lines {symbol.line_start}-{symbol.line_end})"
        else:
            source = file_source(file_path, max_tokens=CODE_CONTEXT_TOKENS)
            label = "Source of the target file"
        return (
            f"{import_instructions(file_path, root, symbol.name if symbol else None)}\n"
            f"{label}:\n```{fence_language(file_path)}\n{source}\n```"
        )

    @staticmethod
    def _is_async_def(source: str) -> bool:
        """Checks the symbol's own def line (decorators may precede it)."""
        match = re.search(r"^\s*(async\s+)?def\s", source, re.MULTILINE)
        return bool(match and match.group(1))

    @staticmethod
    def _has_required_params(source: str) -> bool:
        """True when the function takes at least one argument without a default.

        A probe passes None for every required argument, so a function without any would be
        called as-is: `main()`, `run_server()`, `reset_db()` and friends would execute their real
        side effects (or hang until the sandbox timeout) while testing nothing about None inputs.
        """
        try:
            tree = ast.parse(textwrap.dedent(source))
        except SyntaxError:
            return False
        fn = next((n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))), None)
        if fn is None:
            return False
        positional = fn.args.posonlyargs + fn.args.args
        required_positional = len(positional) - len(fn.args.defaults)
        required_kwonly = sum(1 for d in fn.args.kw_defaults if d is None)
        return required_positional > 0 or required_kwonly > 0

    def build_offline_probes(self, symbols: List[CodeSymbol]) -> List[GeneratedTest]:
        """
        Deterministic None-input robustness probes for module-level synchronous Python functions
        that take at least one required argument (argument-less functions are never invoked).
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
            if not self._has_required_params(sym.source_code):
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
