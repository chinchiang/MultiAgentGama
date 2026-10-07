import ast
import re
import os
import time
import logging
import xml.etree.ElementTree as ET
from typing import List, Tuple, Optional, Dict, Set
from core.models import GeneratedTest, TestExecutionResult, TestStatus
from core.sandbox import LocalSubprocessSandbox, TIMEOUT_EXIT_CODE
from core.codecheck import check_test_code

logger = logging.getLogger("VibeHarness.TestExecutor")

# Exceptions that indicate a broken generated test / harness setup rather than a defect in the target
HARNESS_ERROR_EXCEPTIONS = (
    "ImportError", "ModuleNotFoundError", "NameError", "SyntaxError", "IndentationError"
)

# A TypeError about call arity/keywords means the generated test called the target with the wrong
# signature — but only when it was raised in the test module itself (the innermost traceback
# frame). The same message raised inside the target is a genuine defect in the target.
_SIGNATURE_TYPEERROR_RE = re.compile(
    r"^TypeError: .*(missing \d+ required (?:positional|keyword-only) argument|"
    r"takes \d+ positional arguments? but \d+ (?:was|were) given|takes no arguments|"
    r"got an unexpected keyword argument|got multiple values for argument|"
    r"takes from \d+ to \d+ positional arguments)"
)
_RAISED_IN_TEST_MODULE_RE = re.compile(r"test_vh_\d+\.py:\d+: TypeError\s*$")


class TestSuiteExecutor:
    __test__ = False
    """
    Runs generated test functions inside the sandbox, one module per test so that a broken
    test cannot poison the others, and maps per-test outcomes from pytest's JUnit XML report.
    Only genuine assertion failures in black-box tests count as confirmed security exploits.
    """

    def __init__(self, sandbox: LocalSubprocessSandbox, per_test_timeout_seconds: int = 30):
        self.sandbox = sandbox
        self.per_test_timeout_seconds = per_test_timeout_seconds

    def execute_test_suite(
        self,
        tests: List[GeneratedTest],
        working_dir: str = ".",
        collect_coverage: bool = False
    ) -> Tuple[List[TestExecutionResult], Optional[float]]:
        if not tests:
            return [], None

        abs_target = os.path.abspath(working_dir)
        parent_dir = os.path.dirname(abs_target)
        header = "\n".join([
            "import pytest",
            "import sys",
            "import os",
            "from typing import Any, Dict",
            # The parent dir goes in first so the target itself ends up with the highest
            # priority (last insert wins position 0), matching the sandbox PYTHONPATH order.
            # Otherwise a same-named module in the parent directory (e.g. proj\utils.py vs
            # proj\app\utils.py) would shadow the target module under test.
            f"sys.path.insert(0, {parent_dir!r})",
            f"sys.path.insert(0, {abs_target!r})",
            "# --- VibeHarness Auto-Generated Test ---",
        ])

        unique_ids = self._unique_test_ids(tests)
        results: Dict[int, TestExecutionResult] = {}
        files: Dict[str, str] = {}
        module_to_idx: Dict[str, int] = {}

        for idx, t in enumerate(tests):
            is_valid, problem = check_test_code(t.code)
            if not is_valid:
                results[idx] = self._result(
                    t, unique_ids[idx], TestStatus.ERROR,
                    failure_reason=f"Generated test is not executable ({problem}); not run"
                )
                continue
            module = f"test_vh_{idx:03d}"
            module_to_idx[module] = idx
            preamble, body = self._split_future_imports(t.code)
            files[f"{module}.py"] = (
                f"{preamble}{header}\n# Target: {self._header_field(t.target_component)} | Test: {self._header_field(t.title)}\n{body}\n"
            )

        coverage_pct: Optional[float] = None
        if files:
            logger.info(f"Executing {len(files)} test module(s) in sandbox (coverage={collect_coverage})...")
            exit_code, stdout, stderr, duration, coverage_pct, junit_xml = self.sandbox.execute_pytest_files(
                files,
                working_dir=working_dir,
                collect_coverage=collect_coverage,
                coverage_target=working_dir
            )
            cases = self._parse_junit(junit_xml)
            timed_out: Set[str] = set()
            not_rerun: Set[str] = set()
            if exit_code == TIMEOUT_EXIT_CODE and len(files) > 1:
                # One hanging test must not void the whole batch: rerun each module on its own budget
                logger.warning("Batch run timed out; re-running each test module individually to isolate the hang.")
                coverage_pct = None
                cases, timed_out, not_rerun = self._run_individually(files, working_dir)
                junit_xml = ""  # per-module outcomes are now in `cases` / `timed_out`

            for module, idx in module_to_idx.items():
                t = tests[idx]
                module_cases = cases.get(module)
                if module in not_rerun:
                    results[idx] = self._result(
                        t, unique_ids[idx], TestStatus.ERROR,
                        failure_reason="Rerun budget exhausted after the batch timeout; module was not re-run"
                    )
                elif junit_xml is None:
                    if exit_code == TIMEOUT_EXIT_CODE:
                        results[idx] = self._result(
                            t, unique_ids[idx], TestStatus.ERROR,
                            failure_reason=(f"Test batch timed out after {getattr(self.sandbox, 'timeout_seconds', '?')}s "
                                            "and no per-test report was produced")
                        )
                    else:
                        results[idx] = self._result(
                            t, unique_ids[idx], TestStatus.ERROR,
                            failure_reason=f"Sandbox run produced no report: {stderr.strip()[:200] or f'exit code {exit_code}'}",
                            stdout=stdout, stderr=stderr
                        )
                elif not module_cases and module in timed_out:
                    results[idx] = self._result(
                        t, unique_ids[idx], TestStatus.ERROR,
                        failure_reason=f"Test timed out after {self.per_test_timeout_seconds}s; not run to completion"
                    )
                elif not module_cases:
                    results[idx] = self._result(
                        t, unique_ids[idx], TestStatus.ERROR,
                        failure_reason="No test was collected from the generated code",
                        stdout=stdout, stderr=stderr
                    )
                else:
                    results[idx] = self._aggregate(t, unique_ids[idx], module_cases)

        return [results[i] for i in range(len(tests))], coverage_pct

    def _run_individually(
        self, files: Dict[str, str], working_dir: str
    ) -> Tuple[Dict[str, List[dict]], Set[str], Set[str]]:
        """Runs each module in its own process.

        Returns (junit cases by module, modules that timed out, modules skipped because the
        rerun budget (the sandbox's own batch budget) was exhausted).
        """
        cases: Dict[str, List[dict]] = {}
        timed_out: Set[str] = set()
        not_rerun: Set[str] = set()
        deadline = time.monotonic() + float(getattr(self.sandbox, "timeout_seconds", 0) or 0)
        for filename, code in files.items():
            module = filename[:-3]
            if time.monotonic() >= deadline:
                not_rerun.add(module)
                continue
            exit_code, _, _, _, _, junit_xml = self.sandbox.execute_pytest_files(
                {filename: code}, working_dir=working_dir, timeout_seconds=self.per_test_timeout_seconds
            )
            if exit_code == TIMEOUT_EXIT_CODE:
                timed_out.add(module)
                continue
            cases.update(self._parse_junit(junit_xml))
        return cases, timed_out, not_rerun

    @staticmethod
    def _split_future_imports(code: str) -> Tuple[str, str]:
        """Splits off the leading docstring and `from __future__` imports, which must stay at the very top.

        The harness header is inserted between the two parts; prepending it to the whole module
        turned every `from __future__ import annotations` into a SyntaxError (collection failure).
        Returns ("", code) when there is nothing to hoist. The code was already validated by
        check_test_code(), so it parses.
        """
        tree = ast.parse(code)
        last_line = 0
        for i, node in enumerate(tree.body):
            if isinstance(node, ast.ImportFrom) and node.module == "__future__":
                last_line = node.end_lineno or node.lineno
            elif i == 0 and isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant) \
                    and isinstance(node.value.value, str):
                continue  # module docstring may precede future imports
            else:
                break
        if not last_line:
            return "", code
        lines = code.splitlines(keepends=True)
        preamble = "".join(lines[:last_line])
        return (preamble if preamble.endswith("\n") else preamble + "\n"), "".join(lines[last_line:])

    @staticmethod
    def _header_field(text: Optional[str]) -> str:
        """Metadata interpolated into a '#' comment in generated source.

        CR/LF (and other line separators) would escape the comment and inject code that
        check_test_code() never validated, so every line separator becomes a space.
        """
        return " ".join(str(text or "").splitlines()) or "-"

    @staticmethod
    def _unique_test_ids(tests: List[GeneratedTest]) -> List[str]:
        """Disambiguates duplicate test_ids (e.g. from LLM output) so each result is traceable."""
        seen: Dict[str, int] = {}
        unique = []
        for t in tests:
            count = seen.get(t.test_id, 0) + 1
            seen[t.test_id] = count
            unique.append(t.test_id if count == 1 else f"{t.test_id}-{count}")
        return unique

    @staticmethod
    def _parse_junit(junit_xml: Optional[str]) -> Dict[str, List[dict]]:
        """Groups JUnit testcases by generated module name (test_vh_NNN)."""
        grouped: Dict[str, List[dict]] = {}
        if not junit_xml:
            return grouped
        try:
            root = ET.fromstring(junit_xml)
        except ET.ParseError as e:
            logger.error(f"Unable to parse JUnit XML: {e}")
            return grouped

        for tc in root.iter("testcase"):
            # Collection errors: classname="" and name=<module>; regular tests: classname=<module>
            match = re.search(r"test_vh_\d+", tc.get("classname") or "") or re.search(r"test_vh_\d+", tc.get("name") or "")
            if not match:
                continue
            outcome, message, details = "passed", None, None
            out, err = "", ""
            for child in tc:
                if child.tag in ("failure", "error", "skipped") and outcome == "passed":
                    outcome = child.tag
                    message = child.get("message") or ""
                    details = child.text or ""
                elif child.tag == "system-out":
                    out += child.text or ""
                elif child.tag == "system-err":
                    err += child.text or ""
            try:
                case_time = float(tc.get("time") or 0.0)
            except (TypeError, ValueError):
                case_time = 0.0  # the XML came from a container running untrusted code; never crash on it
            grouped.setdefault(match.group(0), []).append({
                "name": tc.get("name"),
                "time": case_time,
                "outcome": outcome,
                "message": message,
                "details": details,
                "stdout": out,
                "stderr": err,
            })
        return grouped

    def _aggregate(
        self,
        test: GeneratedTest,
        test_id: str,
        cases: List[dict]
    ) -> TestExecutionResult:
        duration = round(sum(c["time"] for c in cases), 3)
        # Report this test's own captured output rather than the whole batch's
        stdout = "".join(c["stdout"] for c in cases)
        stderr = "".join(c["stderr"] for c in cases)
        errors = [c for c in cases if c["outcome"] == "error"]
        failures = [c for c in cases if c["outcome"] == "failure"]
        harness_failures = [c for c in failures if self._is_harness_failure(c)]
        defect_failures = [c for c in failures if c not in harness_failures]

        if defect_failures:
            case = defect_failures[0]
            return self._result(
                test, test_id, TestStatus.FAILED,
                failure_reason=self._first_line(case["message"]) or f"Assertion failed during {test.title}",
                traceback=case["details"], duration=duration, stdout=stdout, stderr=stderr,
                is_exploit=test.test_type == "blackbox_security" and self._is_assertion(case["message"]),
                poc=self._generate_poc(test, case["name"])
            )
        if errors or harness_failures:
            case = (errors or harness_failures)[0]
            reason = self._first_line(case["message"]) or self._first_line(case["details"]) or "Unknown execution failure"
            return self._result(
                test, test_id, TestStatus.ERROR,
                failure_reason=f"Test could not run correctly: {reason}",
                traceback=case["details"], duration=duration, stdout=stdout, stderr=stderr
            )
        if all(c["outcome"] == "skipped" for c in cases):
            return self._result(
                test, test_id, TestStatus.SKIPPED,
                failure_reason=self._first_line(cases[0]["message"]) or "Skipped",
                duration=duration, stdout=stdout, stderr=stderr
            )
        passed = self._result(test, test_id, TestStatus.PASSED, duration=duration, stdout=stdout, stderr=stderr)
        skipped_count = sum(1 for c in cases if c["outcome"] == "skipped")
        if skipped_count:
            # A partially skipped module is weaker evidence than a clean pass; say so explicitly
            # instead of counting unverified boundaries as defended.
            passed.failure_reason = (
                f"{skipped_count} of {len(cases)} case(s) were skipped inside this module; "
                "only the executed cases verify the boundary"
            )
        return passed

    @staticmethod
    def _is_harness_failure(case: dict) -> bool:
        """A failure caused by the generated test itself rather than by the target's behaviour."""
        message = case["message"] or ""
        if message.startswith(HARNESS_ERROR_EXCEPTIONS):
            return True
        return bool(_SIGNATURE_TYPEERROR_RE.match(message)
                    and _RAISED_IN_TEST_MODULE_RE.search(case["details"] or ""))

    @staticmethod
    def _is_assertion(message: Optional[str]) -> bool:
        """pytest reports explicit AssertionErrors, rewritten bare asserts ('assert x == y'),
        and explicit test failures via pytest.fail() ('Failed: ...')."""
        msg = (message or "").strip()
        return (
            msg.startswith("AssertionError")
            or msg.startswith("assert ")
            or msg.startswith("assert\n")
            or msg == "assert"
            or msg.startswith("Failed:")
            or msg.startswith("Failed ")
            or msg == "Failed"
        )

    @staticmethod
    def _first_line(text: Optional[str]) -> str:
        return (text or "").strip().splitlines()[0][:300] if (text or "").strip() else ""

    @staticmethod
    def _result(
        test: GeneratedTest,
        test_id: str,
        status: TestStatus,
        failure_reason: Optional[str] = None,
        traceback: Optional[str] = None,
        duration: float = 0.0,
        stdout: str = "",
        stderr: str = "",
        is_exploit: bool = False,
        poc: Optional[str] = None
    ) -> TestExecutionResult:
        return TestExecutionResult(
            test_id=test_id,
            test_type=test.test_type,
            status=status,
            duration_seconds=duration,
            stdout=stdout[:500],
            stderr=stderr[:500],
            traceback=traceback[:2000] if traceback else None,
            failure_reason=failure_reason,
            is_security_exploit_confirmed=is_exploit,
            reproduction_poc=poc,
            source_ref=test.source_ref
        )

    def _generate_poc(self, test: GeneratedTest, fn_name: str) -> str:
        """Constructs a reproduction script for a confirmed failure."""
        return (
            f"# === Reproduction PoC ===\n"
            f"# Target: {self._header_field(test.target_component)}\n"
            f"# Failure Context: {self._header_field(test.title)}\n"
            f"# Test Function: {fn_name}\n"
            f"# Test Code:\n{test.code}\n"
        )
