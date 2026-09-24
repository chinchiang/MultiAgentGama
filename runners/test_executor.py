import re
import os
import logging
from typing import List, Tuple, Optional
from core.models import GeneratedTest, TestExecutionResult, TestStatus
from core.sandbox import LocalSubprocessSandbox

logger = logging.getLogger("VibeHarness.TestExecutor")


class TestSuiteExecutor:
    __test__ = False
    """
    Assembles generated test functions into an executable suite,
    ensures unique test function names, runs them inside the sandbox,
    and accurately parses test outcomes and code coverage.
    """

    def __init__(self, sandbox: LocalSubprocessSandbox):
        self.sandbox = sandbox

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

        # Assemble full python script with imports and uniquely namespaced test functions
        script_parts = [
            "import pytest",
            "import sys",
            "import os",
            "from typing import Any, Dict",
            f"sys.path.insert(0, r'{abs_target}')",
            f"sys.path.insert(0, r'{parent_dir}')",
            "# --- VibeHarness Auto-Generated Test Suite ---"
        ]

        test_fn_map = {}  # test_id -> unique_fn_name

        for idx, t in enumerate(tests):
            clean_id = re.sub(r"[^a-zA-Z0-9_]", "_", t.test_id.lower())
            # Find original function name
            match_fn = re.search(r"def\s+([a-zA-Z0-9_]+)\s*\(", t.code)
            orig_fn = match_fn.group(1) if match_fn else f"case_{idx+1}"
            unique_fn = f"test_{clean_id}_{orig_fn}"
            test_fn_map[t.test_id] = unique_fn

            # Rename function definition in code snippet to guarantee uniqueness
            modified_code = re.sub(r"def\s+[a-zA-Z0-9_]+\s*\(", f"def {unique_fn}(", t.code, count=1)

            script_parts.append(f"\n# Target: {t.target_component} | Test: {t.title}")
            script_parts.append(modified_code)

        combined_script = "\n".join(script_parts)

        logger.info(f"Executing test suite containing {len(tests)} test cases in sandbox (coverage={collect_coverage})...")
        exit_code, stdout, stderr, duration, coverage_pct = self.sandbox.execute_python_code(
            combined_script,
            working_dir=working_dir,
            collect_coverage=collect_coverage,
            coverage_target=working_dir
        )

        results: List[TestExecutionResult] = []
        overall_text = stdout + "\n" + stderr

        for t in tests:
            unique_fn = test_fn_map.get(t.test_id, t.test_id)

            if f"::{unique_fn} PASSED" in overall_text:
                status = TestStatus.PASSED
                failure_reason = None
                poc = None
            elif f"::{unique_fn} FAILED" in overall_text:
                status = TestStatus.FAILED
                failure_reason = f"Assertion failed or defensive check violated during {t.title}"
                poc = self._generate_poc(t, unique_fn, stdout, stderr)
            elif f"::{unique_fn} ERROR" in overall_text:
                status = TestStatus.ERROR
                failure_reason = "Test raised unhandled runtime/collection error"
                poc = self._generate_poc(t, unique_fn, stdout, stderr)
            else:
                # Fallback based on overall suite result
                if exit_code == 0:
                    status = TestStatus.PASSED
                    failure_reason = None
                    poc = None
                else:
                    status = TestStatus.FAILED
                    failure_reason = "Test failed in suite execution"
                    poc = self._generate_poc(t, unique_fn, stdout, stderr)

            is_security_exploit = (
                status == TestStatus.FAILED and t.test_type == "blackbox_security"
            )

            results.append(TestExecutionResult(
                test_id=t.test_id,
                test_type=t.test_type,
                status=status,
                duration_seconds=round(duration / max(1, len(tests)), 3),
                stdout=stdout[:500],
                stderr=stderr[:500],
                failure_reason=failure_reason,
                is_security_exploit_confirmed=is_security_exploit,
                reproduction_poc=poc
            ))

        return results, coverage_pct

    def _generate_poc(self, test: GeneratedTest, fn_name: str, stdout: str, stderr: str) -> str:
        """Constructs a minimal reproduction script for a confirmed failure."""
        return (
            f"# === Minimal Reproduction PoC ===\n"
            f"# Target: {test.target_component}\n"
            f"# Failure Context: {test.title}\n"
            f"# Test Function: {fn_name}\n"
            f"# Test Code:\n{test.code}\n"
        )
