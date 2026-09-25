import subprocess
import tempfile
import os
import sys
import time
import re
import shutil
from typing import Dict, Any, Optional, Tuple, List


class LocalSubprocessSandbox:
    """
    Subprocess sandbox for executing test scripts and dynamic payloads.
    Provides process isolation, execution timeout enforcement,
    per-test JUnit XML reporting, and automatic code coverage collection.
    Generated test files and coverage data are kept in a throwaway temp directory,
    never inside the target codebase.
    """

    def __init__(self, timeout_seconds: int = 30):
        self.timeout_seconds = timeout_seconds

    def execute_python_code(
        self,
        code_content: str,
        custom_env: Optional[Dict[str, str]] = None,
        working_dir: Optional[str] = None,
        collect_coverage: bool = False,
        coverage_target: Optional[str] = None
    ) -> Tuple[int, str, str, float, Optional[float]]:
        """
        Executes a single Python test module in an isolated subprocess.
        Returns: (exit_code, stdout, stderr, execution_duration_seconds, line_coverage_percent)
        """
        exit_code, stdout, stderr, duration, coverage, _ = self.execute_pytest_files(
            {"test_exec.py": code_content},
            custom_env=custom_env,
            working_dir=working_dir,
            collect_coverage=collect_coverage,
            coverage_target=coverage_target
        )
        return exit_code, stdout, stderr, duration, coverage

    def execute_pytest_files(
        self,
        files: Dict[str, str],
        custom_env: Optional[Dict[str, str]] = None,
        working_dir: Optional[str] = None,
        collect_coverage: bool = False,
        coverage_target: Optional[str] = None
    ) -> Tuple[int, str, str, float, Optional[float], Optional[str]]:
        """
        Writes each {filename: code} entry as a separate test module and runs them in one pytest process.
        A collection error in one module does not abort the others.
        Returns: (exit_code, stdout, stderr, duration_seconds, line_coverage_percent, junit_xml_text)
        """
        base_dir = os.path.abspath(working_dir or os.getcwd())
        project_root = os.path.abspath(os.getcwd())
        parent_dir = os.path.dirname(base_dir)

        run_dir = tempfile.mkdtemp(prefix="vibe_sandbox_")
        test_paths: List[str] = []
        for filename, code in files.items():
            path = os.path.join(run_dir, filename)
            with open(path, "w", encoding="utf-8") as f:
                f.write(code)
            test_paths.append(path)
        junit_path = os.path.join(run_dir, "junit.xml")

        env = os.environ.copy()
        # Inject paths into PYTHONPATH to resolve target modules reliably
        paths_to_inject = [base_dir, project_root, parent_dir]
        existing_pythonpath = env.get("PYTHONPATH", "")
        if existing_pythonpath:
            paths_to_inject.append(existing_pythonpath)
        env["PYTHONPATH"] = os.pathsep.join(paths_to_inject)
        # Keep coverage data out of the target directory
        env["COVERAGE_FILE"] = os.path.join(run_dir, ".coverage")

        if custom_env:
            env.update(custom_env)

        cmd = [
            sys.executable, "-m", "pytest", *test_paths, "-v",
            "--continue-on-collection-errors",
            "-p", "no:cacheprovider",
            f"--rootdir={run_dir}",
            f"--junitxml={junit_path}",
        ]
        if collect_coverage:
            cov_pkg = coverage_target or base_dir
            cmd.extend([f"--cov={cov_pkg}", "--cov-report=term-missing"])

        start_time = time.time()
        coverage_percent: Optional[float] = None

        try:
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
                cwd=base_dir,
                env=env
            )
            duration = time.time() - start_time
            stdout = process.stdout
            stderr = process.stderr

            if collect_coverage:
                coverage_percent = self._extract_coverage_percent(stdout)

            junit_xml = None
            if os.path.exists(junit_path):
                with open(junit_path, "r", encoding="utf-8") as f:
                    junit_xml = f.read()

            return process.returncode, stdout, stderr, duration, coverage_percent, junit_xml
        except subprocess.TimeoutExpired:
            duration = time.time() - start_time
            return -1, "", f"Execution timed out after {self.timeout_seconds} seconds.", duration, None, None
        except Exception as e:
            duration = time.time() - start_time
            return -2, "", f"Execution failed: {str(e)}", duration, None, None
        finally:
            shutil.rmtree(run_dir, ignore_errors=True)

    def _extract_coverage_percent(self, stdout: str) -> Optional[float]:
        """Extracts total coverage percentage from pytest-cov output table."""
        match = re.search(r"TOTAL\s+\d+\s+\d+\s+(\d+)%", stdout)
        if match:
            try:
                return float(match.group(1))
            except ValueError:
                pass
        return None
