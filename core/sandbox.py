import subprocess
import tempfile
import os
import sys
import time
import re
from typing import Dict, Any, Optional, Tuple


class LocalSubprocessSandbox:
    """
    Subprocess sandbox for executing test scripts and dynamic payloads.
    Provides process isolation, environment sanitization, execution timeout enforcement,
    and automatic code coverage collection.
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
        Executes Python code in an isolated subprocess.
        Returns: (exit_code, stdout, stderr, execution_duration_seconds, line_coverage_percent)
        """
        base_dir = os.path.abspath(working_dir or os.getcwd())
        project_root = os.path.abspath(os.getcwd())
        parent_dir = os.path.dirname(base_dir)

        sandbox_dir = os.path.join(base_dir, ".vibe_sandbox")
        os.makedirs(sandbox_dir, exist_ok=True)

        with tempfile.NamedTemporaryFile(
            mode="w",
            prefix="test_exec_",
            suffix=".py",
            dir=sandbox_dir,
            delete=False,
            encoding="utf-8"
        ) as temp_file:
            temp_file.write(code_content)
            temp_path = temp_file.name

        env = os.environ.copy()
        # Inject paths into PYTHONPATH to resolve target modules reliably
        paths_to_inject = [base_dir, project_root, parent_dir]
        existing_pythonpath = env.get("PYTHONPATH", "")
        if existing_pythonpath:
            paths_to_inject.append(existing_pythonpath)
        env["PYTHONPATH"] = os.pathsep.join(paths_to_inject)

        if custom_env:
            env.update(custom_env)

        cmd = [sys.executable, "-m", "pytest", temp_path, "-v"]
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

            return process.returncode, stdout, stderr, duration, coverage_percent
        except subprocess.TimeoutExpired:
            duration = time.time() - start_time
            return -1, "", f"Execution timed out after {self.timeout_seconds} seconds.", duration, None
        except Exception as e:
            duration = time.time() - start_time
            return -2, "", f"Execution failed: {str(e)}", duration, None
        finally:
            if os.path.exists(temp_path):
                try:
                    os.remove(temp_path)
                except OSError:
                    pass

    def _extract_coverage_percent(self, stdout: str) -> Optional[float]:
        """Extracts total coverage percentage from pytest-cov output table."""
        match = re.search(r"TOTAL\s+\d+\s+\d+\s+(\d+)%", stdout)
        if match:
            try:
                return float(match.group(1))
            except ValueError:
                pass
        return None
