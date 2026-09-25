import subprocess
import tempfile
import os
import sys
import time
import re
import shutil
import signal
from typing import Dict, Optional, Tuple, List

# Exit code returned when the pytest run exceeds its time budget
TIMEOUT_EXIT_CODE = -1

# Environment variables forwarded to generated test code. Everything else (API keys, cloud
# credentials, tokens) is withheld, because generated tests are untrusted model output.
_SAFE_ENV_VARS = {
    "PATH", "PATHEXT", "SYSTEMROOT", "SYSTEMDRIVE", "WINDIR", "COMSPEC", "OS",
    "NUMBER_OF_PROCESSORS", "PROCESSOR_ARCHITECTURE",
    "TEMP", "TMP", "TMPDIR", "HOME", "USERPROFILE", "HOMEDRIVE", "HOMEPATH",
    "APPDATA", "LOCALAPPDATA", "PROGRAMDATA",  # Windows user site-packages live under APPDATA
    "LANG", "LANGUAGE", "TZ", "TERM",
    "VIRTUAL_ENV", "CONDA_PREFIX", "PYTHONHOME", "PYTHONPATH", "PYTHONIOENCODING", "PYTHONUTF8",
    "SSL_CERT_FILE", "SSL_CERT_DIR", "REQUESTS_CA_BUNDLE",
}


def build_safe_env(extra: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    """Allowlisted copy of the current environment, plus `extra` overrides."""
    env = {k: v for k, v in os.environ.items() if k.upper() in _SAFE_ENV_VARS or k.upper().startswith("LC_")}
    if extra:
        env.update(extra)
    return env


class LocalSubprocessSandbox:
    """
    Subprocess sandbox for executing test scripts and dynamic payloads.
    Provides process isolation, an allowlisted environment (no API keys or credentials),
    timeout enforcement that kills the whole process tree, per-test JUnit XML reporting,
    and automatic code coverage collection.
    Generated test files and coverage data are kept in a throwaway temp directory,
    never inside the target codebase.
    NOTE: this is NOT a security boundary. Generated code still runs as the current user with
    filesystem and network access; use a container/VM for untrusted targets.
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
        coverage_target: Optional[str] = None,
        timeout_seconds: Optional[int] = None
    ) -> Tuple[int, str, str, float, Optional[float], Optional[str]]:
        """
        Writes each {filename: code} entry as a separate test module and runs them in one pytest process.
        A collection error in one module does not abort the others.
        Returns: (exit_code, stdout, stderr, duration_seconds, line_coverage_percent, junit_xml_text)
        """
        timeout = timeout_seconds or self.timeout_seconds
        base_dir = os.path.abspath(working_dir or os.getcwd())
        parent_dir = os.path.dirname(base_dir)

        run_dir = tempfile.mkdtemp(prefix="vibe_sandbox_")
        test_paths: List[str] = []
        for filename, code in files.items():
            path = os.path.join(run_dir, filename)
            with open(path, "w", encoding="utf-8") as f:
                f.write(code)
            test_paths.append(path)
        junit_path = os.path.join(run_dir, "junit.xml")

        # Inject paths into PYTHONPATH to resolve target modules reliably
        paths_to_inject = [base_dir, parent_dir]
        existing_pythonpath = os.environ.get("PYTHONPATH", "")
        if existing_pythonpath:
            paths_to_inject.append(existing_pythonpath)
        env = build_safe_env({
            "PYTHONPATH": os.pathsep.join(paths_to_inject),
            # Keep coverage data out of the target directory
            "COVERAGE_FILE": os.path.join(run_dir, ".coverage"),
            # Importing the target must not leave __pycache__ behind in it
            "PYTHONDONTWRITEBYTECODE": "1",
        })
        if custom_env:
            env.update(custom_env)

        cmd = [
            sys.executable, "-m", "pytest", *test_paths, "-v",
            "--continue-on-collection-errors",
            "-p", "no:cacheprovider",
            "-o", "junit_logging=all",
            f"--rootdir={run_dir}",
            f"--junitxml={junit_path}",
        ]
        if collect_coverage:
            cov_pkg = coverage_target or base_dir
            cmd.extend([f"--cov={cov_pkg}", "--cov-report=term-missing"])

        start_time = time.time()
        coverage_percent: Optional[float] = None

        try:
            returncode, stdout, stderr = self._run(cmd, cwd=base_dir, env=env, timeout=timeout)
            duration = time.time() - start_time
            if returncode is None:
                return TIMEOUT_EXIT_CODE, stdout, f"Execution timed out after {timeout} seconds.", duration, None, None

            if collect_coverage:
                coverage_percent = self._extract_coverage_percent(stdout)

            junit_xml = None
            if os.path.exists(junit_path):
                with open(junit_path, "r", encoding="utf-8") as f:
                    junit_xml = f.read()

            return returncode, stdout, stderr, duration, coverage_percent, junit_xml
        except Exception as e:
            duration = time.time() - start_time
            return -2, "", f"Execution failed: {str(e)}", duration, None, None
        finally:
            shutil.rmtree(run_dir, ignore_errors=True)

    @staticmethod
    def _run(cmd: List[str], cwd: str, env: Dict[str, str], timeout: int) -> Tuple[Optional[int], str, str]:
        """Runs cmd in its own process group; on timeout kills the whole tree and returns returncode None."""
        popen_kwargs = {}
        if sys.platform == "win32":
            popen_kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
        else:
            popen_kwargs["start_new_session"] = True
        proc = subprocess.Popen(
            cmd, cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, encoding="utf-8", errors="replace", **popen_kwargs
        )
        try:
            stdout, stderr = proc.communicate(timeout=timeout)
            return proc.returncode, stdout, stderr
        except subprocess.TimeoutExpired:
            LocalSubprocessSandbox._kill_tree(proc)
            stdout, stderr = proc.communicate()
            return None, stdout or "", stderr or ""

    @staticmethod
    def _kill_tree(proc: subprocess.Popen):
        """Kills the process and any children it spawned (e.g. servers started by a test)."""
        try:
            if sys.platform == "win32":
                subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)], capture_output=True)
            else:
                os.killpg(proc.pid, signal.SIGKILL)
            proc.kill()
        except Exception:
            pass

    def _extract_coverage_percent(self, stdout: str) -> Optional[float]:
        """Extracts total coverage percentage from pytest-cov output table (statement or branch layout)."""
        match = re.search(r"^TOTAL\s+(?:\d+\s+)+(\d+(?:\.\d+)?)%", stdout, re.MULTILINE)
        if match:
            try:
                return float(match.group(1))
            except ValueError:
                pass
        return None
