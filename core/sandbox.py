import subprocess
import tempfile
import os
import sys
import time
import re
import shutil
import signal
import uuid
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


class SandboxUnavailableError(RuntimeError):
    """The configured sandbox cannot run on this machine (e.g. Docker or its image is missing)."""


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
    filesystem and network access; use DockerSandbox (sandbox_provider: docker) for untrusted targets.
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

        run_dir = tempfile.mkdtemp(prefix="vibe_sandbox_")
        for filename, code in files.items():
            with open(os.path.join(run_dir, filename), "w", encoding="utf-8") as f:
                f.write(self._prepare_code(code, base_dir))
        junit_path = os.path.join(run_dir, "junit.xml")

        start_time = time.time()
        try:
            cmd, cwd, env = self._build_command(
                run_dir, list(files), base_dir, collect_coverage, coverage_target, custom_env
            )
            returncode, stdout, stderr = self._run(cmd, cwd=cwd, env=env, timeout=timeout)
            duration = time.time() - start_time
            if returncode is None:
                self._after_timeout(cmd)
                return TIMEOUT_EXIT_CODE, stdout, f"Execution timed out after {timeout} seconds.", duration, None, None

            coverage_percent = self._extract_coverage_percent(stdout) if collect_coverage else None
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

    # --- Hooks overridden by container sandboxes ------------------------------------

    def _prepare_code(self, code: str, base_dir: str) -> str:
        return code

    def _build_command(
        self,
        run_dir: str,
        filenames: List[str],
        base_dir: str,
        collect_coverage: bool,
        coverage_target: Optional[str],
        custom_env: Optional[Dict[str, str]]
    ) -> Tuple[List[str], str, Dict[str, str]]:
        """Returns (command, cwd, env) for one pytest run over the modules in run_dir."""
        # Inject paths into PYTHONPATH to resolve target modules reliably
        paths_to_inject = [base_dir, os.path.dirname(base_dir)]
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
        cmd = [sys.executable, "-m", "pytest", *[os.path.join(run_dir, f) for f in filenames]]
        cmd += self._pytest_options(run_dir, os.path.join(run_dir, "junit.xml"))
        if collect_coverage:
            cmd.extend([f"--cov={coverage_target or base_dir}", "--cov-report=term-missing"])
        return cmd, base_dir, env

    def _after_timeout(self, cmd: List[str]):
        """Called with the timed-out command after its process tree has been killed."""

    @staticmethod
    def _pytest_options(rootdir: str, junit_path: str) -> List[str]:
        return [
            "-v",
            "--continue-on-collection-errors",
            "-p", "no:cacheprovider",
            "-o", "junit_logging=all",
            f"--rootdir={rootdir}",
            f"--junitxml={junit_path}",
        ]

    # --- Process control ------------------------------------------------------------

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


# --- Docker sandbox -----------------------------------------------------------------

DEFAULT_DOCKER_IMAGE = "vibeharness-sandbox:latest"
CONTAINER_WORK_ROOT = "/work"      # the target is mounted at /work/<target name>
CONTAINER_RUN_DIR = "/sandbox"     # generated test modules, JUnit XML and coverage data
# Forwarded to the docker CLI itself (never into the container) so remote daemons / contexts keep working
_DOCKER_CLI_ENV_VARS = {"DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_CONFIG", "DOCKER_CERT_PATH", "DOCKER_TLS_VERIFY"}


def container_target_dir(host_dir: str) -> str:
    """Where the target directory is mounted inside the container."""
    name = os.path.basename(os.path.normpath(host_dir))
    if name in (".", "..") or not re.fullmatch(r"[A-Za-z0-9_.-]+", name):
        name = "target"
    return f"{CONTAINER_WORK_ROOT}/{name}"


def rewrite_host_paths(text: str, mapping: List[Tuple[str, str]], windows: Optional[bool] = None) -> str:
    """
    Replaces host paths under each mapped host directory with the corresponding container path.
    Generated tests embed absolute host paths (sys.path inserts, importlib file locations); inside the
    container those must point at the mount. On Windows the raw, repr-escaped and forward-slash forms of
    the path are matched case-insensitively and backslash separators become '/'.
    """
    windows = sys.platform == "win32" if windows is None else windows
    alternatives: List[Tuple[str, str]] = []
    for host, container in mapping:
        variants = {host}
        if windows:
            variants |= {host.replace("\\", "\\\\"), host.replace("\\", "/")}
        alternatives += [(v, container) for v in variants]
    if not alternatives:
        return text
    # Longest first so a mapped directory wins over its mapped parent at the same position
    alternatives.sort(key=lambda a: len(a[0]), reverse=True)
    separator = r"(?:\\\\|\\|/)" if windows else "/"
    name_char = r"[^\\/'\"\s]" if windows else r"[^/'\"\s]"
    pattern = re.compile(
        "(?:" + "|".join(f"(?P<g{i}>{re.escape(v)})" for i, (v, _) in enumerate(alternatives)) + ")"
        # The match must end at a path boundary: C:\proj must not match C:\proj2
        + r"(?![A-Za-z0-9_.-])"
        + f"(?P<tail>(?:{separator}{name_char}*)*)",
        re.IGNORECASE if windows else 0
    )

    def replace(match: "re.Match") -> str:
        container = next(c for i, (_, c) in enumerate(alternatives) if match.group(f"g{i}") is not None)
        return container + re.sub(separator, "/", match.group("tail"))

    return pattern.sub(replace, text)


class DockerSandbox(LocalSubprocessSandbox):
    """
    Runs each pytest batch in a throwaway Docker container, which IS an isolation boundary:
    no network (by default), read-only root filesystem and read-only target mount, all capabilities
    dropped, no privilege escalation, an unprivileged user, memory / CPU / PID limits, and only the
    environment variables set explicitly here. Only the per-run temp directory is writable.
    The target is mounted at /work/<name>; host paths in generated code are rewritten to it.
    The image must already contain pytest, pytest-cov and the target's dependencies, because the
    container has no network to install them (see docker/sandbox.Dockerfile).
    """

    def __init__(
        self,
        timeout_seconds: int = 120,
        image: str = DEFAULT_DOCKER_IMAGE,
        network: str = "none",
        memory: str = "1g",
        cpus: str = "2",
        pids_limit: int = 256,
        docker_bin: str = "docker",
        verify: bool = True
    ):
        super().__init__(timeout_seconds)
        self.image = image
        self.network = network
        self.memory = memory
        self.cpus = str(cpus)
        self.pids_limit = int(pids_limit)
        self.docker = shutil.which(docker_bin) or docker_bin
        if verify:
            self._verify_available()

    def _verify_available(self):
        if not shutil.which(self.docker):
            raise SandboxUnavailableError(
                "sandbox_provider 'docker' needs the docker CLI on PATH; install Docker or use 'local_subprocess'."
            )
        try:
            result = subprocess.run(
                [self.docker, "image", "inspect", self.image],
                capture_output=True, text=True, encoding="utf-8", errors="replace", env=self._cli_env(), timeout=60
            )
        except (OSError, subprocess.TimeoutExpired) as e:
            raise SandboxUnavailableError(f"Docker is not usable: {e}") from e
        if result.returncode != 0:
            raise SandboxUnavailableError(
                f"Docker image '{self.image}' is not available (or the Docker daemon is not running): "
                f"{result.stderr.strip()}\nBuild it with: docker build -t {self.image} -f docker/sandbox.Dockerfile ."
            )

    @staticmethod
    def _cli_env() -> Dict[str, str]:
        env = build_safe_env()
        env.update({k: v for k, v in os.environ.items() if k.upper() in _DOCKER_CLI_ENV_VARS})
        return env

    @staticmethod
    def _path_mapping(base_dir: str) -> List[Tuple[str, str]]:
        mapping = [(base_dir, container_target_dir(base_dir))]
        parent = os.path.dirname(base_dir)
        # The parent is also on sys.path locally; map it to /work, where only the target is visible.
        # Never map a filesystem root: that would rewrite every absolute path.
        if os.path.dirname(parent) != parent:
            mapping.append((parent, CONTAINER_WORK_ROOT))
        return mapping

    def _prepare_code(self, code: str, base_dir: str) -> str:
        return rewrite_host_paths(code, self._path_mapping(base_dir))

    @staticmethod
    def _bind(source: str, target: str, readonly: bool) -> str:
        # --mount is parsed as CSV: a comma in a host path needs the field quoted
        src = f'"source={source}"' if "," in source else f"source={source}"
        return f"type=bind,{src},target={target}" + (",readonly" if readonly else "")

    @staticmethod
    def _user() -> str:
        # The host user on POSIX, so files written to the run directory stay removable; otherwise nobody
        if hasattr(os, "getuid"):
            return f"{os.getuid()}:{os.getgid()}"
        return "65534:65534"

    def _build_command(
        self,
        run_dir: str,
        filenames: List[str],
        base_dir: str,
        collect_coverage: bool,
        coverage_target: Optional[str],
        custom_env: Optional[Dict[str, str]]
    ) -> Tuple[List[str], str, Dict[str, str]]:
        target = container_target_dir(base_dir)
        env = {
            "PYTHONPATH": f"{target}:{CONTAINER_WORK_ROOT}",
            "COVERAGE_FILE": f"{CONTAINER_RUN_DIR}/.coverage",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONIOENCODING": "utf-8",
            "HOME": "/tmp",
        }
        if custom_env:
            env.update(custom_env)

        cmd = [
            self.docker, "run", "--rm",
            "--name", f"vibeharness-{uuid.uuid4().hex[:12]}",
            "--network", self.network,
            "--read-only", "--tmpfs", "/tmp:rw,nosuid,size=256m",
            "--memory", self.memory, "--cpus", self.cpus, "--pids-limit", str(self.pids_limit),
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--user", self._user(),
            "--mount", self._bind(base_dir, target, readonly=True),
            "--mount", self._bind(run_dir, CONTAINER_RUN_DIR, readonly=False),
            "-w", target,
        ]
        for key, value in env.items():
            cmd += ["-e", f"{key}={value}"]
        cmd += [self.image, "python", "-m", "pytest", *[f"{CONTAINER_RUN_DIR}/{f}" for f in filenames]]
        cmd += self._pytest_options(CONTAINER_RUN_DIR, f"{CONTAINER_RUN_DIR}/junit.xml")
        if collect_coverage:
            cov = target
            if coverage_target:
                cov = rewrite_host_paths(os.path.abspath(coverage_target), self._path_mapping(base_dir))
            cmd.extend([f"--cov={cov}", "--cov-report=term-missing"])
        return cmd, run_dir, self._cli_env()

    def _after_timeout(self, cmd: List[str]):
        # Killing the docker CLI does not stop the container; remove it explicitly
        name = cmd[cmd.index("--name") + 1]
        try:
            subprocess.run([self.docker, "rm", "-f", name], capture_output=True, env=self._cli_env(), timeout=60)
        except (OSError, subprocess.TimeoutExpired):
            pass
