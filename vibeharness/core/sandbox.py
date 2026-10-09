import subprocess
import tempfile
import os
import sys
import time
import re
import shutil
import signal
import uuid
import logging
from typing import Dict, Optional, Tuple, List, Any

from vibeharness.core.i18n import bi

logger = logging.getLogger("VibeHarness.Sandbox")

# Exit code returned when the pytest run exceeds its time budget.
# 124 follows GNU timeout convention; values outside the 1..-31 signal range can never be
# confused with a test process that died from a signal (e.g. SIGHUP maps to returncode -1).
TIMEOUT_EXIT_CODE = 124
# Exit code returned when the sandbox itself failed to run the tests (e.g. broken pipe, OSError)
EXECUTION_FAILURE_EXIT_CODE = 125

# How long to wait for the killed process's pipes to drain before giving up. A grandchild that
# daemonized into a new session can survive the kill and hold the pipes open; without this cap
# the harness would hang forever on proc.communicate().
_POST_KILL_DRAIN_SECONDS = 5.0

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


# Keys in custom_env that are never forwarded, however they are spelled (uppercase or not):
# credentials (the allowlist already keeps host secrets out, but callers could pass their own)
# and injection vectors a generated test could abuse to escape into a shell on import.
_CUSTOM_ENV_DENY_RE = re.compile(r"(API_?KEY|SECRET|TOKEN|PASSWORD|PASSWD|CREDENTIAL|^BASH_ENV$|^ENV$|^LD_PRELOAD$|^LD_LIBRARY_PATH$|^PYTHONINSPECT$|^PYTHONSTARTUP$|^NODE_OPTIONS$|^NODE_REPL_EXTERNAL_MODULE$)", re.IGNORECASE)


def filter_custom_env(custom_env: Optional[Dict[str, str]]) -> Dict[str, str]:
    """Drops credential-looking and interpreter-injection keys from caller-supplied env additions."""
    if not custom_env:
        return {}
    kept, dropped = {}, []
    for key, value in custom_env.items():
        if _CUSTOM_ENV_DENY_RE.search(key):
            dropped.append(key)
        else:
            kept[key] = value
    if dropped:
        logger.warning(bi(f"拒絕把憑證／注入類環境變數轉送進沙盒：{', '.join(sorted(dropped))}",
                          f"Refused to forward credential/injection env vars into the sandbox: {', '.join(sorted(dropped))}"))
    return kept


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

    def __init__(self, timeout_seconds: int = 30, memory_mb: int = 0):
        self.timeout_seconds = timeout_seconds
        # Address-space cap (RLIMIT_AS, POSIX only) for the pytest process tree; 0 disables. Not a security
        # boundary, but it stops a generated test from eating the host's memory or CPU time.
        self.memory_mb = int(memory_mb or 0)

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
                run_dir, list(files), base_dir, collect_coverage, coverage_target, custom_env, timeout
            )
            returncode, stdout, stderr = self._run(cmd, cwd=cwd, env=env, timeout=timeout, limits=self._limits(timeout))
            duration = time.time() - start_time
            if returncode is None:
                self._after_timeout(cmd)
                return TIMEOUT_EXIT_CODE, stdout, (
                    f"Execution timed out after {timeout} seconds; module(s) attempted: {', '.join(sorted(files))}."
                ), duration, None, None

            coverage_percent = self._extract_coverage_percent(stdout) if collect_coverage else None
            junit_xml = None
            if os.path.exists(junit_path):
                with open(junit_path, "r", encoding="utf-8") as f:
                    junit_xml = f.read()
            return returncode, stdout, stderr, duration, coverage_percent, junit_xml
        except Exception as e:
            duration = time.time() - start_time
            return EXECUTION_FAILURE_EXIT_CODE, "", f"Execution failed: {str(e)}", duration, None, None
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
        custom_env: Optional[Dict[str, str]],
        timeout_seconds: Optional[int] = None
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
            env.update(filter_custom_env(custom_env))
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

    def _limits(self, timeout: int) -> Dict[str, int]:
        """Resource limits for the test process: memory (if configured) and CPU seconds (the batch budget
        plus slack, so a busy loop that ignores signals still dies)."""
        limits: Dict[str, int] = {"cpu_seconds": int(timeout) + 10}
        if self.memory_mb > 0:
            limits["memory_bytes"] = self.memory_mb * 1024 * 1024
        return limits

    @staticmethod
    def _apply_limits(limits: Dict[str, int]):
        """preexec_fn applying `limits` in the child (POSIX); unsupported limits are ignored."""
        def apply() -> None:
            try:
                import resource
            except ImportError:  # pragma: no cover - POSIX only
                return
            for name, value in (("RLIMIT_AS", limits.get("memory_bytes")), ("RLIMIT_CPU", limits.get("cpu_seconds"))):
                if not value or not hasattr(resource, name):
                    continue
                try:
                    soft, hard = resource.getrlimit(getattr(resource, name))
                    cap = value if hard == resource.RLIM_INFINITY else min(value, hard)
                    resource.setrlimit(getattr(resource, name), (cap, hard))
                except (ValueError, OSError):
                    pass
        return apply

    @staticmethod
    def _run(
        cmd: List[str], cwd: str, env: Dict[str, str], timeout: int, limits: Optional[Dict[str, int]] = None
    ) -> Tuple[Optional[int], str, str]:
        """Runs cmd in its own process group; on timeout kills the whole tree and returns returncode None."""
        popen_kwargs: Dict[str, Any] = {}
        if sys.platform == "win32":
            popen_kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
        else:
            popen_kwargs["start_new_session"] = True
            if limits:
                popen_kwargs["preexec_fn"] = LocalSubprocessSandbox._apply_limits(limits)
        proc = subprocess.Popen(
            cmd, cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, encoding="utf-8", errors="replace", **popen_kwargs
        )
        try:
            stdout, stderr = proc.communicate(timeout=timeout)
            return proc.returncode, stdout, stderr
        except subprocess.TimeoutExpired:
            LocalSubprocessSandbox._kill_tree(proc)
            try:
                stdout, stderr = proc.communicate(timeout=_POST_KILL_DRAIN_SECONDS)
            except subprocess.TimeoutExpired as e:
                # The kill only reaches the process group; a grandchild that started a new
                # session can survive and keep the pipes open. Close our ends and give up
                # on further output instead of hanging forever.
                for stream in (proc.stdout, proc.stderr):
                    if stream is None:
                        continue
                    try:
                        stream.close()
                    except Exception:
                        pass
                stdout, stderr = e.stdout or "", e.stderr or ""
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

    # A Windows file URL carries the drive after the authority (file:///C:/proj/x.mjs); once the
    # drive path becomes /work/proj the URL must keep exactly three slashes (file:///work/proj/x.mjs)
    return pattern.sub(replace, text).replace("file:////", "file:///")


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
        super().__init__(timeout_seconds, memory_mb=0)
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
            raise SandboxUnavailableError(bi(
                "sandbox_provider 'docker' 需要 PATH 上有 docker CLI；請安裝 Docker 或改用 'local_subprocess'。",
                "sandbox_provider 'docker' needs the docker CLI on PATH; install Docker or use 'local_subprocess'."
            ))
        try:
            result = subprocess.run(
                [self.docker, "image", "inspect", self.image],
                capture_output=True, text=True, encoding="utf-8", errors="replace", env=self._cli_env(), timeout=60
            )
        except (OSError, subprocess.TimeoutExpired) as e:
            raise SandboxUnavailableError(bi(f"Docker 無法使用：{e}", f"Docker is not usable: {e}")) from e
        if result.returncode != 0:
            raise SandboxUnavailableError(bi(
                f"Docker 映像檔 '{self.image}' 無法取得（或 Docker 服務未啟動）：{result.stderr.strip()}",
                f"Docker image '{self.image}' is not available (or the Docker daemon is not running): "
                f"{result.stderr.strip()}"
            ) + f"\n{bi('建置指令', 'Build it with')}: docker build -t {self.image} -f docker/sandbox.Dockerfile .")

    @staticmethod
    def _cli_env() -> Dict[str, str]:
        env = build_safe_env()
        env.update({k: v for k, v in os.environ.items() if k.upper() in _DOCKER_CLI_ENV_VARS})
        return env

    @staticmethod
    def _path_mapping(base_dir: str) -> List[Tuple[str, str]]:
        # Only the target is mounted, so only the target's own paths can be rewritten to the
        # container. The parent directory is deliberately NOT mapped: rewriting a sibling path
        # to /work/<sibling> would point at a file that does not exist in the container, while
        # leaving the host path intact makes the failure (and its cause) obvious.
        return [(base_dir, container_target_dir(base_dir))]

    def _prepare_code(self, code: str, base_dir: str) -> str:
        return rewrite_host_paths(code, self._path_mapping(base_dir))

    @staticmethod
    def _bind(source: str, target: str, readonly: bool) -> str:
        # --mount is parsed as CSV: a comma in a host path needs the field quoted
        src = f'"source={source}"' if "," in source else f"source={source}"
        return f"type=bind,{src},target={target}" + (",readonly" if readonly else "")

    @staticmethod
    def _user() -> str:
        # The host user on POSIX, so files written to the run directory stay removable; otherwise nobody.
        # A root harness (common in CI) would otherwise silently run a root container, contradicting
        # the documented non-root isolation; nobody is used instead and the run dir is opened up.
        if sys.platform == "win32":
            return "65534:65534"
        if os.getuid() == 0:
            return "65534:65534"
        return f"{os.getuid()}:{os.getgid()}"

    def _build_command(
        self,
        run_dir: str,
        filenames: List[str],
        base_dir: str,
        collect_coverage: bool,
        coverage_target: Optional[str],
        custom_env: Optional[Dict[str, str]],
        timeout_seconds: Optional[int] = None
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
            env.update(filter_custom_env(custom_env))
        cmd = self._docker_run_prefix(run_dir, base_dir, env)
        cmd += [self.image, "timeout", "--kill-after=5", str(timeout_seconds or self.timeout_seconds),
                "python", "-m", "pytest", *[f"{CONTAINER_RUN_DIR}/{f}" for f in filenames]]
        cmd += self._pytest_options(CONTAINER_RUN_DIR, f"{CONTAINER_RUN_DIR}/junit.xml")
        if collect_coverage:
            cov = target
            if coverage_target:
                cov = rewrite_host_paths(os.path.abspath(coverage_target), self._path_mapping(base_dir))
            cmd.extend([f"--cov={cov}", "--cov-report=term-missing"])
        return cmd, run_dir, self._cli_env()

    def _docker_run_prefix(self, run_dir: str, base_dir: str, env: Dict[str, str]) -> List[str]:
        """`docker run` with the hardening flags, mounts and environment, up to (not including) the image."""
        target = container_target_dir(base_dir)
        if hasattr(os, "getuid") and os.getuid() == 0:
            # The container writes junit.xml/coverage into the run dir as nobody (see _user);
            # a root-owned 0755 dir would make every run fail with no report.
            os.chmod(run_dir, 0o777)

        # `timeout` is the in-container backstop: if the host-side cleanup (docker rm -f) ever
        # fails, pytest still dies instead of running forever. Its 124 exit matches TIMEOUT_EXIT_CODE.
        # It uses this run's own budget: a per-test rerun must not get the whole batch budget.
        cmd = [
            self.docker, "run", "--rm",
            "--name", f"vibeharness-{uuid.uuid4().hex[:12]}",
            "--network", self.network,
            "--read-only", "--tmpfs", "/tmp:rw,nosuid,noexec,size=256m",
            "--memory", self.memory, "--cpus", self.cpus, "--pids-limit", str(self.pids_limit),
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--user", self._user(),
            "--mount", self._bind(base_dir, target, readonly=True),
            # NOTE: noexec/nosuid cannot be applied to this writable bind: --mount type=bind
            # rejects bare mount flags and the -v mode field only accepts ro/propagation/selinux.
            # The writable area stays bounded by non-root user, no-new-privileges, resource
            # limits and the read-only root filesystem.
            "--mount", self._bind(run_dir, CONTAINER_RUN_DIR, readonly=False),
            "-w", target,
        ]
        for key, value in env.items():
            cmd += ["-e", f"{key}={value}"]
        return cmd

    def _limits(self, timeout: int) -> Dict[str, int]:
        return {}  # the container carries --memory/--cpus and the in-container `timeout`

    def _after_timeout(self, cmd: List[str]):
        # Killing the docker CLI does not stop the container; remove it explicitly
        name = cmd[cmd.index("--name") + 1]
        try:
            result = subprocess.run([self.docker, "rm", "-f", name], capture_output=True, env=self._cli_env(), timeout=60)
            if getattr(result, "returncode", 0) != 0:
                logger.warning(bi(f"'{self.docker} rm -f {name}' 失敗（rc={result.returncode}）；"
                                  "容器受其內部逾時限制，但可能殘留。",
                                  f"'{self.docker} rm -f {name}' failed (rc={result.returncode}); "
                                  "the container is bounded by its in-container timeout but may linger."))
        except (OSError, subprocess.TimeoutExpired) as e:
            logger.warning(bi(f"逾時後無法移除容器 {name}：{e}", f"Could not remove container {name} after timeout: {e}"))


# --- Node (JavaScript / TypeScript) sandboxes --------------------------------------------------

MIN_NODE_VERSION = (20, 0, 0)
MIN_NODE_VERSION_TS = (22, 6, 0)  # --experimental-strip-types
DEFAULT_DOCKER_NODE_IMAGE = "vibeharness-sandbox-node:latest"
NODE_TEST_FILE_EXT = ".mjs"


def parse_node_version(text: str) -> Optional[Tuple[int, int, int]]:
    """'v22.6.0' -> (22, 6, 0); None for anything else."""
    m = re.match(r"\s*v?(\d+)\.(\d+)\.(\d+)", text or "")
    return (int(m.group(1)), int(m.group(2)), int(m.group(3))) if m else None


def detect_node(node_bin: str = "node") -> Tuple[Optional[str], Optional[Tuple[int, int, int]], Optional[str]]:
    """(resolved path, version, problem): the problem names what is missing when the first two are None."""
    path = shutil.which(node_bin)
    if not path:
        minimum = '.'.join(map(str, MIN_NODE_VERSION))
        return None, None, bi(f"找不到 node_bin {node_bin!r} 可用的 Node 執行環境（需要 Node >= {minimum}）",
                              f"no usable Node runtime found for node_bin {node_bin!r} (need Node >= {minimum})")
    try:
        result = subprocess.run([path, "--version"], capture_output=True, text=True, encoding="utf-8", errors="replace",
                                env=build_safe_env(), timeout=10)
    except (OSError, subprocess.TimeoutExpired) as e:
        return None, None, bi(f"{node_bin} --version 執行失敗：{e}", f"{node_bin} --version failed: {e}")
    version = parse_node_version(result.stdout)
    if version is None:
        return None, None, bi(f"{node_bin} --version 回傳 {result.stdout.strip()!r}，不是版本號",
                              f"{node_bin} --version returned {result.stdout.strip()!r}, not a version")
    if version < MIN_NODE_VERSION:
        found, minimum = '.'.join(map(str, version)), '.'.join(map(str, MIN_NODE_VERSION))
        return None, version, bi(f"Node v{found} 低於最低需求 {minimum}", f"Node v{found} is below the minimum {minimum}")
    return path, version, None


def node_test_command(node: str, files: List[str], junit_path: str, strip_types: bool,
                      collect_coverage: bool, max_old_space_mb: int) -> List[str]:
    """`node --test` with the spec reporter on stdout and the junit reporter into junit_path."""
    cmd = [node]
    if max_old_space_mb > 0:
        cmd.append(f"--max-old-space-size={max_old_space_mb}")
    if strip_types:
        cmd.append("--experimental-strip-types")
    cmd += ["--test", "--test-reporter=spec", "--test-reporter-destination=stdout",
            "--test-reporter=junit", f"--test-reporter-destination={junit_path}"]
    if collect_coverage:
        cmd.append("--experimental-test-coverage")
    cmd += files
    return cmd


def link_node_modules(run_dir: str, base_dir: str) -> Optional[str]:
    """Makes the target's node_modules resolvable from the run directory (bare specifiers resolve by
    walking up from the importing file): a symlink, a junction on Windows, else None (the caller falls
    back to NODE_PATH, which only CommonJS honours)."""
    source = os.path.join(base_dir, "node_modules")
    if not os.path.isdir(source):
        return None
    link = os.path.join(run_dir, "node_modules")
    try:
        os.symlink(source, link, target_is_directory=True)
        return link
    except (OSError, NotImplementedError):
        pass
    if sys.platform == "win32":
        try:
            result = subprocess.run(["cmd", "/c", "mklink", "/J", link, source], capture_output=True, timeout=30)
            if result.returncode == 0:
                return link
        except (OSError, subprocess.TimeoutExpired):
            pass
    return None


class NodeSubprocessSandbox(LocalSubprocessSandbox):
    """Runs `node:test` modules (ESM, test_vh_NNN.mjs) with Node's built-in runner. Same driver and
    timeout handling as the Python sandbox; no RLIMIT_AS (V8 reserves a large address space at
    start-up and aborts under one), the heap is capped with --max-old-space-size instead."""

    def __init__(self, timeout_seconds: int = 30, memory_mb: int = 0, node_bin: str = "node", strip_types: bool = False,
                 supports_typescript: bool = True):
        super().__init__(timeout_seconds, memory_mb=memory_mb)
        self.node = shutil.which(node_bin) or node_bin
        self.strip_types = strip_types
        self.supports_typescript = supports_typescript

    def _build_command(
        self,
        run_dir: str,
        filenames: List[str],
        base_dir: str,
        collect_coverage: bool,
        coverage_target: Optional[str],
        custom_env: Optional[Dict[str, str]],
        timeout_seconds: Optional[int] = None
    ) -> Tuple[List[str], str, Dict[str, str]]:
        extra: Dict[str, str] = {"NODE_ENV": "test"}
        if link_node_modules(run_dir, base_dir) is None and os.path.isdir(os.path.join(base_dir, "node_modules")):
            extra["NODE_PATH"] = os.path.join(base_dir, "node_modules")
        env = build_safe_env(extra)
        if custom_env:
            env.update(filter_custom_env(custom_env))
        cmd = node_test_command(self.node, [os.path.join(run_dir, f) for f in filenames],
                                os.path.join(run_dir, "junit.xml"), self.strip_types, False, self.memory_mb)
        return cmd, base_dir, env

    def _limits(self, timeout: int) -> Dict[str, int]:
        return {"cpu_seconds": int(timeout) + 10}

    def _extract_coverage_percent(self, stdout: str) -> Optional[float]:
        return None  # JS coverage is not collected (v1); line coverage stays Python-only


class NodeDockerSandbox(DockerSandbox):
    """The Node flavour of the container sandbox: same hardening, a Node image (docker/sandbox-node.Dockerfile)."""

    def __init__(
        self,
        timeout_seconds: int = 120,
        image: str = DEFAULT_DOCKER_NODE_IMAGE,
        network: str = "none",
        memory: str = "1g",
        cpus: str = "2",
        pids_limit: int = 256,
        docker_bin: str = "docker",
        verify: bool = True,
        strip_types: bool = False,
        supports_typescript: bool = True,
    ):
        self.strip_types = strip_types
        self.supports_typescript = supports_typescript
        super().__init__(timeout_seconds, image, network, memory, cpus, pids_limit, docker_bin, verify)

    def _verify_available(self):
        try:
            super()._verify_available()
        except SandboxUnavailableError as e:
            raise SandboxUnavailableError(str(e).replace("docker/sandbox.Dockerfile", "docker/sandbox-node.Dockerfile")) from e

    def _build_command(
        self,
        run_dir: str,
        filenames: List[str],
        base_dir: str,
        collect_coverage: bool,
        coverage_target: Optional[str],
        custom_env: Optional[Dict[str, str]],
        timeout_seconds: Optional[int] = None
    ) -> Tuple[List[str], str, Dict[str, str]]:
        target = container_target_dir(base_dir)
        env = {"HOME": "/tmp", "NODE_ENV": "test", "NODE_PATH": f"{target}/node_modules"}
        if custom_env:
            env.update(filter_custom_env(custom_env))
        cmd = self._docker_run_prefix(run_dir, base_dir, env)
        cmd += [self.image, "timeout", "--kill-after=5", str(timeout_seconds or self.timeout_seconds)]
        cmd += node_test_command("node", [f"{CONTAINER_RUN_DIR}/{f}" for f in filenames],
                                 f"{CONTAINER_RUN_DIR}/junit.xml", self.strip_types, False, 0)
        return cmd, run_dir, self._cli_env()
