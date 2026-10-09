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

# pytest 執行超過時間預算時回傳的結束碼。
# 124 遵循 GNU timeout 慣例；落在 1..-31 訊號範圍之外的值，絕不會與
# 因訊號而死亡的測試行程混淆（例如 SIGHUP 對應到 returncode -1）。
# Exit code returned when the pytest run exceeds its time budget.
# 124 follows GNU timeout convention; values outside the 1..-31 signal range can never be
# confused with a test process that died from a signal (e.g. SIGHUP maps to returncode -1).
TIMEOUT_EXIT_CODE = 124
# 沙盒本身無法執行測試時回傳的結束碼（例如 broken pipe、OSError）
# Exit code returned when the sandbox itself failed to run the tests (e.g. broken pipe, OSError)
EXECUTION_FAILURE_EXIT_CODE = 125

# 被砍掉的行程其管線排空前要等多久才放棄。已 daemon 化到新 session 的孫行程
# 可能在砍殺後存活並持續佔住管線；沒有這個上限，
# harness 會在 proc.communicate() 上永遠卡住。
# How long to wait for the killed process's pipes to drain before giving up. A grandchild that
# daemonized into a new session can survive the kill and hold the pipes open; without this cap
# the harness would hang forever on proc.communicate().
_POST_KILL_DRAIN_SECONDS = 5.0

# 會轉送給產生的測試程式碼的環境變數。其他所有變數（API 金鑰、雲端
# 憑證、權杖）都會被扣住，因為產生的測試是不受信任的模型輸出。
# Environment variables forwarded to generated test code. Everything else (API keys, cloud
# credentials, tokens) is withheld, because generated tests are untrusted model output.
_SAFE_ENV_VARS = {
    "PATH", "PATHEXT", "SYSTEMROOT", "SYSTEMDRIVE", "WINDIR", "COMSPEC", "OS",
    "NUMBER_OF_PROCESSORS", "PROCESSOR_ARCHITECTURE",
    "TEMP", "TMP", "TMPDIR", "HOME", "USERPROFILE", "HOMEDRIVE", "HOMEPATH",
    "APPDATA", "LOCALAPPDATA", "PROGRAMDATA",  # Windows 的使用者 site-packages 位於 APPDATA 底下 ／ Windows user site-packages live under APPDATA
    "LANG", "LANGUAGE", "TZ", "TERM",
    "VIRTUAL_ENV", "CONDA_PREFIX", "PYTHONHOME", "PYTHONPATH", "PYTHONIOENCODING", "PYTHONUTF8",
    "SSL_CERT_FILE", "SSL_CERT_DIR", "REQUESTS_CA_BUNDLE",
}


class SandboxUnavailableError(RuntimeError):
    """設定的沙盒無法在這台機器上執行（例如缺少 Docker 或其映像檔）。
    The configured sandbox cannot run on this machine (e.g. Docker or its image is missing)."""


# custom_env 中無論大小寫怎麼拼都絕不轉送的鍵：
# 憑證（允許清單已擋住主機的機密，但呼叫端可能自己傳入），
# 以及產生的測試可能濫用、在 import 時逃逸到 shell 的注入途徑。
# Keys in custom_env that are never forwarded, however they are spelled (uppercase or not):
# credentials (the allowlist already keeps host secrets out, but callers could pass their own)
# and injection vectors a generated test could abuse to escape into a shell on import.
_CUSTOM_ENV_DENY_RE = re.compile(r"(API_?KEY|SECRET|TOKEN|PASSWORD|PASSWD|CREDENTIAL|^BASH_ENV$|^ENV$|^LD_PRELOAD$|^LD_LIBRARY_PATH$|^PYTHONINSPECT$|^PYTHONSTARTUP$|^NODE_OPTIONS$|^NODE_REPL_EXTERNAL_MODULE$)", re.IGNORECASE)


def filter_custom_env(custom_env: Optional[Dict[str, str]]) -> Dict[str, str]:
    """從呼叫端提供的環境變數附加項中，剔除看起來像憑證以及會注入直譯器的鍵。
    Drops credential-looking and interpreter-injection keys from caller-supplied env additions."""
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
    """目前環境變數的允許清單副本，再加上 `extra` 覆寫。
    Allowlisted copy of the current environment, plus `extra` overrides."""
    env = {k: v for k, v in os.environ.items() if k.upper() in _SAFE_ENV_VARS or k.upper().startswith("LC_")}
    if extra:
        env.update(extra)
    return env


class LocalSubprocessSandbox:
    """
    用來執行測試腳本與動態酬載的子行程沙盒。
    提供行程隔離、允許清單式的環境變數（不含 API 金鑰或憑證）、
    會砍掉整個行程樹的逾時強制、逐一測試的 JUnit XML 回報，
    以及自動蒐集程式碼涵蓋率。
    產生的測試檔與涵蓋率資料放在用完即丟的暫存目錄裡，
    絕不會放進目標程式碼庫。
    注意：這不是資安邊界。產生的程式碼仍以目前使用者的身分執行，且擁有
    檔案系統與網路存取；不受信任的目標請改用 DockerSandbox（sandbox_provider: docker）。
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
        # pytest 行程樹的位址空間上限（RLIMIT_AS，僅限 POSIX）；0 表示停用。這不是資安
        # 邊界，但能阻止產生的測試吃光主機的記憶體或 CPU 時間。
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
        在隔離的子行程中執行單一個 Python 測試模組。
        回傳：(exit_code, stdout, stderr, execution_duration_seconds, line_coverage_percent)
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
        把每個 {filename: code} 項目寫成獨立的測試模組，並在同一個 pytest 行程中執行。
        某一模組的收集錯誤不會中止其他模組。
        回傳：(exit_code, stdout, stderr, duration_seconds, line_coverage_percent, junit_xml_text)
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

    # --- 由容器沙盒覆寫的掛鉤 ---------------------------------------------------
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
        """回傳對 run_dir 內各模組執行一次 pytest 所需的 (command, cwd, env)。
        Returns (command, cwd, env) for one pytest run over the modules in run_dir."""
        # 把路徑注入 PYTHONPATH，讓目標模組能可靠地被解析
        # Inject paths into PYTHONPATH to resolve target modules reliably
        paths_to_inject = [base_dir, os.path.dirname(base_dir)]
        existing_pythonpath = os.environ.get("PYTHONPATH", "")
        if existing_pythonpath:
            paths_to_inject.append(existing_pythonpath)
        env = build_safe_env({
            "PYTHONPATH": os.pathsep.join(paths_to_inject),
            # 讓涵蓋率資料不落在目標目錄裡
            # Keep coverage data out of the target directory
            "COVERAGE_FILE": os.path.join(run_dir, ".coverage"),
            # 匯入目標時不能在裡面留下 __pycache__
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
        """在逾時指令的行程樹被砍掉之後，以該指令呼叫。
        Called with the timed-out command after its process tree has been killed."""

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

    # --- 行程控制 --------------------------------------------------------------------
    # --- Process control ------------------------------------------------------------

    def _limits(self, timeout: int) -> Dict[str, int]:
        """測試行程的資源限制：記憶體（若有設定）與 CPU 秒數（批次預算
        再加上寬裕量，讓對訊號無反應的忙碌迴圈仍會死掉）。
        Resource limits for the test process: memory (if configured) and CPU seconds (the batch budget
        plus slack, so a busy loop that ignores signals still dies)."""
        limits: Dict[str, int] = {"cpu_seconds": int(timeout) + 10}
        if self.memory_mb > 0:
            limits["memory_bytes"] = self.memory_mb * 1024 * 1024
        return limits

    @staticmethod
    def _apply_limits(limits: Dict[str, int]):
        """在子行程（POSIX）中套用 `limits` 的 preexec_fn；不支援的限制會被跳過。
        preexec_fn applying `limits` in the child (POSIX); unsupported limits are ignored."""
        def apply() -> None:
            try:
                import resource
            except ImportError:  # pragma: no cover - 僅限 POSIX ／ POSIX only
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
        """在自己的行程群組中執行 cmd；逾時時砍掉整棵行程樹並回傳 returncode None。
        Runs cmd in its own process group; on timeout kills the whole tree and returns returncode None."""
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
                # 砍殺只會到達行程群組；開了新 session 的孫行程
                # 可能存活並持續佔住管線。關閉我們這一端，
                # 放棄後續輸出，而不是永遠卡住。
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
        """砍掉該行程及其衍生的所有子行程（例如測試啟動的伺服器）。
        Kills the process and any children it spawned (e.g. servers started by a test)."""
        try:
            if sys.platform == "win32":
                subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)], capture_output=True)
            else:
                os.killpg(proc.pid, signal.SIGKILL)
            proc.kill()
        except Exception:
            pass

    def _extract_coverage_percent(self, stdout: str) -> Optional[float]:
        """從 pytest-cov 的輸出表格（陳述式或分支版面）擷取總涵蓋率百分比。
        Extracts total coverage percentage from pytest-cov output table (statement or branch layout)."""
        match = re.search(r"^TOTAL\s+(?:\d+\s+)+(\d+(?:\.\d+)?)%", stdout, re.MULTILINE)
        if match:
            try:
                return float(match.group(1))
            except ValueError:
                pass
        return None


# --- Docker 沙盒 -------------------------------------------------------------------
# --- Docker sandbox -----------------------------------------------------------------

DEFAULT_DOCKER_IMAGE = "vibeharness-sandbox:latest"
CONTAINER_WORK_ROOT = "/work"      # 目標掛載在 /work/<目標名稱> ／ the target is mounted at /work/<target name>
CONTAINER_RUN_DIR = "/sandbox"     # 產生的測試模組、JUnit XML 與涵蓋率資料 ／ generated test modules, JUnit XML and coverage data
# 轉送給 docker CLI 本身（絕不進入容器），讓遠端 daemon／context 能繼續運作
# Forwarded to the docker CLI itself (never into the container) so remote daemons / contexts keep working
_DOCKER_CLI_ENV_VARS = {"DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_CONFIG", "DOCKER_CERT_PATH", "DOCKER_TLS_VERIFY"}


def container_target_dir(host_dir: str) -> str:
    """目標目錄在容器內的掛載位置。
    Where the target directory is mounted inside the container."""
    name = os.path.basename(os.path.normpath(host_dir))
    if name in (".", "..") or not re.fullmatch(r"[A-Za-z0-9_.-]+", name):
        name = "target"
    return f"{CONTAINER_WORK_ROOT}/{name}"


def rewrite_host_paths(text: str, mapping: List[Tuple[str, str]], windows: Optional[bool] = None) -> str:
    """
    把每個已對應主機目錄底下的主機路徑，換成對應的容器路徑。
    產生的測試內嵌有主機的絕對路徑（sys.path 插入、importlib 的檔案位置）；在容器內
    這些路徑必須指向掛載點。在 Windows 上，路徑的原始、repr 跳脫與正斜線三種形式
    都以不分大小寫方式比對，而反斜線分隔符會變成 '/'。
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
    # 最長的優先，讓已對應的目錄在同一位置勝過其已對應的父目錄
    # Longest first so a mapped directory wins over its mapped parent at the same position
    alternatives.sort(key=lambda a: len(a[0]), reverse=True)
    separator = r"(?:\\\\|\\|/)" if windows else "/"
    name_char = r"[^\\/'\"\s]" if windows else r"[^/'\"\s]"
    pattern = re.compile(
        "(?:" + "|".join(f"(?P<g{i}>{re.escape(v)})" for i, (v, _) in enumerate(alternatives)) + ")"
        # 比對必須結束在路徑邊界：C:\proj 不能比對到 C:\proj2
        # The match must end at a path boundary: C:\proj must not match C:\proj2
        + r"(?![A-Za-z0-9_.-])"
        + f"(?P<tail>(?:{separator}{name_char}*)*)",
        re.IGNORECASE if windows else 0
    )

    def replace(match: "re.Match") -> str:
        container = next(c for i, (_, c) in enumerate(alternatives) if match.group(f"g{i}") is not None)
        return container + re.sub(separator, "/", match.group("tail"))

    # Windows 的檔案 URL 在 authority 之後帶著磁碟機代號（file:///C:/proj/x.mjs）；一旦
    # 磁碟機路徑變成 /work/proj，URL 必須正好保留三個斜線（file:///work/proj/x.mjs）
    # A Windows file URL carries the drive after the authority (file:///C:/proj/x.mjs); once the
    # drive path becomes /work/proj the URL must keep exactly three slashes (file:///work/proj/x.mjs)
    return pattern.sub(replace, text).replace("file:////", "file:///")


class DockerSandbox(LocalSubprocessSandbox):
    """
    在用完即丟的 Docker 容器中執行每個 pytest 批次，而這「是」一道隔離邊界：
    （預設）無網路、唯讀的根檔案系統與唯讀的目標掛載、卸除所有 capability、
    禁止提權、非特權使用者、記憶體／CPU／PID 限制，且只有此處明確設定的
    環境變數。只有每次執行專用的暫存目錄可寫入。
    目標掛載在 /work/<name>；產生的程式碼中的主機路徑會被改寫成該位置。
    映像檔必須已經包含 pytest、pytest-cov 與目標的相依套件，因為容器沒有網路
    可以安裝它們（見 docker/sandbox.Dockerfile）。
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
        # 只有目標被掛載，所以只有目標自己的路徑能被改寫成容器路徑。
        # 父目錄是刻意「不」對應的：把同層目錄的路徑改寫成
        # /work/<sibling> 會指向容器內不存在的檔案，而
        # 保留主機路徑則讓失敗（及其原因）一目了然。
        # Only the target is mounted, so only the target's own paths can be rewritten to the
        # container. The parent directory is deliberately NOT mapped: rewriting a sibling path
        # to /work/<sibling> would point at a file that does not exist in the container, while
        # leaving the host path intact makes the failure (and its cause) obvious.
        return [(base_dir, container_target_dir(base_dir))]

    def _prepare_code(self, code: str, base_dir: str) -> str:
        return rewrite_host_paths(code, self._path_mapping(base_dir))

    @staticmethod
    def _bind(source: str, target: str, readonly: bool) -> str:
        # --mount 以 CSV 解析：主機路徑含逗號時該欄位需要加引號
        # --mount is parsed as CSV: a comma in a host path needs the field quoted
        src = f'"source={source}"' if "," in source else f"source={source}"
        return f"type=bind,{src},target={target}" + (",readonly" if readonly else "")

    @staticmethod
    def _user() -> str:
        # POSIX 上使用主機使用者，讓寫入執行目錄的檔案仍可刪除；否則使用 nobody。
        # 以 root 執行的 harness（CI 中很常見）否則會默默跑出 root 容器，與
        # 文件所述的非 root 隔離相牴觸；因此改用 nobody，並把執行目錄權限放寬。
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
        """帶有強化旗標、掛載與環境變數的 `docker run`，到映像檔之前（不含映像檔）為止。
        `docker run` with the hardening flags, mounts and environment, up to (not including) the image."""
        target = container_target_dir(base_dir)
        if hasattr(os, "getuid") and os.getuid() == 0:
            # 容器會以 nobody 身分把 junit.xml／涵蓋率寫進執行目錄（見 _user）；
            # root 擁有的 0755 目錄會讓每次執行都失敗且沒有報告。
            # The container writes junit.xml/coverage into the run dir as nobody (see _user);
            # a root-owned 0755 dir would make every run fail with no report.
            os.chmod(run_dir, 0o777)

        # `timeout` 是容器內的最後防線：如果主機端的清理（docker rm -f）
        # 失敗了，pytest 仍會死掉而不是永遠跑下去。它的 124 結束碼與 TIMEOUT_EXIT_CODE 一致。
        # 它使用這次執行自己的預算：逐一測試的重跑不能拿到整個批次的預算。
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
            # 注意：noexec／nosuid 無法套用在這個可寫入的 bind 上：--mount type=bind
            # 不接受裸的掛載旗標，而 -v 的模式欄位只接受 ro／propagation／selinux。
            # 可寫入區域仍受非 root 使用者、no-new-privileges、資源
            # 限制與唯讀根檔案系統所約束。
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
        return {}  # 容器自帶 --memory／--cpus 與容器內的 `timeout` ／ the container carries --memory/--cpus and the in-container `timeout`

    def _after_timeout(self, cmd: List[str]):
        # 砍掉 docker CLI 不會停止容器；要明確移除它
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


# --- Node（JavaScript／TypeScript）沙盒 ----------------------------------------------
# --- Node (JavaScript / TypeScript) sandboxes --------------------------------------------------

MIN_NODE_VERSION = (20, 0, 0)
MIN_NODE_VERSION_TS = (22, 6, 0)  # --experimental-strip-types 所需 ／ --experimental-strip-types
DEFAULT_DOCKER_NODE_IMAGE = "vibeharness-sandbox-node:latest"
NODE_TEST_FILE_EXT = ".mjs"


def parse_node_version(text: str) -> Optional[Tuple[int, int, int]]:
    """'v22.6.0' -> (22, 6, 0)；其他任何輸入回傳 None。
    'v22.6.0' -> (22, 6, 0); None for anything else."""
    m = re.match(r"\s*v?(\d+)\.(\d+)\.(\d+)", text or "")
    return (int(m.group(1)), int(m.group(2)), int(m.group(3))) if m else None


def detect_node(node_bin: str = "node") -> Tuple[Optional[str], Optional[Tuple[int, int, int]], Optional[str]]:
    """(解析後的路徑, 版本, 問題)：前兩者為 None 時，problem 會說明缺了什麼。
    (resolved path, version, problem): the problem names what is missing when the first two are None."""
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
    """`node --test`，spec 報告器輸出到 stdout，junit 報告器寫入 junit_path。
    `node --test` with the spec reporter on stdout and the junit reporter into junit_path."""
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
    """讓目標的 node_modules 能從執行目錄被解析到（裸露的模組指定符會從匯入檔往上
    逐層尋找）：建立 symlink，在 Windows 上則建立 junction，否則回傳 None（呼叫端會退回
    NODE_PATH，而只有 CommonJS 會遵循它）。
    Makes the target's node_modules resolvable from the run directory (bare specifiers resolve by
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
    """用 Node 內建的執行器執行 `node:test` 模組（ESM，test_vh_NNN.mjs）。驅動方式與逾時處理
    和 Python 沙盒相同；不使用 RLIMIT_AS（V8 啟動時會保留很大的位址空間，受限時會中止），
    改以 --max-old-space-size 限制堆積大小。
    Runs `node:test` modules (ESM, test_vh_NNN.mjs) with Node's built-in runner. Same driver and
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
        return None  # 不蒐集 JS 涵蓋率（v1）；行涵蓋率仍僅限 Python ／ JS coverage is not collected (v1); line coverage stays Python-only


class NodeDockerSandbox(DockerSandbox):
    """容器沙盒的 Node 版本：同樣的強化措施，換成 Node 映像檔（docker/sandbox-node.Dockerfile）。
    The Node flavour of the container sandbox: same hardening, a Node image (docker/sandbox-node.Dockerfile)."""

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
