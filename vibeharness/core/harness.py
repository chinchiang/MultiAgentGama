import datetime as _dt
import json
import logging
import os
import subprocess
import tempfile
import sys
from typing import Any, Dict, Optional, List, Tuple
from rich.console import Console
from rich.markup import escape
from rich.panel import Panel

from vibeharness import __version__
from vibeharness.core.models import (
    CodeSymbol,
    MutationReport,
    RunMetadata,
    VibeHarnessSummary,
    FindingSeverity,
    TestStatus,
    MultiModelDebateResult,
    ThreatModelReport,
    AgentCallRecord,
)
from vibeharness.core.llm_gateway import LLMGateway, DEFAULT_CONFIG_PATH
from vibeharness.core.sandbox import (
    LocalSubprocessSandbox, DockerSandbox, DEFAULT_DOCKER_IMAGE as DEFAULT_DOCKER_IMAGE, MIN_NODE_VERSION_TS,
    NodeDockerSandbox, NodeSubprocessSandbox, detect_node, parse_node_version,
)
from vibeharness.core.baseline import Baseline, annotate_report_payload
from vibeharness.core.gate import (
    ExecutionEvidence, GateEvidence, GateLimits, ReviewEvidence, ScopeDisclosure, evaluate,
)
from vibeharness.core.settings import Overrides, SandboxSettings, Settings, load_settings
from vibeharness.core.verdict import Verdict
from vibeharness.core.mutation import run_mutation_testing
from vibeharness.core.i18n import bi
from vibeharness.agents.whitebox.ast_extractor import ASTExtractor
from vibeharness.agents.whitebox.ai_static_scanner import AISecurityStaticScanner
from vibeharness.agents.whitebox.multi_reviewer import HeterogeneousReviewerEnsemble
from vibeharness.agents.whitebox.debater import MultiModelDebater
from vibeharness.agents.whitebox.deduplicator import deduplicate_findings
from vibeharness.agents.whitebox.test_generator import WhiteboxTestGenerator
from vibeharness.agents.blackbox.threat_modeler import AutomatedThreatModeler
from vibeharness.agents.blackbox.scenario_builder import ThreatScenarioBuilder
from vibeharness.runners.test_executor import TestSuiteExecutor
from vibeharness.reports.report_generator import JSON_SCHEMA_VERSION, ReportGenerator, agreement_display

logger = logging.getLogger("VibeHarness.Commander")

# 預設值定義在 core/settings.py，這裡以同名重新匯出 ／ the defaults are defined in core/settings.py and re-exported here
from vibeharness.core.settings import (  # noqa: E402
    DEFAULT_DOCKER_PIDS_LIMIT as DEFAULT_DOCKER_PIDS_LIMIT,
    DEFAULT_MUTATION_MAX_MUTANTS as DEFAULT_MUTATION_MAX_MUTANTS,
    DEFAULT_MUTATION_MIN_SCORE as DEFAULT_MUTATION_MIN_SCORE,
    DEFAULT_PER_TEST_TIMEOUT_SECONDS as DEFAULT_PER_TEST_TIMEOUT_SECONDS,
    DEFAULT_SANDBOX_MEMORY_MB as DEFAULT_SANDBOX_MEMORY_MB,
    DEFAULT_SANDBOX_PROVIDER as DEFAULT_SANDBOX_PROVIDER,
    DEFAULT_SANDBOX_TIMEOUT_SECONDS as DEFAULT_SANDBOX_TIMEOUT_SECONDS,
)


def sorted_call_log(call_log: List[AgentCallRecord]) -> List[AgentCallRecord]:
    """呼叫紀錄依穩定的鍵排序：代理在執行緒池上並行呼叫，完成順序每次都不同，排序後 JSON 輸出才會逐次一致。
    鍵是（代理、原始提示的 SHA、attempt），所以同一次邏輯呼叫的紀錄維持時間順序：先是各次 "retried"，
    最後才是 "live"／"invalid"／"simulated"；其餘欄位只用來打破完全相同的提示之間的平手。
    The call log in a stable order: agents call in parallel on a thread pool, so the completion order differs
    from run to run; sorting keeps the JSON output identical across runs. The key is (agent, original prompt
    SHA, attempt), so the entries of one logical call stay chronological: its "retried" entries first, then the
    final "live" / "invalid" / "simulated" one; the other fields only break ties between identical prompts."""
    return sorted(call_log, key=lambda r: (
        r.agent_id, r.prompt_sha256 or "", r.attempt, r.model_alias, r.model_name, r.mode, r.reason or "", r.cached
    ))


def force_utf8_stdio() -> None:
    """
    將 stdout/stderr 設為 UTF-8（取代無法呈現的字元），讓 emoji、框線字元與 CJK 輸出
    在 Windows 上被重導向時（例如 cp950 字碼頁）永不當機或變成亂碼。
    具冪等性；在串流已能處理 Unicode 或無法重新設定時則不做任何事。
    Makes stdout/stderr UTF-8 (replacing unrenderable characters) so emoji, box-drawing and
    CJK output never crashes or garbles when redirected on Windows (e.g. a cp950 codepage).
    Idempotent, and a no-op where streams already handle Unicode or cannot be reconfigured.
    """
    if sys.platform != "win32":
        return
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            reconfigure(encoding="utf-8", errors="replace")
        except (OSError, ValueError):
            pass


class VibeHarnessCommander:
    """
    Commander Harness：主要的 AI 協調器，負責指揮、排程並同步
    白箱與黑箱測試階段中的各子代理。
    Commander Harness: Primary AI Orchestrator that directs, schedules,
    and synchronizes sub-agents across White-Box and Black-Box testing phases.
    """

    def __init__(self, config_path: str = DEFAULT_CONFIG_PATH, execution_mode: Optional[str] = None, *,
                 settings: Optional[Settings] = None):
        """`settings` 是 load_settings 驗證過的設定；省略時以 `config_path`（視為指定的設定檔）與 `execution_mode` 載入。
        `settings` are the settings load_settings validated; when omitted they are loaded from `config_path` (as an
        Explicit config) and `execution_mode`."""
        # 即使 harness 作為函式庫使用，也要保護主控台輸出（vibeharness/cli.py 也會這麼做）
        # Protect console output even when the harness is used as a library (vibeharness/cli.py does this too)
        force_utf8_stdio()
        self.console = Console(force_terminal=False)
        if settings is None:
            settings = load_settings(config_path, origin="explicit", overrides=Overrides(execution_mode=execution_mode))
        self.settings = settings
        self.gateway = LLMGateway(settings=settings)
        self.sandbox = self._build_sandbox(settings.sandbox)
        self.ast_extractor = ASTExtractor()
        self.static_scanner = AISecurityStaticScanner()
        self.multi_reviewer = HeterogeneousReviewerEnsemble(self.gateway)
        self.debater = MultiModelDebater(self.gateway)
        self.whitebox_test_gen = WhiteboxTestGenerator(self.gateway)
        self.threat_modeler = AutomatedThreatModeler(self.gateway)
        self.scenario_builder = ThreatScenarioBuilder(self.gateway)
        self.executor = TestSuiteExecutor(
            self.sandbox, per_test_timeout_seconds=settings.sandbox.per_test_timeout,
            js_sandbox_factory=self._build_node_sandbox,
        )
        # JS/TS 測試以 Node 內建的執行器執行；沙盒採延遲建立，在第一次需要時才建立（它的設定在載入時就驗證過）
        # JS/TS tests run with Node's built-in runner; the sandbox is built lazily, the first time one is needed
        # (its settings were validated at load time)
        self.node_bin = settings.node.node_bin
        self.sandbox_node_provider = settings.node.provider
        # 突變測試：開關優先順序為 CLI（set_mutation）> global.mutation_testing > 預設關閉，來源記進 RunMetadata
        # Mutation testing: the switch precedence is CLI (set_mutation) > global.mutation_testing > off by default,
        # and the source is recorded in RunMetadata
        self.mutation_testing: bool = settings.mutation.enabled
        self.mutation_source: str = settings.sources["mutation_testing"]
        self.node_runtime: Optional[str] = None
        self.node_runtime_problem: Optional[str] = None
        self.node_typescript_problem: Optional[str] = None
        self.reporter = ReportGenerator()
        self.max_files = settings.scope.max_files
        self.max_file_bytes = settings.scope.max_file_bytes
        self.config_path = os.path.abspath(settings.path)
        self.sandbox_provider = settings.sandbox.provider
        # 檔案選取（CLI 的 --include/--exclude 會覆寫設定檔中的清單；--changed-since 會加入 only_files）
        # File selection (CLI --include/--exclude override the config lists; --changed-since adds only_files)
        self.include_patterns: List[str] = list(settings.scope.include)
        self.exclude_patterns: List[str] = list(settings.scope.exclude)
        self.changed_since: Optional[str] = settings.scope.changed_since
        # --baseline：先前的 JSON 報告；其中已包含的問題仍會列出，但不計入
        # --baseline: a previous JSON report; problems it already contains are reported but not counted
        self.baseline: Optional[Baseline] = None

    @staticmethod
    def work_dir_for(target_dir: str) -> str:
        """測試執行所在、也是匯入解析所依據的目錄：目標本身，或單一檔案的父目錄。
        The directory tests run from and imports resolve against: the target, or a single file's parent."""
        return target_dir if os.path.isdir(target_dir) else os.path.dirname(os.path.abspath(target_dir))

    def select_symbols(self, target_dir: str) -> Tuple[List[CodeSymbol], List[str]]:
        """第 1 階段的檔案選取與符號擷取（不涉及模型）：要審查的符號，以及
        所套用篩選條件的描述。由執行流程與 --estimate 共用。
        Phase 1 file selection and symbol extraction (no model involved): the symbols to review and a
        description of the filters that applied. Shared by the run and by --estimate."""
        only_files: Optional[List[str]] = None
        filters: List[str] = []
        if self.changed_since:
            only_files = self.changed_files(target_dir, self.changed_since)
            filters.append(f"changed-since={self.changed_since} ({len(only_files)} file(s))")
        if self.include_patterns:
            filters.append("include=" + ",".join(self.include_patterns))
        if self.exclude_patterns:
            filters.append("exclude=" + ",".join(self.exclude_patterns))
        symbols = self.ast_extractor.parse_directory(
            target_dir, max_files=self.max_files, include=self.include_patterns or None,
            exclude=self.exclude_patterns or None, only_files=only_files, max_file_bytes=self.max_file_bytes
        )
        return symbols, filters

    @staticmethod
    def _git(args: List[str], cwd: str) -> Optional[str]:
        """在 cwd 執行 git 指令的 stdout；當 git 或版本庫不可用時為 None。
        stdout of a git command run in cwd, or None when git/the repository is unavailable."""
        try:
            result = subprocess.run(
                ["git", *args], cwd=cwd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30
            )
        except (OSError, subprocess.TimeoutExpired):
            return None
        return result.stdout if result.returncode == 0 else None

    def _target_revision(self, target_dir: str) -> tuple:
        """包含目標的版本庫的 (commit, dirty)；不在版本庫內時為 (None, None)。
        (commit, dirty) of the repository containing the target; (None, None) outside a repository."""
        cwd = self.work_dir_for(target_dir)
        head = self._git(["rev-parse", "HEAD"], cwd)
        if head is None:
            return None, None
        status = self._git(["status", "--porcelain", "--", os.path.abspath(target_dir)], cwd)
        return head.strip(), (bool(status.strip()) if status is not None else None)

    def changed_files(self, target_dir: str, since_ref: str) -> List[str]:
        """目標之下與 `since_ref` 有差異的檔案絕對路徑（已提交、已暫存、
        未暫存與未追蹤），供 --changed-since 使用。ref 無法解析時拋出 ValueError。
        Absolute paths of files under the target that differ from `since_ref` (committed, staged,
        unstaged and untracked), for --changed-since. Raises ValueError when the ref cannot be resolved."""
        cwd = self.work_dir_for(target_dir)
        top = self._git(["rev-parse", "--show-toplevel"], cwd)
        if top is None:
            raise ValueError(bi("--changed-since 需要目標位於 git 版本庫內", "--changed-since needs the target to be inside a git repository")
                             + f": {target_dir}")
        root = top.strip()
        if self._git(["rev-parse", "--verify", "--quiet", f"{since_ref}^{{commit}}"], cwd) is None:
            raise ValueError(bi(f"--changed-since：git ref {since_ref!r} 無法在 {root} 解析",
                                f"--changed-since: git ref {since_ref!r} cannot be resolved in {root}"))
        spec = os.path.realpath(target_dir)
        shown = os.path.abspath(target_dir)
        # 兩個指令都在版本庫根目錄執行，因此其輸出路徑相對於根目錄；-z 讓非 ASCII 檔名原樣輸出，不被 C 風格加引號
        # Both commands run from the repository root so their output paths are root-relative; -z keeps non-ASCII
        # names verbatim instead of C-quoting them
        diff = self._git(["diff", "--name-only", "-z", "--diff-filter=ACMR", since_ref, "--", spec], root) or ""
        untracked = self._git(["ls-files", "-z", "--others", "--exclude-standard", "--", spec], root) or ""
        paths = set()
        for name in (diff + untracked).split("\0"):
            if not name:
                continue
            real = os.path.normpath(os.path.join(root, name))
            # git 回報解析過 symlink 的真實路徑，走訪卻用目標原本的寫法：換回目標的寫法才對得上
            # git reports symlink-resolved real paths but the walk uses the target as given: map back so they match
            rel = os.path.relpath(real, spec)
            paths.add(real if rel.startswith("..") else os.path.normpath(os.path.join(shown, rel)))
        return sorted(p for p in paths if os.path.isfile(p))

    def set_mutation(self, enabled: bool, source: str = "cli") -> None:
        """依 CLI 旗標開啟或關閉突變測試（優先於設定檔）。
        Turns mutation testing on or off from a CLI flag (it wins over the config file)."""
        self.mutation_testing = enabled
        self.mutation_source = source

    def _build_node_sandbox(self) -> Optional[LocalSubprocessSandbox]:
        """供 `node:test` 模組使用的沙盒；沒有可用的 Node 執行環境時為 None（並設定 `node_runtime_problem`）：
        缺少執行環境是 JS/TS 測試的證據缺口，絕不是啟動失敗。docker provider 用映像檔自帶的 Node，
        不需要主機上的 node。
        The sandbox for `node:test` modules, or None (with `node_runtime_problem` set) when no usable
        Node runtime exists: a missing runtime is an evidence gap for the JS/TS tests, never a start-up failure.
        The docker provider uses the image's own Node and needs no node binary on the host."""
        sandbox_cfg, docker_cfg = self.settings.sandbox, self.settings.sandbox.docker
        image = self.settings.node.image
        has_ts = any(f.lower().endswith((".ts", ".tsx", ".mts", ".cts")) for f in self.ast_extractor.analyzed_files)
        sandbox: LocalSubprocessSandbox
        version: Optional[Tuple[int, int, int]]
        if self.sandbox_node_provider == "docker":
            # 先建沙盒（確認映像檔存在），再用與測試相同的 docker run 前綴在容器內讀 Node 版本：
            # 它既是 RunMetadata 的執行環境來源，也決定 TypeScript 的型別剝除；讀不到就不猜
            # Build the sandbox first (the image must exist), then read the Node version inside the container with the
            # same docker run prefix as the tests: it is the runtime provenance in RunMetadata and decides TypeScript
            # type stripping; no guessing when it cannot be read
            docker_sandbox = NodeDockerSandbox(
                timeout_seconds=sandbox_cfg.timeout, image=image, network=docker_cfg.network, memory=docker_cfg.memory,
                cpus=docker_cfg.cpus, pids_limit=docker_cfg.pids_limit, docker_bin=docker_cfg.bin,
            )
            version = self._docker_node_version(docker_sandbox)
            runtime = f"docker {image}" + (f" (node v{'.'.join(map(str, version))})" if version else "")
            supports_ts = version is not None and version >= MIN_NODE_VERSION_TS
            docker_sandbox.supports_typescript = supports_ts
            docker_sandbox.node_version = version  # 決定 JS/TS 涵蓋率旗標；未知時不收集 ／ decides the JS/TS coverage flags; unknown means none
            docker_sandbox.strip_types = has_ts and supports_ts
            sandbox = docker_sandbox
        else:
            path, version, problem = detect_node(self.node_bin)
            if path is None or version is None:
                self.node_runtime_problem = problem
                return None
            runtime = f"node v{'.'.join(map(str, version))}"
            supports_ts = version >= MIN_NODE_VERSION_TS
            sandbox = NodeSubprocessSandbox(
                timeout_seconds=sandbox_cfg.timeout, memory_mb=sandbox_cfg.memory_mb, node_bin=self.node_bin,
                strip_types=has_ts and supports_ts, supports_typescript=supports_ts, node_version=version,
            )
        if has_ts and not supports_ts:
            min_ts = '.'.join(map(str, MIN_NODE_VERSION_TS))
            found = runtime if version is not None else bi(f"無法讀取 {runtime} 內的 Node 版本", f"the Node version inside {runtime} could not be read")
            self.node_typescript_problem = bi(
                f"TypeScript 測試需要 Node >= {min_ts}（型別剝除）；找到的是 {found}",
                f"TypeScript tests need Node >= {min_ts} (type stripping); found {found}"
            )
        # 沙盒建立成功後才記錄執行環境：建構失敗（例如缺映像檔）時 RunMetadata 不能宣稱有 Node
        # The runtime is recorded only once the sandbox exists: after a failed construction (e.g. a missing image)
        # RunMetadata must not claim a Node runtime
        self.node_runtime = runtime
        return sandbox

    @staticmethod
    def _docker_node_version(sandbox: NodeDockerSandbox) -> Optional[Tuple[int, int, int]]:
        """映像檔內的 Node 版本：用與測試相同的 `docker run` 前綴（同樣的使用者、掛載與限制）執行 `node --version`，
        查不到時為 None。映像檔已由沙盒建構時的 `image inspect` 確認存在，不會觸發 pull；容器內有 `timeout` 兜底，
        主機端逾時則移除容器（與測試批次相同）。
        The Node version inside the image: `node --version` run with the same `docker run` prefix as the tests
        (same user, mounts and limits), or None when it cannot be read. The image's presence was confirmed by the
        sandbox's `image inspect`, so no pull is triggered; an in-container `timeout` backstops the command and a
        host-side timeout removes the container (as a test batch does)."""
        try:
            with tempfile.TemporaryDirectory(prefix="vibe_node_probe_") as run_dir, \
                    tempfile.TemporaryDirectory(prefix="vibe_node_target_") as base_dir:
                cmd = sandbox._docker_run_prefix(run_dir, base_dir, {"HOME": "/tmp"}) + [
                    sandbox.image, "timeout", "--kill-after=5", "20", "node", "--version"]
                try:
                    result = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30,
                                            env=sandbox._cli_env())
                except subprocess.TimeoutExpired:
                    sandbox._after_timeout(cmd)
                    return None
        except OSError:
            return None
        return parse_node_version(result.stdout) if result.returncode == 0 else None

    @staticmethod
    def _build_sandbox(sandbox: SandboxSettings) -> LocalSubprocessSandbox:
        """執行 Python 測試的沙盒；provider 與 docker_* 已在載入時驗證，docker 是否可用則在這裡檢查（SandboxUnavailableError）。
        The sandbox for the Python tests; the provider and docker_* were validated at load time, whether docker is
        available is checked here (SandboxUnavailableError)."""
        if sandbox.provider == "docker":
            docker = sandbox.docker
            return DockerSandbox(
                timeout_seconds=sandbox.timeout,
                image=docker.image,
                network=docker.network,
                memory=docker.memory,
                cpus=docker.cpus,
                pids_limit=docker.pids_limit,
                docker_bin=docker.bin,
            )
        return LocalSubprocessSandbox(timeout_seconds=sandbox.timeout, memory_mb=sandbox.memory_mb)

    def run_full_pipeline(
        self,
        target_dir: str,
        system_description: Optional[str] = None,
        base_url: Optional[str] = None,
        output_report_path: str = "vibe_harness_report.md",
        output_format: str = "md",
        output_sarif_path: Optional[str] = None
    ) -> VibeHarnessSummary:
        """
        執行完整的雙引擎測試工作流程：
        第 1 階段：程式碼匯入、AST 擷取與確定性 AI 資安規則
        第 2 階段：異質多模型白箱審查與辯論
        第 3 階段：白箱單元測試產生與沙盒執行
        第 4 階段：強制 STRIDE/OWASP 威脅建模
        第 5 階段：威脅衍生的黑箱動態測試執行
        第 6 階段：品質閘門綜合判定與報告產生
        Executes the complete dual-engine testing workflow:
        Phase 1: Code Ingestion, AST Extraction & deterministic AI-security rules
        Phase 2: Heterogeneous Multi-Model White-Box Review & Debate
        Phase 3: White-Box Unit Test Generation & Sandbox Execution
        Phase 4: Mandatory STRIDE/OWASP Threat Modeling
        Phase 5: Threat-Derived Black-Box Dynamic Test Execution
        Phase 6: Quality Gate Synthesis & Report Generation
        """
        if output_format not in ("md", "json"):
            raise ValueError(bi(f"未知的 output_format '{output_format}'（應為 'md' 或 'json'）",
                                f"Unknown output_format '{output_format}' (expected 'md' or 'json')"))
        reviewer_models = self.multi_reviewer.distinct_models
        ensemble_label = " | ".join(r["model_alias"] for r in self.multi_reviewer.reviewer_agents) or "none configured"
        self.console.print(Panel.fit(
            f"[bold cyan][VibeHarness-MAS] {bi('Commander Harness 已啟動', 'Commander Harness Active')}[/bold cyan]\n"
            f"[yellow]{bi('目標程式庫', 'Target Codebase')}:[/yellow] {escape(os.path.abspath(target_dir))}\n"
            f"[green]{bi('多模型集成', 'Multi-Model Ensemble')}:[/green] {escape(ensemble_label)}\n"
            f"[magenta]{bi('執行模式', 'Execution Mode')}:[/magenta] {self.gateway.execution_mode}",
            title=bi("AI 測試協調引擎", "AI Test Orchestration Engine"),
            border_style="cyan"
        ))

        # 凡是當機時原本會被丟掉的內容（已付費的模型回答、已執行的測試），都會在錯誤往外傳遞之前
        # 寫成部分 JSON 報告，放在要求的輸出檔旁邊
        # Everything a crash would otherwise throw away (paid-for model answers, executed tests) is
        # written as a partial JSON report next to the requested output before the error propagates
        progress: Dict[str, Any] = {"phase": 0}
        try:
            # -------------------------------------------------------------
            # 第 1 階段：AST 擷取
            # Phase 1: AST Extraction
            # -------------------------------------------------------------
            self.console.print(f"\n[bold blue]=== {bi('第 1 階段：AST 擷取與語意抽取', 'Phase 1: AST Ingestion & Semantic Extraction')} ===[/bold blue]")
            # 單一檔案的目標會從其所在目錄執行測試
            # A single-file target runs its tests from the containing directory
            work_dir = self.work_dir_for(target_dir)
            symbols, filters = self.select_symbols(target_dir)
            if filters:
                n_out = self.ast_extractor.filtered_out
                self.console.print(f"[+] {bi('檔案篩選', 'File selection')}: {escape('; '.join(filters))} "
                                   f"({bi(f'{n_out} 個原始碼檔案依要求排除', f'{n_out} source file(s) left out by request')})")
            routes = [s.name for s in symbols if s.symbol_type == "route"]
            # 已排序，使列出的技術堆疊不受集合迭代順序影響而保持確定性
            # Sorted so the reported stack is deterministic regardless of set iteration order
            detected_langs = sorted(self.ast_extractor.detected_languages) or ["Python"]
            lang_str = ", ".join(detected_langs)
            self.console.print(f"[+] {bi('偵測到的目標技術堆疊', 'Detected Target Stack')}: [bold green]{lang_str}[/bold green]")
            self.console.print(f"[+] {bi(f'已從目標檔案擷取 [bold]{len(symbols)}[/bold] 個程式碼符號。', f'Extracted [bold]{len(symbols)}[/bold] code symbols across target files.')}")
            if routes:
                self.console.print(f"[+] {bi(f'偵測到 [bold]{len(routes)}[/bold] 個 API 路由處理器', f'Detected [bold]{len(routes)}[/bold] API route handlers')}: {escape(', '.join(routes[:5]))}")

            # 確定性規則在任何模型看到程式碼之前先執行：它們不會受到提示注入
            # Deterministic rules run before any model sees the code: they cannot be prompt-injected
            static_findings = self.static_scanner.scan_files(self.ast_extractor.analyzed_files)
            # 設定類檔案（.env、YAML、Dockerfile …）只在本機做密鑰掃描，絕不送給模型
            # Configuration-like files (.env, YAML, Dockerfile ...) only get the local secret scan, never a model
            static_findings += self.static_scanner.scan_config_files(self.ast_extractor.config_files)
            progress.update(phase=1, static_findings=static_findings, symbols=len(symbols))
            ai_components = self.static_scanner.ai_components
            if ai_components:
                self.console.print(
                    f"[+] {bi('偵測到的 AI/LLM 元件', 'AI/LLM components detected')}: [bold]{escape(', '.join(ai_components))}[/bold] "
                    f"({bi('已啟用 OWASP LLM Top 10 2026 威脅建模', 'OWASP LLM Top 10 2026 threat modeling enabled')})"
                )
            self.console.print(f"[+] {bi('確定性 AI 資安規則', 'Deterministic AI-security rules')}: [bold]{len(static_findings)}[/bold] {bi('次命中', 'hit(s)')}")
            for sf in static_findings:
                self.console.print(
                    f"   - [{sf.severity.value}] {sf.rule_id} {escape(sf.title)} "
                    f"({escape(os.path.basename(sf.file_path))}:{sf.line_number})"
                )

            # -------------------------------------------------------------
            # 第 2 階段：異質白箱審查與多模型辯論
            # Phase 2: Heterogeneous White-Box Review & Multi-Model Debate
            # -------------------------------------------------------------
            self.console.print(f"\n[bold blue]=== {bi('第 2 階段：異質多模型白箱審查', 'Phase 2: Heterogeneous Multi-Model White-Box Review')} ===[/bold blue]")
            raw_findings = self.multi_reviewer.review_symbols(symbols, root_dir=work_dir)
            self.console.print(f"[+] {bi(f'已從 {escape(ensemble_label)} 收到 [bold]{len(raw_findings)}[/bold] 筆原始審查發現。', f'Received [bold]{len(raw_findings)}[/bold] raw review findings from {escape(ensemble_label)}.')}")
            if len(reviewer_models) < 2:
                # 同一模型的多個副本意見一致只是一致性，而非交叉佐證（OWASP LLM07:2026）
                # Agreement among copies of one model is consistency, not corroboration (OWASP LLM07:2026)
                self.console.print(f"[yellow][!] {bi('不同的審查模型少於兩個：跨模型驗證無法執行。', 'Fewer than two distinct reviewer models: cross-model verification cannot run.')}[/yellow]")
            findings = deduplicate_findings(raw_findings)
            progress.update(phase=2, findings=findings)
            corroborated = sum(1 for f in findings if f.corroborated_by)
            if len(findings) < len(raw_findings):
                self.console.print(f"[+] {bi(f'重複項已合併為 [bold]{len(findings)}[/bold] 筆不同的發現（{corroborated} 筆由多個模型回報）。', f'Merged duplicates into [bold]{len(findings)}[/bold] distinct findings ({corroborated} reported by more than one model).')}")

            self.console.print(f"[yellow]{bi('正在交叉驗證發現：每筆由未回報它的模型裁決……', 'Cross-verifying findings: each is ruled on by the models that did not report it...')}[/yellow]")
            debate_result: MultiModelDebateResult = self.debater.arbitrate(findings, symbols=symbols, root_dir=work_dir)
            progress.update(debate=debate_result)
            if debate_result.arbitration_applied:
                ratio_display = agreement_display(debate_result)
                n_disputed = len(debate_result.disputed_findings)
                self.console.print(f"[+] {bi('跨模型一致度', 'Cross-Model Agreement')}: [bold green]{ratio_display}[/bold green] | {bi(f'{n_disputed} 筆有爭議', f'{n_disputed} disputed')}")
            else:
                self.console.print(f"[yellow][!] {bi('未套用跨模型驗證；發現是未經過濾的審查者假設。', 'Cross-model verification not applied; findings are unfiltered reviewer hypotheses.')}[/yellow]")
            # 沒有套用驗證就沒有任何發現被確認：它們仍是未經過濾的假設，已確認數為 None（JSON 為 null、報告顯示 N/A），
            # 不是 0 —— 0 會被讀成「審查過、沒有缺陷」
            # Without verification nothing was confirmed: the findings stay unfiltered hypotheses, so the
            # confirmed count is None (null in JSON, N/A in the report), not 0, which would read as "reviewed, no flaws"
            confirmed_majority: Optional[int] = (
                len(debate_result.confirmed_findings) - debate_result.undecided_count
                if debate_result.arbitration_applied else None
            )
            if debate_result.arbitration_applied:
                n_tie = debate_result.undecided_count
                tie_note = f" (+{bi(f'{n_tie} 個未決的平手已保留供測試', f'{n_tie} undecided tie(s) kept for testing')})" if n_tie else ""
                self.console.print(f"[+] {bi('已確認的缺陷假設', 'Confirmed Defect Hypotheses')}: [bold red]{confirmed_majority}[/bold red]{tie_note}")
            else:
                n_unverified = len(debate_result.confirmed_findings)
                self.console.print(
                    f"[+] {bi('已確認的缺陷假設', 'Confirmed Defect Hypotheses')}: [bold]N/A[/bold] "
                    f"({bi(f'{n_unverified} 個未經驗證的假設交付測試', f'{n_unverified} unverified hypotheses passed to testing')})"
                )

            # -------------------------------------------------------------
            # 第 3 階段：白箱測試產生與沙盒執行
            # Phase 3: White-Box Test Generation & Sandbox Execution
            # -------------------------------------------------------------
            self.console.print(f"\n[bold blue]=== {bi('第 3 階段：白箱測試產生與沙盒執行', 'Phase 3: White-Box Test Generation & Sandbox Execution')} ===[/bold blue]")
            wb_tests = self.whitebox_test_gen.generate_tests_for_findings(
                debate_result.confirmed_findings, symbols, root_dir=work_dir
            )
            self.console.print(f"[+] {bi(f'已產生 [bold]{len(wb_tests)}[/bold] 個針對性的 Pytest 單元／邊界測試（含自我修復驗證）。', f'Generated [bold]{len(wb_tests)}[/bold] targeted Pytest unit/boundary tests (with self-healing validation).')}")

            wb_results, cov_pct = self.executor.execute_test_suite(
                wb_tests,
                working_dir=work_dir,
                collect_coverage=True
            )
            # JS/TS 的行涵蓋率另外存放（cov_pct 維持只代表 Python）；收集不到時執行器已記錄原因，不算證據缺口（與 Python 一致）
            # JS/TS line coverage is kept separately (cov_pct keeps meaning Python); when it could not be collected the
            # executor has logged why, and it is not an evidence gap (same as Python)
            js_cov_pct = getattr(self.executor, "last_js_line_coverage_pct", None)
            wb_passed = sum(1 for r in wb_results if r.status == TestStatus.PASSED)
            progress.update(phase=3, whitebox_tests=wb_tests, whitebox_results=wb_results)
            wb_failed = sum(1 for r in wb_results if r.status == TestStatus.FAILED)
            wb_errored = sum(1 for r in wb_results if r.status in (TestStatus.ERROR, TestStatus.SKIPPED))
            cov_display = f"{cov_pct:.1f}%" if cov_pct is not None else "N/A"
            js_cov_display = ""
            if any(t.language != "python" for t in wb_tests):
                js_cov_display = (f" | {bi('行涵蓋率（JS/TS）', 'Line Coverage (JS/TS)')}: [bold cyan]"
                                  f"{f'{js_cov_pct:.1f}%' if js_cov_pct is not None else 'N/A'}[/bold cyan]")
            self.console.print(
                f"[+] {bi('白箱執行結果', 'White-Box Execution Outcome')}: [green]{wb_passed} {bi('通過', 'Passed')}[/green] | "
                f"[red]{wb_failed} {bi('失敗／已暴露', 'Failed/Exposed')}[/red] | [yellow]{wb_errored} {bi('錯誤／未執行', 'Error/Not Run')}[/yellow] | "
                f"{bi('行涵蓋率（Python）', 'Line Coverage (Python)')}: [bold cyan]{cov_display}[/bold cyan]{js_cov_display}"
            )

            # -------------------------------------------------------------
            # 第 3.5 階段：突變測試（選用，--mutation）
            # Phase 3.5: Mutation Testing (optional, --mutation)
            # -------------------------------------------------------------
            mutation_report: Optional[MutationReport] = None
            if self.mutation_testing:
                self.console.print(f"\n[bold blue]=== {bi('第 3.5 階段：突變測試', 'Phase 3.5: Mutation Testing')} ===[/bold blue]")
                try:
                    mutation_report = run_mutation_testing(
                        self.executor.run_mutant_batch, wb_tests, wb_results, debate_result.confirmed_findings, symbols,
                        work_dir, self.settings.mutation.max_mutants, self.settings.mutation.timeout,
                        self.settings.mutation.max_copy_mb,
                    )
                except Exception as e:  # 突變測試出錯不能拖垮整個稽核：揭露為證據缺口 ／ a mutation failure must not sink the audit: disclosed as an evidence gap
                    logger.error(bi(f"突變測試失敗：{type(e).__name__}", f"Mutation testing failed: {type(e).__name__}") + f": {self.gateway._safe_reason(str(e))}")
                    mutation_report = MutationReport(enabled=True, skipped_reason=bi(
                        f"突變測試執行失敗（{type(e).__name__}）", f"mutation testing failed ({type(e).__name__})"))
                progress.update(mutation=mutation_report)
                if mutation_report.skipped_reason and mutation_report.score is None:
                    self.console.print(f"[!] {bi('突變測試沒有結論', 'Mutation testing has no conclusion')}: {escape(mutation_report.skipped_reason)}")
                else:
                    score_text = f"{mutation_report.score:.1f}%" if mutation_report.score is not None else "N/A"
                    self.console.print(
                        f"[+] {bi('突變測試結果', 'Mutation Testing Outcome')}: [green]{mutation_report.killed} {bi('殺死', 'Killed')}[/green] | "
                        f"[red]{mutation_report.survived} {bi('存活', 'Survived')}[/red] | [yellow]{mutation_report.invalid} {bi('無效', 'Invalid')}[/yellow] | "
                        f"{bi('分數', 'Score')}: [bold cyan]{score_text}[/bold cyan]"
                    )

            # -------------------------------------------------------------
            # 第 4 階段：強制黑箱威脅建模（STRIDE 與 OWASP）
            # Phase 4: Mandatory Black-Box Threat Modeling (STRIDE & OWASP)
            # -------------------------------------------------------------
            self.console.print(f"\n[bold blue]=== {bi('第 4 階段：強制黑箱威脅建模', 'Phase 4: Mandatory Black-Box Threat Modeling')} ===[/bold blue]")
            sys_desc = system_description or f"Vibe-coded application in {os.path.basename(target_dir)}"
            threat_report: ThreatModelReport = self.threat_modeler.model_system(
                system_description=sys_desc,
                entrypoints=routes or ["HTTP/REST Endpoints"],
                detected_routes=routes,
                symbols=symbols,
                root_dir=work_dir,
                ai_components=ai_components
            )
            n_threats = len(threat_report.threats)
            self.console.print(f"[+] {bi('STRIDE 矩陣已建構', 'STRIDE Matrix Constructed')}: [bold yellow]{n_threats}[/bold yellow] {bi('個攻擊情境已識別。', 'attack scenarios identified.')}")
            progress.update(phase=4, threat_model=threat_report)
            for t in threat_report.threats:
                self.console.print(f"   - [[bold magenta]{t.stride_category.value}[/bold magenta]] ({t.severity.value}) {escape(t.title)}")

            # -------------------------------------------------------------
            # 第 5 階段：威脅衍生的黑箱動態測試執行
            # Phase 5: Threat-Derived Black-Box Dynamic Test Execution
            # -------------------------------------------------------------
            self.console.print(f"\n[bold blue]=== {bi('第 5 階段：威脅衍生的黑箱測試執行', 'Phase 5: Threat-Derived Black-Box Test Execution')} ===[/bold blue]")
            bb_tests = self.scenario_builder.build_test_cases_from_threats(
                threat_report.threats, base_url=base_url, symbols=symbols, root_dir=work_dir
            )
            self.console.print(f"[+] {bi(f'已合成 [bold]{len(bb_tests)}[/bold] 個針對已識別威脅的黑箱攻擊腳本。', f'Synthesized [bold]{len(bb_tests)}[/bold] black-box attack scripts targeting identified threats.')}")

            bb_results, _ = self.executor.execute_test_suite(
                bb_tests,
                working_dir=work_dir,
                collect_coverage=False
            )
            bb_passed = sum(1 for r in bb_results if r.status == TestStatus.PASSED)
            progress.update(phase=5, blackbox_tests=bb_tests, blackbox_results=bb_results)
            bb_breaches = sum(1 for r in bb_results if r.is_security_exploit_confirmed)
            # 不符合嚴格利用判定條件的 FAILED 攻擊測試屬於模糊證據：
            # 它不可悄悄地從閘門中消失（過去曾如此，導致攻擊腳本實際上
            # 正對目標失敗時，整次執行的判定結果仍為 READY_TO_SHIP）
            # A FAILED attack test that does not match the strict exploit predicate is ambiguous
            # evidence: it must not silently disappear from the gate (it used to, letting the run
            # pass as READY_TO_SHIP while an attack script was actually failing against the target)
            bb_failed_unclassified = [
                r for r in bb_results if r.status == TestStatus.FAILED and not r.is_security_exploit_confirmed
            ]
            bb_errored = sum(1 for r in bb_results if r.status in (TestStatus.ERROR, TestStatus.SKIPPED))
            tested_threat_ids = {t.source_ref for t in bb_tests}
            untested_threats = [t.threat_id for t in threat_report.threats if t.threat_id not in tested_threat_ids]
            self.console.print(
                f"[+] {bi('動態黑箱結果', 'Dynamic Black-Box Outcome')}: [green]{bb_passed} {bi('已防禦', 'Defended')}[/green] | "
                f"[red]{bb_breaches} {bi('已確認突破', 'Confirmed Breaches')}[/red] | "
                f"[yellow]{len(bb_failed_unclassified)} {bi('失敗（未分類）', 'Failed (unclassified)')}[/yellow] | "
                f"[yellow]{bb_errored} {bi('錯誤／未執行', 'Error/Not Run')}[/yellow] | {len(untested_threats)} {bi('個威脅未測試', 'Threats Not Tested')}"
            )

            # -------------------------------------------------------------
            # 第 6 階段：品質閘門綜合判定與報告
            # Phase 6: Quality Gate Synthesis & Reporting
            # -------------------------------------------------------------
            self.console.print(f"\n[bold blue]=== {bi('第 6 階段：Commander 品質閘門綜合判定', 'Phase 6: Commander Quality Gate Synthesis')} ===[/bold blue]")
            critical_threats = sum(1 for t in threat_report.threats if t.severity == FindingSeverity.CRITICAL)

            ast = self.ast_extractor
            js_reason = self.executor.js_runner_unavailable_reason
            gate = evaluate(GateEvidence(
                target_dir=target_dir,
                threat_report=threat_report,
                baseline=self.baseline,
                limits=GateLimits(
                    max_model_calls=self.gateway.max_model_calls, max_files=self.max_files,
                    max_file_bytes=self.max_file_bytes, mutation_min_score=self.settings.mutation.min_score,
                ),
                call_log=self.gateway.call_log,
                review=ReviewEvidence(
                    reviewers_configured=bool(self.multi_reviewer.reviewer_agents),
                    reviewer_models=reviewer_models,
                    arbitration_applied=debate_result.arbitration_applied,
                    confirmed_findings=debate_result.confirmed_findings,
                    findings_without_model_tests=self.whitebox_test_gen.findings_without_model_tests,
                ),
                scope=ScopeDisclosure(
                    symbols_found=bool(symbols),
                    detected_langs=detected_langs,
                    parse_failures=ast.parse_failures,
                    oversized_files=ast.oversized_files,
                    skipped_files=ast.skipped_files,
                    unsupported_count=ast.unsupported_count,
                    unsupported_languages=ast.unsupported_languages,
                    unsupported_files=ast.unsupported_files,
                    incomplete_files=self.static_scanner.incomplete_files,
                    config_files_not_fully_scanned=[
                        *ast.skipped_config_files, *ast.oversized_config_files, *self.static_scanner.incomplete_config_files
                    ],
                ),
                static_findings=static_findings,
                execution=ExecutionEvidence(
                    wb_tests=wb_tests, bb_tests=bb_tests, wb_results=wb_results, bb_results=bb_results,
                    js_runner_problem=(self.node_runtime_problem or js_reason) if js_reason else None,
                    ts_problem=self.node_typescript_problem,
                    mutation_report=mutation_report,
                ),
                untested_threats=untested_threats,
            ))
            overall_status, inconclusive_reasons, recommendations = gate.verdict, gate.reasons, gate.recommendations
            wb_failed, bb_breaches, suppressed = gate.whitebox_failed, gate.breaches, gate.suppressed
            if suppressed and self.baseline is not None:
                self.console.print(
                    f"[yellow][!] {bi('基準', 'Baseline')}: "
                    + bi(f"來自 {escape(self.baseline.path)} 的 {len(suppressed)} 個已知問題已列出但不計入",
                         f"{len(suppressed)} known problem(s) from {escape(self.baseline.path)} are reported but not counted")
                    + f" ({escape(', '.join(s.id for s in suppressed))})[/yellow]"
                )
            for reason in inconclusive_reasons:
                self.console.print(f"[yellow][!] {bi('證據缺口', 'Evidence gap')}: {reason}[/yellow]")

            commit, dirty = self._target_revision(target_dir)
            run_meta = RunMetadata(
                generated_at=_dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds"),
                harness_version=__version__,
                execution_mode=self.gateway.execution_mode,
                config_path=self.config_path,
                sandbox_provider=self.sandbox_provider,
                target_path=os.path.abspath(target_dir),
                target_git_commit=commit,
                target_git_dirty=dirty,
                file_filters=filters,
                node_runtime=self.node_runtime,
                mutation_enabled=self.mutation_testing,
                mutation_source=self.mutation_source,
            )
            summary = VibeHarnessSummary(
                overall_status=overall_status,
                run=run_meta,
                total_whitebox_findings=len(raw_findings),
                distinct_whitebox_findings=len(findings),
                confirmed_whitebox_bugs=confirmed_majority,
                whitebox_tests_passed=wb_passed,
                whitebox_tests_failed=wb_failed,
                whitebox_tests_errored=wb_errored,
                total_threats_modeled=len(threat_report.threats),
                critical_threats_count=critical_threats,
                blackbox_tests_passed=bb_passed,
                blackbox_security_breaches=bb_breaches,
                blackbox_tests_failed=len(bb_failed_unclassified),
                blackbox_tests_errored=bb_errored,
                untested_threat_ids=untested_threats,
                agent_calls=sorted_call_log(self.gateway.call_log),
                inconclusive_reasons=inconclusive_reasons,
                line_coverage_pct=cov_pct,
                js_line_coverage_pct=js_cov_pct,
                mutation=mutation_report,
                detected_language=lang_str,
                key_recommendations=recommendations,
                static_findings=static_findings,
                ai_components=ai_components,
                reviewer_models=reviewer_models,
                new_blocking_rule_hits=len(gate.blocking_rule_hits),
                baseline_path=self.baseline.path if self.baseline else None,
                baseline_suppressed=suppressed,
            )

            # 輸出報告
            # Output report
            report_args: Dict[str, Any] = dict(
                summary=summary,
                debate_result=debate_result,
                threat_model=threat_report,
                whitebox_results=wb_results,
                blackbox_results=bb_results,
                target_path=target_dir
            )
            # 測試程式碼是稽核軌跡的一部分（md / json）；SARIF 只承載發現
            # The tests' code is part of the audit trail (md / json); SARIF carries findings only
            test_args: Dict[str, Any] = dict(whitebox_tests=wb_tests, blackbox_tests=bb_tests)
            if output_format == "json":
                payload = json.loads(self.reporter.generate_json_report(**report_args, **test_args))
                annotate_report_payload(
                    payload, target_dir, static_findings, debate_result.confirmed_findings, wb_results, bb_results,
                    threat_report.threats
                )
                md_content = json.dumps(payload, indent=2, ensure_ascii=False, default=str)
            else:
                md_content = self.reporter.generate_markdown_report(**report_args, **test_args)

            with open(output_report_path, "w", encoding="utf-8") as f:
                f.write(md_content)

            self.console.print(f"[+] {bi('最終稽核報告已寫入', 'Final audit report written to')}: [bold green]{output_report_path}[/bold green]")

            if output_sarif_path:
                sarif_content = self.reporter.generate_sarif_report(symbols=symbols, **report_args)
                with open(output_sarif_path, "w", encoding="utf-8") as f:
                    f.write(sarif_content)
                self.console.print(f"[+] {bi('SARIF 報告已寫入', 'SARIF report written to')}: [bold green]{output_sarif_path}[/bold green] ({bi('供 GitHub Code Scanning 使用', 'for GitHub Code Scanning')})")
            verdict_color = {Verdict.READY_TO_SHIP: "green", Verdict.INCONCLUSIVE: "yellow"}.get(overall_status, "red")
            self.console.print(Panel.fit(
                f"[bold]{bi('品質閘門判定結果', 'Quality Gate Verdict')}:[/bold] [{verdict_color} bold]{overall_status}[/{verdict_color} bold]\n"
                f"{bi('白箱通過', 'White-Box Passed')}: {wb_passed} | {bi('黑箱突破', 'Black-Box Breaches')}: {bb_breaches}\n"
                f"{bi('報告', 'Report')}: {output_report_path}",
                title=bi("驗證摘要", "Verification Summary"),
                border_style=verdict_color
            ))

            return summary
        except (Exception, KeyboardInterrupt) as exc:
            self._write_partial_report(output_report_path, target_dir, progress, exc)
            raise

    def _write_partial_report(self, output_report_path: str, target_dir: str, progress: Dict[str, Any], exc: BaseException) -> None:
        """將 `exc` 中止執行前已產出的所有內容寫入 `<output>.partial.json`。
        Writes `<output>.partial.json` with whatever the run produced before `exc` stopped it."""
        path = f"{output_report_path}.partial.json"

        def dump(value: Any) -> Any:
            if isinstance(value, list):
                return [dump(v) for v in value]
            return value.model_dump() if hasattr(value, "model_dump") else value

        payload = {
            "tool": "vibeharness-mas",
            "partial": True,
            "schema_version": JSON_SCHEMA_VERSION,
            "generated_at": _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds"),
            "harness_version": __version__,
            "execution_mode": self.gateway.execution_mode,
            "target_path": os.path.abspath(target_dir),
            "phase_reached": progress.get("phase", 0),
            "error": {"type": type(exc).__name__, "message": self.gateway._safe_reason(str(exc))},
            "agent_calls": [rec.model_dump() for rec in sorted_call_log(self.gateway.call_log)],
            **{key: dump(value) for key, value in progress.items() if key != "phase"},
        }
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2, ensure_ascii=False, default=str)
        except OSError as e:
            logger.warning(bi(f"無法把部分報告寫入 {path}", f"Could not write the partial report to {path}") + f": {e}")
            return
        self.console.print(
            "[yellow][!] "
            + bi(f"執行在第 {payload['phase_reached']} 階段停止（{type(exc).__name__}）；部分結果已寫入 {escape(path)}",
                 f"Run stopped in phase {payload['phase_reached']} ({type(exc).__name__}); partial results written to {escape(path)}")
            + "[/yellow]"
        )
