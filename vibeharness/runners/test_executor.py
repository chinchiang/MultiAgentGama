import ast
import math
import os
import time
import logging
from dataclasses import dataclass
from typing import Any, Callable, List, Tuple, Optional, Dict, Set
from vibeharness.core.models import GeneratedTest, TestExecutionResult, TestStatus
from vibeharness.core.sandbox import (
    REASON_JS_COVERAGE_UNSUPPORTED as REASON_JS_COVERAGE_UNSUPPORTED, NodeRuntime, Sandbox, SandboxUnavailableError,
    TIMEOUT_EXIT_CODE,
)
from vibeharness.core.codecheck import check_test_code_for
from vibeharness.core.jscoverage import JsLineCoverage
from vibeharness.core.i18n import bi
from vibeharness.runners.attribution import _header_field, _is_harness_failure, _result, attribute, parse_junit

logger = logging.getLogger("VibeHarness.TestExecutor")

# 使用者可見的原因字串（中文 ／ English）；測試以 == / startswith 比對的匯出為常數
# User-visible reason strings (Chinese / English); the ones tests compare with == / startswith are exported
REASON_NO_TEST_COLLECTED = bi("產生的程式碼中沒有收集到任何測試", "No test was collected from the generated code")
REASON_REPORT_UNPARSEABLE = bi("沙盒測試報告無法解析；沒有逐一測試的判定結果",
                               "Sandbox test report could not be parsed; no per-test verdict available")
REASON_RERUN_BUDGET_EXHAUSTED = bi("批次逾時後重跑預算已用盡；此模組未重新執行",
                                   "Rerun budget exhausted after the batch timeout; module was not re-run")
REASON_JS_RUNNER_NOT_CONFIGURED = bi("未設定 JavaScript/TypeScript 執行器", "no JavaScript/TypeScript runner is configured")
REASON_NO_NODE_RUNTIME = bi("找不到可用的 Node 執行環境", "no usable Node runtime was found")
REASON_JS_NOT_RUN = bi("JavaScript/TypeScript 測試未執行", "JavaScript/TypeScript test was not run")
REASON_TS_NOT_RUN = bi("TypeScript 測試未執行：Node 執行環境低於 22.6（不支援型別剝除）",
                       "TypeScript test was not run: the Node runtime is older than 22.6 (no type stripping)")
REASON_JS_COVERAGE_NO_REPORT = bi("沒有任何模組產生 lcov 涵蓋率報告（全部逾時，或 Node 沒有寫出報告）",
                                  "no module produced an lcov coverage report (all timed out, or Node wrote none)")
REASON_JS_COVERAGE_NO_TARGET_FILE = bi("lcov 報告中沒有任何載入過的目標原始檔（測試可能沒有匯入目標）",
                                       "the lcov reports contain no loaded target source file (the tests may not "
                                       "have imported the target)")
# JS/TS 模組每 _JS_MODULES_PER_BATCH 個一組，每組各自當作一個批次、拿一份 sandbox_timeout_seconds 預算（見
# _run_js_modules）：Python 的整批只付一次直譯器啟動成本，而每個 JS 模組都要付一次 `node --test` 啟動成本
# JS/TS modules are grouped _JS_MODULES_PER_BATCH at a time, each group being one batch with its own
# sandbox_timeout_seconds budget (see _run_js_modules): a Python batch pays the interpreter start-up once, every JS
# module pays a `node --test` start-up of its own
_JS_MODULES_PER_BATCH = 10

def _remaining_seconds(deadline: float, budget: float) -> int:
    """到 deadline 為止剩下的整數秒，不超過 budget。先扣一點容差再進位：monotonic() 的值很大時，
    (t0 + 30.0) - t0 可能因浮點誤差變成 30.000000000004，直接進位會多出一秒（Windows 上曾出現 31 秒）。
    Whole seconds left until deadline, never more than budget. A small tolerance is taken off before rounding up:
    with large monotonic() values, (t0 + 30.0) - t0 can come out as 30.000000000004 through float error, and a plain
    ceil would add a second (31s was seen on Windows)."""
    return min(int(math.ceil(budget)), math.ceil(deadline - time.monotonic() - 1e-6))



@dataclass(frozen=True)
class SuiteResult:
    """一次 execute_test_suite 的結果。`results` 依輸入順序；`python_coverage_pct` 與 `js_coverage_pct` 只有
    collect_coverage 時才有值（各自只代表自己的語言），`js_coverage_problem` 是收集了卻算不出 JS/TS 涵蓋率的原因；
    `js_runner_problem` 只在這組測試含 JS/TS、卻沒有可用的 JS 執行器時才有值；`node_runtime` 是這組測試含 JS/TS 時
    解析出的 Node 執行環境（工廠拋出例外或沒有設定工廠時為 None）。
    The outcome of one execute_test_suite call. `results` is in input order; `python_coverage_pct` and
    `js_coverage_pct` are only set with collect_coverage (each covers its own language only), and
    `js_coverage_problem` says why JS/TS coverage was collected but could not be computed; `js_runner_problem` is only
    set when the suite holds JS/TS tests and no JS runner is available; `node_runtime` is the Node runtime resolved when
    the suite holds JS/TS tests (None when the factory raised or none is configured)."""
    results: List[TestExecutionResult]
    python_coverage_pct: Optional[float] = None
    js_coverage_pct: Optional[float] = None
    js_coverage_problem: Optional[str] = None
    js_runner_problem: Optional[str] = None
    node_runtime: Optional[NodeRuntime] = None


class TestSuiteExecutor:
    __test__ = False
    """
    在沙盒內執行產生的測試函式，每個測試一個模組，讓壞掉的
    測試無法毒害其他測試，並從 pytest 的 JUnit XML 報告對應出逐一測試的結果。
    只有黑箱測試中真正的斷言失敗才算已確認的資安利用。
    Runs generated test functions inside the sandbox, one module per test so that a broken
    test cannot poison the others, and maps per-test outcomes from pytest's JUnit XML report.
    Only genuine assertion failures in black-box tests count as confirmed security exploits.
    """

    def __init__(
        self,
        sandbox: Sandbox,
        per_test_timeout_seconds: int = 30,
        js_sandbox_factory: Optional[Callable[[], NodeRuntime]] = None,
    ):
        self.sandbox = sandbox
        self.per_test_timeout_seconds = per_test_timeout_seconds
        # 第一次使用時才建立（只有存在 JS/TS 測試時才需要 Node）；None 代表「無法執行 JS」
        # Built on first use (Node is only needed when a JS/TS test exists); None means "cannot run JS"
        self._js_sandbox_factory = js_sandbox_factory
        self._js_sandbox: Optional[Sandbox] = None
        self._node_runtime: Optional[NodeRuntime] = None
        self._js_sandbox_resolved = False
        # 沒有 JS 沙盒的原因，與沙盒一起只解析一次 ／ Why there is no JS sandbox, resolved once along with it
        self._js_runner_problem: Optional[str] = None

    def _js_sandbox_or_none(self) -> Optional[Sandbox]:
        if not self._js_sandbox_resolved:
            self._js_sandbox_resolved = True
            if self._js_sandbox_factory is None:
                self._js_runner_problem = REASON_JS_RUNNER_NOT_CONFIGURED
            else:
                try:
                    self._node_runtime = self._js_sandbox_factory()
                    self._js_sandbox = self._node_runtime.sandbox
                except (SandboxUnavailableError, OSError) as e:
                    # 缺少 docker 映像檔、壞掉的 node 執行檔：會揭露，但不致命；設定錯誤已在啟動時驗證，其餘例外照常拋出
                    # a missing docker image, a broken node binary: disclosed, not fatal; configuration errors are
                    # validated at start-up, any other exception propagates
                    self._js_runner_problem = f"{type(e).__name__}: {e}"
                if self._js_sandbox is None and not self._js_runner_problem:
                    # 執行環境說得出缺什麼時（哪個 node_bin、版本太舊）每個測試都用它，與閘門的證據缺口相同
                    # When the runtime can say what is missing (which node_bin, a version too old) every test uses it,
                    # the same as the gate's evidence gap
                    self._js_runner_problem = (self._node_runtime and self._node_runtime.problem) or REASON_NO_NODE_RUNTIME
        return self._js_sandbox

    def execute_test_suite(
        self,
        tests: List[GeneratedTest],
        working_dir: str = ".",
        collect_coverage: bool = False
    ) -> SuiteResult:
        """執行一組測試；Python 與 JS/TS 的行涵蓋率分開回報（見 SuiteResult）。
        Runs a set of tests; Python and JS/TS line coverage are reported separately (see SuiteResult)."""
        if not tests:
            return SuiteResult(results=[])
        unique_ids = self._unique_test_ids(tests)
        results: Dict[int, TestExecutionResult] = {}
        py_idx = [i for i, t in enumerate(tests) if t.language == "python"]
        js_idx = [i for i, t in enumerate(tests) if t.language != "python"]

        coverage_pct, _ = self._run_group(tests, py_idx, unique_ids, results, working_dir, collect_coverage,
                                          "python", self.sandbox) if py_idx else (None, None)
        js_coverage_pct: Optional[float] = None
        js_coverage_problem: Optional[str] = None
        if js_idx:
            sandbox = self._js_sandbox_or_none()
            runnable = []
            for i in js_idx:
                t = tests[i]
                if sandbox is None:
                    results[i] = _result(
                        t, unique_ids[i], TestStatus.ERROR,
                        failure_reason=f"{REASON_JS_NOT_RUN}: {self._js_runner_problem}"
                    )
                elif t.language == "typescript" and not sandbox.supports_typescript:
                    results[i] = _result(
                        t, unique_ids[i], TestStatus.ERROR,
                        failure_reason=REASON_TS_NOT_RUN
                    )
                else:
                    runnable.append(i)
            if runnable and sandbox is not None:
                js_coverage, js_coverage_problem = self._run_group(
                    tests, runnable, unique_ids, results, working_dir, collect_coverage, "javascript", sandbox)
                js_coverage_pct = js_coverage if collect_coverage else None
        return SuiteResult(
            results=[results[i] for i in range(len(tests))], python_coverage_pct=coverage_pct,
            js_coverage_pct=js_coverage_pct, js_coverage_problem=js_coverage_problem,
            js_runner_problem=self._js_runner_problem if js_idx else None,
            node_runtime=self._node_runtime if js_idx else None,
        )

    def run_mutant_batch(self, tests: List[GeneratedTest], working_dir: str, timeout_seconds: int) -> str:
        """突變測試用：把已通過的 Python 測試當作**一個**沙盒批次對 working_dir 執行，不走逾時後逐測重跑的路徑
        （無窮迴圈的變異體會讓重跑拖很久）。回傳 "killed"（有測試失敗、或批次逾時）、"survived"（全部通過）、
        "invalid"（沙盒沒有報告、報告解析不了，或變異體讓匯入／載入壞掉，無法判斷）。
        For mutation testing: runs the PASSED Python tests as ONE sandbox batch against working_dir, without the
        per-test rerun after a timeout (a mutant with an endless loop would make that rerun very slow). Returns
        "killed" (a test failed, or the batch timed out), "survived" (all passed) or "invalid" (no report, an
        unparsable report, or the mutant broke import/load so nothing can be concluded)."""
        header = self._python_header(working_dir)
        files: Dict[str, str] = {}
        for idx, t in enumerate(tests):
            preamble, body = self._split_future_imports(t.code)
            files[f"test_vh_{idx:03d}.py"] = (
                f"{preamble}{header}\n# Target: {_header_field(t.target_component)} | "
                f"Test: {_header_field(t.title)}\n{body}\n"
            )
        run = self.sandbox.execute_pytest_files(
            files, working_dir=working_dir, collect_coverage=False, timeout_seconds=timeout_seconds
        )
        if run.exit_code == TIMEOUT_EXIT_CODE:
            return "killed"
        cases = parse_junit(run.junit_xml, "python")
        if not cases:
            return "invalid"
        flat = [case for module_cases in cases.values() for case in module_cases]
        if any(c["outcome"] == "failure" and not _is_harness_failure(c) for c in flat):
            return "killed"
        if any(c["outcome"] in ("error", "failure") for c in flat) or not flat:
            return "invalid"
        return "survived"

    @staticmethod
    def _python_header(working_dir: str) -> str:
        abs_target = os.path.abspath(working_dir)
        parent_dir = os.path.dirname(abs_target)
        return "\n".join([
            "import pytest",
            "import sys",
            "import os",
            "from typing import Any, Dict",
            # 父目錄先插入，讓目標本身最後落在最高
            # 優先順序（最後插入的佔據位置 0），與沙盒的 PYTHONPATH 順序一致。
            # 否則父目錄中同名的模組（例如 proj\utils.py 對上
            # proj\app\utils.py）會遮蔽受測的目標模組。
            # The parent dir goes in first so the target itself ends up with the highest
            # priority (last insert wins position 0), matching the sandbox PYTHONPATH order.
            # Otherwise a same-named module in the parent directory (e.g. proj\utils.py vs
            # proj\app\utils.py) would shadow the target module under test.
            f"sys.path.insert(0, {parent_dir!r})",
            f"sys.path.insert(0, {abs_target!r})",
            "# --- VibeHarness Auto-Generated Test ---",
        ])

    @staticmethod
    def _js_header(working_dir: str) -> str:
        # 只放註解：在這裡 `import` 會與模組自己的 `import { test }` 衝突
        # Comments only: an `import` here would collide with the module's own `import { test }`
        abs_target = os.path.abspath(working_dir)
        return "\n".join([
            "// --- VibeHarness Auto-Generated Test (node:test, ESM) ---",
            f"// Target directory: {abs_target}",
            "// The target is imported through the file:// URL given in the prompt; bare specifiers resolve",
            f"// from {os.path.join(abs_target, 'node_modules')} (linked into this run directory); nothing may be installed.",
        ])

    def _run_group(
        self,
        tests: List[GeneratedTest],
        indices: List[int],
        unique_ids: List[str],
        results: Dict[int, TestExecutionResult],
        working_dir: str,
        collect_coverage: bool,
        language: str,
        sandbox: Sandbox,
    ) -> Tuple[Optional[float], Optional[str]]:
        """把某一語言的測試當作一個沙盒批次執行（模組名稱使用全域索引，所以 id
        在各群組間保持唯一），並為這些索引填入 `results`。回傳 (行涵蓋率, 收集了卻算不出 JS/TS 涵蓋率的原因)。
        Runs one language's tests as one sandbox batch (module names use the global index, so ids
        stay unique across groups) and fills `results` for those indices. Returns (line coverage, why JS/TS coverage
        was collected but could not be computed)."""
        is_js = language != "python"
        header = self._js_header(working_dir) if is_js else self._python_header(working_dir)
        ext = ".mjs" if is_js else ".py"
        comment = "//" if is_js else "#"
        files: Dict[str, str] = {}
        module_to_idx: Dict[str, int] = {}

        for idx in indices:
            t = tests[idx]
            is_valid, problem = check_test_code_for(t.code, t.language)
            if not is_valid:
                results[idx] = _result(
                    t, unique_ids[idx], TestStatus.ERROR,
                    failure_reason=bi(f"產生的測試無法執行（{problem}）；未執行", f"Generated test is not executable ({problem}); not run")
                )
                continue
            module = f"test_vh_{idx:03d}"
            module_to_idx[module] = idx
            preamble, body = ("", t.code) if is_js else self._split_future_imports(t.code)
            files[f"{module}{ext}"] = (
                f"{preamble}{header}\n{comment} Target: {_header_field(t.target_component)} | "
                f"Test: {_header_field(t.title)}\n{body}\n"
            )

        coverage_pct: Optional[float] = None
        coverage_problem: Optional[str] = None
        if not files:
            return None, None
        logger.info(bi(f"在沙盒中執行 {len(files)} 個 {language} 測試模組（coverage={collect_coverage}）...",
                       f"Executing {len(files)} {language} test module(s) in sandbox (coverage={collect_coverage})..."))
        # 每個模組：(結束碼, stdout, stderr, junit xml)；Python 批次共用一次執行，JS 模組
        # 則各自有自己的行程（Node 的 junit 報告器不會記錄最上層測試來自哪個檔案）
        # Per module: (exit code, stdout, stderr, junit xml); a Python batch shares one run, a JS module
        # gets its own process (Node's junit reporter does not name the file a top-level test came from)
        runs: Dict[str, Tuple[int, str, str, Optional[str]]] = {}
        cases: Optional[Dict[str, List[dict]]] = {}
        timed_out: Set[str] = set()
        not_rerun: Set[str] = set()
        parse_failed: Set[str] = set()
        batch_timeout: Optional[int] = None
        # 實際使用的逾時（秒），供逾時原因字串使用：絕不能回報一個沒有真正生效的預算
        # The timeout actually used (seconds), for the timeout reason: never report a budget that did not apply
        timeout_used: Dict[str, int] = {}
        if is_js:
            js_coverage, coverage_problem = self._js_coverage_or_none(sandbox) if collect_coverage else (None, None)
            cases, timed_out, not_rerun, parse_failed = self._run_js_modules(
                files, working_dir, sandbox, language, runs, timeout_used, coverage=js_coverage
            )
            if js_coverage is not None:
                coverage_pct = js_coverage.percent()
                if coverage_pct is None:
                    coverage_problem = (REASON_JS_COVERAGE_NO_TARGET_FILE if js_coverage.reports
                                        else REASON_JS_COVERAGE_NO_REPORT)
                    logger.warning(bi(f"JS/TS 行涵蓋率無法計算：{coverage_problem}",
                                      f"JS/TS line coverage could not be computed: {coverage_problem}"))
                else:
                    logger.info(bi(f"JS/TS 行涵蓋率 {coverage_pct:.1f}%（{len(js_coverage.files)} 個載入過的目標檔案，"
                                   f"{js_coverage.covered_lines}／{js_coverage.instrumented_lines} 行）",
                                   f"JS/TS line coverage {coverage_pct:.1f}% ({len(js_coverage.files)} loaded target "
                                   f"file(s), {js_coverage.covered_lines}/{js_coverage.instrumented_lines} lines)"))
        else:
            run = sandbox.execute_pytest_files(
                files,
                working_dir=working_dir,
                collect_coverage=collect_coverage,
                coverage_target=working_dir
            )
            exit_code, stdout, stderr, coverage_pct, junit_xml = (
                run.exit_code, run.stdout, run.stderr, run.coverage_pct, run.junit_xml)
            cases = parse_junit(junit_xml, language)
            if exit_code == TIMEOUT_EXIT_CODE and len(files) > 1:
                # 一個卡住的測試不能讓整個批次作廢：用各自的預算重跑每個模組
                # One hanging test must not void the whole batch: rerun each module on its own budget
                logger.warning(bi("批次執行逾時；逐一重新執行每個測試模組以找出卡住的測試。",
                                  "Batch run timed out; re-running each test module individually to isolate the hang."))
                coverage_pct = None
                cases, timed_out, not_rerun, parse_failed = self._run_individually(
                    files, working_dir, sandbox, language, timeout_used, runs
                )
                junit_xml = ""  # 逐模組的結果現在在 `cases`／`timed_out` 裡 ／ per-module outcomes are now in `cases` / `timed_out`
            elif exit_code == TIMEOUT_EXIT_CODE:
                batch_timeout = sandbox.timeout_seconds
            # 重跑過的模組保留自己那次的結果（含沒有報告的情況）；其餘沿用批次的結果
            # A rerun module keeps its own outcome (including no report); the others take the batch's
            for module in module_to_idx:
                runs.setdefault(module, (exit_code, stdout, stderr, junit_xml))

        for module, idx in module_to_idx.items():
            t = tests[idx]
            exit_code, stdout, stderr, junit_xml = runs[module]
            module_cases = cases.get(module) if cases is not None else None
            if module in not_rerun:
                results[idx] = _result(
                    t, unique_ids[idx], TestStatus.ERROR,
                    failure_reason=REASON_RERUN_BUDGET_EXHAUSTED
                )
            elif module in parse_failed:
                results[idx] = _result(
                    t, unique_ids[idx], TestStatus.ERROR,
                    failure_reason=REASON_REPORT_UNPARSEABLE,
                    stderr=stderr
                )
            elif module in timed_out and (is_js or not module_cases):
                used = timeout_used.get(module, self._per_test_budget(sandbox))
                results[idx] = _result(
                    t, unique_ids[idx], TestStatus.ERROR,
                    failure_reason=bi(f"測試在 {used} 秒後逾時；未執行完畢",
                                      f"Test timed out after {used}s; not run to completion")
                )
            elif junit_xml is None:
                if exit_code == TIMEOUT_EXIT_CODE:
                    results[idx] = _result(
                        t, unique_ids[idx], TestStatus.ERROR,
                        failure_reason=bi(f"測試批次在 {batch_timeout or '?'} 秒後逾時，且沒有產生逐一測試的報告",
                                          f"Test batch timed out after {batch_timeout or '?'}s "
                                          "and no per-test report was produced")
                    )
                else:
                    results[idx] = _result(
                        t, unique_ids[idx], TestStatus.ERROR,
                        failure_reason=f"{bi('沙盒執行沒有產生報告', 'Sandbox run produced no report')}: "
                                       f"{stderr.strip()[:200] or f'exit code {exit_code}'}",
                        stdout=stdout, stderr=stderr
                    )
            elif cases is None:
                results[idx] = _result(
                    t, unique_ids[idx], TestStatus.ERROR,
                    failure_reason=REASON_REPORT_UNPARSEABLE,
                    stdout=stdout, stderr=stderr
                )
            elif not module_cases:
                results[idx] = _result(
                    t, unique_ids[idx], TestStatus.ERROR,
                    failure_reason=REASON_NO_TEST_COLLECTED,
                    stdout=stdout, stderr=stderr
                )
            else:
                results[idx] = attribute(t, unique_ids[idx], module_cases)
        return coverage_pct, coverage_problem

    def _run_individually(
        self, files: Dict[str, str], working_dir: str, sandbox: Optional[Sandbox] = None,
        language: str = "python", timeout_used: Optional[Dict[str, int]] = None,
        runs: Optional[Dict[str, Tuple[int, str, str, Optional[str]]]] = None
    ) -> Tuple[Dict[str, List[dict]], Set[str], Set[str], Set[str]]:
        """在各自的行程中執行每個模組。每次重跑的逾時是 min(單測預算, 剩下的重跑預算)，所以重跑的總時間
        不會超出沙盒的批次預算（只差無條件進位的不到 1 秒），而不是在最後一個模組多出整整一份單測預算。
        實際使用的逾時填入 `timeout_used`（若有給）；每次重跑的 (結束代碼, stdout, stderr, junit xml) 填入 `runs`（若有給），
        讓沒有產生報告的重跑回報成沙盒問題，而不是「沒有收集到測試」。
        Runs each module in its own process. Each rerun's timeout is min(per-test budget, rerun budget left), so the
        reruns never exceed the sandbox's batch budget in total (up to sub-second rounding up), instead of
        overshooting by a whole per-test budget on the last module. The timeout actually used goes into
        `timeout_used` (when given); each rerun's (exit code, stdout, stderr, junit xml) goes into `runs` (when given), so
        a rerun that produced no report is reported as a sandbox problem rather than "no test collected".

        回傳 (依模組分組的 junit 案例, 逾時的模組, 因重跑預算（沙盒自己的批次預算）
        用盡而跳過的模組, JUnit 報告無法解析的模組)。
        Returns (junit cases by module, modules that timed out, modules skipped because the
        rerun budget (the sandbox's own batch budget) was exhausted, modules whose JUnit
        report could not be parsed).
        """
        cases: Dict[str, List[dict]] = {}
        timed_out: Set[str] = set()
        not_rerun: Set[str] = set()
        parse_failed: Set[str] = set()
        sandbox = sandbox or self.sandbox
        per_test = self._per_test_budget(sandbox)
        budget = float(sandbox.timeout_seconds or 0)
        deadline = time.monotonic() + budget
        for filename, code in files.items():
            module = os.path.splitext(filename)[0]
            remaining = _remaining_seconds(deadline, budget)
            if remaining < 1:
                not_rerun.add(module)
                continue
            timeout = min(per_test, remaining)
            if timeout_used is not None:
                timeout_used[module] = timeout
            run = sandbox.execute_pytest_files(
                {filename: code}, working_dir=working_dir, timeout_seconds=timeout
            )
            if runs is not None:
                runs[module] = (run.exit_code, run.stdout, run.stderr, run.junit_xml)
            if run.exit_code == TIMEOUT_EXIT_CODE:
                timed_out.add(module)
                continue
            module_cases = parse_junit(run.junit_xml, language)
            if module_cases is None:
                parse_failed.add(module)
                continue
            cases.update(module_cases)
        return cases, timed_out, not_rerun, parse_failed

    def _js_coverage_or_none(self, sandbox: Sandbox) -> Tuple[Optional[JsLineCoverage], Optional[str]]:
        """(這次 JS/TS 執行要用的涵蓋率累加器, None)；沙盒不支援（不收集涵蓋率的沙盒、舊版 Node）時為 (None, 原因)。
        (The coverage accumulator for this JS/TS run, None); (None, the reason) when the sandbox cannot collect it
        (a sandbox that collects none, an old Node)."""
        problem = sandbox.js_coverage_problem()
        if problem:
            logger.warning(bi(f"不收集 JS/TS 行涵蓋率：{problem}", f"JS/TS line coverage is not collected: {problem}"))
            return None, problem
        return JsLineCoverage(), None

    def _per_test_budget(self, sandbox: Sandbox) -> int:
        """逐測重跑實際使用的逾時（秒）。非正數的 per_test_timeout_seconds（設定驗證交給 harness）會讓沙盒
        退回自己的批次預算，所以這裡也回報那個值，而不是「0 秒後逾時」。
        The timeout (seconds) a per-test rerun actually gets. A non-positive per_test_timeout_seconds (config
        validation is the harness's job) makes the sandbox fall back to its batch budget, so that is reported here
        too instead of "timed out after 0s"."""
        per_test = self.per_test_timeout_seconds
        if isinstance(per_test, int) and per_test > 0:
            return per_test
        return int(sandbox.timeout_seconds or 0) or 30

    def _run_js_modules(
        self, files: Dict[str, str], working_dir: str, sandbox: Sandbox, language: str,
        runs: Dict[str, Tuple[int, str, str, Optional[str]]], timeout_used: Dict[str, int],
        coverage: Optional[JsLineCoverage] = None
    ) -> Tuple[Dict[str, List[dict]], Set[str], Set[str], Set[str]]:
        """每個 JS/TS 模組各自一個 `node --test` 行程（Node 的 junit 報告器不會記錄最上層測試來自哪個檔案），
        但逾時語意與 Python 批次一致（docs/configuration.md：sandbox_timeout_seconds 是一批的總預算，
        per_test_timeout_seconds 只用於批次逾時後的逐測重跑）。
        批次大小規則：模組依序每 _JS_MODULES_PER_BATCH 個分成一批，每批各自拿一份 sandbox_timeout_seconds。
        Python 的一批只付一次直譯器啟動成本，JS 卻每個模組都要付一次 Node 啟動成本；所有模組共用一份預算時，
        許多「慢但會通過」的模組光是啟動成本就會把預算吃光，最後被標成未重跑（INCONCLUSIVE）。分批讓預算
        隨模組數成長，同時每個模組第一輪拿到的逾時仍不超過一份批次預算（卡住的模組吃不到別批的預算）。
        最壞情況總時間 = ceil(模組數 / _JS_MODULES_PER_BATCH) × 2 × sandbox_timeout_seconds（第一輪＋重跑）。
        每一批之內：第一輪依序執行各模組，每個模組拿到這一批「剩下的」預算；某個模組逾時就代表這一批逾時，
        尚未執行（或逾時時拿到的預算比單測預算還少）的模組進入第二輪，各用 min(單測預算, 剩下的重跑預算) 重跑，
        所以第二輪總時間不會超出這一批的預算（只差無條件進位的不到 1 秒），超出的模組標為未重跑。
        填入 `runs` 與 `timeout_used`；回傳 (依模組分組的 junit 案例, 逾時的模組, 未重跑的模組, 報告無法解析的模組)。
        Each JS/TS module gets its own `node --test` process (Node's junit reporter does not name the file a
        top-level test came from), but the timeout semantics match a Python batch (docs/configuration.md:
        sandbox_timeout_seconds is the whole batch's budget, per_test_timeout_seconds only applies to per-test
        reruns after a batch timeout).
        Batch sizing rule: the modules are split, in order, into batches of _JS_MODULES_PER_BATCH, each with its
        own sandbox_timeout_seconds. A Python batch pays the interpreter start-up once, but every JS module pays a
        Node start-up; with one budget shared by all modules, the start-up cost alone of many slow-but-passing
        modules used it up and left them marked not re-run (INCONCLUSIVE). Batching makes the budget grow with the
        module count while a module's first-pass timeout still never exceeds one batch budget (a hanging module
        cannot eat another batch's budget). Worst-case total = ceil(modules / _JS_MODULES_PER_BATCH) x 2 x
        sandbox_timeout_seconds (first pass + reruns).
        Within one batch: the first pass runs the modules in order, each on whatever is LEFT of the batch budget;
        a module timing out means the batch timed out, and the modules not yet run (or that timed out on less than
        the per-test budget) go to a second pass, each re-run on min(per-test budget, rerun budget left), so the
        second pass never exceeds the batch budget (up to sub-second rounding up); modules beyond it are marked
        not re-run.
        Fills `runs` and `timeout_used`; returns (junit cases by module, timed-out modules, modules not re-run,
        modules whose report could not be parsed).
        給了 `coverage` 時，每個執行完（未逾時）的模組都帶著涵蓋率執行，其 lcov 結果以聯集併入 `coverage`；
        逾時後重跑成功的模組也算。
        With `coverage`, every module runs with coverage on and the lcov result of each one that finished (did not time
        out) is merged into `coverage` as a union; a module that succeeded on its rerun after a timeout counts too."""
        cases: Dict[str, List[dict]] = {}
        timed_out: Set[str] = set()
        not_rerun: Set[str] = set()
        parse_failed: Set[str] = set()
        per_test = self._per_test_budget(sandbox)
        batch_budget = float(sandbox.timeout_seconds or 0) or float(per_test)

        def run_one(filename: str, code: str, timeout: int) -> bool:
            # 執行一個模組並記錄結果；逾時時回傳 False ／ Runs one module and records it; False on a timeout
            module = os.path.splitext(filename)[0]
            # 只有要收集涵蓋率時才傳涵蓋率參數：沙盒替身不必認得它們
            # The coverage arguments are only passed when coverage is collected: sandbox stand-ins need not know them
            coverage_kwargs: Dict[str, Any] = {} if coverage is None else {
                "collect_coverage": True, "coverage_target": working_dir, "coverage_sink": coverage}
            run = sandbox.execute_pytest_files(
                {filename: code}, working_dir=working_dir, timeout_seconds=timeout, **coverage_kwargs
            )
            stdout = run.stdout
            runs[module] = (run.exit_code, stdout, run.stderr, run.junit_xml)
            timeout_used[module] = timeout
            if run.exit_code == TIMEOUT_EXIT_CODE:
                return False
            timed_out.discard(module)
            parsed = parse_junit(run.junit_xml, language, module=module, runner_stdout=stdout)
            if parsed is None:
                parse_failed.add(module)
                return True
            cases.update(parsed)
            return True

        items = list(files.items())
        for first in range(0, len(items), _JS_MODULES_PER_BATCH):
            pending: List[Tuple[str, str]] = []
            deadline = time.monotonic() + batch_budget
            for filename, code in items[first:first + _JS_MODULES_PER_BATCH]:
                remaining = _remaining_seconds(deadline, batch_budget)
                if remaining < 1:
                    pending.append((filename, code))
                elif not run_one(filename, code, remaining):
                    timed_out.add(os.path.splitext(filename)[0])
                    if remaining < per_test:
                        # 逾時時拿到的預算比單測預算少：要重跑才公平
                        # Timed out on less than the per-test budget: only a rerun is fair
                        pending.append((filename, code))
            if not pending:
                continue
            logger.warning(bi("JS/TS 批次預算已用盡；以單測預算逐一重跑這一批剩下的模組。",
                              "JS/TS batch budget exhausted; re-running the batch's remaining modules on the "
                              "per-test budget."))
            deadline = time.monotonic() + batch_budget
            for filename, code in pending:
                module = os.path.splitext(filename)[0]
                remaining = _remaining_seconds(deadline, batch_budget)
                if remaining < 1:
                    not_rerun.add(module)
                    timed_out.discard(module)
                    runs.setdefault(module, (TIMEOUT_EXIT_CODE, "", "", None))
                elif not run_one(filename, code, min(per_test, remaining)):
                    timed_out.add(module)
        return cases, timed_out, not_rerun, parse_failed

    @staticmethod
    def _split_future_imports(code: str) -> Tuple[str, str]:
        """切出開頭的 docstring 與 `from __future__` 匯入，它們必須留在最頂端。

        harness 的標頭會插在這兩部分之間；若把它加在整個模組前面，
        每個 `from __future__ import annotations` 都會變成 SyntaxError（收集失敗）。
        沒有東西需要提前時回傳 ("", code)。程式碼已經由
        check_test_code() 驗證過，所以能解析。
        Splits off the leading docstring and `from __future__` imports, which must stay at the very top.

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
                continue  # 模組 docstring 可以出現在 future 匯入之前 ／ module docstring may precede future imports
            else:
                break
        if not last_line:
            return "", code
        lines = code.splitlines(keepends=True)
        preamble = "".join(lines[:last_line])
        return (preamble if preamble.endswith("\n") else preamble + "\n"), "".join(lines[last_line:])

    @staticmethod
    def _unique_test_ids(tests: List[GeneratedTest]) -> List[str]:
        """消除重複的 test_id（例如來自 LLM 輸出），讓每個結果都可追溯。
        Disambiguates duplicate test_ids (e.g. from LLM output) so each result is traceable."""
        seen: Dict[str, int] = {}
        unique = []
        for t in tests:
            count = seen.get(t.test_id, 0) + 1
            seen[t.test_id] = count
            unique.append(t.test_id if count == 1 else f"{t.test_id}-{count}")
        return unique
