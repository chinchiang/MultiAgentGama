import ast
import re
import os
import time
import logging
import xml.etree.ElementTree as ET
from typing import Callable, List, Tuple, Optional, Dict, Set
from vibeharness.core.models import GeneratedTest, TestExecutionResult, TestStatus
from vibeharness.core.sandbox import LocalSubprocessSandbox, SandboxUnavailableError, TIMEOUT_EXIT_CODE
from vibeharness.core.codecheck import check_test_code_for
from vibeharness.core.i18n import bi

logger = logging.getLogger("VibeHarness.TestExecutor")

# 使用者可見的原因字串（中文 ／ English）；測試以 == / startswith 比對的匯出為常數
# User-visible reason strings (Chinese / English); the ones tests compare with == / startswith are exported
REASON_NOT_RUN_CORRECTLY = bi("測試無法正常執行", "Test could not run correctly")
REASON_TARGET_BROKEN = bi("目標程式碼已損壞，此測試從未實際執行到它", "Target code is broken and was never exercised by this test")
REASON_NO_TEST_COLLECTED = bi("產生的程式碼中沒有收集到任何測試", "No test was collected from the generated code")
REASON_REPORT_UNPARSEABLE = bi("沙盒測試報告無法解析；沒有逐一測試的判定結果",
                               "Sandbox test report could not be parsed; no per-test verdict available")
REASON_RERUN_BUDGET_EXHAUSTED = bi("批次逾時後重跑預算已用盡；此模組未重新執行",
                                   "Rerun budget exhausted after the batch timeout; module was not re-run")
REASON_UNKNOWN_FAILURE = bi("不明的執行失敗", "Unknown execution failure")
REASON_SKIPPED = bi("已略過", "Skipped")
REASON_JS_RUNNER_NOT_CONFIGURED = bi("未設定 JavaScript/TypeScript 執行器", "no JavaScript/TypeScript runner is configured")
REASON_NO_NODE_RUNTIME = bi("找不到可用的 Node 執行環境", "no usable Node runtime was found")
REASON_JS_NOT_RUN = bi("JavaScript/TypeScript 測試未執行", "JavaScript/TypeScript test was not run")
REASON_TS_NOT_RUN = bi("TypeScript 測試未執行：Node 執行環境低於 22.6（不支援型別剝除）",
                       "TypeScript test was not run: the Node runtime is older than 22.6 (no type stripping)")
POC_HEADER_PY = "# === " + bi("重現 PoC", "Reproduction PoC") + " ==="
POC_HEADER_JS = "// === " + bi("重現 PoC", "Reproduction PoC") + " ==="

# 代表產生的測試／harness 設定壞掉、而非目標缺陷的例外
# Exceptions that indicate a broken generated test / harness setup rather than a defect in the target
HARNESS_ERROR_EXCEPTIONS = (
    "ImportError", "ModuleNotFoundError", "NameError", "SyntaxError", "IndentationError"
)

# 關於呼叫參數數量／關鍵字的 TypeError，代表產生的測試用了錯誤的簽章呼叫目標——
# 但只有當它是在測試模組本身拋出時（最內層的回溯
# 框架）才算。同樣的訊息若在目標內部拋出，就是目標真正的缺陷。
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

# --- JavaScript／TypeScript（node:test）分類 ---------------------------------------
# --- JavaScript / TypeScript (node:test) classification ---------------------------------------
# 產生的模組本身的載入／解析失敗，絕不是目標的缺陷
# Load / resolution failures of the generated module itself, never a defect in the target
_JS_HARNESS_MARKERS = ("ERR_MODULE_NOT_FOUND", "Cannot find module", "Cannot find package", "ERR_UNKNOWN_FILE_EXTENSION",
                       "ERR_UNSUPPORTED_DIR_IMPORT", "ERR_REQUIRE_ESM", "ERR_PACKAGE_PATH_NOT_EXPORTED",
                       "ERR_UNSUPPORTED_TYPESCRIPT_SYNTAX", "SyntaxError")
# 從產生的模組（最內層 V8 框架）拋出時屬於測試端的錯誤
# Test-side mistakes when raised from the generated module (innermost V8 frame)
_JS_TEST_SIDE_ERRORS = ("ReferenceError", "TypeError")
# V8 堆疊框架最內層在前："    at fn (file:///x/y.mjs:3:9)" 或 "    at file:///x/y.mjs:3:9"
# V8 stack frames are innermost-first: "    at fn (file:///x/y.mjs:3:9)" or "    at file:///x/y.mjs:3:9"
_V8_FRAME_RE = re.compile(r"^\s+at (?:.*?\()?((?:file:///|/|[A-Za-z]:[\\/])[^\s)]+?):\d+:\d+\)?\s*$", re.MULTILINE)
_JS_CAUSE_RE = re.compile(r"^\s*cause:\s*([^'\"\s].*?)\s*\{?\s*$", re.MULTILINE)  # 加了引號的 cause（'test failed'）什麼都沒說 ／ a quoted cause ('test failed') says nothing
_JS_ERROR_LINE_RE = re.compile(r"^\s*\[?(\w*Error(?: \[\w+\])?: .+)$", re.MULTILINE)
_JS_FILE_CASE_RE = re.compile(r"test_vh_\d+\.(?:mjs|cjs|js)$")


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
        sandbox: LocalSubprocessSandbox,
        per_test_timeout_seconds: int = 30,
        js_sandbox_factory: Optional[Callable[[], Optional[LocalSubprocessSandbox]]] = None,
    ):
        self.sandbox = sandbox
        self.per_test_timeout_seconds = per_test_timeout_seconds
        # 第一次使用時才建立（只有存在 JS/TS 測試時才需要 Node）；None 代表「無法執行 JS」
        # Built on first use (Node is only needed when a JS/TS test exists); None means "cannot run JS"
        self._js_sandbox_factory = js_sandbox_factory
        self._js_sandbox: Optional[LocalSubprocessSandbox] = None
        self._js_sandbox_resolved = False
        self.js_runner_unavailable_reason: Optional[str] = None

    def _js_sandbox_or_none(self) -> Optional[LocalSubprocessSandbox]:
        if not self._js_sandbox_resolved:
            self._js_sandbox_resolved = True
            if self._js_sandbox_factory is None:
                self.js_runner_unavailable_reason = REASON_JS_RUNNER_NOT_CONFIGURED
            else:
                try:
                    self._js_sandbox = self._js_sandbox_factory()
                except (SandboxUnavailableError, OSError) as e:
                    # 缺少 docker 映像檔、壞掉的 node 執行檔：會揭露，但不致命；設定錯誤已在啟動時驗證，其餘例外照常拋出
                    # a missing docker image, a broken node binary: disclosed, not fatal; configuration errors are
                    # validated at start-up, any other exception propagates
                    self.js_runner_unavailable_reason = f"{type(e).__name__}: {e}"
                if self._js_sandbox is None and not self.js_runner_unavailable_reason:
                    self.js_runner_unavailable_reason = REASON_NO_NODE_RUNTIME
        return self._js_sandbox

    def execute_test_suite(
        self,
        tests: List[GeneratedTest],
        working_dir: str = ".",
        collect_coverage: bool = False
    ) -> Tuple[List[TestExecutionResult], Optional[float]]:
        if not tests:
            return [], None
        unique_ids = self._unique_test_ids(tests)
        results: Dict[int, TestExecutionResult] = {}
        py_idx = [i for i, t in enumerate(tests) if t.language == "python"]
        js_idx = [i for i, t in enumerate(tests) if t.language != "python"]

        coverage_pct = self._run_group(tests, py_idx, unique_ids, results, working_dir, collect_coverage,
                                       "python", self.sandbox) if py_idx else None
        if js_idx:
            sandbox = self._js_sandbox_or_none()
            runnable = []
            for i in js_idx:
                t = tests[i]
                if sandbox is None:
                    results[i] = self._result(
                        t, unique_ids[i], TestStatus.ERROR,
                        failure_reason=f"{REASON_JS_NOT_RUN}: {self.js_runner_unavailable_reason}"
                    )
                elif t.language == "typescript" and not getattr(sandbox, "supports_typescript", True):
                    results[i] = self._result(
                        t, unique_ids[i], TestStatus.ERROR,
                        failure_reason=REASON_TS_NOT_RUN
                    )
                else:
                    runnable.append(i)
            if runnable and sandbox is not None:
                self._run_group(tests, runnable, unique_ids, results, working_dir, False, "javascript", sandbox)
        return [results[i] for i in range(len(tests))], coverage_pct

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
        sandbox: LocalSubprocessSandbox,
    ) -> Optional[float]:
        """把某一語言的測試當作一個沙盒批次執行（模組名稱使用全域索引，所以 id
        在各群組間保持唯一），並為這些索引填入 `results`。
        Runs one language's tests as one sandbox batch (module names use the global index, so ids
        stay unique across groups) and fills `results` for those indices."""
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
                results[idx] = self._result(
                    t, unique_ids[idx], TestStatus.ERROR,
                    failure_reason=bi(f"產生的測試無法執行（{problem}）；未執行", f"Generated test is not executable ({problem}); not run")
                )
                continue
            module = f"test_vh_{idx:03d}"
            module_to_idx[module] = idx
            preamble, body = ("", t.code) if is_js else self._split_future_imports(t.code)
            files[f"{module}{ext}"] = (
                f"{preamble}{header}\n{comment} Target: {self._header_field(t.target_component)} | "
                f"Test: {self._header_field(t.title)}\n{body}\n"
            )

        coverage_pct: Optional[float] = None
        if not files:
            return None
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
        if is_js:
            for filename, code in files.items():
                module = os.path.splitext(filename)[0]
                exit_code, stdout, stderr, _, _, junit_xml = sandbox.execute_pytest_files(
                    {filename: code}, working_dir=working_dir, timeout_seconds=self.per_test_timeout_seconds
                )
                runs[module] = (exit_code, stdout, stderr, junit_xml)
                if exit_code == TIMEOUT_EXIT_CODE:
                    timed_out.add(module)
                    continue
                parsed = self._parse_junit(junit_xml, language, module=module)
                if parsed is None:
                    parse_failed.add(module)
                elif cases is not None:
                    for case in parsed.get(module, []):
                        # 載入失敗的模組是單一個檔案層級的案例，其 junit 內文只說
                        # "test failed"；實際的錯誤（ERR_MODULE_NOT_FOUND、載入時的 ReferenceError）
                        # 在執行器的 stdout 上，分類時需要先看到它。
                        # A module that failed to load is one file-level case whose junit body only says
                        # "test failed"; the actual error (ERR_MODULE_NOT_FOUND, a ReferenceError at load)
                        # is on the runner's stdout, which the classification needs to see first.
                        if case["outcome"] == "failure" and _JS_FILE_CASE_RE.search(os.path.basename(case["name"] or "")):
                            case["details"] = f"{stdout[:6000]}\n{case['details'] or ''}"
                    cases.update(parsed)
        else:
            exit_code, stdout, stderr, duration, coverage_pct, junit_xml = sandbox.execute_pytest_files(
                files,
                working_dir=working_dir,
                collect_coverage=collect_coverage,
                coverage_target=working_dir
            )
            cases = self._parse_junit(junit_xml, language)
            if exit_code == TIMEOUT_EXIT_CODE and len(files) > 1:
                # 一個卡住的測試不能讓整個批次作廢：用各自的預算重跑每個模組
                # One hanging test must not void the whole batch: rerun each module on its own budget
                logger.warning(bi("批次執行逾時；逐一重新執行每個測試模組以找出卡住的測試。",
                                  "Batch run timed out; re-running each test module individually to isolate the hang."))
                coverage_pct = None
                cases, timed_out, not_rerun, parse_failed = self._run_individually(files, working_dir, sandbox, language)
                junit_xml = ""  # 逐模組的結果現在在 `cases`／`timed_out` 裡 ／ per-module outcomes are now in `cases` / `timed_out`
            elif exit_code == TIMEOUT_EXIT_CODE:
                batch_timeout = getattr(sandbox, "timeout_seconds", None)
            for module in module_to_idx:
                runs[module] = (exit_code, stdout, stderr, junit_xml)

        for module, idx in module_to_idx.items():
            t = tests[idx]
            exit_code, stdout, stderr, junit_xml = runs[module]
            module_cases = cases.get(module) if cases is not None else None
            if module in not_rerun:
                results[idx] = self._result(
                    t, unique_ids[idx], TestStatus.ERROR,
                    failure_reason=REASON_RERUN_BUDGET_EXHAUSTED
                )
            elif module in parse_failed:
                results[idx] = self._result(
                    t, unique_ids[idx], TestStatus.ERROR,
                    failure_reason=REASON_REPORT_UNPARSEABLE,
                    stderr=stderr
                )
            elif module in timed_out and (is_js or not module_cases):
                results[idx] = self._result(
                    t, unique_ids[idx], TestStatus.ERROR,
                    failure_reason=bi(f"測試在 {self.per_test_timeout_seconds} 秒後逾時；未執行完畢",
                                      f"Test timed out after {self.per_test_timeout_seconds}s; not run to completion")
                )
            elif junit_xml is None:
                if exit_code == TIMEOUT_EXIT_CODE:
                    results[idx] = self._result(
                        t, unique_ids[idx], TestStatus.ERROR,
                        failure_reason=bi(f"測試批次在 {batch_timeout or '?'} 秒後逾時，且沒有產生逐一測試的報告",
                                          f"Test batch timed out after {batch_timeout or '?'}s "
                                          "and no per-test report was produced")
                    )
                else:
                    results[idx] = self._result(
                        t, unique_ids[idx], TestStatus.ERROR,
                        failure_reason=f"{bi('沙盒執行沒有產生報告', 'Sandbox run produced no report')}: "
                                       f"{stderr.strip()[:200] or f'exit code {exit_code}'}",
                        stdout=stdout, stderr=stderr
                    )
            elif cases is None:
                results[idx] = self._result(
                    t, unique_ids[idx], TestStatus.ERROR,
                    failure_reason=REASON_REPORT_UNPARSEABLE,
                    stdout=stdout, stderr=stderr
                )
            elif not module_cases:
                results[idx] = self._result(
                    t, unique_ids[idx], TestStatus.ERROR,
                    failure_reason=REASON_NO_TEST_COLLECTED,
                    stdout=stdout, stderr=stderr
                )
            else:
                results[idx] = self._aggregate(t, unique_ids[idx], module_cases)
        return coverage_pct

    def _run_individually(
        self, files: Dict[str, str], working_dir: str, sandbox: Optional[LocalSubprocessSandbox] = None,
        language: str = "python"
    ) -> Tuple[Dict[str, List[dict]], Set[str], Set[str], Set[str]]:
        """在各自的行程中執行每個模組。

        回傳 (依模組分組的 junit 案例, 逾時的模組, 因重跑預算（沙盒自己的批次預算）
        用盡而跳過的模組, JUnit 報告無法解析的模組)。
        Runs each module in its own process.

        Returns (junit cases by module, modules that timed out, modules skipped because the
        rerun budget (the sandbox's own batch budget) was exhausted, modules whose JUnit
        report could not be parsed).
        """
        cases: Dict[str, List[dict]] = {}
        timed_out: Set[str] = set()
        not_rerun: Set[str] = set()
        parse_failed: Set[str] = set()
        sandbox = sandbox or self.sandbox
        deadline = time.monotonic() + float(getattr(sandbox, "timeout_seconds", 0) or 0)
        for filename, code in files.items():
            module = os.path.splitext(filename)[0]
            if time.monotonic() >= deadline:
                not_rerun.add(module)
                continue
            exit_code, _, _, _, _, junit_xml = sandbox.execute_pytest_files(
                {filename: code}, working_dir=working_dir, timeout_seconds=self.per_test_timeout_seconds
            )
            if exit_code == TIMEOUT_EXIT_CODE:
                timed_out.add(module)
                continue
            module_cases = self._parse_junit(junit_xml, language)
            if module_cases is None:
                parse_failed.add(module)
                continue
            cases.update(module_cases)
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
    def _header_field(text: Optional[str]) -> str:
        """插入產生的原始碼中 '#' 註解的中繼資料。

        CR／LF（及其他行分隔符）會逃出註解並注入 check_test_code()
        從未驗證過的程式碼，所以每個行分隔符都換成空格。
        Metadata interpolated into a '#' comment in generated source.

        CR/LF (and other line separators) would escape the comment and inject code that
        check_test_code() never validated, so every line separator becomes a space.
        """
        return " ".join(str(text or "").splitlines()) or "-"

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

    @staticmethod
    def _parse_junit(junit_xml: Optional[str], language: str = "python",
                     module: Optional[str] = None) -> Optional[Dict[str, List[dict]]]:
        """把 JUnit 的 testcase 依產生的模組名稱（test_vh_NNN）分組。

        pytest 把模組放在 `classname`（收集錯誤時放在 `name`）。Node 的 junit 報告器
        兩者都不填（classname 是字面上的 "test"；只有從未執行到 test() 的檔案
        會以名稱出現），所以 Node 的報告是每個模組各產一份，由 `module` 把每個案例
        歸給它；外層的 `<testsuite name>` 祖先則作為後備來搜尋。從未執行到 test() 的
        Node 檔案會被回報成單一個通過的檔案層級案例：這個
        偽案例會被丟棄（空檔案不能算通過），而失敗的那種
        （載入錯誤）則保留為該模組的失敗。
        什麼都沒產生（或什麼都沒比對到）時回傳 {}，報告存在但無法解析時回傳
        None——呼叫端不得把後者回報成「沒有收集到測試」，那會把壞掉的沙盒報告
        歸咎於產生的程式碼。
        Groups JUnit testcases by generated module name (test_vh_NNN).

        pytest puts the module in `classname` (collection errors: in `name`). Node's junit reporter
        names neither (classname is the literal "test"; only a file that never reached a test()
        appears by name), so a Node report is produced per module and `module` assigns every case
        to it; the enclosing `<testsuite name>` ancestors are searched as a fallback. A Node file
        that never reached a test() is reported as a single passing file-level case: that
        pseudo-case is dropped (an empty file must not count as a pass), while a failing one (a
        load error) is kept as the module's failure.
        Returns {} when nothing was produced (or nothing matched), and None when a report
        existed but could not be parsed — the caller must not report that as "no test
        collected", which blames the generated code for a broken sandbox report.
        """
        grouped: Dict[str, List[dict]] = {}
        if module is not None:
            grouped[module] = []  # 模組有執行；沒有任何案例就是「沒有收集到測試」，絕不是通過 ／ the module ran; without any case it is "no test collected", never a pass
        if not junit_xml:
            return grouped
        try:
            root = ET.fromstring(junit_xml)
        except ET.ParseError as e:
            logger.error(bi(f"無法解析 JUnit XML：{e}", f"Unable to parse JUnit XML: {e}"))
            return None

        parents = {child: parent for parent in root.iter() for child in parent}
        for tc in root.iter("testcase"):
            match = re.search(r"test_vh_\d+", tc.get("classname") or "") or re.search(r"test_vh_\d+", tc.get("name") or "")
            node = tc
            while match is None and node in parents:
                node = parents[node]
                if node.tag == "testsuite":
                    match = re.search(r"test_vh_\d+", node.get("name") or "")
            group = match.group(0) if match else module
            if not group:
                continue
            is_file_case = language != "python" and bool(_JS_FILE_CASE_RE.search(os.path.basename(tc.get("name") or "")))
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
            if is_file_case and outcome == "passed":
                grouped.setdefault(group, [])  # 檔案有執行，但裡面沒有 test()：沒有可計算的東西 ／ the file ran, but no test() inside it: nothing to count
                continue
            try:
                case_time = float(tc.get("time") or 0.0)
            except (TypeError, ValueError):
                case_time = 0.0  # 這份 XML 來自執行不受信任程式碼的容器；絕不能因它崩潰 ／ the XML came from a container running untrusted code; never crash on it
            grouped.setdefault(group, []).append({
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
        # 呈現這個測試自己擷取到的輸出，而不是整個批次的
        # Report this test's own captured output rather than the whole batch's
        stdout = "".join(c["stdout"] for c in cases)
        stderr = "".join(c["stderr"] for c in cases)
        is_js = test.language != "python"
        errors = [c for c in cases if c["outcome"] == "error"]
        failures = [c for c in cases if c["outcome"] == "failure"]
        harness_failures = [c for c in failures if (self._js_is_harness_failure(c) if is_js else self._is_harness_failure(c))]
        defect_failures = [c for c in failures if c not in harness_failures]

        if defect_failures:
            case = defect_failures[0]
            is_assertion = self._js_is_assertion(case) if is_js else self._is_assertion(case["message"])
            reason = (self._js_exception_summary(case) if is_js else "") or self._first_line(case["message"]) \
                or bi(f"於 {test.title} 期間斷言失敗", f"Assertion failed during {test.title}")
            return self._result(
                test, test_id, TestStatus.FAILED,
                failure_reason=reason,
                traceback=case["details"], duration=duration, stdout=stdout, stderr=stderr,
                is_exploit=test.test_type == "blackbox_security" and is_assertion,
                poc=self._generate_poc(test, case["name"])
            )
        if errors or harness_failures:
            case = (errors or harness_failures)[0]
            if is_js:
                summary = self._js_exception_summary(case)
                if self._js_raised_in_target_code(case) and any(m in summary for m in _JS_HARNESS_MARKERS):
                    return self._result(
                        test, test_id, TestStatus.ERROR,
                        failure_reason=(f"{REASON_TARGET_BROKEN}: "
                                        f"{summary} (raised outside the generated test module)"),
                        traceback=case["details"], duration=duration, stdout=stdout, stderr=stderr
                    )
                return self._result(
                    test, test_id, TestStatus.ERROR,
                    failure_reason=f"{REASON_NOT_RUN_CORRECTLY}: {summary or REASON_UNKNOWN_FAILURE}",
                    traceback=case["details"], duration=duration, stdout=stdout, stderr=stderr
                )
            if case["outcome"] == "error" and self._raised_in_target_code(case):
                summary = self._exception_summary(case)
                if summary.startswith(HARNESS_ERROR_EXCEPTIONS):
                    # 匯入／語法失敗發生在目標（或其相依套件）裡，
                    # 而不是產生的測試裡：邊界從未被測到，
                    # 報告不可因目標壞掉而怪罪測試。
                    # The import/syntax failure happened in the target (or its dependencies),
                    # not in the generated test: the boundary was never exercised and the
                    # report must not blame the test for the target being broken.
                    return self._result(
                        test, test_id, TestStatus.ERROR,
                        failure_reason=(f"{REASON_TARGET_BROKEN}: "
                                        f"{summary} (raised outside the generated test module)"),
                        traceback=case["details"], duration=duration, stdout=stdout, stderr=stderr
                    )
            reason = (self._exception_summary(case) or self._first_line(case["message"])
                      or self._first_line(case["details"]) or REASON_UNKNOWN_FAILURE)
            return self._result(
                test, test_id, TestStatus.ERROR,
                failure_reason=f"{REASON_NOT_RUN_CORRECTLY}: {reason}",
                traceback=case["details"], duration=duration, stdout=stdout, stderr=stderr
            )
        if all(c["outcome"] == "skipped" for c in cases):
            return self._result(
                test, test_id, TestStatus.SKIPPED,
                failure_reason=self._first_line(cases[0]["message"]) or REASON_SKIPPED,
                duration=duration, stdout=stdout, stderr=stderr
            )
        passed = self._result(test, test_id, TestStatus.PASSED, duration=duration, stdout=stdout, stderr=stderr)
        skipped_count = sum(1 for c in cases if c["outcome"] == "skipped")
        if skipped_count:
            # 部分被跳過的模組，其證據比完全通過弱；要明確說出來，
            # 而不是把未驗證的邊界算成已防禦。
            # A partially skipped module is weaker evidence than a clean pass; say so explicitly
            # instead of counting unverified boundaries as defended.
            passed.failure_reason = bi(
                f"此模組內 {len(cases)} 個案例中有 {skipped_count} 個被略過；只有實際執行的案例能驗證邊界",
                f"{skipped_count} of {len(cases)} case(s) were skipped inside this module; "
                "only the executed cases verify the boundary"
            )
        return passed

    @staticmethod
    def _is_harness_failure(case: dict) -> bool:
        """由產生的測試本身、而非目標行為所造成的失敗。
        A failure caused by the generated test itself rather than by the target's behaviour."""
        message = case["message"] or ""
        if message.startswith(HARNESS_ERROR_EXCEPTIONS):
            return True
        return bool(_SIGNATURE_TYPEERROR_RE.match(message)
                    and _RAISED_IN_TEST_MODULE_RE.search(case["details"] or ""))

    @staticmethod
    def _exception_summary(case: dict) -> str:
        """pytest 回溯中拋出的例外（'E   ModuleNotFoundError: ...'）。

        JUnit 對收集錯誤的訊息只有 'collection failure'，完全看不出
        實際壞在哪裡；回溯中的 E 開頭那一行才會點出例外。
        The raised exception ('E   ModuleNotFoundError: ...') from pytest's traceback.

        JUnit's message for collection errors is just 'collection failure', which says
        nothing about what actually broke; the traceback's E-line names the exception.
        """
        details = case["details"] or ""
        e_lines = re.findall(r"^E\s+(.+)$", details, re.MULTILINE)
        return (e_lines[-1].strip() if e_lines else (case["message"] or "").strip())[:300]

    @staticmethod
    def _raised_in_target_code(case: dict) -> bool:
        """最內層的回溯框架不是產生的測試模組時為 True（pytest 的
        junit 回溯使用簡短的 'path.py:LINE: in ...' 格式）：是目標或它的
        相依鏈拋出的。沒有可用的回溯時，答案維持保守
        （歸在測試端），以免有任何東西被過度歸咎於目標。
        True when the innermost traceback frame is not the generated test module (pytest
        junit tracebacks use the short 'path.py:LINE: in ...' format): the target, or its
        dependency chain, is what raised. Without a usable traceback the answer stays
        conservative (test-side framing) so nothing is over-attributed to the target."""
        details = case["details"] or ""
        frames = re.findall(r'File "([^"]+?\.py)"', details) \
            or re.findall(r"^(.+\.py):\d+: in ", details, re.MULTILINE)
        if not frames:
            return False
        return not os.path.basename(frames[-1]).startswith("test_vh_")

    @staticmethod
    def _js_is_harness_failure(case: dict) -> bool:
        """由產生的模組造成的 node:test 失敗（無法解析的匯入、語法），或由
        該模組本身拋出的測試端 ReferenceError／TypeError。
        A node:test failure caused by the generated module (unresolvable import, syntax) or by a
        test-side ReferenceError/TypeError raised from the module itself."""
        # 只看 Node 回報的例外本身（cause 行或第一個 XError 行）：斷言失敗的內文可能提到目標拋出的
        # SyntaxError（例如 assert.doesNotThrow 的 actual），整段比對會把真正的突破降級成 harness 錯誤
        # Only the exception Node reports (the cause line or the first XError line): an assertion failure's body may
        # mention a SyntaxError the target threw (e.g. assert.doesNotThrow's actual), and matching the whole body
        # would downgrade a genuine breach to a harness error
        if _JS_FILE_CASE_RE.search(os.path.basename(case.get("name") or "")):
            return True  # 檔案層級的失敗 = 模組沒載入，從未執行任何 test() ／ a file-level failure = the module never loaded, no test() ran
        summary = TestSuiteExecutor._js_exception_summary(case)
        if any(marker in summary for marker in _JS_HARNESS_MARKERS):
            return True
        return summary.startswith(_JS_TEST_SIDE_ERRORS) and not TestSuiteExecutor._js_raised_in_target_code(case) \
            and bool(_V8_FRAME_RE.search(case.get("details") or ""))

    @staticmethod
    def _js_raised_in_target_code(case: dict) -> bool:
        """V8 堆疊把最內層框架列在最前面；沒有框架時，什麼都不會歸咎於目標。
        V8 stacks list the innermost frame first; without frames nothing is attributed to the target."""
        frames = _V8_FRAME_RE.findall(case.get("details") or "")
        if not frames:
            return False
        return not os.path.basename(frames[0]).startswith("test_vh_")

    @staticmethod
    def _js_exception_summary(case: dict) -> str:
        """Node 回報的錯誤：junit 內文的 `cause:` 行，否則是第一個 `XError: ...` 行，
        否則是 junit 訊息（對斷言而言就是單純的期望文字）。
        The error Node reports: the `cause:` line of the junit body, else the first `XError: ...` line,
        else the junit message (which for assertions is the bare expectation text)."""
        details = case.get("details") or ""
        cause = _JS_CAUSE_RE.search(details)
        if cause:
            return cause.group(1).strip().rstrip("{").strip()[:300]
        # 檔案層級失敗的 junit 內文只有「Error: test failed」佔位行，真正的錯誤（例如 ERR_MODULE_NOT_FOUND）
        # 在 runner 輸出裡；跳過佔位行，取第一個有內容的 XError 行
        # A file-level failure's junit body only has the "Error: test failed" placeholder; the real error (e.g.
        # ERR_MODULE_NOT_FOUND) is in the runner output, so skip the placeholder and take the first real XError line
        candidates = [line.group(1).strip() for line in _JS_ERROR_LINE_RE.finditer(details)
                      if not line.group(1).strip().startswith("Error: test failed")]
        # 補進來的 runner 輸出可能含目標自己印的「Error: …」行：優先取帶有 harness 標記（載入錯誤）的那一行
        # The folded runner output may contain "Error: ..." lines the target printed itself: prefer the line that
        # carries a harness marker (a load error)
        for text in candidates:
            if any(marker in text for marker in _JS_HARNESS_MARKERS):
                return text[:300]
        if candidates:
            return candidates[0][:300]
        return (case.get("message") or "").strip()[:300]

    @staticmethod
    def _js_is_assertion(case: dict) -> bool:
        """node:assert 的失敗會在內文帶有 ERR_ASSERTION／AssertionError（junit 訊息是
        單純的期望文字）；expect() 風格的函式庫則會寫出該呼叫的名稱。
        node:assert failures carry ERR_ASSERTION / AssertionError in the body (the junit message is the
        bare expectation text); expect()-style libraries name the call."""
        text = f"{case.get('message') or ''}\n{case.get('details') or ''}"
        return "ERR_ASSERTION" in text or "AssertionError" in text or "Error: expect(" in text

    @staticmethod
    def _is_assertion(message: Optional[str]) -> bool:
        """pytest 會回報明確的 AssertionError、改寫過的裸 assert（'assert x == y'），
        以及透過 pytest.fail() 的明確測試失敗（'Failed: ...'）。
        pytest reports explicit AssertionErrors, rewritten bare asserts ('assert x == y'),
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
            source_ref=test.source_ref,
            language=test.language,
        )

    def _generate_poc(self, test: GeneratedTest, fn_name: str) -> str:
        """為已確認的失敗建構重現腳本。
        Constructs a reproduction script for a confirmed failure."""
        is_js = test.language != "python"
        c = "//" if is_js else "#"
        header = POC_HEADER_JS if is_js else POC_HEADER_PY
        return (
            f"{header}\n"
            f"{c} {bi('目標', 'Target')}: {self._header_field(test.target_component)}\n"
            f"{c} {bi('失敗情境', 'Failure Context')}: {self._header_field(test.title)}\n"
            f"{c} {bi('測試函式', 'Test Function')}: {fn_name}\n"
            f"{c} {bi('測試程式碼', 'Test Code')}:\n{test.code}\n"
        )
