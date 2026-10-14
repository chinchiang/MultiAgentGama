"""JS／TS 行涵蓋率：lcov 解析、路徑解析與篩選（含 Windows 路徑與容器路徑）、跨模組聯集、Node 指令的版本偵測、
執行器與報告的接線，以及真正的 Node（可用時）與 Docker 容器（VIBEHARNESS_REQUIRE_DOCKER_NODE=1 時強制）執行。
JS/TS line coverage: lcov parsing, path resolution and filtering (including Windows and container paths), the union
across modules, version detection in the Node command, the executor and report wiring, and real Node runs (when
available) and Docker container runs (forced with VIBEHARNESS_REQUIRE_DOCKER_NODE=1)."""
import json
import os
import shutil
import subprocess

import pytest

from vibeharness.core.codecontext import target_file_url
from vibeharness.core.harness import VibeHarnessCommander
from vibeharness.core.jscoverage import (
    LCOV_REPORT_NAME, JsLineCoverage, node_coverage_args, node_coverage_problem, parse_lcov, resolve_source_path,
    target_relative_path,
)
from vibeharness.core.models import (
    GeneratedTest, MultiModelDebateResult, TestExecutionResult, TestStatus, ThreatModelReport, VibeHarnessSummary,
)
from vibeharness.core.sandbox import (
    DEFAULT_DOCKER_NODE_IMAGE, TIMEOUT_EXIT_CODE, LocalSubprocessSandbox, NodeDockerSandbox, NodeSubprocessSandbox,
    SandboxRun, detect_node, node_test_command,
)
from vibeharness.reports.report_generator import ReportGenerator
from vibeharness.runners.test_executor import (
    REASON_JS_COVERAGE_NO_REPORT, REASON_JS_COVERAGE_NO_TARGET_FILE, REASON_JS_COVERAGE_UNSUPPORTED, TestSuiteExecutor,
)

_NODE_PATH, _NODE_VERSION, _NODE_PROBLEM = detect_node("node")
# 與 test_js_execution.py 相同：VIBEHARNESS_REQUIRE_NODE=1（CI）時缺少 Node 是失敗而不是略過；Node 存在但對某個功能
# 太舊時仍以說明原因的方式略過
# As in test_js_execution.py: with VIBEHARNESS_REQUIRE_NODE=1 (CI) a missing Node is a failure, not a skip; a Node that
# exists but is too old for one feature is still skipped with the reason
_NODE_REQUIRED = os.environ.get("VIBEHARNESS_REQUIRE_NODE") == "1"
if _NODE_REQUIRED and _NODE_PATH is None:
    raise RuntimeError(f"VIBEHARNESS_REQUIRE_NODE=1 but no usable Node runtime: {_NODE_PROBLEM}")
_COVERAGE_PROBLEM = _NODE_PROBLEM if _NODE_PATH is None else node_coverage_problem(_NODE_VERSION)
_COVERAGE_OK = _NODE_PATH is not None and _COVERAGE_PROBLEM is None
node_coverage_only = pytest.mark.skipif(not _COVERAGE_OK, reason=f"Node with the lcov reporter unavailable: {_COVERAGE_PROBLEM}")
_TS_OK = _COVERAGE_OK and _NODE_VERSION is not None and _NODE_VERSION >= (22, 6, 0)
_FOUND = "v" + ".".join(map(str, _NODE_VERSION)) if _NODE_VERSION else "none"


def _js_test(test_id, code, language="javascript", test_type="whitebox_unit"):
    return GeneratedTest(test_id=test_id, test_type=test_type, target_component="x", title=f"t {test_id}",
                         code=code, rationale="", expected_outcome="", language=language)


def _esm_test(imports, body):
    return f'import {{ test }} from "node:test";\nimport assert from "node:assert/strict";\n{imports}\n{body}\n'


# --- lcov 解析 -----------------------------------------------------------------------------------
# --- lcov parsing --------------------------------------------------------------------------------------

LCOV = """TN:
SF:../run/test_vh_000.mjs
DA:1,1
end_of_record
SF:lib.mjs
FN:1,add
FNDA:1,add
FNF:1
FNH:1
BRDA:2,0,0,1
BRDA:2,1,0,0
BRF:2
BRH:1
DA:1,1
DA:2,1
DA:3,0
DA:4,0,abcdef
DA:x,1
DA:0,5
DA:5
LH:2
LF:4
end_of_record
"""


def test_parse_lcov_reads_sf_and_da_only():
    records = parse_lcov(LCOV)
    assert [path for path, _ in records] == ["../run/test_vh_000.mjs", "lib.mjs"]
    # BRDA／FN／LF 不影響行；壞掉的 DA（非數字、行號 0、缺欄位）被跳過；帶 checksum 的 DA 照讀
    # BRDA / FN / LF do not touch the lines; broken DA lines (non-numeric, line 0, missing field) are skipped; a DA
    # with a checksum is still read
    assert records[1][1] == {1: 1, 2: 1, 3: 0, 4: 0}


def test_parse_lcov_tolerates_crlf_missing_end_of_record_and_repeated_da():
    text = "SF:a.mjs\r\nDA:1,0\r\nDA:1,3\r\nSF:b.mjs\r\nDA:2,1\r\n"
    assert parse_lcov(text) == [("a.mjs", {1: 3}), ("b.mjs", {2: 1})]
    assert parse_lcov("") == [] and parse_lcov("DA:1,1\nend_of_record\n") == []


# --- 路徑解析與篩選 -------------------------------------------------------------------------------
# --- Path resolution and filtering ---------------------------------------------------------------------

def test_resolve_source_path_posix_relative_and_file_url():
    assert resolve_source_path("lib.mjs", "/srv/app", windows=False) == "/srv/app/lib.mjs"
    assert resolve_source_path("../run/test_vh_000.mjs", "/srv/app", windows=False) == "/srv/run/test_vh_000.mjs"
    assert resolve_source_path("file:///srv/app/a%20b.mjs", "/x", windows=False) == "/srv/app/a b.mjs"


def test_resolve_source_path_windows_styles():
    assert resolve_source_path(r"src\lib.mjs", r"C:\proj\app", windows=True) == r"C:\proj\app\src\lib.mjs"
    assert resolve_source_path(r"D:\proj\app\x.js", r"C:\cwd", windows=True) == r"D:\proj\app\x.js"
    assert resolve_source_path("file:///C:/proj/app/x.mjs", r"C:\cwd", windows=True) == r"C:\proj\app\x.mjs"


def test_target_relative_path_filters_windows_paths_case_insensitively():
    roots = [r"C:\Proj\App"]
    assert target_relative_path(r"c:\proj\app\src\Lib.mjs", roots, windows=True) == "src/lib.mjs"
    assert target_relative_path(r"C:\Proj\App2\x.mjs", roots, windows=True) is None  # 同名前綴的兄弟目錄 ／ a sibling sharing the prefix
    assert target_relative_path(r"C:\Proj\App\Node_Modules\dep\i.js", roots, windows=True) is None
    assert target_relative_path(r"C:\Proj\App\test_vh_003.mjs", roots, windows=True) is None
    assert target_relative_path(r"C:\Temp\vibe_sandbox_x\test_vh_000.mjs", roots, windows=True) is None


def test_target_relative_path_posix_rules_are_case_sensitive():
    assert target_relative_path("/srv/app/lib/a.mjs", ["/srv/app"], windows=False) == "lib/a.mjs"
    assert target_relative_path("/srv/App/a.mjs", ["/srv/app"], windows=False) is None
    assert target_relative_path("/srv/app", ["/srv/app"], windows=False) is None
    assert target_relative_path("/srv/app/node_modules/x/i.js", ["/srv/app"], windows=False) is None


# --- 合併 ---------------------------------------------------------------------------------------------
# --- Merging --------------------------------------------------------------------------------------------

def test_duplicate_sf_entries_and_modules_merge_as_a_union():
    cov = JsLineCoverage()
    # 同一份報告裡同一個檔案出現兩次（例如經由兩個 URL 載入）：行取聯集
    # The same file twice in one report (e.g. loaded through two URLs): its lines are united
    cov.add_lcov("SF:lib.mjs\nDA:1,1\nDA:2,0\nend_of_record\nSF:/srv/app/lib.mjs\nDA:2,0\nDA:3,1\nend_of_record\n",
                 ["/srv/app"], "/srv/app", windows=False)
    assert cov.files == {"lib.mjs": {1: True, 2: False, 3: True}}
    other = JsLineCoverage()
    other.add_lcov("SF:lib.mjs\nDA:2,4\nDA:3,0\nend_of_record\nSF:util.mjs\nDA:1,0\nend_of_record\n",
                   ["/srv/app"], "/srv/app", windows=False)
    cov.merge(other)
    # 任一模組執行過就算涵蓋：lib 3/3、util 0/1 -> 3/4
    # Covered when any module executed it: lib 3/3, util 0/1 -> 3/4
    assert cov.files["lib.mjs"] == {1: True, 2: True, 3: True}
    assert (cov.covered_lines, cov.instrumented_lines, cov.reports) == (3, 4, 2)
    assert cov.percent() == 75.0


def test_percent_is_none_without_instrumented_target_lines():
    cov = JsLineCoverage()
    assert cov.percent() is None and cov.reports == 0
    cov.add_lcov("SF:../run/test_vh_000.mjs\nDA:1,1\nend_of_record\n", ["/srv/app"], "/srv/app", windows=False)
    assert cov.percent() is None and cov.reports == 1


# --- Node 指令與版本偵測 --------------------------------------------------------------------------
# --- The Node command and version detection -----------------------------------------------------------

def test_node_coverage_problem_by_version():
    assert node_coverage_problem((22, 14, 0)) is None and node_coverage_problem((20, 11, 0)) is None
    assert node_coverage_problem((21, 3, 0)) is None
    for old in ((20, 10, 0), (21, 1, 0), None):
        problem = node_coverage_problem(old)
        assert problem and "JS/TS line coverage is not collected" in problem


def test_node_coverage_args_only_use_globs_where_supported():
    # POSIX 路徑明確以 POSIX 規則判斷（預設看目前平台，Windows CI 上會改用 Windows 規則）
    # POSIX paths judged by POSIX rules explicitly (the default follows the current platform, Windows on Windows CI)
    options, filters = node_coverage_args((22, 14, 0), "/srv/app", windows=False)
    assert options == ["--experimental-test-coverage", "--disable-warning=MaxListenersExceededWarning"]
    assert filters == ["--test-coverage-include=/srv/app/**", "--test-coverage-exclude=/srv/app/**/node_modules/**",
                       "--test-coverage-exclude=**/test_vh_*"]
    assert node_coverage_args((20, 11, 0), "/srv/app", windows=False)[1] == []  # 22.5 之前沒有 glob 篩選 ／ no glob filters before 22.5
    # 含 glob 特殊字元的根目錄不加 include（只剩排除模式，靠自己的篩選）。Windows 絕對路徑改成正斜線後可以
    # A root with glob metacharacters gets no include (only the excludes, our own filtering does the rest). A Windows
    # absolute path can, once rewritten to forward slashes
    for root in ("/srv/app[1]", None, r"C:\proj\app[1]"):
        assert not any(f.startswith("--test-coverage-include") for f in node_coverage_args((22, 14, 0), root)[1])
    _, win = node_coverage_args((22, 14, 0), r"C:\proj\app")
    assert win[0] == "--test-coverage-include=C:/proj/app/**"


def test_node_test_command_keeps_spec_and_junit_and_adds_lcov():
    cmd = node_test_command("node", ["/r/test_vh_000.mjs"], "/r/junit.xml", False, True, 0,
                            lcov_path="/r/lcov.info", node_version=(22, 14, 0), coverage_include_root="/srv/app",
                            coverage_windows=False)
    test_at = cmd.index("--test")
    assert cmd[1:test_at] == ["--experimental-test-coverage", "--disable-warning=MaxListenersExceededWarning"]
    assert cmd[test_at + 1:test_at + 7] == ["--test-reporter=spec", "--test-reporter-destination=stdout",
                                            "--test-reporter=junit", "--test-reporter-destination=/r/junit.xml",
                                            "--test-reporter=lcov", "--test-reporter-destination=/r/lcov.info"]
    assert "--test-coverage-include=/srv/app/**" in cmd and cmd[-1] == "/r/test_vh_000.mjs"
    # 沒有版本或 lcov 路徑時維持舊行為 ／ without a version or an lcov path the old behaviour stays
    plain = node_test_command("node", [], "/r/junit.xml", False, False, 0, lcov_path="/r/lcov.info",
                              node_version=(22, 14, 0))
    assert not any("coverage" in a or "lcov" in a for a in plain)


def test_node_subprocess_sandbox_adds_coverage_only_for_a_capable_node(tmp_path):
    target, run_dir = tmp_path / "app", tmp_path / "run"
    target.mkdir()
    run_dir.mkdir()
    modern = NodeSubprocessSandbox(node_bin="node-binary-that-does-not-exist", node_version=(22, 14, 0))
    cmd, _, _ = modern._build_command(str(run_dir), ["test_vh_000.mjs"], str(target), True, str(target), None)
    assert f"--test-reporter-destination={run_dir / LCOV_REPORT_NAME}" in cmd
    root = os.path.realpath(target)
    if os.name == "nt":
        root = root.replace("\\", "/").rstrip("/")
    assert f"--test-coverage-include={root}/**" in cmd
    cmd, _, _ = modern._build_command(str(run_dir), ["test_vh_000.mjs"], str(target), False, None, None)
    assert "--experimental-test-coverage" not in cmd  # 黑箱執行不收集 ／ black-box runs do not collect
    old = NodeSubprocessSandbox(node_bin="node-binary-that-does-not-exist", node_version=(20, 5, 0))
    assert old.js_coverage_problem()
    cmd, _, _ = old._build_command(str(run_dir), ["test_vh_000.mjs"], str(target), True, str(target), None)
    assert not any("lcov" in a for a in cmd)  # 舊版 Node 看到 lcov 報告器會整個失敗 ／ an old Node would fail outright on the lcov reporter
    # 沒給版本時探測一次；探測失敗 -> 不收集，而不是讓執行失敗
    # Without a version it is probed once; a failed probe -> no coverage, never a failed run
    unknown = NodeSubprocessSandbox(node_bin="node-binary-that-does-not-exist")
    assert unknown.js_coverage_problem() and unknown._node_version_probed


def test_node_docker_sandbox_coverage_command_and_container_path_translation(tmp_path):
    target, run_dir = tmp_path / "app", tmp_path / "run"
    target.mkdir()
    run_dir.mkdir()
    sandbox = NodeDockerSandbox(verify=False, node_version=(22, 23, 3))
    cmd, _, _ = sandbox._build_command(str(run_dir), ["test_vh_000.mjs"], str(target), True, str(target), None)
    assert "--test-reporter-destination=/sandbox/lcov.info" in cmd and "--test-coverage-include=/work/app/**" in cmd
    assert cmd.index("--experimental-test-coverage") < cmd.index("--test")
    # 容器內的 SF：相對於 -w /work/app 的路徑、/work/app 的絕對路徑都對應到同一個目標相對路徑；/sandbox 的測試模組與
    # 掛載點以外的檔案被排除
    # SF values from the container: a path relative to -w /work/app and an absolute /work/app path map to the same
    # target-relative path; the /sandbox test modules and files outside the mount drop out
    (run_dir / LCOV_REPORT_NAME).write_text(
        "SF:lib.mjs\nDA:1,1\nDA:2,0\nend_of_record\n"
        "SF:/work/app/lib.mjs\nDA:2,1\nend_of_record\n"
        "SF:/work/app/sub/b.cjs\nDA:1,0\nend_of_record\n"
        "SF:../../sandbox/test_vh_000.mjs\nDA:1,1\nend_of_record\n"
        "SF:/sandbox/test_vh_000.mjs\nDA:1,1\nend_of_record\n"
        "SF:/work/other/x.mjs\nDA:1,1\nend_of_record\n"
        "SF:/work/app/node_modules/dep/index.js\nDA:1,1\nend_of_record\n", encoding="utf-8")
    sink = JsLineCoverage()
    pct = sandbox._collect_coverage(str(run_dir), "", str(target), str(target), sink)
    assert sink.files == {"lib.mjs": {1: True, 2: True}, "sub/b.cjs": {1: False}}
    assert pct == pytest.approx(66.7) and sink.percent() == pytest.approx(66.7)
    # 映像檔內的 Node 版本未知 -> 不加任何涵蓋率旗標 ／ unknown Node version inside the image -> no coverage flag at all
    unknown = NodeDockerSandbox(verify=False)
    assert unknown.js_coverage_problem()
    cmd, _, _ = unknown._build_command(str(run_dir), ["test_vh_000.mjs"], str(target), True, str(target), None)
    assert not any("coverage" in a or "lcov" in a for a in cmd)


def test_harness_passes_the_node_version_to_the_sandboxes(tmp_path, monkeypatch):
    import vibeharness.core.harness as harness_module
    config = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "vibeharness", "config",
                          "agents_config.yaml")
    commander = VibeHarnessCommander(config_path=config, execution_mode="mock")
    monkeypatch.setattr(harness_module, "detect_node", lambda node_bin: ("/usr/bin/node", (22, 14, 0), None))
    sandbox = commander._build_node_sandbox()
    assert isinstance(sandbox, NodeSubprocessSandbox) and sandbox.node_version == (22, 14, 0)


# --- 執行器接線 ---------------------------------------------------------------------------------------
# --- Executor wiring --------------------------------------------------------------------------------------

PASS_JUNIT = '<testsuites><testcase name="a" time="0.01" classname="test"/></testsuites>'


class _CoverageSandbox:
    """Node 沙盒的替身：依模組回應預先準備的 lcov，並照真正的沙盒一樣併入 coverage_sink；逾時的模組什麼都不併入。
    Stands in for a Node sandbox: answers each module with a canned lcov and merges it into coverage_sink like the
    real sandbox does; a timed-out module merges nothing."""
    timeout_seconds = 30
    supports_typescript = True

    def __init__(self, lcov_by_module, timeouts=(), problem=None):
        self.lcov_by_module = lcov_by_module
        self.timeouts = set(timeouts)
        self.problem = problem
        self.kwargs = []

    def js_coverage_problem(self):
        return self.problem

    def execute_pytest_files(self, files, working_dir=None, timeout_seconds=None, **kw):
        self.kwargs.append(kw)
        module = os.path.splitext(next(iter(files)))[0]
        if module in self.timeouts:
            return SandboxRun(TIMEOUT_EXIT_CODE, "", "timed out", 1.0, None, None)
        sink = kw.get("coverage_sink")
        if kw.get("collect_coverage") and sink is not None and module in self.lcov_by_module:
            sink.add_lcov(self.lcov_by_module[module], [working_dir], working_dir, windows=False)
        return SandboxRun(0, "", "", 0.1, None, PASS_JUNIT)


_LCOV_A = "SF:lib.mjs\nDA:1,1\nDA:2,1\nDA:3,0\nDA:4,0\nend_of_record\n"
_LCOV_B = "SF:lib.mjs\nDA:1,1\nDA:2,0\nDA:3,1\nDA:4,0\nend_of_record\n"
_GOOD = _esm_test('import { add } from "file:///tmp/app/lib.mjs";', 'test("a", () => { assert.equal(add(1, 2), 3); });')


def test_executor_unions_module_coverage_and_keeps_python_coverage_separate(tmp_path):
    js = _CoverageSandbox({"test_vh_000": _LCOV_A, "test_vh_001": _LCOV_B})
    executor = TestSuiteExecutor(sandbox=None, js_sandbox_factory=lambda: js)
    suite = executor.execute_test_suite([_js_test("A", _GOOD), _js_test("B", _GOOD)],
                                        working_dir=str(tmp_path), collect_coverage=True)
    assert all(r.status == TestStatus.PASSED for r in suite.results)
    assert suite.python_coverage_pct is None  # python_coverage_pct 只代表 Python ／ python_coverage_pct only means Python
    assert suite.js_coverage_pct == 75.0 and suite.js_coverage_problem is None
    # 黑箱（collect_coverage=False）不傳涵蓋率參數，也沒有 JS/TS 涵蓋率
    # Black-box (collect_coverage=False) passes no coverage arguments and has no JS/TS coverage
    js.kwargs.clear()
    blackbox = executor.execute_test_suite([_js_test("A", _GOOD)], working_dir=str(tmp_path))
    assert js.kwargs == [{}] and blackbox.js_coverage_pct is None


def test_executor_timed_out_modules_do_not_contribute(tmp_path):
    js = _CoverageSandbox({"test_vh_000": _LCOV_A, "test_vh_001": _LCOV_B}, timeouts={"test_vh_001"})
    executor = TestSuiteExecutor(sandbox=None, js_sandbox_factory=lambda: js, per_test_timeout_seconds=30)
    suite = executor.execute_test_suite([_js_test("A", _GOOD), _js_test("B", _GOOD)],
                                        working_dir=str(tmp_path), collect_coverage=True)
    assert suite.results[1].status == TestStatus.ERROR
    assert suite.js_coverage_pct == 50.0
    js = _CoverageSandbox({}, timeouts={"test_vh_000"})
    executor = TestSuiteExecutor(sandbox=None, js_sandbox_factory=lambda: js, per_test_timeout_seconds=30)
    suite = executor.execute_test_suite([_js_test("A", _GOOD)], working_dir=str(tmp_path), collect_coverage=True)
    assert suite.js_coverage_pct is None
    assert suite.js_coverage_problem == REASON_JS_COVERAGE_NO_REPORT


def test_executor_reports_why_js_coverage_is_missing(tmp_path):
    js = _CoverageSandbox({"test_vh_000": "SF:../run/test_vh_000.mjs\nDA:1,1\nend_of_record\n"})
    executor = TestSuiteExecutor(sandbox=None, js_sandbox_factory=lambda: js)
    suite = executor.execute_test_suite([_js_test("A", _GOOD)], working_dir=str(tmp_path), collect_coverage=True)
    assert suite.js_coverage_pct is None
    assert suite.js_coverage_problem == REASON_JS_COVERAGE_NO_TARGET_FILE
    old = _CoverageSandbox({"test_vh_000": _LCOV_A}, problem="Node v20.5.0 has no lcov test reporter")
    executor = TestSuiteExecutor(sandbox=None, js_sandbox_factory=lambda: old)
    suite = executor.execute_test_suite([_js_test("A", _GOOD)], working_dir=str(tmp_path), collect_coverage=True)
    assert suite.results[0].status == TestStatus.PASSED and old.kwargs == [{}]  # 測試照常執行 ／ the tests still run
    assert suite.js_coverage_pct is None and "lcov" in suite.js_coverage_problem

    class _Plain(_CoverageSandbox):
        # 沒有覆寫涵蓋率介面的沙盒沿用 LocalSubprocessSandbox 的預設值
        # A sandbox that does not override the coverage interface keeps LocalSubprocessSandbox's default
        js_coverage_problem = LocalSubprocessSandbox.js_coverage_problem

    executor = TestSuiteExecutor(sandbox=None, js_sandbox_factory=lambda: _Plain({}))
    suite = executor.execute_test_suite([_js_test("A", _GOOD)], working_dir=str(tmp_path), collect_coverage=True)
    assert suite.js_coverage_problem == REASON_JS_COVERAGE_UNSUPPORTED


# --- 報告 ---------------------------------------------------------------------------------------------
# --- Reports ---------------------------------------------------------------------------------------------

def _summary(**kw):
    return VibeHarnessSummary(overall_status="READY_TO_SHIP", total_whitebox_findings=0, confirmed_whitebox_bugs=0,
                              whitebox_tests_passed=1, whitebox_tests_failed=0, total_threats_modeled=0,
                              critical_threats_count=0, blackbox_tests_passed=0, blackbox_security_breaches=0, **kw)


def _coverage_row(summary, wb_results, tmp_path):
    md = ReportGenerator().generate_markdown_report(
        summary, MultiModelDebateResult(confirmed_findings=[], disputed_findings=[], consensus_summary="c"),
        ThreatModelReport(system_description="s", entrypoints=[], trust_boundaries=[], assets=[], threats=[]),
        wb_results, [], str(tmp_path))
    return next(line for line in md.splitlines() if "Code Line Coverage" in line)


def test_markdown_lists_both_languages_only_when_js_coverage_applies(tmp_path):
    py_result = TestExecutionResult(test_id="P", test_type="whitebox_unit", status=TestStatus.PASSED)
    js_result = TestExecutionResult(test_id="J", test_type="whitebox_unit", status=TestStatus.PASSED,
                                    language="javascript")
    assert "`88.0%`" in _coverage_row(_summary(line_coverage_pct=88.0), [py_result], tmp_path)  # 純 Python 維持原樣 ／ Python-only unchanged
    row = _coverage_row(_summary(line_coverage_pct=88.0, js_line_coverage_pct=71.4), [py_result, js_result], tmp_path)
    assert "`Python 88.0% / JS/TS 71.4%`" in row and "程式碼行涵蓋率" in row
    assert "`Python N/A / JS/TS N/A`" in _coverage_row(_summary(), [js_result], tmp_path)


def test_json_summary_carries_js_line_coverage_additively(tmp_path):
    payload = json.loads(ReportGenerator().generate_json_report(
        _summary(line_coverage_pct=None, js_line_coverage_pct=71.4),
        MultiModelDebateResult(confirmed_findings=[], disputed_findings=[], consensus_summary="c"),
        ThreatModelReport(system_description="s", entrypoints=[], trust_boundaries=[], assets=[], threats=[]),
        [], [], str(tmp_path)))
    assert payload["schema_version"] == "2"  # 新增欄位不改版 ／ an additive field keeps the version
    assert payload["summary"]["js_line_coverage_pct"] == 71.4 and payload["summary"]["line_coverage_pct"] is None


# --- 真正的 Node 執行 ---------------------------------------------------------------------------------
# --- Real Node runs ----------------------------------------------------------------------------------------

_ESM_LIB = ("export function add(a, b) {\n  if (a > 100) {\n    return -1;\n  }\n  return a + b;\n}\n"
            "export function neg(x) {\n  return -x;\n}\n")
_CJS_LIB = ("function add(a, b) {\n  if (a > 100) {\n    return -1;\n  }\n  return a + b;\n}\n"
            "function neg(x) {\n  return -x;\n}\nmodule.exports = { add, neg };\n")


def _run_two_modules(target, imports, sandbox):
    """兩個模組各自走 add 的一條分支；回傳 (只跑 A, 只跑 B) 的 JS/TS 涵蓋率，以及兩個一起跑的 SuiteResult。
    Two modules, each taking one branch of add; returns the JS/TS coverage of (A alone, B alone) and the SuiteResult
    of both together."""
    a = _js_test("A", _esm_test(imports, 'test("small", () => { assert.equal(add(1, 2), 3); });'))
    b = _js_test("B", _esm_test(imports, 'test("big", () => { assert.equal(add(101, 2), -1); });'))
    singles = []
    for t in (a, b):
        executor = TestSuiteExecutor(sandbox=None, js_sandbox_factory=lambda: sandbox, per_test_timeout_seconds=30)
        single = executor.execute_test_suite([t], working_dir=str(target), collect_coverage=True)
        assert single.results[0].status == TestStatus.PASSED, single.results[0].failure_reason
        singles.append(single.js_coverage_pct)
    executor = TestSuiteExecutor(sandbox=None, js_sandbox_factory=lambda: sandbox, per_test_timeout_seconds=30)
    suite = executor.execute_test_suite([a, b], working_dir=str(target), collect_coverage=True)
    assert all(r.status == TestStatus.PASSED for r in suite.results) and suite.python_coverage_pct is None
    return singles, suite


def _assert_union(singles, suite):
    pct_a, pct_b = singles
    union = suite.js_coverage_pct
    assert pct_a is not None and pct_b is not None and union is not None, suite.js_coverage_problem
    # 各自走一條分支：聯集比任何一個單獨的模組都高，但 neg() 從未被呼叫，所以不到 100%
    # Each takes one branch: the union beats either module alone, but neg() was never called, so it is below 100%
    assert max(pct_a, pct_b) < union < 100.0


def _lines_of(sandbox, target, test):
    """直接對沙盒跑一個模組並回傳合併後的逐行涵蓋率 ／ Runs one module on the sandbox and returns the merged per-line coverage."""
    sink = JsLineCoverage()
    sandbox.execute_pytest_files({"test_vh_000.mjs": test.code}, working_dir=str(target), collect_coverage=True,
                                 coverage_target=str(target), coverage_sink=sink)
    return sink


@node_coverage_only
def test_real_node_esm_target_union_across_two_modules(tmp_path):
    target = tmp_path / "app"
    (target / "node_modules" / "dep").mkdir(parents=True)
    (target / "node_modules" / "dep" / "package.json").write_text('{"name": "dep", "type": "module", "main": "i.js"}',
                                                                  encoding="utf-8")
    (target / "node_modules" / "dep" / "i.js").write_text("export const one = 1;\n", encoding="utf-8")
    (target / "lib.mjs").write_text(_ESM_LIB, encoding="utf-8")
    (target / "unused.mjs").write_text("export const z = 1;\n", encoding="utf-8")
    sandbox = NodeSubprocessSandbox(timeout_seconds=60, node_version=_NODE_VERSION)
    imports = f'import {{ add }} from "{target_file_url(str(target / "lib.mjs"))}";\nimport {{ one }} from "dep";'
    singles, suite = _run_two_modules(target, imports, sandbox)
    _assert_union(singles, suite)
    sink = _lines_of(sandbox, target, _js_test("A", _esm_test(imports, 'test("s", () => { assert.equal(add(one, 2), 3); });')))
    # 只有目標自己載入過的檔案：沒有 node_modules、沒有產生的測試模組、沒有從未載入的 unused.mjs
    # Only the target's own loaded files: no node_modules, no generated test module, no never-loaded unused.mjs
    assert list(sink.files) == ["lib.mjs"]
    assert sink.files["lib.mjs"][3] is False and sink.files["lib.mjs"][5] is True


@node_coverage_only
def test_real_node_cjs_target_union_across_two_modules(tmp_path):
    target = tmp_path / "legacy"
    target.mkdir()
    (target / "lib.cjs").write_text(_CJS_LIB, encoding="utf-8")
    url = target_file_url(str(target / "lib.cjs"))
    imports = f'import lib from "{url}";\nconst {{ add }} = lib;'
    sandbox = NodeSubprocessSandbox(timeout_seconds=60, node_version=_NODE_VERSION)
    singles, suite = _run_two_modules(target, imports, sandbox)
    _assert_union(singles, suite)


@pytest.mark.skipif(not _TS_OK, reason=f"Node >= 22.6 (type stripping) with the lcov reporter unavailable (found {_FOUND})")
def test_real_node_typescript_target_coverage(tmp_path):
    target = tmp_path / "svc"
    target.mkdir()
    (target / "lib.ts").write_text(
        "export function add(a: number, b: number): number {\n  if (a > 100) {\n    return -1;\n  }\n"
        "  return a + b;\n}\nexport function neg(x: number): number {\n  return -x;\n}\n", encoding="utf-8")
    imports = f'import {{ add }} from "{target_file_url(str(target / "lib.ts"))}";'
    sandbox = NodeSubprocessSandbox(timeout_seconds=60, strip_types=True, node_version=_NODE_VERSION)
    singles, suite = _run_two_modules(target, imports, sandbox)
    _assert_union(singles, suite)


# --- Docker 容器 -------------------------------------------------------------------------------------
# --- Docker container ----------------------------------------------------------------------------------

def _docker_node_ready():
    if not shutil.which("docker"):
        return False
    return subprocess.run(["docker", "image", "inspect", DEFAULT_DOCKER_NODE_IMAGE], capture_output=True).returncode == 0


_DOCKER_NODE_REQUIRED = os.environ.get("VIBEHARNESS_REQUIRE_DOCKER_NODE") == "1"
if _DOCKER_NODE_REQUIRED and not _docker_node_ready():
    raise RuntimeError(f"VIBEHARNESS_REQUIRE_DOCKER_NODE=1 but Docker or image {DEFAULT_DOCKER_NODE_IMAGE} is unavailable")


@pytest.mark.skipif(not _docker_node_ready(), reason=f"Docker or image {DEFAULT_DOCKER_NODE_IMAGE} unavailable")
def test_node_container_collects_js_coverage_from_the_mounted_target(tmp_path):
    target = tmp_path / "app"
    target.mkdir()
    (target / "lib.mjs").write_text(_ESM_LIB, encoding="utf-8")
    sandbox = NodeDockerSandbox(timeout_seconds=60)
    sandbox.node_version = VibeHarnessCommander._docker_node_version(sandbox)
    assert sandbox.node_version is not None and sandbox.js_coverage_problem() is None
    imports = f'import {{ add }} from "{target_file_url(str(target / "lib.mjs"))}";'
    singles, suite = _run_two_modules(target, imports, sandbox)
    _assert_union(singles, suite)
    sink = _lines_of(sandbox, target, _js_test("A", _esm_test(imports, 'test("s", () => { assert.equal(add(1, 2), 3); });')))
    assert list(sink.files) == ["lib.mjs"]  # 容器路徑已對應回目標相對路徑 ／ container paths mapped back to target-relative paths
