"""第三輪審查（執行器／沙盒／JS 涵蓋率）的回歸測試：目標自己解析檔案時的 SyntaxError 不算載入失敗、JS 寫入碰到
單檔大小上限（EFBIG）是 harness 錯誤、極深的輔助函式鏈不讓靜態閘門崩潰、暫存目錄與 V8 涵蓋率資料留在執行目錄裡、
涵蓋率 glob 篩選的實驗功能警告不汙染 stderr、位於 node_modules 底下的目標仍收得到涵蓋率，以及 Windows 上大小寫不同的
同一個模組不重複計算。
Regression tests for the third review round (executor / sandbox / JS coverage): a SyntaxError from the target parsing
a file itself is not a load failure, a JS write hitting the per-file size cap (EFBIG) is a harness error, a very deep
helper chain cannot crash the static gate, temp files and V8 coverage data stay inside the run directory, the
coverage glob filters' experimental warning does not pollute stderr, a target living under node_modules still gets
coverage, and the same module spelled in different letter case on Windows is not counted twice."""
import glob
import os
import sys
import tempfile

import pytest

import vibeharness.core.sandbox as sandbox_mod
from vibeharness.core.codecheck import check_test_code
from vibeharness.core.codecontext import target_file_url
from vibeharness.core.jscoverage import (
    JsLineCoverage, node_coverage_args, node_coverage_problem, strip_coverage_glob_warning, target_relative_path,
)
from vibeharness.core.models import GeneratedTest, TestStatus
from vibeharness.core.sandbox import (
    LocalSubprocessSandbox, NodeSubprocessSandbox, detect_node, sandbox_temp_env,
)
from vibeharness.runners.test_executor import REASON_NOT_RUN_CORRECTLY, REASON_TARGET_BROKEN, TestSuiteExecutor

_NODE_PATH, _NODE_VERSION, _NODE_PROBLEM = detect_node("node")
node_only = pytest.mark.skipif(_NODE_PATH is None, reason=f"Node unavailable: {_NODE_PROBLEM}")
node_coverage_only = pytest.mark.skipif(_NODE_PATH is None or node_coverage_problem(_NODE_VERSION) is not None,
                                        reason="Node with JS coverage support unavailable")
node_globs_only = pytest.mark.skipif(_NODE_VERSION is None or _NODE_VERSION < (22, 5, 0) or _NODE_PATH is None,
                                     reason="Node >= 22.5 (coverage include / exclude) unavailable")
posix_only = pytest.mark.skipif(sys.platform == "win32", reason="POSIX rlimit / temp-dir semantics")


def _test(test_id, code, language="python", test_type="whitebox_unit"):
    return GeneratedTest(test_id=test_id, test_type=test_type, target_component="x", title=f"t {test_id}",
                         code=code, rationale="", expected_outcome="", language=language)


def _esm_test(imports, body):
    return f'import {{ test }} from "node:test";\nimport assert from "node:assert/strict";\n{imports}\n{body}\n'


class _PySandbox:
    """這些測試不跑 Python 模組 ／ These tests run no Python module."""

    timeout_seconds = 30


def _js_executor(sandbox, **kwargs):
    return TestSuiteExecutor(sandbox=_PySandbox(), js_sandbox_factory=lambda: sandbox, **kwargs)


# --- 1. 目標自己用 compile()／ast.parse() 解析檔案拋出的 SyntaxError 是缺陷，不是載入失敗 ----------------
# --- 1. A SyntaxError the target raises by parsing a file with compile() / ast.parse() is a defect -----

_APP = (
    "import ast\n"
    "import importlib\n"
    "def comp(path):\n"
    "    with open(path, encoding='utf-8') as f:\n"
    "        return compile(f.read(), path, 'exec')\n"
    "def parse(path):\n"
    "    with open(path, encoding='utf-8') as f:\n"
    "        return ast.parse(f.read(), filename=path)\n"
    "def sub():\n"
    "    import r3_badsub\n"
    "    return r3_badsub.x\n"
    "def dyn():\n"
    "    return importlib.import_module('r3_badsub').x\n"
)


@pytest.fixture
def target(tmp_path):
    (tmp_path / "r3_app.py").write_text(_APP, encoding="utf-8")
    (tmp_path / "r3_badsub.py").write_text("x = (\n", encoding="utf-8")
    (tmp_path / "user_input.py").write_text("y = (\n", encoding="utf-8")
    return tmp_path


def test_target_parsing_a_real_file_is_a_defect_but_importing_a_broken_module_is_target_broken(target):
    user_file = str(target / "user_input.py")
    executor = TestSuiteExecutor(LocalSubprocessSandbox(timeout_seconds=60))
    results, _ = executor.execute_test_suite([
        _test("COMPILE", f"import r3_app\n\ndef test_a():\n    assert r3_app.comp({user_file!r})\n"),
        _test("AST", f"import r3_app\n\ndef test_a():\n    assert r3_app.parse({user_file!r})\n"),
        _test("SUB", "import r3_app\n\ndef test_a():\n    assert r3_app.sub() == 1\n"),
        _test("DYN", "import r3_app\n\ndef test_a():\n    assert r3_app.dyn() == 1\n"),
        _test("IN_TEST", "def test_a():\n    import r3_badsub\n    assert r3_badsub.x\n"),
    ], working_dir=str(target))
    by_id = {r.test_id: r for r in results}
    # 目標沒有包住自己解析時的錯誤：缺陷（FAILED），即使檔名是真實的 .py 路徑
    # The target does not wrap its own parsing error: a defect (FAILED), even under a real .py file name
    for test_id in ("COMPILE", "AST"):
        assert by_id[test_id].status == TestStatus.FAILED, (test_id, by_id[test_id].failure_reason)
        assert not by_id[test_id].is_security_exploit_confirmed
    # 匯入壞掉的子模組（import 陳述式或 importlib.import_module）：目標載入不了
    # Importing a broken submodule (an import statement or importlib.import_module): the target cannot load
    for test_id in ("SUB", "DYN", "IN_TEST"):
        result = by_id[test_id]
        assert result.status == TestStatus.ERROR, (test_id, result.failure_reason)
        assert result.failure_reason.startswith(REASON_TARGET_BROKEN), (test_id, result.failure_reason)


def test_target_failed_to_load_unit_cases():
    loaded = TestSuiteExecutor._target_failed_to_load
    syntax = 'E     File "/srv/app/sub.py", line 1\nE       x = (\nE   SyntaxError: \'(\' was never closed\n\n'
    sep = "\n_ _ _ _ _ _ _ _ _ _\n\n"
    import_stmt = {"message": "", "details": "def test_a():\n>       r()\n\n/run/test_vh_000.py:4: " + sep
                   + "    def sub():\n>       import sub\n" + syntax + "/srv/app/app.py:3: SyntaxError"}
    assert loaded(import_stmt)
    from_stmt = dict(import_stmt, details=import_stmt["details"].replace("import sub", "from pkg import sub"))
    assert loaded(from_stmt)
    machinery = {"message": "", "details": "<frozen importlib._bootstrap>:1387: in _gcd_import\n    ???" + sep
                 + ">   ???\n" + syntax + "<frozen importlib._bootstrap>:488: SyntaxError"}
    assert loaded(machinery)
    compiled = {"message": "", "details": "    def comp(path):\n>       return compile(src, path, 'exec')\n" + syntax
                + "/srv/app/app.py:7: SyntaxError"}
    assert not loaded(compiled)
    parsed = {"message": "", "details": "/srv/app/app.py:9: in parse\n    return ast.parse(s, filename=p)" + sep
              + ">       return compile(source, filename, mode, flags,\n" + syntax + "/usr/lib/python3.12/ast.py:52: SyntaxError"}
    assert not loaded(parsed)
    # 錯誤指向的不是 .py 原始檔（目標解析的設定檔之類），即使從匯入行拋出也不算
    # The error points at something other than a .py source (a config file the target parses): never a load failure
    assert not loaded(dict(import_stmt, details=import_stmt["details"].replace("/srv/app/sub.py", "/srv/app/conf.txt")))
    # 延遲匯入沙盒中沒有的選用套件仍是 ERROR（刻意的設計）
    # A lazy import of an optional package missing from the sandbox stays an ERROR (by design)
    lazy = {"message": "", "details": ">       import yaml\nE   ModuleNotFoundError: No module named 'yaml'\n\n"
            "/srv/app/app.py:2: ModuleNotFoundError"}
    assert loaded(lazy)


# --- 2. JS 寫入碰到單檔大小上限（EFBIG）是 harness 錯誤 -------------------------------------------------
# --- 2. A JS write hitting the per-file size cap (EFBIG) is a harness error -----------------------------

def _js_case(details):
    return {"name": "writes", "message": "EFBIG: file too large, write", "details": details}


def test_js_efbig_classification_needs_the_system_error_fields():
    harness = TestSuiteExecutor._js_is_harness_failure
    system = ("[Error [ERR_TEST_FAILURE]: EFBIG: file too large, write] {\n  code: 'ERR_TEST_FAILURE',\n"
              "  cause: Error: EFBIG: file too large, write\n      at Object.writeSync (node:fs:924:3)\n"
              "      at big (file:///srv/app/app.mjs:3:31) {\n    errno: -27,\n    syscall: 'write',\n"
              "    code: 'EFBIG'\n  }\n}\n")
    assert harness(_js_case(system))
    # 目標自己 new Error('EFBIG: ...') 拋出（沒有 errno）：維持為目標的行為
    # The target throwing new Error('EFBIG: ...') itself (no errno): stays target behaviour
    forged = system.replace("    errno: -27,\n    syscall: 'write',\n", "")
    assert not harness(_js_case(forged))


@node_only
@posix_only
def test_real_node_write_beyond_the_cap_is_an_error_not_a_defect(tmp_path, monkeypatch):
    monkeypatch.setattr(sandbox_mod, "SANDBOX_MAX_FILE_BYTES", 2 * 1024 * 1024)
    (tmp_path / "app.mjs").write_text(
        'import fs from "node:fs";\nimport path from "node:path";\n'
        'export function big(dir) { fs.writeFileSync(path.join(dir, "big.bin"), Buffer.alloc(4 * 1024 * 1024)); '
        'return 1; }\n'
        'export function own() { const e = new Error("EFBIG: file too large, write"); e.code = "EFBIG"; throw e; }\n',
        encoding="utf-8")
    imports = f'import {{ big, own }} from "{target_file_url(str(tmp_path / "app.mjs"))}";\nimport os from "node:os";'
    executor = _js_executor(NodeSubprocessSandbox(timeout_seconds=60))
    results, _ = executor.execute_test_suite([
        _test("BIG", _esm_test(imports, 'test("b", () => { assert.equal(big(os.tmpdir()), 1); });'), "javascript"),
        _test("OWN", _esm_test(imports, 'test("o", () => { assert.equal(own(), 1); });'), "javascript"),
    ], working_dir=str(tmp_path))
    big, own = results
    assert big.status == TestStatus.ERROR and big.failure_reason.startswith(REASON_NOT_RUN_CORRECTLY)
    assert "EFBIG" in big.failure_reason
    assert own.status == TestStatus.FAILED  # 目標自己拋出的同樣訊息 ／ the same message thrown by the target itself


# --- 3. 極深的輔助函式鏈不讓靜態閘門崩潰 ---------------------------------------------------------------
# --- 3. A very deep helper chain cannot crash the static gate --------------------------------------------

def _chain(depth, leaf):
    helpers = "".join(f"def h{i}():\n    h{i + 1}()\n" for i in range(depth))
    return helpers + f"def h{depth}():\n    {leaf}\n" + "def test_a():\n    h0()\n"


def test_deep_helper_chain_is_walked_without_recursion():
    assert check_test_code(_chain(3000, "assert 1")) == (True, None)
    ok, problem = check_test_code(_chain(3000, "pass"))
    assert not ok and "without any assertion" in problem
    methods = "".join(f"    def m{i}(self):\n        self.m{i + 1}()\n" for i in range(3000))
    cls = f"class TestDeep:\n{methods}    def m3000(self):\n        assert 1\n    def test_a(self):\n        self.m0()\n"
    assert check_test_code(cls) == (True, None)


# --- 4. 暫存目錄與 V8 涵蓋率資料留在執行目錄裡 ---------------------------------------------------------
# --- 4. Temp files and V8 coverage data stay inside the run directory ------------------------------------

def test_sandbox_temp_env_points_inside_the_run_dir(tmp_path):
    env = sandbox_temp_env(str(tmp_path))
    temp = str(tmp_path / "tmp")
    assert env == {"TMPDIR": temp, "TMP": temp, "TEMP": temp} and os.path.isdir(temp)


def test_python_sandbox_child_temp_dir_is_inside_the_run_dir(tmp_path):
    code = ("import os, tempfile\n"
            "def test_a():\n"
            "    here = os.path.dirname(os.path.abspath(__file__))\n"
            "    assert os.path.realpath(tempfile.gettempdir()) == os.path.realpath(os.path.join(here, 'tmp'))\n")
    results, _ = TestSuiteExecutor(LocalSubprocessSandbox(timeout_seconds=60)).execute_test_suite(
        [_test("TMP", code)], working_dir=str(tmp_path))
    assert results[0].status == TestStatus.PASSED, results[0].failure_reason


def test_node_command_env_pins_v8_coverage_inside_the_run_dir(tmp_path):
    sandbox = NodeSubprocessSandbox(timeout_seconds=30, node_version=(22, 14, 0))
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    _, _, env = sandbox._build_command(str(run_dir), ["test_vh_000.mjs"], str(tmp_path), True, None,
                                       {"NODE_V8_COVERAGE": "/elsewhere"})
    assert env["NODE_V8_COVERAGE"] == str(run_dir / "v8-coverage")
    assert env["TMPDIR"] == env["TMP"] == env["TEMP"] == str(run_dir / "tmp")


@node_coverage_only
@posix_only
def test_timed_out_js_module_with_coverage_leaves_nothing_in_the_host_temp_dir(tmp_path, monkeypatch):
    host_tmp = tmp_path / "host-tmp"
    host_tmp.mkdir()
    monkeypatch.setenv("TMPDIR", str(host_tmp))
    monkeypatch.setattr(tempfile, "tempdir", str(host_tmp))
    sandbox = NodeSubprocessSandbox(timeout_seconds=3, node_version=_NODE_VERSION)
    executor = _js_executor(sandbox, per_test_timeout_seconds=2)
    hang = _test("HANG", _esm_test("", 'test("spin", () => { while (true) {} assert.ok(1); });'), "javascript")
    results, _ = executor.execute_test_suite([hang], working_dir=str(tmp_path), collect_coverage=True)
    assert results[0].status == TestStatus.ERROR and "timed out" in results[0].failure_reason
    assert os.listdir(host_tmp) == []  # 沒有 node-coverage-XXXX，執行目錄也已刪除 ／ no node-coverage-XXXX, the run dir is gone too
    assert not glob.glob(str(host_tmp / "node-coverage-*"))


# --- 5. 涵蓋率 glob 篩選的實驗功能警告不汙染 stderr ----------------------------------------------------
# --- 5. The coverage glob filters' experimental warning does not pollute stderr --------------------------

def test_strip_coverage_glob_warning_removes_only_that_warning():
    warning = ("(node:123) ExperimentalWarning: glob is an experimental feature and might change at any time\n"
               "(Use `node --trace-warnings ...` to show where the warning was created)\n")
    assert strip_coverage_glob_warning(warning + "Error: real\n") == "Error: real\n"
    assert strip_coverage_glob_warning(warning.rstrip("\n")) == ""
    other = "(node:123) ExperimentalWarning: Type Stripping is an experimental feature\n"
    assert strip_coverage_glob_warning(other) == other
    assert strip_coverage_glob_warning("") == ""


@node_globs_only
def test_real_node_coverage_run_has_no_glob_warning_on_stderr(tmp_path):
    (tmp_path / "lib.mjs").write_text("export const add = (a, b) => a + b;\n", encoding="utf-8")
    code = _esm_test(f'import {{ add }} from "{target_file_url(str(tmp_path / "lib.mjs"))}";',
                     'test("a", () => { assert.equal(add(1, 2), 3); });')
    sandbox = NodeSubprocessSandbox(timeout_seconds=60, node_version=_NODE_VERSION)
    _, _, stderr, _, pct, _ = sandbox.execute_pytest_files({"test_vh_000.mjs": code}, working_dir=str(tmp_path),
                                                           collect_coverage=True, coverage_sink=JsLineCoverage())
    assert pct == 100.0
    assert "ExperimentalWarning" not in stderr, stderr


# --- 6. 位於 node_modules 底下的目標仍收得到涵蓋率 ---------------------------------------------------------
# --- 6. A target living under node_modules still gets coverage ---------------------------------------------

def test_node_modules_exclusion_is_relative_to_the_target_root():
    _, filters = node_coverage_args((22, 14, 0), "/x/node_modules/pkg", windows=False)
    assert filters == ["--test-coverage-include=/x/node_modules/pkg/**",
                       "--test-coverage-exclude=/x/node_modules/pkg/**/node_modules/**",
                       "--test-coverage-exclude=**/test_vh_*"]
    # Windows 路徑改成正斜線後同樣只排除目標底下的 node_modules；含 glob 特殊字元時才退回排除任何 node_modules
    # A Windows path, rewritten to forward slashes, likewise excludes only node_modules under the target; a path
    # with glob metacharacters falls back to excluding every node_modules
    _, win = node_coverage_args((22, 14, 0), r"C:\x\node_modules\pkg")
    assert win[0] == "--test-coverage-include=C:/x/node_modules/pkg/**"
    assert "--test-coverage-exclude=C:/x/node_modules/pkg/**/node_modules/**" in win
    assert "--test-coverage-exclude=**/node_modules/**" in node_coverage_args((22, 14, 0), r"C:\x\app (1)")[1]
    roots = ["/x/node_modules/pkg"]
    assert target_relative_path("/x/node_modules/pkg/m.mjs", roots, windows=False) == "m.mjs"
    assert target_relative_path("/x/node_modules/pkg/node_modules/dep/d.mjs", roots, windows=False) is None


@node_globs_only
def test_real_node_target_under_node_modules_is_covered(tmp_path):
    target = tmp_path / "node_modules" / "pkg"
    (target / "node_modules" / "dep").mkdir(parents=True)
    (target / "node_modules" / "dep" / "d.mjs").write_text("export const g = (x) => x;\n", encoding="utf-8")
    (target / "m.mjs").write_text('import { g } from "./node_modules/dep/d.mjs";\nexport const f = (x) => g(x) + 1;\n',
                                  encoding="utf-8")
    code = _esm_test(f'import {{ f }} from "{target_file_url(str(target / "m.mjs"))}";',
                     'test("a", () => { assert.equal(f(1), 2); });')
    sink = JsLineCoverage()
    NodeSubprocessSandbox(timeout_seconds=60, node_version=_NODE_VERSION).execute_pytest_files(
        {"test_vh_000.mjs": code}, working_dir=str(target), collect_coverage=True, coverage_sink=sink)
    assert list(sink.files) == ["m.mjs"]


# --- 7. 版本門檻的說明 -------------------------------------------------------------------------------------
# --- 7. The version gate's explanation ------------------------------------------------------------------

def test_coverage_problem_names_the_real_gate():
    problem = node_coverage_problem((20, 10, 0))
    assert problem and "--disable-warning" in problem and "lcov test reporter" not in problem


# --- 8. Windows 上大小寫不同的同一個模組不重複計算 --------------------------------------------------------
# --- 8. The same module in different letter case on Windows is not counted twice -----------------------------

def test_windows_letter_case_variants_merge_into_one_file():
    lcov = ("SF:C:\\Proj\\App\\src\\Lib.mjs\nDA:1,1\nDA:2,0\nend_of_record\n"
            "SF:c:\\proj\\app\\SRC\\lib.mjs\nDA:1,0\nDA:2,1\nend_of_record\n")
    coverage = JsLineCoverage()
    coverage.add_lcov(lcov, [r"C:\Proj\App"], r"C:\Proj\App", windows=True)
    assert coverage.files == {"src/lib.mjs": {1: True, 2: True}}
    assert coverage.percent() == 100.0
    # POSIX 規則下大小寫有意義：兩個不同的檔案 ／ under the POSIX rules letter case matters: two different files
    posix = JsLineCoverage()
    posix.add_lcov("SF:/a/Lib.mjs\nDA:1,1\nend_of_record\nSF:/a/lib.mjs\nDA:1,0\nend_of_record\n", ["/a"], "/a",
                   windows=False)
    assert sorted(posix.files) == ["Lib.mjs", "lib.mjs"]
