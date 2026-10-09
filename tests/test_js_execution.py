"""JavaScript / TypeScript dynamic execution: the JS code gate, module-kind detection and import
instructions, Node JUnit parsing and classification, the Node sandboxes (real `node` when available,
forced with VIBEHARNESS_REQUIRE_NODE=1), the executor's language split and the harness evidence gaps."""
import json
import os
import pathlib
import shutil
import subprocess
import textwrap

import pytest

from vibeharness.core.codecheck import check_js_test_code, check_test_code_for
from vibeharness.core.codecontext import (
    import_instructions, js_exported_names, js_module_kind, language_for_file, target_file_url,
)
from vibeharness.core.harness import VibeHarnessCommander
from vibeharness.core.models import GeneratedTest, TestStatus
from vibeharness.core.sandbox import (
    DEFAULT_DOCKER_NODE_IMAGE, MIN_NODE_VERSION, TIMEOUT_EXIT_CODE, NodeDockerSandbox, NodeSubprocessSandbox,
    detect_node, node_test_command, parse_node_version,
)
from vibeharness.runners.test_executor import TestSuiteExecutor

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG = os.path.join(REPO_ROOT, "vibeharness", "config", "agents_config.yaml")

_NODE_PATH, _NODE_VERSION, _NODE_PROBLEM = detect_node("node")
_NODE_REQUIRED = os.environ.get("VIBEHARNESS_REQUIRE_NODE") == "1"
if _NODE_REQUIRED and _NODE_PATH is None:
    raise RuntimeError(f"VIBEHARNESS_REQUIRE_NODE=1 but no usable Node runtime: {_NODE_PROBLEM}")
node_only = pytest.mark.skipif(_NODE_PATH is None, reason=f"Node >= {MIN_NODE_VERSION} unavailable: {_NODE_PROBLEM}")
_TS_OK = _NODE_VERSION is not None and _NODE_VERSION >= (22, 6, 0)
node_ts_only = pytest.mark.skipif(not _TS_OK, reason="Node >= 22.6 (type stripping) unavailable")


def _js_test(test_id, code, language="javascript", test_type="whitebox_unit"):
    return GeneratedTest(test_id=test_id, test_type=test_type, target_component="x", title=f"t {test_id}",
                         code=code, rationale="", expected_outcome="", language=language)


def _py_test(test_id, code):
    return GeneratedTest(test_id=test_id, test_type="whitebox_unit", target_component="x", title=f"t {test_id}",
                         code=code, rationale="", expected_outcome="")


def _esm_test(url, body):
    return f'import {{ test }} from "node:test";\nimport assert from "node:assert/strict";\n{url}\n{body}\n'


# --- The JS code gate -------------------------------------------------------------------------------

GOOD = textwrap.dedent('''
    import { test } from "node:test";
    import assert from "node:assert/strict";
    import { add } from "file:///tmp/app.mjs";

    test("adds", () => {
      assert.equal(add(1, 2), 3);
    });
    it("throws on null", () => {
      assert.throws(() => add(null, 1));
    });
''')


def test_gate_accepts_a_node_test_module():
    assert check_js_test_code(GOOD) == (True, None)
    assert check_test_code_for(GOOD, "typescript") == (True, None)


@pytest.mark.parametrize("code,problem", [
    ("", "empty"),
    ("   \n", "empty"),
    ("test('x', () => { assert.ok(1\x00) })", "NUL"),
    ("test('x', () => { assert.ok(1); }", "unbalanced"),
    ("test('x', () => { assert.ok(1)); });", "unbalanced"),
    ("const x = 1;\nassert.ok(x);", "no test()/it() call"),
    ("test('vacuous one', () => { const y = 1; });", "without any assertion: vacuous one"),
    ("test('a', () => { assert.ok(1); });\ntest('needs assert', () => { console.log(1); });",
     "without any assertion: needs assert"),
    ("import { execSync } from 'node:child_process';\ntest('x', () => { execSync('npm install left-pad'); assert.ok(1); });",
     "installs packages"),
    ("test('x', async () => { await $`pnpm add evil`; assert.ok(1); });", "installs packages"),
    ("test('x', () => { require('child_process').execSync('yarn add evil'); assert.ok(1); });", "installs packages"),
    ("test('x', () => { spawnSync('bun', ['install']); assert.ok(1); });", "installs packages"),
    ("test('x', () => { spawnSync('npx', ['cowsay']); assert.ok(1); });", "installs packages"),
])
def test_gate_rejects(code, problem):
    ok, reason = check_js_test_code(code)
    assert not ok and problem in reason


def test_gate_ignores_strings_and_comments_for_delimiters_and_test_calls():
    code = textwrap.dedent('''
        // test("commented out", () => {})
        const s = "a ( string with { unbalanced";
        test("real", () => { assert.equal(s.length, 24); });
    ''')
    assert check_js_test_code(code) == (True, None)
    only_in_string = 'const s = "test(\\"x\\", () => {})";\nassert.ok(s);'
    assert check_js_test_code(only_in_string)[1] == "no test()/it() call defined"


def test_gate_counts_throw_and_rejects_as_assertions():
    code = 'test("a", async () => { await assert.rejects(f()); });\ntest("b", () => { if (!g()) throw new Error("x"); });'
    assert check_js_test_code(code) == (True, None)


def test_python_gate_is_still_used_for_python():
    assert check_test_code_for("def test_a():\n    assert 1 == 1\n", "python") == (True, None)
    assert check_test_code_for(GOOD, "python")[0] is False


# --- Module kind, exports, import instructions -----------------------------------------------------

def test_language_for_file():
    assert language_for_file("a.ts") == "typescript" and language_for_file("a.tsx") == "typescript"
    assert language_for_file("a.mjs") == "javascript" and language_for_file("a.cjs") == "javascript"
    assert language_for_file("a.jsx") == "javascript"
    assert language_for_file("a.py") == "python" and language_for_file("a.go") == "python"


@pytest.mark.parametrize("name,source,expected", [
    ("a.mjs", "module.exports = 1", "esm"),
    ("a.mts", "", "esm"),
    ("a.cjs", "export const x = 1", "cjs"),
    ("a.cts", "", "cjs"),
    ("a.js", "import fs from 'node:fs';\nexport function f() {}", "esm"),
    ("a.js", "export default function f() {}", "esm"),
    ("a.js", "const fs = require('node:fs');\nmodule.exports = { f };", "cjs"),
    ("a.js", "exports.f = () => 1;", "cjs"),
    ("a.js", "// export const fake = 1\nconst s = 'require(\"x\")';\nfunction f() {}", "unknown"),
    ("a.js", "const p = import('./lazy.js');", "unknown"),  # a dynamic import() is valid in both systems
])
def test_js_module_kind_from_extension_and_syntax(tmp_path, name, source, expected):
    path = tmp_path / name
    path.write_text(source, encoding="utf-8")
    assert js_module_kind(str(path)) == expected
    assert js_module_kind(str(path), source) == expected


def test_js_module_kind_falls_back_to_the_nearest_package_json(tmp_path):
    (tmp_path / "package.json").write_text('{"type": "module"}', encoding="utf-8")
    nested = tmp_path / "src" / "lib"
    nested.mkdir(parents=True)
    plain = nested / "a.js"
    plain.write_text("function f() {}", encoding="utf-8")
    assert js_module_kind(str(plain)) == "esm"
    (tmp_path / "src" / "package.json").write_text('{"name": "x"}', encoding="utf-8")  # no type: CommonJS
    assert js_module_kind(str(plain)) == "cjs"
    (tmp_path / "src" / "package.json").write_text("{not json", encoding="utf-8")
    assert js_module_kind(str(plain)) == "unknown"
    assert js_module_kind(str(tmp_path / "missing.js")) in ("esm", "unknown")  # unreadable: package.json decides


def test_js_exported_names_in_order_and_deduplicated(tmp_path):
    source = textwrap.dedent('''
        export function alpha() {}
        export default class Beta {}
        export const gamma = 1, delta = 2;
        export async function* epsilon() {}
        export { zeta, eta as theta };
        exports.iota = 1;
        module.exports = { kappa, lambda: 1, alpha };
        // export function commented() {}
        const s = "export const inString = 1";
    ''')
    names = js_exported_names("x.js", source)
    assert names[:4] == ["alpha", "Beta", "gamma", "epsilon"]
    assert "zeta" in names and "theta" in names and "iota" in names and "kappa" in names and "lambda" in names
    assert "commented" not in names and "inString" not in names and names.count("alpha") == 1
    assert js_exported_names(str(tmp_path / "missing.js")) == []
    assert len(js_exported_names("x.js", "\n".join(f"export const n{i} = 1;" for i in range(50)), limit=5)) == 5


def test_import_instructions_for_esm_cjs_and_typescript(tmp_path):
    esm = tmp_path / "esm.js"
    esm.write_text("export function add(a, b) { return a + b; }\n", encoding="utf-8")
    text = import_instructions(str(esm), str(tmp_path), "add")
    assert target_file_url(str(esm)) in text and "Module system: ESM" in text
    assert f'import {{ add }} from "{target_file_url(str(esm))}"' in text
    assert "Exported names detected: add" in text and "never install packages" in text

    cjs = tmp_path / "svc.js"
    cjs.write_text("const x = require('x');\nmodule.exports = { handler };\n", encoding="utf-8")
    text = import_instructions(str(cjs), str(tmp_path), "handler.run")
    assert "Module system: CommonJS" in text and "createRequire" in text and "const { handler } = target" in text

    unknown = tmp_path / "plain.js"
    unknown.write_text("function f() {}\n", encoding="utf-8")
    assert "not detected" in import_instructions(str(unknown), str(tmp_path))

    ts = tmp_path / "typed.ts"
    ts.write_text("export function f(x: number): number { return x; }\n", encoding="utf-8")
    text = import_instructions(str(ts), str(tmp_path), "f")
    assert "TypeScript" in text and "type stripping" in text and '".ts" extension' in text
    assert "importlib" not in text and "sys.path" not in text


def test_target_file_url_shapes():
    posix = target_file_url("/home/u/proj/app.mjs", pathlib.PurePosixPath) if os.name != "nt" else None
    if posix is not None:
        assert posix == "file:///home/u/proj/app.mjs"
    windows = pathlib.PureWindowsPath(r"C:\proj\app.mjs").as_uri()
    assert windows == "file:///C:/proj/app.mjs"
    assert target_file_url("app.mjs").startswith("file:///")


# --- Node JUnit parsing and classification ---------------------------------------------------------

NODE_JUNIT = textwrap.dedent('''\
    <?xml version="1.0" encoding="utf-8"?>
    <testsuites>
    \t<testcase name="ok" time="0.000576" classname="test"/>
    \t<testsuite name="grp" time="0.001181" disabled="0" errors="0" tests="1" failures="1" skipped="0" hostname="vm">
    \t\t<testcase name="bad" time="0.000956" classname="test" failure="Expected values to be strictly equal:1 !== 2">
    \t\t\t<failure type="testCodeFailure" message="Expected values to be strictly equal:1 !== 2">
    Error [ERR_TEST_FAILURE]: Expected values to be strictly equal:

    1 !== 2
      cause: AssertionError [ERR_ASSERTION]: Expected values to be strictly equal:
          at TestContext.&lt;anonymous> (file:///run/test_vh_000.mjs:4:52)
          at Test.runInAsyncScope (node:async_hooks:214:14) {
        code: 'ERR_ASSERTION',
      }
    }
    \t\t\t</failure>
    \t\t</testcase>
    \t</testsuite>
    </testsuites>
    ''')

FILE_FAIL_JUNIT = textwrap.dedent('''\
    <?xml version="1.0" encoding="utf-8"?>
    <testsuites>
    \t<testcase name="/run/test_vh_001.mjs" time="0.048" classname="test" failure="test failed">
    \t\t<failure type="testCodeFailure" message="test failed">
    [Error: test failed] { code: 'ERR_TEST_FAILURE', failureType: 'testCodeFailure', cause: 'test failed', exitCode: 1 }
    \t\t</failure>
    \t</testcase>
    </testsuites>
    ''')

EMPTY_FILE_JUNIT = ('<?xml version="1.0" encoding="utf-8"?>\n<testsuites>\n'
                    '\t<testcase name="/run/test_vh_002.mjs" time="0.02" classname="test"/>\n</testsuites>\n')

SUITE_NAMED_JUNIT = ('<?xml version="1.0" encoding="utf-8"?>\n<testsuites>\n'
                     '<testsuite name="/run/test_vh_007.mjs"><testsuite name="grp">'
                     '<testcase name="deep" time="0.1" classname="test"/></testsuite></testsuite></testsuites>\n')


def test_parse_node_junit_assigns_every_case_to_the_module():
    cases = TestSuiteExecutor._parse_junit(NODE_JUNIT, "javascript", module="test_vh_000")
    assert list(cases) == ["test_vh_000"]
    assert [c["name"] for c in cases["test_vh_000"]] == ["ok", "bad"]
    assert cases["test_vh_000"][1]["outcome"] == "failure"
    assert "ERR_ASSERTION" in cases["test_vh_000"][1]["details"]


def test_parse_node_junit_file_level_cases():
    failed = TestSuiteExecutor._parse_junit(FILE_FAIL_JUNIT, "javascript", module="test_vh_001")
    assert len(failed["test_vh_001"]) == 1 and failed["test_vh_001"][0]["outcome"] == "failure"
    # A passing file-level pseudo-case means "nothing ran": the module exists but has no case
    empty = TestSuiteExecutor._parse_junit(EMPTY_FILE_JUNIT, "javascript", module="test_vh_002")
    assert empty == {"test_vh_002": []}
    # Without a module the file name itself still groups the case (older/other reporters)
    assert TestSuiteExecutor._parse_junit(FILE_FAIL_JUNIT, "javascript") == {
        "test_vh_001": [failed["test_vh_001"][0]]
    }
    # pytest keeps a passing module-named case: only JS drops it
    assert len(TestSuiteExecutor._parse_junit(EMPTY_FILE_JUNIT, "python", module="test_vh_002")["test_vh_002"]) == 1


def test_parse_node_junit_searches_ancestor_suite_names():
    assert list(TestSuiteExecutor._parse_junit(SUITE_NAMED_JUNIT, "javascript")) == ["test_vh_007"]
    assert TestSuiteExecutor._parse_junit("", "javascript", module="test_vh_003") == {"test_vh_003": []}
    assert TestSuiteExecutor._parse_junit("<broken", "javascript", module="test_vh_003") is None


def _case(message, details, name="c"):
    return {"name": name, "time": 0.0, "outcome": "failure", "message": message, "details": details,
            "stdout": "", "stderr": ""}


ASSERTION_CASE = _case("Expected values to be strictly equal:1 !== 2",
                       "Error [ERR_TEST_FAILURE]: x\n  cause: AssertionError [ERR_ASSERTION]: Expected values to be "
                       "strictly equal:\n      at TestContext.<anonymous> (file:///run/test_vh_000.mjs:4:52)\n")
TARGET_TYPEERROR_CASE = _case("Cannot read properties of null (reading 'id')",
                              "Error [ERR_TEST_FAILURE]: x\n  cause: TypeError: Cannot read properties of null (reading 'id')\n"
                              "      at handler (file:///app/svc.mjs:9:20)\n"
                              "      at TestContext.<anonymous> (file:///run/test_vh_000.mjs:6:3)\n")
TEST_SIDE_REFERROR_CASE = _case("nope is not defined",
                                "Error [ERR_TEST_FAILURE]: x\n  cause: ReferenceError: nope is not defined\n"
                                "      at TestContext.<anonymous> (file:///run/test_vh_000.mjs:6:3)\n")
TEST_MODULE_NOT_FOUND = _case("test failed", "[Error: test failed] { cause: 'test failed' }\n"
                              "Error [ERR_MODULE_NOT_FOUND]: Cannot find module '/run/missing.mjs' imported from "
                              "/run/test_vh_000.mjs\n")
TARGET_BROKEN = _case("Cannot find package 'left-pad' imported from /app/svc.mjs",
                      "Error [ERR_TEST_FAILURE]: x\n  cause: Error [ERR_MODULE_NOT_FOUND]: Cannot find package 'left-pad' "
                      "imported from /app/svc.mjs\n      at packageResolve (node:internal/modules/esm/resolve:1:1)\n"
                      "      at file:///app/svc.mjs:1:1\n      at TestContext.<anonymous> (file:///run/test_vh_000.mjs:2:1)\n")


def test_js_case_helpers():
    ex = TestSuiteExecutor
    assert ex._js_is_assertion(ASSERTION_CASE) and not ex._js_is_assertion(TARGET_TYPEERROR_CASE)
    assert ex._js_exception_summary(ASSERTION_CASE).startswith("AssertionError [ERR_ASSERTION]")
    assert ex._js_exception_summary(TARGET_TYPEERROR_CASE).startswith("TypeError: Cannot read")
    assert ex._js_exception_summary(_case("bare message", "no error line here")) == "bare message"
    assert ex._js_exception_summary(_case("m", "SyntaxError: Unexpected token\n    at x")) == "SyntaxError: Unexpected token"
    assert ex._js_raised_in_target_code(TARGET_TYPEERROR_CASE)
    assert not ex._js_raised_in_target_code(TEST_SIDE_REFERROR_CASE)
    assert not ex._js_raised_in_target_code(_case("m", "no frames"))
    assert ex._js_is_harness_failure(TEST_SIDE_REFERROR_CASE)
    assert ex._js_is_harness_failure(TEST_MODULE_NOT_FOUND)
    assert not ex._js_is_harness_failure(TARGET_TYPEERROR_CASE)
    assert not ex._js_is_harness_failure(ASSERTION_CASE)


def test_js_aggregation_classifies_outcomes():
    executor = TestSuiteExecutor(sandbox=None)
    bb = _js_test("BB", "x", test_type="blackbox_security")
    wb = _js_test("WB", "x")
    exploit = executor._aggregate(bb, "BB", [ASSERTION_CASE])
    assert exploit.status == TestStatus.FAILED and exploit.is_security_exploit_confirmed
    assert exploit.language == "javascript" and exploit.reproduction_poc.startswith("// === Reproduction PoC ===")
    crash = executor._aggregate(bb, "BB", [TARGET_TYPEERROR_CASE])
    assert crash.status == TestStatus.FAILED and not crash.is_security_exploit_confirmed
    assert crash.failure_reason.startswith("TypeError: Cannot read")
    test_side = executor._aggregate(wb, "WB", [TEST_SIDE_REFERROR_CASE])
    assert test_side.status == TestStatus.ERROR and "ReferenceError" in test_side.failure_reason
    missing = executor._aggregate(wb, "WB", [TEST_MODULE_NOT_FOUND])
    assert missing.status == TestStatus.ERROR and missing.failure_reason.startswith("Test could not run correctly")
    broken = executor._aggregate(wb, "WB", [TARGET_BROKEN])
    assert broken.status == TestStatus.ERROR and broken.failure_reason.startswith("Target code is broken")
    passed = executor._aggregate(wb, "WB", [{**ASSERTION_CASE, "outcome": "passed"}])
    assert passed.status == TestStatus.PASSED and passed.language == "javascript"


# --- Executor dispatch (no Node needed) ------------------------------------------------------------

class _RecordingSandbox:
    """Stands in for a Node sandbox: records each module run and answers with a canned report."""
    timeout_seconds = 30
    supports_typescript = True

    def __init__(self, junit_by_module=None, exit_code=0):
        self.calls = []
        self.junit_by_module = junit_by_module or {}
        self.exit_code = exit_code

    def execute_pytest_files(self, files, working_dir=None, timeout_seconds=None, **kw):
        self.calls.append((list(files), timeout_seconds))
        module = os.path.splitext(next(iter(files)))[0]
        junit = self.junit_by_module.get(module, EMPTY_FILE_JUNIT.replace("test_vh_002", module))
        return self.exit_code, "", "", 0.1, None, junit


class _PySandbox:
    timeout_seconds = 30

    def execute_pytest_files(self, files, **kw):
        cases = "".join(f'<testcase classname="{os.path.splitext(f)[0]}" name="test_a" time="0.1"/>' for f in files)
        return 0, "", "", 0.1, 88.0, f"<testsuites><testsuite>{cases}</testsuite></testsuites>"


def test_executor_keeps_order_across_languages_and_runs_js_modules_one_per_process(tmp_path):
    js = _RecordingSandbox({"test_vh_001": NODE_JUNIT.replace("test_vh_000", "test_vh_001")})
    executor = TestSuiteExecutor(sandbox=_PySandbox(), js_sandbox_factory=lambda: js, per_test_timeout_seconds=7)
    tests = [
        _py_test("P1", "def test_a():\n    assert 1 == 1\n"),
        _js_test("J1", GOOD),
        _js_test("J2", GOOD),
    ]
    results, coverage = executor.execute_test_suite(tests, working_dir=str(tmp_path))
    assert [r.test_id for r in results] == ["P1", "J1", "J2"]
    assert [r.language for r in results] == ["python", "javascript", "javascript"]
    assert results[0].status == TestStatus.PASSED and coverage == 88.0
    assert results[1].status == TestStatus.FAILED  # the assertion failure in NODE_JUNIT
    assert results[2].status == TestStatus.ERROR and "No test was collected" in results[2].failure_reason
    assert js.calls == [(["test_vh_001.mjs"], 7), (["test_vh_002.mjs"], 7)]  # global index, one process each


def test_executor_js_timeout_and_unparseable_report(tmp_path):
    js = _RecordingSandbox(exit_code=TIMEOUT_EXIT_CODE)
    executor = TestSuiteExecutor(sandbox=_PySandbox(), js_sandbox_factory=lambda: js, per_test_timeout_seconds=3)
    results, _ = executor.execute_test_suite([_js_test("J", GOOD)], working_dir=str(tmp_path))
    assert results[0].status == TestStatus.ERROR and "timed out after 3s" in results[0].failure_reason
    js = _RecordingSandbox({"test_vh_000": "<broken"})
    executor = TestSuiteExecutor(sandbox=_PySandbox(), js_sandbox_factory=lambda: js)
    results, _ = executor.execute_test_suite([_js_test("J", GOOD)], working_dir=str(tmp_path))
    assert results[0].status == TestStatus.ERROR and "could not be parsed" in results[0].failure_reason


def test_executor_without_js_runner_reports_every_js_test_as_not_run(tmp_path):
    executor = TestSuiteExecutor(sandbox=_PySandbox())
    results, _ = executor.execute_test_suite([_js_test("J", GOOD), _py_test("P", "def test_a():\n    assert 1\n")],
                                             working_dir=str(tmp_path))
    assert results[0].status == TestStatus.ERROR
    assert "was not run: no JavaScript/TypeScript runner is configured" in results[0].failure_reason
    assert results[1].status == TestStatus.PASSED

    def boom():
        raise RuntimeError("docker image missing")
    executor = TestSuiteExecutor(sandbox=_PySandbox(), js_sandbox_factory=boom)
    results, _ = executor.execute_test_suite([_js_test("J", GOOD)], working_dir=str(tmp_path))
    assert "RuntimeError: docker image missing" in results[0].failure_reason
    assert executor.js_runner_unavailable_reason == "RuntimeError: docker image missing"

    executor = TestSuiteExecutor(sandbox=_PySandbox(), js_sandbox_factory=lambda: None)
    results, _ = executor.execute_test_suite([_js_test("J", GOOD)], working_dir=str(tmp_path))
    assert "no usable Node runtime was found" in results[0].failure_reason


def test_executor_skips_typescript_when_the_runtime_cannot_strip_types(tmp_path):
    js = _RecordingSandbox()
    js.supports_typescript = False
    executor = TestSuiteExecutor(sandbox=_PySandbox(), js_sandbox_factory=lambda: js)
    results, _ = executor.execute_test_suite([_js_test("T", GOOD, language="typescript"), _js_test("J", GOOD)],
                                             working_dir=str(tmp_path))
    assert results[0].status == TestStatus.ERROR and "older than 22.6" in results[0].failure_reason
    assert js.calls == [(["test_vh_001.mjs"], 30)]


def test_executor_js_gate_failure_is_an_error_without_a_run(tmp_path):
    js = _RecordingSandbox()
    executor = TestSuiteExecutor(sandbox=_PySandbox(), js_sandbox_factory=lambda: js)
    results, _ = executor.execute_test_suite([_js_test("J", "test('x', () => {});")], working_dir=str(tmp_path))
    assert results[0].status == TestStatus.ERROR and "not executable" in results[0].failure_reason
    assert js.calls == []


# --- Node command, version parsing, Docker argv shape (no Node / Docker needed) --------------------

def test_parse_node_version_and_detect():
    assert parse_node_version("v22.6.0\n") == (22, 6, 0)
    assert parse_node_version("20.11.1") == (20, 11, 1)
    assert parse_node_version("") is None and parse_node_version("latest") is None
    path, version, problem = detect_node("definitely-not-a-node-binary-xyz")
    assert path is None and version is None and "no usable Node runtime" in problem


def test_detect_node_rejects_old_or_odd_binaries(monkeypatch):
    import vibeharness.core.sandbox as sandbox_mod
    monkeypatch.setattr(sandbox_mod.shutil, "which", lambda name: "/fake/bin/node")
    answers = iter(["v18.20.0\n", "banana\n"])
    monkeypatch.setattr(sandbox_mod.subprocess, "run",
                        lambda *a, **k: subprocess.CompletedProcess(a[0], 0, stdout=next(answers), stderr=""))
    path, version, problem = detect_node("node")
    assert path is None and version == (18, 20, 0) and "below the minimum" in problem
    assert "not a version" in detect_node("node")[2]

    def broken(*a, **k):
        raise OSError("exec format error")
    monkeypatch.setattr(sandbox_mod.subprocess, "run", broken)
    assert "--version failed" in detect_node("node")[2]


def test_windows_file_url_is_rewritten_for_the_container():
    from vibeharness.core.sandbox import rewrite_host_paths
    code = 'import { f } from "file:///D:/work/proj/svc.mjs";\n'
    mapping = [(r"D:\work\proj", "/work/proj"), (r"D:\work", "/work")]
    assert rewrite_host_paths(code, mapping, windows=True) == 'import { f } from "file:///work/proj/svc.mjs";\n'


def test_node_test_command_flags():
    cmd = node_test_command("/usr/bin/node", ["/r/test_vh_000.mjs"], "/r/junit.xml", strip_types=True,
                            collect_coverage=False, max_old_space_mb=512)
    assert cmd[:3] == ["/usr/bin/node", "--max-old-space-size=512", "--experimental-strip-types"]
    assert "--test" in cmd and "--test-reporter=junit" in cmd and "--test-reporter-destination=/r/junit.xml" in cmd
    assert cmd[-1] == "/r/test_vh_000.mjs"
    plain = node_test_command("node", [], "/r/junit.xml", False, True, 0)
    assert "--max-old-space-size" not in " ".join(plain) and "--experimental-strip-types" not in plain
    assert "--experimental-test-coverage" in plain


def test_node_subprocess_sandbox_command_env_and_limits(tmp_path, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-secret")
    monkeypatch.setenv("NODE_OPTIONS", "--require /evil.js")
    target = tmp_path / "app"
    (target / "node_modules" / "dep").mkdir(parents=True)
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    sandbox = NodeSubprocessSandbox(timeout_seconds=20, memory_mb=256, node_bin="node-binary-that-does-not-exist",
                                    strip_types=True)
    cmd, cwd, env = sandbox._build_command(str(run_dir), ["test_vh_000.mjs"], str(target), False, None,
                                           {"NODE_OPTIONS": "--inspect", "TARGET_URL": "http://svc"})
    assert cmd[0] == "node-binary-that-does-not-exist" and "--max-old-space-size=256" in cmd
    assert "--experimental-strip-types" in cmd and cmd[-1] == str(run_dir / "test_vh_000.mjs")
    assert cwd == str(target) and env["NODE_ENV"] == "test" and env["TARGET_URL"] == "http://svc"
    assert "OPENAI_API_KEY" not in env and "NODE_OPTIONS" not in env
    linked = run_dir / "node_modules"
    assert linked.is_symlink() or "NODE_PATH" in env  # bare specifiers resolve either way
    assert sandbox._limits(20) == {"cpu_seconds": 30}  # no RLIMIT_AS for V8
    assert sandbox._extract_coverage_percent("anything") is None


def test_node_docker_sandbox_argv_and_path_rewrite(tmp_path):
    target = tmp_path / "app"
    target.mkdir()
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    sandbox = NodeDockerSandbox(timeout_seconds=25, verify=False, strip_types=True, memory="256m")
    cmd, cwd, cli_env = sandbox._build_command(str(run_dir), ["test_vh_000.mjs"], str(target), False, None,
                                               {"NODE_OPTIONS": "--inspect"})
    joined = " ".join(cmd)
    for flag in ("--rm", "--read-only", "--network none", "--cap-drop ALL", "--memory 256m", "--pids-limit 256"):
        assert flag in joined
    assert f"type=bind,source={target},target=/work/app,readonly" in joined
    assert "NODE_PATH=/work/app/node_modules" in cmd and "HOME=/tmp" in cmd and "NODE_ENV=test" in cmd
    assert not any(e.startswith("NODE_OPTIONS=") for e in cmd) and "PYTHONPATH" not in joined
    image_at = cmd.index(DEFAULT_DOCKER_NODE_IMAGE)
    assert cmd[image_at + 1:image_at + 6] == ["timeout", "--kill-after=5", "25", "node", "--experimental-strip-types"]
    assert "--test-reporter-destination=/sandbox/junit.xml" in cmd and cmd[-1] == "/sandbox/test_vh_000.mjs"
    assert cwd == str(run_dir)
    code = f'import {{ f }} from "{target_file_url(str(target / "svc.mjs"))}";\n'
    assert sandbox._prepare_code(code, str(target)) == 'import { f } from "file:///work/app/svc.mjs";\n'


def test_node_docker_sandbox_names_its_own_dockerfile(tmp_path, monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda name: None)
    with pytest.raises(Exception) as info:
        NodeDockerSandbox(verify=True)
    assert "sandbox-node.Dockerfile" in str(info.value) or "docker" in str(info.value).lower()


# --- Real Node runs ----------------------------------------------------------------------------------

@node_only
def test_node_runs_esm_cjs_and_bare_specifier_modules(tmp_path):
    target = tmp_path / "app"
    target.mkdir()
    (target / "calc.mjs").write_text("export function add(a, b) {\n  if (a === null) throw new TypeError('null');\n"
                                     "  return a + b;\n}\n", encoding="utf-8")
    (target / "legacy.cjs").write_text("module.exports = { twice: (x) => x * 2 };\n", encoding="utf-8")
    dep = target / "node_modules" / "leftpad"
    dep.mkdir(parents=True)
    (dep / "package.json").write_text('{"name": "leftpad", "type": "module", "main": "index.js"}', encoding="utf-8")
    (dep / "index.js").write_text("export const pad = (s) => ' ' + s;\n", encoding="utf-8")
    calc_url = target_file_url(str(target / "calc.mjs"))
    legacy_url = target_file_url(str(target / "legacy.cjs"))
    tests = [
        _js_test("ok", _esm_test(f'import {{ add }} from "{calc_url}";',
                                 'test("adds", () => { assert.equal(add(1, 2), 3); });')),
        _js_test("fails", _esm_test(f'import {{ add }} from "{calc_url}";',
                                    'test("wrong", () => { assert.equal(add(1, 1), 3); });'), test_type="blackbox_security"),
        _js_test("crash", _esm_test(f'import {{ add }} from "{calc_url}";',
                                    'test("null", () => { assert.equal(add(null, 1), 1); });')),
        _js_test("missing", _esm_test('import { nope } from "./does_not_exist.mjs";',
                                      'test("never", () => { assert.ok(nope); });')),
        _js_test("cjs", _esm_test(f'import legacy from "{legacy_url}";',
                                  'test("twice", () => { assert.equal(legacy.twice(4), 8); });')),
        _js_test("bare", _esm_test('import { pad } from "leftpad";',
                                   'test("pad", () => { assert.equal(pad("x"), " x"); });')),
        _js_test("secret", _esm_test("",
                                     'test("env", () => { assert.equal(process.env.OPENAI_API_KEY, undefined); '
                                     'assert.equal(process.env.NODE_OPTIONS, undefined); });')),
        _js_test("empty", "test('x', () => { assert.ok(1); });"),  # no imports: ReferenceError on assert -> test-side
    ]
    os.environ["OPENAI_API_KEY"] = "sk-secret"
    os.environ["NODE_OPTIONS"] = "--require /nonexistent/evil.js"
    try:
        sandbox = NodeSubprocessSandbox(timeout_seconds=60, memory_mb=512)
        executor = TestSuiteExecutor(sandbox=_PySandbox(), js_sandbox_factory=lambda: sandbox, per_test_timeout_seconds=30)
        results, _ = executor.execute_test_suite(tests, working_dir=str(target))
    finally:
        del os.environ["OPENAI_API_KEY"], os.environ["NODE_OPTIONS"]
    by_id = {r.test_id: r for r in results}
    assert by_id["ok"].status == TestStatus.PASSED
    assert by_id["fails"].status == TestStatus.FAILED and by_id["fails"].is_security_exploit_confirmed
    assert by_id["crash"].status == TestStatus.FAILED and not by_id["crash"].is_security_exploit_confirmed
    assert by_id["crash"].failure_reason.startswith("TypeError: null")
    assert by_id["missing"].status == TestStatus.ERROR and by_id["missing"].failure_reason.startswith("Test could not run correctly")
    assert "ERR_MODULE_NOT_FOUND" in by_id["missing"].failure_reason or "Cannot find module" in by_id["missing"].failure_reason
    assert by_id["cjs"].status == TestStatus.PASSED
    assert by_id["bare"].status == TestStatus.PASSED
    assert by_id["secret"].status == TestStatus.PASSED
    assert by_id["empty"].status == TestStatus.ERROR and "ReferenceError" in by_id["empty"].failure_reason


@node_only
def test_node_hang_is_killed_on_the_per_test_budget(tmp_path):
    sandbox = NodeSubprocessSandbox(timeout_seconds=30)
    executor = TestSuiteExecutor(sandbox=_PySandbox(), js_sandbox_factory=lambda: sandbox, per_test_timeout_seconds=2)
    hang = _js_test("hang", _esm_test("", 'test("spin", () => { while (true) {} assert.ok(1); });'))
    results, _ = executor.execute_test_suite([hang], working_dir=str(tmp_path))
    assert results[0].status == TestStatus.ERROR and "timed out after 2s" in results[0].failure_reason


@node_only
def test_node_file_without_tests_is_not_a_pass(tmp_path):
    sandbox = NodeSubprocessSandbox(timeout_seconds=30)
    executor = TestSuiteExecutor(sandbox=_PySandbox(), js_sandbox_factory=lambda: sandbox)
    # The gate requires a test() call; a test() that never registers (inside a dead branch) reaches Node
    code = _esm_test("", 'if (false) { test("ghost", () => { assert.ok(1); }); }')
    results, _ = executor.execute_test_suite([_js_test("ghost", code)], working_dir=str(tmp_path))
    assert results[0].status == TestStatus.ERROR and "No test was collected" in results[0].failure_reason


@node_ts_only
def test_node_strips_types_for_typescript_targets(tmp_path):
    target = tmp_path / "app"
    target.mkdir()
    (target / "svc.ts").write_text("export function greet(name: string): string {\n  return 'hi ' + name;\n}\n",
                                   encoding="utf-8")
    url = target_file_url(str(target / "svc.ts"))
    code = _esm_test(f'import {{ greet }} from "{url}";', 'test("greets", () => { assert.equal(greet("a"), "hi a"); });')
    sandbox = NodeSubprocessSandbox(timeout_seconds=30, strip_types=True)
    executor = TestSuiteExecutor(sandbox=_PySandbox(), js_sandbox_factory=lambda: sandbox)
    results, _ = executor.execute_test_suite([_js_test("ts", code, language="typescript")], working_dir=str(target))
    assert results[0].status == TestStatus.PASSED and results[0].language == "typescript"


def _docker_node_ready():
    if not shutil.which("docker"):
        return False
    return subprocess.run(["docker", "image", "inspect", DEFAULT_DOCKER_NODE_IMAGE], capture_output=True).returncode == 0


_DOCKER_NODE_REQUIRED = os.environ.get("VIBEHARNESS_REQUIRE_DOCKER_NODE") == "1"
if _DOCKER_NODE_REQUIRED and not _docker_node_ready():
    raise RuntimeError(f"VIBEHARNESS_REQUIRE_DOCKER_NODE=1 but Docker or image {DEFAULT_DOCKER_NODE_IMAGE} is unavailable")
docker_node_only = pytest.mark.skipif(not _docker_node_ready(), reason=f"Docker or image {DEFAULT_DOCKER_NODE_IMAGE} unavailable")


@docker_node_only
def test_node_container_runs_tests_against_the_mounted_target(tmp_path):
    target = tmp_path / "app"
    target.mkdir()
    (target / "calc.mjs").write_text("export const add = (a, b) => a + b;\n", encoding="utf-8")
    url = target_file_url(str(target / "calc.mjs"))
    tests = [
        _js_test("ok", _esm_test(f'import {{ add }} from "{url}";', 'test("adds", () => { assert.equal(add(1, 2), 3); });')),
        _js_test("bug", _esm_test(f'import {{ add }} from "{url}";', 'test("bug", () => { assert.equal(add(1, 1), 3); });')),
        _js_test("no_net", _esm_test('import { connect } from "node:net";',
                                     'test("net", (t, done) => { const s = connect(80, "1.1.1.1"); '
                                     's.on("error", () => { assert.ok(true); done(); }); s.on("connect", () => { assert.fail("net"); }); });')),
    ]
    sandbox = NodeDockerSandbox(timeout_seconds=60)
    executor = TestSuiteExecutor(sandbox=_PySandbox(), js_sandbox_factory=lambda: sandbox, per_test_timeout_seconds=40)
    results, _ = executor.execute_test_suite(tests, working_dir=str(target))
    by_id = {r.test_id: r for r in results}
    assert by_id["ok"].status == TestStatus.PASSED
    assert by_id["bug"].status == TestStatus.FAILED
    assert by_id["no_net"].status == TestStatus.PASSED


# --- Harness end to end --------------------------------------------------------------------------------

_JS_TARGET = ("export function login(user, password) {\n  if (!user) return { status: 'error' };\n"
              "  return { status: 'ok', token: user + ':' + password };\n}\n")


def _js_responder(expected_status):
    """A fake model: one finding on login, confirmed by every verifier, a node:test for it, one threat
    with an in-process attack test. The generated tests import the URL the prompt gives them."""
    def responder(system, user):
        if "QA Engineer" in system:
            assert "JavaScript/TypeScript QA Engineer" in system, "a JS finding must get the JS test prompt"
            url = [line.split(": ", 1)[1] for line in user.splitlines() if line.startswith("Import URL")][0]
            body = 'test("empty user is rejected", () => { assert.equal(login("", "p").status, "error"); });'
            return json.dumps({"test_id": "WB-TEST-01", "title": "login", "rationale": "", "expected_outcome": "",
                               "code": _esm_test(f'import {{ login }} from "{url}";', body)})
        if "Offensive Security" in system:
            assert "node:test" in system
            url = [line.split(": ", 1)[1] for line in user.splitlines() if line.startswith("Import URL")][0]
            body = ('test("token must not echo the password", () => { '
                    f'assert.equal(login("u", "pw").token.includes("pw"), {"false" if expected_status != "BLOCKED_CRITICAL_RISK" else "false"}); }});')
            return json.dumps({"test_id": "BB-TEST-1", "title": "token leak", "rationale": "", "expected_outcome": "",
                               "code": _esm_test(f'import {{ login }} from "{url}";', body)})
        if "Threat Modeling Specialist" in system:
            return json.dumps({"threats": [{"threat_id": "T1", "stride_category": "Information Disclosure",
                                            "title": "password in token", "severity": "HIGH",
                                            "attack_vector": "call login", "attack_scenario": "login returns the password"}]})
        if "verdicts" in system:
            return json.dumps({"verdicts": [{"index": 0, "verdict": "confirm", "reason": "yes"}]})
        return json.dumps({"findings": [{"symbol_name": "login", "severity": "HIGH", "title": "password echoed in token",
                                         "description": "d", "root_cause": "r", "suggested_test_scenario": "s"}]})
    return responder


@node_only
def test_js_target_is_dynamically_verified_end_to_end(tmp_path, fake_live):
    target = tmp_path / "app"
    target.mkdir()
    (target / "auth.mjs").write_text(_JS_TARGET, encoding="utf-8")
    fake_live(_js_responder("BLOCKED_CRITICAL_RISK"))
    commander = VibeHarnessCommander(config_path=CONFIG, execution_mode="live")
    report = tmp_path / "r.md"
    summary = commander.run_full_pipeline(target_dir=str(target), base_url="http://localhost:59999",
                                          output_report_path=str(report))
    assert not any("statically only" in r for r in summary.inconclusive_reasons)
    assert summary.whitebox_tests_passed >= 1  # the generated node:test ran and passed
    assert summary.blackbox_security_breaches == 1 and summary.overall_status == "BLOCKED_CRITICAL_RISK"
    assert summary.run is not None and summary.run.node_runtime.startswith("node v")
    text = report.read_text(encoding="utf-8")
    assert "```javascript" in text or "````javascript" in text
    assert "// === Reproduction PoC ===" in text
    assert "Line Coverage (Python)" not in text  # console-only label; the report keeps its metric table
    assert summary.line_coverage_pct is None  # JS coverage is not collected


def test_js_target_without_a_node_runtime_is_an_evidence_gap(tmp_path, fake_live):
    target = tmp_path / "app"
    target.mkdir()
    (target / "auth.mjs").write_text(_JS_TARGET, encoding="utf-8")
    fake_live(_js_responder("INCONCLUSIVE"))
    commander = VibeHarnessCommander(config_path=CONFIG, execution_mode="live")
    commander.node_bin = "definitely-not-a-node-binary-xyz"
    summary = commander.run_full_pipeline(target_dir=str(target), base_url="http://localhost:59999",
                                          output_report_path=str(tmp_path / "r.md"))
    assert summary.overall_status == "INCONCLUSIVE"
    gaps = " ".join(summary.inconclusive_reasons)
    assert "could not run" in gaps and "no usable Node runtime" in gaps and "definitely-not-a-node-binary-xyz" in gaps
    assert summary.run.node_runtime is None


def test_mock_mode_discloses_that_no_js_test_was_generated(tmp_path):
    target = tmp_path / "app"
    target.mkdir()
    (target / "auth.mjs").write_text(_JS_TARGET, encoding="utf-8")
    summary = VibeHarnessCommander(config_path=CONFIG, execution_mode="mock").run_full_pipeline(
        target_dir=str(target), base_url="http://localhost:59999", output_report_path=str(tmp_path / "r.md"))
    assert summary.overall_status == "INCONCLUSIVE"
    assert any("no JS/TS test was generated" in r for r in summary.inconclusive_reasons)


def test_other_languages_keep_the_static_only_gap(tmp_path):
    target = tmp_path / "app"
    target.mkdir()
    (target / "main.go").write_text("package main\n\nfunc main() {}\n", encoding="utf-8")
    (target / "ok.py").write_text("def f():\n    return 1\n", encoding="utf-8")
    summary = VibeHarnessCommander(config_path=CONFIG, execution_mode="mock").run_full_pipeline(
        target_dir=str(target), base_url="http://localhost:59999", output_report_path=str(tmp_path / "r.md"))
    assert not any("JS/TS" in r for r in summary.inconclusive_reasons)


def test_harness_node_sandbox_provider_selection(tmp_path, monkeypatch):
    commander = VibeHarnessCommander(config_path=CONFIG, execution_mode="mock")
    monkeypatch.setattr("vibeharness.core.harness.detect_node", lambda node_bin: ("/usr/bin/node", (22, 9, 0), None))
    commander.sandbox_node_provider = "docker"
    monkeypatch.setattr(NodeDockerSandbox, "_verify_available", lambda self: None)
    sandbox = commander._build_node_sandbox()
    assert isinstance(sandbox, NodeDockerSandbox) and commander.node_runtime == "node v22.9.0"
    commander.sandbox_node_provider = "firecracker"
    with pytest.raises(ValueError, match="not implemented"):
        commander._build_node_sandbox()
    monkeypatch.setattr("vibeharness.core.harness.detect_node", lambda node_bin: ("/usr/bin/node", (20, 5, 0), None))
    commander.sandbox_node_provider = "local_subprocess"
    commander.ast_extractor.analyzed_files = ["/app/x.ts"]
    sandbox = commander._build_node_sandbox()
    assert isinstance(sandbox, NodeSubprocessSandbox) and not sandbox.supports_typescript and not sandbox.strip_types
    assert "TypeScript tests need Node >= 22.6" in commander.node_typescript_problem
