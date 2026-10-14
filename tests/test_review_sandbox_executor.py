"""沙盒與測試執行器在審查中發現的問題之回歸測試：環境變數外洩、管線卡住、NameError 歸因、
空洞的類別測試方法、JS 的逾時預算、Node 的錯誤標籤，以及 0 秒的逐測預算。
Regression tests for sandbox / test-executor review findings: environment leaks, pipe hangs, NameError
attribution, vacuous class test methods, the JS timeout budget, Node's error tags and a 0s per-test budget."""
import os
import sys
import time

import pytest

from vibeharness.core.codecheck import check_test_code
from vibeharness.core.models import GeneratedTest, TestStatus
from vibeharness.core.sandbox import TIMEOUT_EXIT_CODE, LocalSubprocessSandbox, SandboxRun, harden_harness_process
from vibeharness.runners.test_executor import REASON_RERUN_BUDGET_EXHAUSTED, TestSuiteExecutor

linux_only = pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux /proc and prctl semantics")
posix_only = pytest.mark.skipif(sys.platform == "win32", reason="POSIX process-group semantics")


def _test(test_id, code, test_type="blackbox_security", language="python"):
    return GeneratedTest(test_id=test_id, test_type=test_type, target_component="x", title=f"t {test_id}",
                         code=code, rationale="", expected_outcome="", language=language)


# --- 1. 本機沙盒不得洩漏 harness 的環境變數或真正的家目錄 ----------------------------------------
# --- 1. The local sandbox must not leak the harness's environment or the real home ------------------

@linux_only
@pytest.mark.skipif(hasattr(os, "geteuid") and os.geteuid() == 0, reason="root can read any /proc/<pid>/environ")
def test_generated_test_cannot_read_the_harness_environ_or_real_home(tmp_path):
    real_home = os.path.expanduser("~")
    code = (
        "import os\n"
        "def test_no_leak():\n"
        "    try:\n"
        "        data = open(f'/proc/{os.getppid()}/environ', 'rb').read()\n"
        "    except PermissionError:\n"
        "        data = None\n"
        "    assert data is None, 'the harness environ is readable'\n"
        f"    assert os.environ['HOME'] != {real_home!r}\n"
        f"    assert os.path.expanduser('~') != {real_home!r}\n"
    )
    run = LocalSubprocessSandbox(timeout_seconds=60).execute_pytest_files(
        {"test_leak.py": code}, working_dir=str(tmp_path)
    )
    assert run.exit_code == 0, run.stdout[-2000:] + run.stderr[-2000:]


@linux_only
def test_harness_process_becomes_non_dumpable():
    import ctypes
    harden_harness_process()
    pr_get_dumpable = 3
    assert ctypes.CDLL(None).prctl(pr_get_dumpable, 0, 0, 0, 0) == 0


def test_sandbox_home_is_the_per_run_directory_and_pytest_still_runs(tmp_path):
    # 假家目錄下 pytest（與 --cov）照常執行 ／ pytest (and --cov) still run under the fake home
    code = (
        "import os\n"
        "def test_home():\n"
        "    assert os.path.isdir(os.environ['HOME'])\n"
        "    assert os.path.basename(os.environ['HOME']) == 'home'\n"
        "    assert 'vibe_sandbox_' in os.environ['HOME']\n"
        "    assert 'HOMEDRIVE' not in os.environ and 'HOMEPATH' not in os.environ\n"
    )
    run = LocalSubprocessSandbox(timeout_seconds=60).execute_pytest_files(
        {"test_home.py": code}, working_dir=str(tmp_path), collect_coverage=True, coverage_target=str(tmp_path)
    )
    assert run.exit_code == 0, run.stdout[-2000:] + run.stderr[-2000:]
    assert run.junit_xml and "test_home" in run.junit_xml


# --- 2. 留下的子行程不能讓一次已結束的執行被當成逾時 ----------------------------------------------
# --- 2. A child left behind must not turn a finished run into a timeout ------------------------------

@posix_only
def test_child_holding_stdout_does_not_turn_a_pass_into_a_timeout_and_is_killed(tmp_path):
    pid_file = tmp_path / "child.pid"
    code = (
        "import subprocess, sys\n"
        "def test_spawns_server():\n"
        "    p = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])\n"
        f"    open({str(pid_file)!r}, 'w').write(str(p.pid))\n"
        "    assert True\n"
    )
    start = time.monotonic()
    run = LocalSubprocessSandbox(timeout_seconds=30).execute_pytest_files(
        {"test_server.py": code}, working_dir=str(tmp_path)
    )
    elapsed = time.monotonic() - start
    assert run.exit_code == 0, run.stdout[-2000:] + run.stderr[-2000:]
    assert elapsed < 20, f"the sandbox waited {elapsed:.1f}s on pipes held by a stray child"
    assert "1 passed" in run.stdout
    child = int(pid_file.read_text())
    # 殘留的子行程隨行程群組一起被砍掉（給 init 一點時間回收）
    # The stray child was killed with the process group (give init a moment to reap it)
    deadline = time.monotonic() + 5
    alive = True
    while alive and time.monotonic() < deadline:
        try:
            os.kill(child, 0)
            with open(f"/proc/{child}/stat") as f:
                alive = f.read().split(")")[-1].split()[0] != "Z"
        except (ProcessLookupError, FileNotFoundError):
            alive = False
        except PermissionError:
            break
        if alive:
            time.sleep(0.1)
    assert not alive, "a child spawned by the test outlived the run"


def test_run_returns_output_and_exit_code_without_pipes(tmp_path):
    returncode, stdout, stderr = LocalSubprocessSandbox._run(
        [sys.executable, "-c", "import sys; print('out'); print('err', file=sys.stderr); sys.exit(3)"],
        cwd=str(tmp_path), env=dict(os.environ), timeout=30
    )
    assert (returncode, stdout, stderr) == (3, "out\n", "err\n")
    returncode, _, _ = LocalSubprocessSandbox._run(
        [sys.executable, "-c", "import time; time.sleep(30)"], cwd=str(tmp_path), env=dict(os.environ), timeout=1
    )
    assert returncode is None


# --- 3. 目標內部拋出的 NameError 是缺陷，不是 harness 錯誤 ---------------------------------------
# --- 3. A NameError raised inside the target is a defect, not a harness error ------------------------

def test_name_error_in_target_is_a_defect_but_in_the_test_is_a_harness_error(tmp_path):
    (tmp_path / "app_ne.py").write_text("def f():\n    return undefined_name\n", encoding="utf-8")
    executor = TestSuiteExecutor(LocalSubprocessSandbox(timeout_seconds=60))
    results = executor.execute_test_suite([
        _test("TARGET", "from app_ne import f\n\ndef test_f():\n    assert f() == 1\n"),
        _test("TEST", "def test_g():\n    assert nope == 1\n"),
    ], working_dir=str(tmp_path)).results
    target, test = results
    assert target.status == TestStatus.FAILED and "NameError" in target.failure_reason
    assert not target.is_security_exploit_confirmed  # 崩潰不是斷言失敗 ／ a crash is not an assertion failure
    assert test.status == TestStatus.ERROR and "NameError" in test.failure_reason


def test_name_error_without_traceback_stays_test_side():
    case = {"message": "NameError: name 'x' is not defined", "details": ""}
    assert TestSuiteExecutor._is_harness_failure(case)
    case["details"] = "    def f():\n>       return x\nE       NameError: name 'x' is not defined\n\n/srv/app.py:2: NameError"
    assert not TestSuiteExecutor._is_harness_failure(case)
    case["details"] = "/tmp/vibe_sandbox_x/test_vh_000.py:5: NameError"
    assert TestSuiteExecutor._is_harness_failure(case)


# --- 4. Test* 類別中每個測試方法都要有斷言 -----------------------------------------------------
# --- 4. Every test method of a Test* class must assert --------------------------------------------

def test_class_with_one_vacuous_method_is_rejected():
    code = (
        "class TestX:\n"
        "    def test_a(self):\n"
        "        assert 1 == 1\n"
        "    def test_b(self):\n"
        "        x = 1\n"
    )
    valid, problem = check_test_code(code)
    assert not valid and "TestX.test_b" in problem and "TestX.test_a" not in problem


def test_class_methods_may_assert_through_a_self_helper():
    code = (
        "class TestX:\n"
        "    def _check(self, v):\n"
        "        assert v == 1\n"
        "    def test_a(self):\n"
        "        self._check(1)\n"
        "    def test_b(self):\n"
        "        assert 2 == 2\n"
    )
    assert check_test_code(code) == (True, None)


# --- 5. JS 模組使用批次預算；只有批次逾時後的重跑才用單測預算 ------------------------------------
# --- 5. JS modules use the batch budget; only reruns after a batch timeout use the per-test one ------

_PASS_JUNIT = '<testsuites><testsuite name="s"><testcase classname="test" name="ok" time="0.1"/></testsuite></testsuites>'
_GOOD_JS = 'import { test } from "node:test";\nimport assert from "node:assert/strict";\ntest("ok", () => { assert.ok(1); });\n'


class _HangingJsSandbox:
    """Node 沙盒的替身：`hang` 中列出的模組會耗盡給它的預算後逾時，其餘模組通過。
    Stands in for a Node sandbox: modules listed in `hang` use up their budget and time out, the rest pass."""
    supports_typescript = True

    def __init__(self, timeout_seconds, hang):
        self.timeout_seconds = timeout_seconds
        self.hang = set(hang)
        self.calls = []

    def execute_pytest_files(self, files, working_dir=None, timeout_seconds=None, **kw):
        module = os.path.splitext(next(iter(files)))[0]
        self.calls.append((module, timeout_seconds))
        if module in self.hang:
            time.sleep(timeout_seconds)
            return SandboxRun(TIMEOUT_EXIT_CODE, "", "timed out", float(timeout_seconds), None, None)
        return SandboxRun(0, "", "", 0.1, None, _PASS_JUNIT)


def test_js_hang_uses_the_batch_budget_and_the_rest_rerun_on_the_per_test_budget(tmp_path):
    js = _HangingJsSandbox(timeout_seconds=2, hang={"test_vh_000"})
    executor = TestSuiteExecutor(sandbox=LocalSubprocessSandbox(), js_sandbox_factory=lambda: js,
                                 per_test_timeout_seconds=1)
    results = executor.execute_test_suite([_test("H", _GOOD_JS, language="javascript"),
                                          _test("OK", _GOOD_JS, language="javascript")], working_dir=str(tmp_path)).results
    assert js.calls == [("test_vh_000", 2), ("test_vh_001", 1)]
    assert results[0].status == TestStatus.ERROR and "timed out after 2s" in results[0].failure_reason
    assert results[1].status == TestStatus.PASSED


def test_js_rerun_pass_is_bounded_by_the_batch_budget(tmp_path):
    js = _HangingJsSandbox(timeout_seconds=1, hang={"test_vh_000", "test_vh_001", "test_vh_002"})
    executor = TestSuiteExecutor(sandbox=LocalSubprocessSandbox(), js_sandbox_factory=lambda: js,
                                 per_test_timeout_seconds=1)
    tests = [_test(f"H{i}", _GOOD_JS, language="javascript") for i in range(3)]
    results = executor.execute_test_suite(tests, working_dir=str(tmp_path)).results
    assert [m for m, _ in js.calls] == ["test_vh_000", "test_vh_001"]
    assert "timed out after 1s" in results[0].failure_reason and "timed out after 1s" in results[1].failure_reason
    assert results[2].status == TestStatus.ERROR and results[2].failure_reason == REASON_RERUN_BUDGET_EXHAUSTED


# --- 6. Node 22 的類別名標籤會被正規化 --------------------------------------------------------
# --- 6. Node 22's class-name tag is normalised -------------------------------------------------------

def test_js_summary_strips_the_class_tag_but_keeps_error_codes():
    summary = TestSuiteExecutor._js_exception_summary
    assert summary({"details": "  cause: TypeError [Error]: null\n      at add (file:///x/calc.mjs:2:9)"}) == "TypeError: null"
    assert summary({"details": "TypeError [Error]: null\n    at add (file:///x/calc.mjs:2:9)"}) == "TypeError: null"
    coded = summary({"details": "Error [ERR_MODULE_NOT_FOUND]: Cannot find module '/x/y.mjs'\n    at f (node:a:1:1)"})
    assert coded.startswith("Error [ERR_MODULE_NOT_FOUND]: ")


# --- 7. 0 秒的逐測預算絕不會被回報成「0 秒後逾時」 ---------------------------------------------
# --- 7. A 0s per-test budget is never reported as "timed out after 0s" -------------------------------

class _AlwaysTimesOut:
    """每次執行都逾時的 Python 沙盒替身，並記錄收到的預算。
    A Python sandbox stand-in whose every run times out; records the budget it was given."""
    timeout_seconds = 30

    def __init__(self):
        self.budgets = []

    def execute_pytest_files(self, files, timeout_seconds=None, **kw):
        self.budgets.append(timeout_seconds)
        return SandboxRun(TIMEOUT_EXIT_CODE, "", "timed out", 0.0, None, None)


def test_zero_per_test_budget_reports_the_budget_actually_used(tmp_path):
    sandbox = _AlwaysTimesOut()
    executor = TestSuiteExecutor(sandbox=sandbox, per_test_timeout_seconds=0)
    results = executor.execute_test_suite([_test("A", "def test_a():\n    assert 1\n"),
                                          _test("B", "def test_b():\n    assert 1\n")], working_dir=str(tmp_path)).results
    assert sandbox.budgets[1:] == [30, 30]  # 逐測重跑退回沙盒的批次預算 ／ the reruns fall back to the sandbox's batch budget
    for result in results:
        assert "after 30s" in result.failure_reason and "after 0s" not in result.failure_reason


def test_sandbox_never_times_out_after_zero_seconds(tmp_path):
    sandbox = LocalSubprocessSandbox(timeout_seconds=1)
    assert sandbox._effective_timeout(0) == 1 and sandbox._effective_timeout(-5) == 1 and sandbox._effective_timeout(7) == 7
    run = sandbox.execute_pytest_files(
        {"test_hang.py": "import time\ndef test_h():\n    time.sleep(30)\n    assert 1\n"},
        working_dir=str(tmp_path), timeout_seconds=0
    )
    assert run.exit_code == TIMEOUT_EXIT_CODE and "after 1 seconds" in run.stderr
