"""沙盒與測試執行器在審查中發現的問題之回歸測試：環境變數外洩、管線卡住、NameError 歸因、
空洞的類別測試方法、JS 的逾時預算、Node 的錯誤標籤，以及 0 秒的逐測預算。
Regression tests for sandbox / test-executor review findings: environment leaks, pipe hangs, NameError
attribution, vacuous class test methods, the JS timeout budget, Node's error tags and a 0s per-test budget."""
import json
import os
import sys
import time

import pytest

from vibeharness.core.codecheck import check_test_code
from vibeharness.core.models import GeneratedTest, TestStatus
from vibeharness.core.sandbox import (
    TIMEOUT_EXIT_CODE, LocalSubprocessSandbox, NodeRuntime, SandboxRun, harden_harness_process,
)
from vibeharness.runners.attribution import REASON_NOT_RUN_CORRECTLY, attribute
from vibeharness.runners.test_executor import REASON_RERUN_BUDGET_EXHAUSTED, TestSuiteExecutor

linux_only = pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux /proc and prctl semantics")
posix_only = pytest.mark.skipif(sys.platform == "win32", reason="POSIX process-group semantics")


def _test(test_id, code, test_type="blackbox_security", language="python"):
    return GeneratedTest(test_id=test_id, test_type=test_type, target_component="x", title=f"t {test_id}",
                         code=code, rationale="", expected_outcome="", language=language)

def _attributed(message, details, test_type="whitebox_unit"):
    """把一個失敗的 pytest case 交給 attribute 判定。
    Hands one failing pytest case to attribute."""
    test = GeneratedTest(test_id="T", test_type=test_type, target_component="m", title="t", code="def test_a():\n    pass\n",
                         rationale="", expected_outcome="")
    case = {"name": "test_a", "time": 0.0, "outcome": "failure", "message": message, "details": details,
            "stdout": "", "stderr": ""}
    return attribute(test, "T", [case])


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
    message = "NameError: name 'x' is not defined"
    assert _attributed(message, "").status == TestStatus.ERROR
    in_target = "    def f():\n>       return x\nE       NameError: name 'x' is not defined\n\n/srv/app.py:2: NameError"
    assert _attributed(message, in_target).status == TestStatus.FAILED
    assert _attributed(message, "/tmp/vibe_sandbox_x/test_vh_000.py:5: NameError").status == TestStatus.ERROR


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
    executor = TestSuiteExecutor(sandbox=LocalSubprocessSandbox(), js_sandbox_factory=lambda: NodeRuntime(js),
                                 per_test_timeout_seconds=1)
    results = executor.execute_test_suite([_test("H", _GOOD_JS, language="javascript"),
                                          _test("OK", _GOOD_JS, language="javascript")], working_dir=str(tmp_path)).results
    assert js.calls == [("test_vh_000", 2), ("test_vh_001", 1)]
    assert results[0].status == TestStatus.ERROR and "timed out after 2s" in results[0].failure_reason
    assert results[1].status == TestStatus.PASSED


def test_js_rerun_pass_is_bounded_by_the_batch_budget(tmp_path):
    js = _HangingJsSandbox(timeout_seconds=1, hang={"test_vh_000", "test_vh_001", "test_vh_002"})
    executor = TestSuiteExecutor(sandbox=LocalSubprocessSandbox(), js_sandbox_factory=lambda: NodeRuntime(js),
                                 per_test_timeout_seconds=1)
    tests = [_test(f"H{i}", _GOOD_JS, language="javascript") for i in range(3)]
    results = executor.execute_test_suite(tests, working_dir=str(tmp_path)).results
    assert [m for m, _ in js.calls] == ["test_vh_000", "test_vh_001"]
    assert "timed out after 1s" in results[0].failure_reason and "timed out after 1s" in results[1].failure_reason
    assert results[2].status == TestStatus.ERROR and results[2].failure_reason == REASON_RERUN_BUDGET_EXHAUSTED


# --- 6. Node 22 的類別名標籤會被正規化 --------------------------------------------------------
# --- 6. Node 22's class-name tag is normalised -------------------------------------------------------

def test_js_summary_strips_the_class_tag_but_keeps_error_codes():
    def reason(details):
        test = GeneratedTest(test_id="J", test_type="whitebox_unit", target_component="m", title="t", code="x",
                             rationale="", expected_outcome="", language="javascript")
        case = {"name": "c", "time": 0.0, "outcome": "failure", "message": "", "details": details, "stdout": "", "stderr": ""}
        return attribute(test, "J", [case]).failure_reason
    assert reason("  cause: TypeError [Error]: null\n      at add (file:///x/calc.mjs:2:9)") == "TypeError: null"
    assert reason("TypeError [Error]: null\n    at add (file:///x/calc.mjs:2:9)") == "TypeError: null"
    coded = reason("Error [ERR_MODULE_NOT_FOUND]: Cannot find module '/x/y.mjs'\n    at f (node:a:1:1)")
    assert coded.startswith(f"{REASON_NOT_RUN_CORRECTLY}: Error [ERR_MODULE_NOT_FOUND]: ")


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


# --- 上層目錄的 conftest.py 不會被載入（#183 第 3 項） -------------------------------------
# --- No ancestor conftest.py is loaded (#183 item 3) --------------------------------------

def test_a_conftest_above_the_run_directory_is_not_loaded(tmp_path, monkeypatch):
    """執行目錄建立在暫存目錄下；暫存目錄裡的 conftest.py（同主機的其他使用者或前一批目標都能寫入）不可改寫結果。
    The run directory is made under the temp dir; a conftest.py there (writable by other users on the host or by an
    earlier target) must not rewrite outcomes."""
    import tempfile

    (tmp_path / "conftest.py").write_text(
        "import pytest\n"
        "@pytest.hookimpl(hookwrapper=True)\n"
        "def pytest_runtest_makereport(item, call):\n"
        "    outcome = yield\n"
        "    report = outcome.get_result()\n"
        "    report.outcome = 'passed'\n"
        "    report.longrepr = None\n"
        "    print('ANCESTOR CONFTEST LOADED')\n",
        encoding="utf-8")
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))
    target = tmp_path / "target"
    target.mkdir()
    run = LocalSubprocessSandbox(timeout_seconds=60).execute_pytest_files(
        {"test_vh_x.py": "def test_a():\n    assert 1 == 2\n"}, working_dir=str(target))
    assert "ANCESTOR CONFTEST LOADED" not in run.stdout
    assert run.exit_code == 1
    assert run.junit_xml is not None and "<failure" in run.junit_xml


# --- 目標頂替測試執行器（#183 第 4 項） -----------------------------------------------------
# --- A target shadowing the test runner (#183 item 4) -------------------------------------

def test_shadowed_runner_modules_lists_every_import_form(tmp_path):
    from vibeharness.core.sandbox import shadowed_runner_modules

    parent = tmp_path / "repo"
    target = parent / "src"
    (target / "_pytest").mkdir(parents=True)
    (target / "_pytest" / "__init__.py").write_text("", encoding="utf-8")
    (target / "pytest.py").write_text("", encoding="utf-8")
    (target / "pluggy.cpython-312-x86_64-linux-gnu.so").write_bytes(b"")
    (target / "coverage").mkdir()  # 命名空間套件：敵不過已安裝的套件 ／ a namespace package: loses to the installed one
    (target / "app.py").write_text("", encoding="utf-8")
    (parent / "sitecustomize.py").write_text("", encoding="utf-8")

    in_target = sorted(str(target / name) for name in ("_pytest", "pytest.py", "pluggy.cpython-312-x86_64-linux-gnu.so"))
    assert shadowed_runner_modules(str(target), include_parent=False) == in_target
    assert shadowed_runner_modules(str(target)) == sorted([*in_target, str(parent / "sitecustomize.py")])


# 目標的 pytest.py：不執行任何測試，替每個產生的測試模組寫出一筆通過的 JUnit 案例，案例的輸出帶著 _FORGED 記號
# The target's pytest.py: runs no test and writes one passing JUnit case for each generated test module, whose output
# carries the _FORGED mark
_FORGED = "forged-by-the-target-pytest"
_FORGED_PYTEST = (
    "import glob, re, sys\n"
    "junit = next(a.split('=', 1)[1] for a in sys.argv if a.startswith('--junitxml='))\n"
    "names = sorted({m for a in sys.argv[1:] + glob.glob('test_vh_*.py') for m in re.findall(r'test_vh_\\d+', a)})\n"
    "cases = ''.join(f'<testcase classname=\"{n}\" name=\"test_ok\" time=\"0.01\">'\n"
    f"                '<system-out>{_FORGED}</system-out></testcase>' for n in names)\n"
    "open(junit, 'w').write(f'<testsuites><testsuite name=\"pytest\">{cases}</testsuite></testsuites>')\n")


def test_a_target_shadowing_pytest_is_an_evidence_gap(clean_live_run, tmp_path):
    """目標的 pytest.py 頂替測試執行器，替每個產生的白箱與黑箱測試寫出「通過」的 JUnit 報告（每筆結果的輸出都帶著
    偽造的記號，證明結果來自它，不是真的 pytest）。產生的測試因此不會被記成「從未執行」（空報告會多出那筆缺口），
    頂替的缺口是唯一的一筆，判定是 INCONCLUSIVE，而不是 READY_TO_SHIP。用 `clean_live_run` 跑，所以斷言的是判定本身
    （#183 第 4 項、#200、#205）。
    The target's pytest.py stands in for the test runner and writes a "passed" JUnit report for every generated
    white-box and black-box test (each result's output carries the forged mark, showing it came from that file and
    not from the real pytest). So the generated tests are not recorded as never run (an empty report would add that
    gap), the shadowing gap is the only one, and the Verdict is INCONCLUSIVE, not READY_TO_SHIP. It runs on
    `clean_live_run`, so it asserts the Verdict itself (#183 item 4, #200, #205)."""
    summary = clean_live_run({"pytest.py": _FORGED_PYTEST}, report="r.json", output_format="json")
    report = json.loads((tmp_path / "r.json").read_text(encoding="utf-8"))
    results = [*report["whitebox"]["test_results"], *report["blackbox_test_results"]]
    assert [r["test_id"] for r in results] == ["WB-TEST-01", "BB-TEST-THREAT-01"], results
    assert all(r["status"] == "PASSED" and _FORGED in r["stdout"] for r in results), results
    assert summary.overall_status == "INCONCLUSIVE"
    assert len(summary.inconclusive_reasons) == 1, summary.inconclusive_reasons
    reason = summary.inconclusive_reasons[0]
    assert "named like the test runner's" in reason and "pytest.py" in reason, reason


# --- 目標自己拋出的 AssertionError 不是突破（#183 第 10 項） ------------------------------------------
# --- An AssertionError the target raised itself is not a Breach (#183 item 10) -----------------------

def test_a_targets_own_assert_validation_is_not_a_breach(tmp_path):
    """目標以 `assert` 驗證輸入；黑箱測試預期 ValueError，結果得到目標的 AssertionError：目標拒絕了輸入，不是被攻破。
    The target validates input with `assert`; the black-box test expects ValueError and gets the target's
    AssertionError: the target refused the input, it was not breached."""
    (tmp_path / "bank.py").write_text(
        "def withdraw(amount):\n    assert amount > 0, 'amount must be positive'\n    return amount\n", encoding="utf-8")
    test = _test("BB-T-01", "import pytest\nfrom bank import withdraw\n\n"
                            "def test_negative_withdrawal_is_rejected():\n"
                            "    with pytest.raises(ValueError):\n        withdraw(-5)\n")
    result = TestSuiteExecutor(LocalSubprocessSandbox(timeout_seconds=60)).execute_test_suite(
        [test], working_dir=str(tmp_path)).results[0]
    assert result.status == TestStatus.FAILED, result.failure_reason
    assert result.is_security_exploit_confirmed is False


def test_the_tests_own_assertion_is_still_a_breach(tmp_path):
    (tmp_path / "bank.py").write_text("def withdraw(amount):\n    return amount\n", encoding="utf-8")
    test = _test("BB-T-01", "from bank import withdraw\n\n"
                            "def test_negative_withdrawal_is_rejected():\n    assert withdraw(-5) is None\n")
    result = TestSuiteExecutor(LocalSubprocessSandbox(timeout_seconds=60)).execute_test_suite(
        [test], working_dir=str(tmp_path)).results[0]
    assert result.is_security_exploit_confirmed is True


@pytest.mark.parametrize("frame, breach", [
    ("/srv/app/bank.py:2: AssertionError", False),
    ("/tmp/vibe_sandbox_x/test_vh_001.py:5: AssertionError", True),
    ("/usr/lib/python3/site-packages/numpy/testing/_private/utils.py:9: AssertionError", True),
])
def test_breach_attribution_follows_the_innermost_python_frame(frame, breach):
    details = f"def test_a():\n>       check()\n\n{frame}"
    assert _attributed("AssertionError: no", details, "blackbox_security").is_security_exploit_confirmed is breach


@pytest.mark.parametrize("frame, breach", [
    ("    at withdraw (file:///srv/app/bank.mjs:2:3)", False),
    ("    at TestContext.<anonymous> (file:///tmp/run/test_vh_001.mjs:5:10)", True),
    ("    at Proxy.assertEqual (file:///srv/app/node_modules/chai/lib/assert.js:9:3)", True),
])
def test_breach_attribution_follows_the_innermost_js_frame(frame, breach):
    test = GeneratedTest(test_id="T", test_type="blackbox_security", target_component="m", title="t",
                         code="test('a', () => { assert.ok(1); });", rationale="", expected_outcome="",
                         language="javascript")
    case = {"name": "a", "time": 0.0, "outcome": "failure", "message": "x",
            "details": f"AssertionError [ERR_ASSERTION]: no\n{frame}\n", "stdout": "", "stderr": ""}
    assert attribute(test, "T", [case]).is_security_exploit_confirmed is breach


# --- 本機沙盒限制行程數（#183 第 18 項） ---------------------------------------------------------
# --- The local sandbox caps the process count (#183 item 18) ----------------------------------------

@linux_only
@pytest.mark.skipif(hasattr(os, "geteuid") and os.geteuid() == 0, reason="RLIMIT_NPROC does not bind root")
def test_the_local_sandbox_caps_the_process_count():
    from vibeharness.core.sandbox import SANDBOX_PROCESS_HEADROOM, _user_process_count

    bound = _user_process_count() + SANDBOX_PROCESS_HEADROOM + 256
    code = ("import resource\n\ndef test_nproc():\n"
            "    soft = resource.getrlimit(resource.RLIMIT_NPROC)[0]\n"
            f"    assert soft != resource.RLIM_INFINITY and soft <= {bound}, soft\n")
    run = LocalSubprocessSandbox(timeout_seconds=60).execute_pytest_files({"test_vh_nproc.py": code})
    assert run.exit_code == 0, run.stdout


# --- 一個黑箱模組裡有多個失敗的 testcase（#182 第 2 組） ---------------------------------------------
# --- Several failing testcases in one black-box module (#182 group 2) --------------------------------

def _case(name, message, frame):
    return {"name": name, "time": 0.0, "outcome": "failure", "message": message,
            "details": f"def {name}():\n>       check()\n\n{frame}", "stdout": "", "stderr": ""}


_TEST_ASSERT = _case("test_b", "AssertionError: admin data returned",
                     "/tmp/vibe_sandbox_x/test_vh_001.py:9: AssertionError")


@pytest.mark.parametrize("first", [
    _case("test_a", "ZeroDivisionError: division by zero", "/srv/app/bank.py:4: ZeroDivisionError"),
    _case("test_a", "AssertionError: amount must be positive", "/srv/app/bank.py:2: AssertionError"),
], ids=["earlier-non-assertion", "earlier-target-assert"])
def test_a_later_assertion_of_the_test_is_still_a_breach(first):
    """前面的 testcase 是非斷言失敗或目標自己的 assert，後面的才是測試自己的斷言：仍是突破，原因取自那個斷言。
    An earlier testcase fails without an assertion or on the target's own assert, a later one on the test's own
    assertion: still a Breach, with the reason taken from that assertion."""
    result = attribute(_test("BB-T-01", "def test_a():\n    pass\n"), "BB-T-01", [first, _TEST_ASSERT])
    assert result.status == TestStatus.FAILED
    assert result.is_security_exploit_confirmed is True
    assert result.failure_reason == "AssertionError: admin data returned"
    assert "test_b" in (result.reproduction_poc or "")


def test_failures_without_a_test_assertion_stay_unclassified():
    cases = [_case("test_a", "ZeroDivisionError: division by zero", "/srv/app/bank.py:4: ZeroDivisionError"),
             _case("test_b", "AssertionError: amount must be positive", "/srv/app/bank.py:2: AssertionError")]
    result = attribute(_test("BB-T-01", "def test_a():\n    pass\n"), "BB-T-01", cases)
    assert result.status == TestStatus.FAILED and result.is_security_exploit_confirmed is False
    assert result.failure_reason == "ZeroDivisionError: division by zero"


def test_a_white_box_test_keeps_reporting_its_first_failure():
    cases = [_case("test_a", "ZeroDivisionError: division by zero", "/srv/app/bank.py:4: ZeroDivisionError"),
             _TEST_ASSERT]
    result = attribute(_test("WB-T-01", "def test_a():\n    pass\n", test_type="whitebox_unit"), "WB-T-01", cases)
    assert result.failure_reason == "ZeroDivisionError: division by zero"
    assert result.is_security_exploit_confirmed is False
