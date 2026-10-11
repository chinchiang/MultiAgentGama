"""第二輪審查（執行器／沙盒）的回歸測試：目標載入失敗的歸因、測試呼叫不存在的函式、單檔大小上限、
harness 不可 dump 的開關、JS 批次預算的分批與重跑上限、同模組輔助函式的斷言、Windows 假家目錄，
以及遺失結束狀態時不偽造結束碼 0。
Regression tests for the second review round (executor / sandbox): attribution of a target that fails to load, a
test calling a function that does not exist, the per-file size cap, the harness non-dumpable switch, JS batch
budget grouping and the rerun cap, assertions in same-module helpers, the Windows fake home, and never faking exit
code 0 when the exit status is lost."""
import logging
import os
import signal
import sys
import time

import pytest

import vibeharness.core.sandbox as sandbox_mod
from vibeharness.core.codecheck import check_test_code
from vibeharness.core.models import GeneratedTest, TestStatus
from vibeharness.core.sandbox import (
    EXECUTION_FAILURE_EXIT_CODE, TIMEOUT_EXIT_CODE, DockerSandbox, LocalSubprocessSandbox, sandbox_home_env,
)
from vibeharness.runners.test_executor import (
    REASON_NOT_RUN_CORRECTLY, REASON_RERUN_BUDGET_EXHAUSTED, REASON_TARGET_BROKEN, TestSuiteExecutor,
)

posix_only = pytest.mark.skipif(sys.platform == "win32", reason="POSIX rlimit / process semantics")


def _test(test_id, code, test_type="blackbox_security", language="python"):
    return GeneratedTest(test_id=test_id, test_type=test_type, target_component="x", title=f"t {test_id}",
                         code=code, rationale="", expected_outcome="", language=language)


# --- 1／2. 目標載入失敗與測試端的 AttributeError 歸因 ------------------------------------------------
# --- 1/2. Attribution of target load failures and test-side AttributeErrors -------------------------

_APP = (
    "import ast\n"
    "def lazy():\n"
    "    import missingpkg_vh_xyz\n"
    "    return 1\n"
    "def sub():\n"
    "    import r2_badsub\n"
    "    return r2_badsub.x\n"
    "def parse(s):\n"
    "    return ast.parse(s)\n"
    "def ne():\n"
    "    return undefined_q\n"
    "def attr():\n"
    "    import os\n"
    "    return os.nonexist\n"
    "class C:\n"
    "    pass\n"
)


@pytest.fixture
def target(tmp_path):
    (tmp_path / "r2_app.py").write_text(_APP, encoding="utf-8")
    (tmp_path / "r2_badsub.py").write_text("x = (\n", encoding="utf-8")
    return tmp_path


def test_target_load_failures_during_a_test_are_target_broken_not_defects(target):
    executor = TestSuiteExecutor(LocalSubprocessSandbox(timeout_seconds=60))
    results, _ = executor.execute_test_suite([
        _test("LAZY", "import r2_app\n\ndef test_a():\n    assert r2_app.lazy() == 1\n"),
        _test("SUB_IN_TARGET", "import r2_app\n\ndef test_a():\n    assert r2_app.sub() == 1\n"),
        _test("SUB_IN_TEST", "def test_a():\n    import r2_badsub\n    assert r2_badsub.x\n"),
        _test("PARSE", "import r2_app\n\ndef test_a():\n    assert r2_app.parse('x = (')\n"),
        _test("NAME", "import r2_app\n\ndef test_a():\n    assert r2_app.ne()\n"),
        _test("TEST_IMPORT", "def test_a():\n    import missingpkg_vh_abc\n    assert 1\n"),
    ], working_dir=str(target))
    by_id = {r.test_id: r for r in results}
    for test_id in ("LAZY", "SUB_IN_TARGET", "SUB_IN_TEST"):
        result = by_id[test_id]
        assert result.status == TestStatus.ERROR, (test_id, result.failure_reason)
        assert result.failure_reason.startswith(REASON_TARGET_BROKEN), (test_id, result.failure_reason)
        assert not result.is_security_exploit_confirmed
    assert "ModuleNotFoundError" in by_id["LAZY"].failure_reason
    assert "SyntaxError" in by_id["SUB_IN_TEST"].failure_reason
    # 執行期解析輸入（'<unknown>' 檔名）是目標行為；目標裡的 NameError 仍是缺陷
    # Parsing input at run time (the '<unknown>' file name) is target behaviour; a NameError in the target stays a defect
    assert by_id["PARSE"].status == TestStatus.FAILED and not by_id["PARSE"].is_security_exploit_confirmed
    assert by_id["NAME"].status == TestStatus.FAILED and "NameError" in by_id["NAME"].failure_reason
    # 測試自己匯入了不存在的套件：測試端的錯誤，不是目標壞掉
    # The test itself imports a package that does not exist: a test-side mistake, not a broken target
    assert by_id["TEST_IMPORT"].status == TestStatus.ERROR
    assert by_id["TEST_IMPORT"].failure_reason.startswith(REASON_NOT_RUN_CORRECTLY)


def test_missing_target_attribute_called_from_the_test_is_a_harness_error(target):
    executor = TestSuiteExecutor(LocalSubprocessSandbox(timeout_seconds=60))
    results, _ = executor.execute_test_suite([
        _test("FN", "import r2_app\n\ndef test_a():\n    assert r2_app.nonexist() == 1\n"),
        _test("CLS", "from r2_app import C\n\ndef test_a():\n    assert C.nope\n"),
        _test("IN_TARGET", "import r2_app\n\ndef test_a():\n    assert r2_app.attr()\n"),
    ], working_dir=str(target))
    by_id = {r.test_id: r for r in results}
    for test_id in ("FN", "CLS"):
        assert by_id[test_id].status == TestStatus.ERROR, by_id[test_id].failure_reason
        assert by_id[test_id].failure_reason.startswith(REASON_NOT_RUN_CORRECTLY)
        assert "AttributeError" in by_id[test_id].failure_reason
    # 目標內部拋出的同樣訊息仍是缺陷 ／ the same message raised inside the target stays a defect
    assert by_id["IN_TARGET"].status == TestStatus.FAILED


def test_is_harness_failure_unit_cases():
    harness = TestSuiteExecutor._is_harness_failure
    lazy = {"message": "ModuleNotFoundError: No module named 'm'",
            "details": "/run/test_vh_000.py:5: \n_ _ _\n    def f():\n>       import m\nE   ModuleNotFoundError\n\n"
                       "/srv/app.py:2: ModuleNotFoundError"}
    assert harness(lazy) and TestSuiteExecutor._target_failed_to_load(lazy)
    runtime_syntax = {"message": '  File "<unknown>", line 1',
                      "details": 'E     File "<unknown>", line 1\nE   SyntaxError: x\n\n/usr/lib/python3/ast.py:52: SyntaxError'}
    assert not harness(runtime_syntax)
    missing = {"message": "AttributeError: module 'app' has no attribute 'nope'",
               "details": "E   AttributeError\n\n/run/test_vh_003.py:4: AttributeError"}
    assert harness(missing)
    assert not harness(dict(missing, details="E   AttributeError\n\n/srv/app.py:4: AttributeError"))
    assert not harness(dict(missing, details=""))  # 沒有回溯時不降級 ／ without a traceback it is not downgraded
    too_large = {"message": "OSError: [Errno 27] File too large", "details": "/srv/app.py:3: OSError"}
    assert harness(too_large)


def test_mutant_that_breaks_a_lazy_import_is_invalid_but_a_name_error_is_killed(target):
    executor = TestSuiteExecutor(LocalSubprocessSandbox(timeout_seconds=60))
    lazy = [_test("L", "import r2_app\n\ndef test_a():\n    assert r2_app.lazy() == 1\n")]
    assert executor.run_mutant_batch(lazy, str(target), 60) == "invalid"
    name = [_test("N", "import r2_app\n\ndef test_a():\n    assert r2_app.ne()\n")]
    assert executor.run_mutant_batch(name, str(target), 60) == "killed"


# --- 3. 單檔大小上限（RLIMIT_FSIZE）與擷取檔的讀回 ------------------------------------------------
# --- 3. The per-file size cap (RLIMIT_FSIZE) and reading back the capture files ----------------------

@posix_only
def test_file_size_cap_bounds_the_output_and_does_not_kill_the_writer(tmp_path):
    cap = 1024 * 1024
    returncode, stdout, stderr = LocalSubprocessSandbox._run(
        ["sh", "-c", "head -c 3000000 /dev/zero | tr '\\0' 'a'; echo done >&2"], cwd=str(tmp_path),
        env=dict(os.environ), timeout=30, limits={"cpu_seconds": 30, "file_bytes": cap}
    )
    assert len(stdout) <= cap
    assert returncode != -signal.SIGXFSZ  # SIGXFSZ 被忽略：只有 EFBIG ／ SIGXFSZ ignored: only EFBIG
    assert "done" in stderr


@posix_only
def test_noisy_test_hits_the_cap_while_junit_and_coverage_still_work(tmp_path, monkeypatch):
    monkeypatch.setattr(sandbox_mod, "SANDBOX_MAX_FILE_BYTES", 2 * 1024 * 1024)
    (tmp_path / "r2_cov.py").write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    executor = TestSuiteExecutor(LocalSubprocessSandbox(timeout_seconds=60))
    noisy = (
        "import os\n"
        "def test_noisy(tmp_path):\n"
        "    with open(os.path.join(str(tmp_path), 'big.bin'), 'wb') as f:\n"
        "        f.write(b'x' * (4 * 1024 * 1024))\n"
        "    assert True\n"
    )
    results, coverage = executor.execute_test_suite([
        _test("OK", "from r2_cov import add\n\ndef test_a():\n    assert add(1, 2) == 3\n"),
        _test("NOISY", noisy),
    ], working_dir=str(tmp_path), collect_coverage=True)
    ok, big = results
    assert ok.status == TestStatus.PASSED
    assert coverage is not None and coverage > 0
    # 寫入超過上限是沙盒的限制，不是目標的缺陷 ／ hitting the cap is a sandbox limit, not a defect in the target
    assert big.status == TestStatus.ERROR and "Errno 27" in big.failure_reason


def test_read_capture_does_not_move_the_shared_offset(monkeypatch):
    import tempfile
    with tempfile.TemporaryFile() as f:
        f.write(b"hello\r\nworld")
        f.flush()  # 真實情況是子行程直接寫 fd ／ in real use the child writes the fd directly
        before = f.tell()
        assert sandbox_mod._read_capture(f) == "hello\nworld"
        assert f.tell() == before
        monkeypatch.setattr(sandbox_mod, "_MAX_CAPTURE_BYTES", 8)
        monkeypatch.setattr(sandbox_mod, "_CAPTURE_HEAD_BYTES", 2)
        text = sandbox_mod._read_capture(f)
        assert text.startswith("he") and text.endswith("\nworld") and "truncated" in text
        assert f.tell() == before


# --- 4. harness 不可 dump：開關、警告、只在本機路徑 ---------------------------------------------
# --- 4. Harness non-dumpable: the switch, the warning, local path only --------------------------------

def test_keep_dumpable_env_skips_prctl(monkeypatch):
    import ctypes
    monkeypatch.setattr(sandbox_mod, "_harness_hardened", False)
    monkeypatch.setattr(sandbox_mod.sys, "platform", "linux")
    monkeypatch.setenv("VIBEHARNESS_KEEP_DUMPABLE", "1")
    called = []
    monkeypatch.setattr(ctypes, "CDLL", lambda *a, **k: called.append(a))
    sandbox_mod.harden_harness_process()
    assert called == []


def test_hardening_failure_is_logged_once_at_warning(monkeypatch, caplog):
    import ctypes
    monkeypatch.setattr(sandbox_mod, "_harness_hardened", False)
    monkeypatch.setattr(sandbox_mod.sys, "platform", "linux")
    monkeypatch.delenv("VIBEHARNESS_KEEP_DUMPABLE", raising=False)

    def broken(*a, **k):
        raise OSError("no libc")
    monkeypatch.setattr(ctypes, "CDLL", broken)
    with caplog.at_level(logging.WARNING, logger="VibeHarness.Sandbox"):
        sandbox_mod.harden_harness_process()
        sandbox_mod.harden_harness_process()
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING and "non-dumpable" in r.getMessage()]
    assert len(warnings) == 1


def test_only_the_local_provider_hardens_the_harness(monkeypatch, tmp_path):
    calls = []
    monkeypatch.setattr(sandbox_mod, "harden_harness_process", lambda: calls.append(1))
    monkeypatch.setattr(LocalSubprocessSandbox, "_run", staticmethod(lambda *a, **k: (0, "", "")))
    DockerSandbox(verify=False).execute_pytest_files({"test_a.py": "def test_a():\n    assert 1\n"},
                                                     working_dir=str(tmp_path))
    assert calls == []
    LocalSubprocessSandbox().execute_pytest_files({"test_a.py": "def test_a():\n    assert 1\n"},
                                                  working_dir=str(tmp_path))
    assert calls == [1]


# --- 5. JS 批次預算依模組數分批；重跑不超出預算 -------------------------------------------------
# --- 5. The JS batch budget is grouped by module count; reruns never exceed the budget ---------------

_PASS_JUNIT = '<testsuites><testsuite name="s"><testcase classname="test" name="ok" time="0.1"/></testsuite></testsuites>'
_GOOD_JS = 'import { test } from "node:test";\nimport assert from "node:assert/strict";\ntest("ok", () => { assert.ok(1); });\n'


class _TimedJsSandbox:
    """Node 沙盒的替身：每個模組花 `delay` 秒（`hang` 中的模組耗盡給它的預算）後回報結果。
    Stands in for a Node sandbox: every module takes `delay` seconds (modules in `hang` use up their budget)."""
    supports_typescript = True

    def __init__(self, timeout_seconds, delay=0.0, hang=()):
        self.timeout_seconds = timeout_seconds
        self.delay = delay
        self.hang = set(hang)
        self.calls = []

    def execute_pytest_files(self, files, working_dir=None, timeout_seconds=None, **kw):
        module = os.path.splitext(next(iter(files)))[0]
        self.calls.append((module, timeout_seconds))
        if module in self.hang or self.delay > timeout_seconds:
            time.sleep(timeout_seconds)
            return TIMEOUT_EXIT_CODE, "", "timed out", float(timeout_seconds), None, None
        time.sleep(self.delay)
        return 0, "", "", self.delay, None, _PASS_JUNIT


def test_many_slow_but_passing_js_modules_all_run(tmp_path):
    # 20 個各 0.3 秒的模組、2 秒的批次預算：每組 10 個時第二輪還有約 0.8 秒餘裕（慢的 CI runner 也夠），
    # 共用一份預算時則有 8 個會被標成未重跑
    # 20 modules of 0.3s each on a 2s batch budget: with groups of 10 the second pass keeps about 0.8s of slack
    # (enough for slow CI runners), while one shared budget left 8 of them not re-run
    js = _TimedJsSandbox(timeout_seconds=2, delay=0.3)
    executor = TestSuiteExecutor(sandbox=LocalSubprocessSandbox(), js_sandbox_factory=lambda: js,
                                 per_test_timeout_seconds=2)
    tests = [_test(f"J{i}", _GOOD_JS, language="javascript") for i in range(20)]
    results, _ = executor.execute_test_suite(tests, working_dir=str(tmp_path))
    assert all(r.status == TestStatus.PASSED for r in results), [r.failure_reason for r in results]
    assert all(budget <= 2 for _, budget in js.calls)  # 每個模組仍不超過一份批次預算 ／ never more than one batch budget


def test_js_rerun_timeouts_are_capped_by_the_remaining_budget(tmp_path):
    js = _TimedJsSandbox(timeout_seconds=3, hang={"test_vh_000", "test_vh_001", "test_vh_002"})
    executor = TestSuiteExecutor(sandbox=LocalSubprocessSandbox(), js_sandbox_factory=lambda: js,
                                 per_test_timeout_seconds=2)
    tests = [_test(f"H{i}", _GOOD_JS, language="javascript") for i in range(3)]
    results, _ = executor.execute_test_suite(tests, working_dir=str(tmp_path))
    # 第一輪：000 拿到整份 3 秒；重跑：001 拿 2 秒，002 只剩 1 秒（不是另一份 2 秒）
    # First pass: 000 gets the whole 3s; reruns: 001 gets 2s, 002 only the 1s left (not another 2s)
    assert js.calls == [("test_vh_000", 3), ("test_vh_001", 2), ("test_vh_002", 1)]
    assert "after 1s" in results[2].failure_reason


class _BatchHangsPySandbox:
    """Python 沙盒的替身：整批逾時，逐測重跑時每個模組耗盡給它的預算。
    A Python sandbox stand-in: the batch times out and every per-test rerun uses up its budget."""
    timeout_seconds = 3

    def __init__(self):
        self.budgets = []

    def execute_pytest_files(self, files, timeout_seconds=None, **kw):
        self.budgets.append(timeout_seconds)
        if timeout_seconds:
            time.sleep(timeout_seconds)
        return TIMEOUT_EXIT_CODE, "", "timed out", 0.0, None, None


# 重跑共睡 3 秒（2 + 1）；上限多留 4 秒給較慢的 runner，涵蓋率啟用時再放寬 2 倍——超出預算的重跑仍會被抓到
# The reruns sleep 3 s in total (2 + 1); the bound adds 4 s of headroom for slower runners and doubles it while
# coverage is active — a rerun that overran the budget would still be caught
_RERUN_BOUND = (3.0 + 4.0) * (2 if "coverage" in sys.modules else 1)


def test_python_rerun_timeouts_are_capped_by_the_remaining_budget(tmp_path):
    sandbox = _BatchHangsPySandbox()
    executor = TestSuiteExecutor(sandbox=sandbox, per_test_timeout_seconds=2)
    tests = [_test(f"P{i}", f"def test_{i}():\n    assert 1\n") for i in range(3)]
    start = time.monotonic()
    results, _ = executor.execute_test_suite(tests, working_dir=str(tmp_path))
    assert sandbox.budgets == [None, 2, 1]
    assert time.monotonic() - start < _RERUN_BOUND  # 重跑總時間不超出 3 秒的批次預算 ／ the reruns stay within the 3s batch budget
    assert "after 2s" in results[0].failure_reason and "after 1s" in results[1].failure_reason
    assert results[2].failure_reason == REASON_RERUN_BUDGET_EXHAUSTED


# --- 6. 同一模組中含斷言的輔助函式與基底類別 ----------------------------------------------------
# --- 6. Asserting helpers and base classes in the same module ----------------------------------------

def test_module_level_helper_assertions_count():
    code = (
        "def _inner(r):\n"
        "    assert r == 1\n"
        "def check(r):\n"
        "    _inner(r)\n"
        "def test_a():\n"
        "    check(1)\n"
        "class TestX:\n"
        "    def test_b(self):\n"
        "        check(1)\n"
    )
    assert check_test_code(code) == (True, None)


def test_base_class_helper_assertions_count():
    code = (
        "class Base:\n"
        "    def verify(self, v):\n"
        "        assert v\n"
        "class TestX(Base):\n"
        "    def test_a(self):\n"
        "        self.verify(1)\n"
    )
    assert check_test_code(code) == (True, None)


def test_helpers_without_assertions_or_external_calls_are_still_rejected():
    code = (
        "import json\n"
        "def noop(r):\n"
        "    return r\n"
        "def test_a():\n"
        "    noop(1)\n"
        "def test_b():\n"
        "    json.loads('1')\n"
        "class TestY:\n"
        "    def test_c(self):\n"
        "        self.missing()\n"
    )
    valid, problem = check_test_code(code)
    assert not valid and "test_a" in problem and "test_b" in problem and "TestY.test_c" in problem


# --- 7. Windows 假家目錄也涵蓋 APPDATA／LOCALAPPDATA ---------------------------------------------
# --- 7. The Windows fake home also covers APPDATA / LOCALAPPDATA --------------------------------------

def test_windows_fake_home_points_appdata_into_the_run_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(sandbox_mod.sys, "platform", "win32")
    env = sandbox_home_env(str(tmp_path))
    home = env["HOME"]
    assert env["USERPROFILE"] == home
    assert env["APPDATA"] == os.path.join(home, "AppData", "Roaming") and os.path.isdir(env["APPDATA"])
    assert env["LOCALAPPDATA"] == os.path.join(home, "AppData", "Local") and os.path.isdir(env["LOCALAPPDATA"])
    assert "PROGRAMDATA" not in env  # 全機共用的設定保留原值 ／ the machine-wide setting keeps its real value


# --- 8. 結束狀態遺失時不偽造結束碼 0；沒有 WNOWAIT 時的後備路徑 --------------------------------------
# --- 8. A lost exit status never becomes exit code 0; the fallback without WNOWAIT --------------------

@posix_only
@pytest.mark.skipif(not hasattr(os, "waitid"), reason="needs os.waitid")
def test_lost_exit_status_is_reported_as_an_execution_failure(tmp_path, monkeypatch):
    def reaped_elsewhere(*a, **k):
        raise ChildProcessError(10, "No child processes")
    monkeypatch.setattr(sandbox_mod.os, "waitid", reaped_elsewhere)
    returncode, _, stderr = LocalSubprocessSandbox._run(
        [sys.executable, "-c", "pass"], cwd=str(tmp_path), env=dict(os.environ), timeout=30
    )
    assert returncode == EXECUTION_FAILURE_EXIT_CODE and "exit status" in stderr


@posix_only
def test_fallback_without_wnowait_keeps_the_exit_code_and_the_timeout(tmp_path, monkeypatch):
    monkeypatch.delattr(sandbox_mod.os, "WNOWAIT", raising=False)
    returncode, stdout, _ = LocalSubprocessSandbox._run(
        [sys.executable, "-c", "print('x'); raise SystemExit(3)"], cwd=str(tmp_path), env=dict(os.environ), timeout=30
    )
    assert (returncode, stdout) == (3, "x\n")
    returncode, _, _ = LocalSubprocessSandbox._run(
        [sys.executable, "-c", "import time; time.sleep(30)"], cwd=str(tmp_path), env=dict(os.environ), timeout=1
    )
    assert returncode is None


@posix_only
def test_fallback_lost_status_is_not_exit_zero(tmp_path, monkeypatch):
    monkeypatch.delattr(sandbox_mod.os, "WNOWAIT", raising=False)
    # macOS 會先走 kqueue；關掉它才能測到 waitpid 輪詢這條後備路徑
    # macOS takes the kqueue path first; turn it off to reach the waitpid polling fallback
    monkeypatch.setattr(LocalSubprocessSandbox, "_wait_kqueue", staticmethod(lambda proc, timeout: None))
    real_waitpid = os.waitpid
    state = {"first": True}

    def waitpid(pid, options):
        # 只有第一次（我們的輪詢）假裝已被回收，之後讓 Popen 正常回收殭屍
        # Only the first call (our poll) pretends it was reaped; afterwards Popen reaps the zombie normally
        if state["first"]:
            state["first"] = False
            raise ChildProcessError(10, "No child processes")
        return real_waitpid(pid, options)
    monkeypatch.setattr(sandbox_mod.os, "waitpid", waitpid)
    returncode, _, _ = LocalSubprocessSandbox._run(
        [sys.executable, "-c", "pass"], cwd=str(tmp_path), env=dict(os.environ), timeout=30
    )
    assert returncode == EXECUTION_FAILURE_EXIT_CODE


def test_remaining_seconds_never_exceeds_the_budget_through_float_error(monkeypatch):
    """monotonic() 很大時 (t0 + 30.0) - t0 的浮點誤差不會讓剩餘預算變成 31 秒。
    With a large monotonic(), the float error in (t0 + 30.0) - t0 never turns the remaining budget into 31s."""
    from vibeharness.runners import test_executor as executor_mod
    t0 = 4090.833771576286  # (t0 + 30.0) - t0 == 30.000000000000455 ／ 會產生浮點誤差的值 ／ a value with float error
    deadline = t0 + 30.0
    monkeypatch.setattr(executor_mod.time, "monotonic", lambda: t0)
    assert deadline - t0 > 30.0  # 前提：真的有浮點誤差 ／ precondition: the float error is real
    assert executor_mod._remaining_seconds(deadline, 30.0) == 30
    monkeypatch.setattr(executor_mod.time, "monotonic", lambda: t0 + 29.5)
    assert executor_mod._remaining_seconds(deadline, 30.0) == 1
