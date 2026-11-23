"""分支新增或改動的測試，在基準 revision 的程式碼上要是紅的（CODING_STANDARDS 第 1 條；#150）。

修正的回歸測試要在修正之前失敗：「a new test that also passes on `master`」是違規。這支 script 找出工作目錄的
`tests/` 裡，相對於與 `--against` 的 merge-base 新增或 AST 不同的測試函式，把 merge-base 掛成暫時的 detached
worktree、換上工作目錄的 `tests/`，跑這些測試所在的檔案，只讀它們的結果，逐一列出它們在基準上是紅、綠還是
skipped。紅的附上失敗原因，看得出是不是因為錯的理由紅（例如 `ImportError`）；參數化的測試算一筆，有任何 case
通過就是綠的，並列出那些 case；在基準上被 skip 的（包括整個檔案被 skip）列成 skipped（它沒在基準上失敗）；
標了 xfail 而在基準上失敗的是紅的。用在新增回歸測試的分支（`fix:`，或關掉繞過漏洞的 `chore:`、`test:`）：
`refactor:` 的測試本來就該兩邊都綠。

挑選的範圍：只看 `tests/` 底下的 `test_*.py`，其中最上層的 `test*` 函式，以及最上層 `Test*` 類別裡的 `test*`
方法；「改了」是指函式本身的 AST 不同。只改 fixture、helper 或 `conftest.py` 時，用到它們的測試不會被選到。

一個檔案在基準上收集失敗時，其他檔案照樣跑完（`--continue-on-collection-errors`），那個檔案裡選到的測試列成紅的、帶
著收集錯誤；有測試收集不到時，無法比對的訊息也點名每個收集失敗的檔案與錯誤的第一行。基準上的那一次 pytest 最多跑
`--timeout` 秒（預設 1200）：超過就停掉它的行程群組（POSIX；測試開的子行程也在裡面，自己用 setsid 另開群組的子行程停
不到，它若還握著輸出的 pipe，最多再等 10 秒就放棄剩下的輸出）或整個行程樹（Windows 的 `taskkill /T`），已經有結果的
測試照進度記錄分類，其餘列成 `hang`（不算紅也不算綠），並印出 pytest 最後的輸出；faulthandler 在一個測試跑超過
60 秒與時限一半中較短的那個（至少 1 秒）時印出它卡在哪裡。

結束碼：0 全部是紅的（或沒有新增、改動的測試），1 有綠的或 skipped 的（列出來），2 無法比對（找不到 merge-base 或
無法建 worktree、測試檔解析不了或不是 UTF-8、pytest 在基準上沒寫出報告（附上它最後幾行輸出）或報告讀不了、
選到的測試在基準上收集不到、超過 `--timeout`）。

用法：
    python scripts/check_new_tests_red_on_base.py --against master [--timeout 1200]

The tests a branch adds or changes must be red on the base revision's code (CODING_STANDARDS rule 1; #150).

A fix's regression test fails before the fix: "a new test that also passes on `master`" is a violation. This script
finds the test functions in the working tree's `tests/` that are new or whose AST differs from the merge-base with
`--against`, adds that merge-base as a temporary detached worktree with the working tree's `tests/` in place of its
own, runs the files those tests are in, reads only their results, and lists each one as red, green or skipped on the
base. A red one shows its failure reason, so a test that is red for the wrong reason (an `ImportError`, say) is
visible; a parametrized test is one entry, green when any case passes, naming those cases; one skipped on the base
(the whole file included) is listed as skipped (it did not fail there), and one marked xfail that fails on the base is
red. For branches that add regression tests (a `fix:`, or a `chore:` or `test:` closing a bypass): a `refactor:`
keeps its tests green on both sides on purpose.

What it selects: only `test_*.py` under `tests/`, and in them the top-level `test*` functions and the `test*` methods
of top-level `Test*` classes; "changed" means the function's own AST differs. A change only to a fixture, a helper or
`conftest.py` does not select the tests that use it.

When a file fails to collect on the base, the other files still run (`--continue-on-collection-errors`) and the file's
selected tests are red with the collection error; when a test is not collected, the could-not-compare message also
names each file that failed to collect with the first line of its error. The one pytest run on the base takes at most
`--timeout` seconds (default 1200): past that its process group is stopped (POSIX; the tests' child processes are in
it, while a child that opened a group of its own with setsid is not stopped, and when it still holds the output pipe
the rest of the output is given up after 10 seconds) or its whole process tree (`taskkill /T` on Windows), the tests
that already have a result are sorted from the progress records, the rest are listed as `hang` (neither red nor
green), and pytest's last output is printed; faulthandler prints where a test is stuck once it runs longer than the
shorter of 60 seconds and half the time limit (at least 1 second).

Exit code: 0 every test is red (or no test is new or changed), 1 some are green or skipped (they are listed), 2 could
not compare (no merge-base or the worktree could not be added, a test file does not parse or is not UTF-8, pytest
wrote no report on the base (its last output lines are shown) or one that does not read, a selected test was not
collected on the base, the run took longer than `--timeout`).

Usage:
    python scripts/check_new_tests_red_on_base.py --against master [--timeout 1200]
"""

from __future__ import annotations

import argparse
import ast
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import NamedTuple

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# 基準上的那一次 pytest 最多跑這麼久（秒），超過就停掉它，沒有結果的測試列成 hang（#186）
# The longest the one pytest run on the base may take (seconds); past it the run is stopped and the tests without a
# result are listed as hang (#186)
DEFAULT_TIMEOUT = 1200.0
# 一個測試跑超過這麼久（秒，且不超過時限的一半），faulthandler 就印出它卡在哪裡
# A test running longer than this (seconds, and no more than half the time limit) gets faulthandler's dump of where
# it is stuck
_DUMP_AFTER = 60.0
# 逾時之後印出的 pytest 最後幾行（含 faulthandler 的輸出）
# The last lines of pytest's output printed after a timeout (faulthandler's dump included)
_HANG_TAIL = 40
# 停掉之後最多再等這麼久（秒）把輸出讀完：逃出行程群組的子行程可能還握著 pipe，不能讓它又把檢查卡住
# After stopping, wait at most this long (seconds) to read the rest of the output: a child that left the process
# group may still hold the pipe, and must not hang the check again
_PIPE_GRACE = 10.0
# 每個測試跑完就記一行的 pytest 外掛：逾時時沒有 JUnit 報告，靠它分出哪些測試已經有結果
# A pytest plugin writing one line as each test finishes: a timed-out run writes no JUnit report, so this tells which
# tests already have a result
_PROGRESS_PLUGIN = """\
import os

_PATH = os.environ["VH_RED_ON_BASE_PROGRESS"]


def _write(nodeid, outcome):
    with open(_PATH, "a", encoding="utf-8") as f:
        f.write(nodeid + "\\t" + outcome + "\\n")


def pytest_runtest_logreport(report):
    if report.failed:
        _write(report.nodeid, "failed")
    elif report.skipped:
        _write(report.nodeid, "failed" if hasattr(report, "wasxfail") else "skipped")
    elif report.when == "call":
        _write(report.nodeid, "passed")


def pytest_collectreport(report):
    if report.failed:
        _write(report.nodeid, "broken")
"""
_PLUGIN_NAME = "vh_red_on_base_progress"


class BaseRun(NamedTuple):
    """基準上那一次 pytest 的結果：每個 node id 的 (狀態, 說明)、收集失敗的檔案與錯誤，以及逾時時 pytest 的最後幾行
    （沒逾時是 None）。
    The one pytest run on the base: each node id's (status, detail), the files that failed to collect with their
    errors, and, after a timeout, pytest's last output lines (None when it finished)."""

    results: dict[str, tuple[str, str]]
    broken_files: dict[str, str]
    hang_tail: list[str] | None


class NoReport(Exception):
    """pytest 在基準上沒寫出報告（無法啟動、或被中途結束），帶著它輸出的最後幾行。
    pytest wrote no report on the base (it could not start, or was ended midway), carrying the last lines of its
    output."""


def _git(repo: str, *args: str) -> str:
    # 明寫 UTF-8：Windows 上 text=True 預設用系統編碼，含中文的測試檔會解不了
    # UTF-8 explicitly: on Windows, text=True defaults to the system code page, which cannot decode a test file with
    # Chinese text
    return subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True, encoding="utf-8").stdout


def test_functions(source: str, filename: str = "<unknown>") -> dict[str, str]:
    """一個測試檔裡每個測試函式的 pytest 名稱（`test_x` 或 `TestY::test_x`）對到它的 AST 傾印，比對內容是否改過。
    Each test function of a test file, by its pytest name (`test_x` or `TestY::test_x`), mapped to its AST dump, to
    tell whether its content changed."""
    found: dict[str, str] = {}
    for node in ast.parse(source, filename=filename).body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith("test"):
            found[node.name] = ast.dump(node)
        elif isinstance(node, ast.ClassDef) and node.name.startswith("Test"):
            for item in node.body:
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)) and item.name.startswith("test"):
                    found[f"{node.name}::{item.name}"] = ast.dump(item)
    return found


def new_and_changed(repo: str, base: str) -> list[str]:
    """工作目錄的 `tests/` 裡，相對於 base 新增或內容改了的測試，寫成 pytest 的 node id。
    The tests in the working tree's `tests/` that are new or changed relative to base, as pytest node ids."""
    selected = []
    for path in sorted(Path(repo, "tests").rglob("test_*.py")):
        rel = path.relative_to(repo).as_posix()
        try:
            old = test_functions(_git(repo, "show", f"{base}:{rel}"), f"{base[:7]}:{rel}")
        except subprocess.CalledProcessError:
            old = {}
        for name, dump in test_functions(path.read_text(encoding="utf-8"), rel).items():
            if old.get(name) != dump:
                selected.append(f"{rel}::{name}")
    return selected


def _file_of(node_id: str) -> str:
    """node id 所在的測試檔（`tests/a/test_x.py::TestY::test_z` 是 `tests/a/test_x.py`）。
    The test file a node id is in (`tests/a/test_x.py::TestY::test_z` is `tests/a/test_x.py`)."""
    return node_id.split("::", 1)[0]


def junit_key(node_id: str) -> tuple[str, str]:
    """一個 node id 在 JUnit 報告裡的 (classname, name)：`tests/a/test_x.py::TestY::test_z` 是
    (`tests.a.test_x.TestY`, `test_z`)。讀報告時用它把結果對回選到的 node id；classname 從 pytest 的 rootdir 算起，
    所以 `run_on_base` 把 rootdir 固定在 worktree。
    A node id's (classname, name) in the JUnit report: `tests/a/test_x.py::TestY::test_z` is (`tests.a.test_x.TestY`,
    `test_z`). Reading the report uses it to map results back to the selected node ids; the classname counts from
    pytest's rootdir, so `run_on_base` pins the rootdir to the worktree."""
    path, *parts = node_id.split("::")
    return ".".join([path.removesuffix(".py").replace("/", "."), *parts[:-1]]), parts[-1]


def _reason(problem: ET.Element) -> str:
    """一筆失敗的原因：pytest 的訊息第一行（例如 `assert -1 == 3`）；收集錯誤的訊息只有「collection failure」，
    改取內容最後一行 `E   …`（例如 `ImportError: cannot import name …`）。
    A failure's reason: the first line of pytest's message (e.g. `assert -1 == 3`); a collection error's message is
    only "collection failure", so its text's last `E   …` line is taken instead (e.g. `ImportError: cannot import
    name …`)."""
    message = (problem.get("message") or "").strip()
    if message and message != "collection failure":
        return message.splitlines()[0]
    lines = [line.strip() for line in (problem.text or "").splitlines() if line.strip()]
    errors = [line[1:].strip() for line in lines if line.startswith("E ")]
    return errors[-1] if errors else (lines[0] if lines else message)


def _module_skip_reason(skip: ET.Element) -> str:
    """整個檔案被 skip 的原因：JUnit 的 message 只寫「collection skipped」，原因在內容裡，形如
    `('tests/test_x.py', 3, "Skipped: could not import 'y'")`；讀不出來就用內容本身。
    Why a whole file was skipped: JUnit's message says only "collection skipped", and the reason is in the text, shaped
    `('tests/test_x.py', 3, "Skipped: could not import 'y'")`; when that does not parse, the text itself is used."""
    text = (skip.text or "").strip()
    try:
        value = ast.literal_eval(text)
    except (ValueError, SyntaxError):
        value = None
    if isinstance(value, tuple) and value and isinstance(value[-1], str):
        # 只取第一行：和紅的測試只帶失敗的第一行一樣，一筆結果印在一行
        # The first line only: as a red test carries only its failure's first line, one result prints on one line
        return next(iter(value[-1].splitlines()), "skipped")
    return text.splitlines()[0] if text else skip.get("message") or "skipped"


def run_on_base(worktree: Path, node_ids: list[str], report: Path, timeout: float = DEFAULT_TIMEOUT) -> BaseRun:
    """在 worktree 裡跑 node_ids 所在的整個檔案，只讀它們的結果，回傳每個 node id 在基準上的 (狀態, 說明)。狀態是
    `red`、`green` 或 `skipped`：參數化的測試算一筆，有任何 case 通過就是綠的，說明列出那些 case；沒有通過但有 case
    被 skip（或整個檔案被 skip）是 skipped，說明是 skip 的原因（它沒在基準上失敗，結束碼和綠的一樣算）；全部失敗是
    紅的，說明是第一個 case 的失敗原因。收集不到的測試檔，裡面每個選到的測試是紅的、帶那個收集錯誤；檔案收集得到、
    報告裡卻沒有的測試是 `not collected`，`main` 把它當成無法比對，絕不算紅或綠。pytest 沒寫出報告時丟出 `NoReport`。
    另外回傳每個收集失敗的檔案與它的錯誤，給 `main` 的無法比對訊息用。超過 timeout 秒還沒跑完時照 `_run_with_timeout` 停掉，
    已經有結果的測試照進度記錄分類，其餘列成 `hang`，並帶回 pytest 的最後幾行。
    Runs the whole files node_ids are in on the worktree, reads only their results, and returns each node id's (status,
    detail) on the base. The status is `red`, `green` or `skipped`: a parametrized test is one entry, green when any
    case passes, with those cases as the detail; skipped when none passes and a case (or the whole file) was skipped,
    with the skip reason as the detail (it did not fail on the base, so the exit code counts it like green); red when
    all fail, with the first case's failure as the detail. Each selected test in a file that failed to collect is red
    with that collection error; a test missing from the report of a file that did collect is `not collected`, which
    `main` takes as could not compare, never as red or green. When pytest writes no report it raises `NoReport`.
    Also returns each file that failed to collect with its error, for `main`'s could-not-compare message. A run past
    timeout seconds is stopped as `_run_with_timeout` does: the tests that already have a result are sorted from the
    progress records, the rest are `hang`, and pytest's last output lines come back with them."""
    # pytest 的結束碼分不出「無法啟動」與「選到的檔案收集失敗」（兩者都可能是 4），所以只讀報告
    # pytest's exit code cannot tell "could not start" from "a selected file failed to collect" (both can be 4), so
    # only the report is read
    # 跑整個檔案、只讀選到的：給 pytest 一個它找不到的 node id（例如有 __init__ 的類別），它會整批不跑
    # Run whole files and read only the selected tests: given one node id it cannot find (say a class with
    # __init__), pytest runs none of the batch
    # --rootdir 固定在 worktree：JUnit 的 classname 從 rootdir 算起，`tests/` 底下的 pytest.ini 不能讓它少了 `tests.`
    # --rootdir is pinned to the worktree: the JUnit classname counts from the rootdir, so a pytest.ini under `tests/`
    # cannot drop its `tests.`
    # --maxfail=0（不設上限）排在基準設定的 addopts 之後，蓋掉 -x／--maxfail：同一個檔案裡先失敗的測試不能讓 pytest
    # 停下，使選到的測試沒有結果
    # --maxfail=0 (no limit) comes after the base config's addopts and overrides -x / --maxfail: a test that fails
    # earlier in the same file must not stop pytest and leave the selected tests without a result
    # --continue-on-collection-errors：一個檔案收集失敗時 pytest 預設整批中斷，其他檔案選到的測試就沒有結果（#186）
    # --continue-on-collection-errors: by default pytest stops the whole run when one file fails to collect, leaving
    # the selected tests of every other file without a result (#186)
    # faulthandler_timeout（pytest 內建）：卡住的測試在時限之前就印出它停在哪一行
    # faulthandler_timeout (built into pytest): a stuck test prints where it stopped before the time limit
    files = sorted({_file_of(node_id) for node_id in node_ids})
    plugin_dir = report.parent / "plugin"
    plugin_dir.mkdir(exist_ok=True)
    (plugin_dir / f"{_PLUGIN_NAME}.py").write_text(_PROGRESS_PLUGIN, encoding="utf-8")
    progress = report.parent / "progress.tsv"
    env = dict(os.environ, VH_RED_ON_BASE_PROGRESS=str(progress),
               PYTHONPATH=os.pathsep.join(p for p in (str(plugin_dir), os.environ.get("PYTHONPATH", "")) if p))
    dump_after = max(1.0, min(_DUMP_AFTER, timeout / 2))
    cmd = [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "-p", _PLUGIN_NAME,
           f"--rootdir={worktree}", "--maxfail=0", "--continue-on-collection-errors",
           "-o", f"faulthandler_timeout={dump_after:g}", f"--junitxml={report}", *files]
    output, finished = _run_with_timeout(cmd, worktree, env, timeout)
    lines = [line for line in output.splitlines() if line.strip()]
    if not finished:
        return _results_after_timeout(progress, node_ids, lines[-_HANG_TAIL:])
    if not report.is_file():
        raise NoReport("pytest wrote no report on the base:\n" + "\n".join(lines[-5:]))
    passed: dict[str, list[str]] = {}
    skipped: dict[str, str] = {}
    failed: dict[str, str] = {}
    broken_files: dict[str, str] = {}
    skipped_files: dict[str, str] = {}
    by_key = {junit_key(node_id): node_id for node_id in node_ids}
    for case in ET.parse(report).getroot().iter("testcase"):
        problem = case.find("failure")
        if problem is None:
            problem = case.find("error")
        if not case.get("classname"):
            # 模組層級的結果：name 是模組路徑（tests.test_x）。整個檔案被 skip（例如 importorskip）不是收集錯誤
            # A module-level result: name is the module path (tests.test_x). A whole file skipped (importorskip, say)
            # is not a collection error
            module_file = case.get("name", "").replace(".", "/") + ".py"
            module_skip = case.find("skipped")
            if problem is None and module_skip is not None:
                skipped_files[module_file] = _module_skip_reason(module_skip)
            else:
                reason = _reason(problem) if problem is not None else ""
                broken_files[module_file] = reason or "collection failure"
            continue
        # `test_x[a-b]` 拆成函式名稱與 case id；沒參數化時 case id 是空的
        # `test_x[a-b]` splits into the function name and the case id; the case id is empty when not parametrized
        function, _, case_id = case.get("name", "").partition("[")
        node_id = by_key.get((case.get("classname", ""), function))
        if node_id is None:
            continue
        skip = case.find("skipped")
        if problem is not None:
            failed.setdefault(node_id, _reason(problem))
        elif skip is not None and skip.get("type") == "pytest.xfail":
            # JUnit 把 xfail 記成 skipped，但它在基準上確實失敗了：是紅的
            # JUnit records an xfail as skipped, but it did fail on the base: it is red
            why = next(iter((skip.get("message") or "").splitlines()), "")
            failed.setdefault(node_id, f"xfail on the base: {why}" if why else "xfail on the base")
        elif skip is not None:
            skipped.setdefault(node_id, (skip.get("message") or "skipped").splitlines()[0])
        else:
            passed.setdefault(node_id, []).append(case_id.removesuffix("]"))
    results: dict[str, tuple[str, str]] = {}
    for node_id in node_ids:
        test_file = _file_of(node_id)
        if node_id in passed:
            cases = [case for case in passed[node_id] if case]
            results[node_id] = ("green", f"green on the base: {', '.join(cases)}" if cases else "")
        elif node_id in skipped:
            results[node_id] = ("skipped", skipped[node_id])
        elif node_id in failed:
            results[node_id] = ("red", failed[node_id])
        elif test_file in skipped_files:
            results[node_id] = ("skipped", skipped_files[test_file])
        elif test_file in broken_files:
            results[node_id] = ("red", broken_files[test_file])
        else:
            results[node_id] = ("not collected", "")
    return BaseRun(results, broken_files, None)


def _run_with_timeout(cmd: list[str], cwd: Path, env: dict[str, str], timeout: float) -> tuple[str, bool]:
    """跑命令，回傳（stdout 與 stderr 合併的輸出, 有沒有在時限內跑完）；逾時就停掉它的行程群組（POSIX）或整個行程樹
    （Windows），停掉之後最多再等 `_PIPE_GRACE` 秒讀完輸出。
    Run a command and return (stdout and stderr combined, whether it finished in time); past the time limit its
    process group (POSIX) or whole process tree (Windows) is stopped, and the output is read for at most `_PIPE_GRACE`
    seconds after that."""
    posix = os.name == "posix"
    proc = subprocess.Popen(cmd, cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            encoding="utf-8", errors="replace", start_new_session=posix)
    try:
        return proc.communicate(timeout=timeout)[0], True
    except subprocess.TimeoutExpired:
        if posix:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        else:
            # /T 連同子行程一起停（venv 的 python 可能是再開真正直譯器的啟動器）
            # /T stops the children too (a venv's python may be a launcher starting the real interpreter)
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)], capture_output=True)
            proc.kill()
        try:
            return proc.communicate(timeout=_PIPE_GRACE)[0], False
        except subprocess.TimeoutExpired:
            # pytest 已經停了，pipe 卻還有別的行程開著：放棄剩下的輸出
            # pytest has stopped but another process still holds the pipe open: the rest of the output is given up
            proc.wait()
            return "(pytest's output was not read: a process outside its group still holds the pipe)", False


def _results_after_timeout(progress: Path, node_ids: list[str], tail: list[str]) -> BaseRun:
    """逾時的那一次：照外掛的進度記錄分類已經有結果的測試（任何 case 通過是綠、有 skip 是 skipped、否則紅），收集失敗
    的檔案裡的測試是紅的，其餘是 `hang`，絕不算紅或綠。
    The timed-out run: the tests with a result are sorted from the plugin's progress records (any passing case green,
    a skip skipped, otherwise red), the tests of a file that failed to collect are red, and the rest are `hang`, never
    red or green."""
    outcomes: dict[str, list[str]] = {}
    broken_paths: set[str] = set()
    if progress.is_file():
        for line in progress.read_text(encoding="utf-8", errors="replace").splitlines():
            nodeid, _, outcome = line.rpartition("\t")
            if outcome == "broken":
                broken_paths.add(nodeid)
            else:
                outcomes.setdefault(nodeid.split("[", 1)[0], []).append(outcome)
    results: dict[str, tuple[str, str]] = {}
    for node_id in node_ids:
        seen = outcomes.get(node_id, [])
        if "passed" in seen:
            results[node_id] = ("green", "green on the base before the run timed out")
        elif "skipped" in seen:
            results[node_id] = ("skipped", "skipped on the base before the run timed out")
        elif seen:
            results[node_id] = ("red", "failed on the base before the run timed out (its reason is in no report)")
        elif _file_of(node_id) in broken_paths:
            results[node_id] = ("red", "failed to collect on the base")
        else:
            results[node_id] = ("hang", "")
    return BaseRun(results, {path: "failed to collect" for path in broken_paths}, tail)


def main(argv: list[str] | None = None, repo: str = _REPO) -> int:
    parser = argparse.ArgumentParser(description="List the new and changed tests that already pass on the base.")
    parser.add_argument("--against", required=True, metavar="REV", help="the revision whose merge-base is the base")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, metavar="SECONDS",
                        help=f"stop the run on the base after this long and list the tests without a result as hang "
                             f"(default: {DEFAULT_TIMEOUT:g})")
    args = parser.parse_args(argv)
    # 解開符號連結（macOS 的 /var/folders 指向 /private/var/folders）：--rootdir 與 pytest 算 node id 用的路徑要相同，
    # classname 才對得上
    # Resolve symlinks (macOS's /var/folders points at /private/var/folders): --rootdir and the path pytest computes
    # node ids from must be the same, or no classname matches
    scratch = Path(tempfile.mkdtemp(prefix="vh_red_on_base_")).resolve()
    worktree = scratch / "base"
    try:
        base = _git(repo, "merge-base", args.against, "HEAD").strip()
        node_ids = new_and_changed(repo, base)
        if not node_ids:
            print("no new or changed tests under tests/")
            return 0
        # worktree add 會跑 post-checkout：hook 指到一個空目錄，開發者的 hook 失敗也不會讓比對失敗（#158）
        # worktree add runs post-checkout: hooks point at an empty directory, so a failing hook of the developer's
        # cannot fail the comparison (#158)
        no_hooks = scratch / "no-hooks"
        no_hooks.mkdir()
        _git(repo, "-c", f"core.hooksPath={no_hooks.as_posix()}", "worktree", "add", "--detach", str(worktree), base)
        # 換上工作目錄的 tests/：要跑的是分支的測試，程式碼是基準的
        # Swap in the working tree's tests/: the branch's tests run against the base's code
        shutil.rmtree(worktree / "tests", ignore_errors=True)
        shutil.copytree(Path(repo, "tests"), worktree / "tests")
        results, broken_files, hang_tail = run_on_base(worktree, node_ids, scratch / "report.xml", args.timeout)
    except (subprocess.CalledProcessError, OSError, ET.ParseError, SyntaxError, UnicodeDecodeError, NoReport) as exc:
        # git 的錯誤在它的 stderr；pytest 沒寫出報告是 NoReport（帶著 pytest 的最後幾行），報告讀不了是 ParseError；
        # 測試檔解析不了是 SyntaxError，不是 UTF-8 是 UnicodeDecodeError
        # git's error is in its stderr; pytest writing no report is NoReport (carrying pytest's last lines), a report
        # that does not read is ParseError; a test file that does not parse raises SyntaxError, and one that is not
        # UTF-8 UnicodeDecodeError
        if isinstance(exc, subprocess.CalledProcessError):
            detail = exc.stderr
        elif isinstance(exc, ET.ParseError):
            # ParseError 是 SyntaxError 的子類別，要先判斷：它沒有檔名與行號
            # ParseError is a subclass of SyntaxError, so it is checked first: it has no file name or line number
            detail = "the report pytest wrote on the base does not read"
        elif isinstance(exc, SyntaxError):
            detail = f"in {exc.filename}, line {exc.lineno}"
        else:
            detail = ""
        print(f"could not compare: {exc}\n{detail}", file=sys.stderr)
        return 2
    finally:
        subprocess.run(["git", "worktree", "remove", "--force", str(worktree)], cwd=repo, capture_output=True)
        subprocess.run(["git", "worktree", "prune"], cwd=repo, capture_output=True)
        shutil.rmtree(scratch, ignore_errors=True)
    missing = [node_id for node_id in node_ids if results[node_id][0] == "not collected"]
    for node_id in node_ids:
        status, detail = results[node_id]
        if status != "not collected":
            print(f"{status:<6} {node_id}  {detail}".rstrip())
    if hang_tail is not None:
        # 逾時：卡住的測試沒有結果，紅綠都不能算；附上 pytest 最後的輸出（faulthandler 點名卡住的測試）
        # Timed out: a stuck test has no result, neither red nor green; pytest's last output follows (faulthandler
        # names the stuck test)
        print(f"could not compare: the run on the base did not finish within {args.timeout:g}s; the tests without "
              "a result are listed as hang. pytest's last output:", file=sys.stderr)
        print("\n".join(hang_tail), file=sys.stderr)
        return 2
    if missing:
        # 沒被收集的測試在基準上沒有結果，紅綠都不能算：整次比對不成立
        # A test that was not collected has no result on the base, neither red nor green: the comparison fails
        print("could not compare: not collected on the base: " + ", ".join(missing), file=sys.stderr)
        # 點名收集失敗的檔案：收集不到常是另一個檔案壞了的連帶結果，只列測試看不出原因（#186）
        # Name the files that failed to collect: an uncollected test is often a side effect of another broken file,
        # and the test list alone does not show the cause (#186)
        if broken_files:
            print("files that failed to collect on the base:", file=sys.stderr)
            for path, error in sorted(broken_files.items()):
                print(f"  {path}: {error}", file=sys.stderr)
        return 2
    return 1 if any(status != "red" for status, _ in results.values()) else 0


if __name__ == "__main__":
    sys.exit(main())
