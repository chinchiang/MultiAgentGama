"""`scripts/check_all.py`：依序跑完整檢查，摘要 log 留下每一步的結束碼與關鍵行，失敗、逾時與略過都寫明。
`scripts/check_all.py`: runs the full check in order; the summary log keeps each step's exit code and key lines, and
names failures, timeouts and skipped steps."""

import importlib.util
import os
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_spec = importlib.util.spec_from_file_location("check_all", os.path.join(REPO_ROOT, "scripts", "check_all.py"))
assert _spec and _spec.loader
tool = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = tool
_spec.loader.exec_module(tool)

PYTEST_OUTPUT = """\
........................................................................ [ 99%]
FAILED tests/test_x.py::test_a - AssertionError: assert 1 == 2
---------- coverage: platform linux, python 3.12.3-final-0 -----------
Name                                 Stmts   Miss  Cover
vibeharness/cli.py                     400     10  97.50%
TOTAL                                 9291    396  95.74%
Required test coverage of 93% reached. Total coverage: 95.74%
1 failed, 2669 passed, 3 skipped in 277.52s (0:04:37)
"""


def _fake_runner(results):
    """依步驟名稱回傳（結束碼, 輸出）的假 runner，並記下被呼叫的步驟。
    A fake runner returning (exit code, output) by step name, recording the steps it was called for."""
    called = []

    def run(cmd, cwd, timeout):
        name = next(n for n, c in tool.steps(sys.executable, "master") if c == list(cmd))
        called.append(name)
        return results.get(name, (0, "ok\n"))

    return run, called


def test_pytest_keeps_the_coverage_total_the_counts_and_the_failures():
    """pytest 的摘要留下失敗、`TOTAL` 覆蓋率、門檻那行與最後的計數，不留逐檔的覆蓋率表。
    pytest's summary keeps the failures, the `TOTAL` coverage, the threshold line and the final counts, not the per-file
    coverage table."""
    assert tool.key_lines("pytest", PYTEST_OUTPUT, failed=True) == [
        "FAILED tests/test_x.py::test_a - AssertionError: assert 1 == 2",
        "TOTAL                                 9291    396  95.74%",
        "Required test coverage of 93% reached. Total coverage: 95.74%",
        "1 failed, 2669 passed, 3 skipped in 277.52s (0:04:37)",
    ]


def test_red_on_base_keeps_its_counts_and_every_result_line():
    """red-on-base 的摘要先寫紅、綠、略過的數量，再列出每一行結果，行數再多也不截斷。
    red-on-base's summary starts with the red, green and skipped counts and then lists every result line, however
    many."""
    lines = [f"red    tests/test_a.py::test_{i}  assert 0 == 1" for i in range(40)]
    lines += [f"green  tests/test_b.py::test_{i}" for i in range(7)]
    lines += ["skipped tests/test_c.py::test_win  only on Windows"]
    kept = tool.key_lines("red_on_base", "\n".join(lines) + "\n", failed=True)
    assert kept[0] == "red=40 green=7 skipped=1 hang=0"
    assert kept[1:] == lines


def test_red_on_base_counts_and_keeps_its_hang_lines():
    """red-on-base 逾時列出的 `hang` 行也算進數量並留在摘要裡（#186），不會被當成沒有結果。
    red-on-base's `hang` lines after a timeout are counted and kept in the summary too (#186), not dropped as no
    result."""
    lines = ["red    tests/test_a.py::test_one  assert 0 == 1", "hang   tests/test_a.py::test_two"]
    kept = tool.key_lines("red_on_base", "\n".join(lines) + "\ncould not compare: did not finish\n", failed=True)
    assert kept[0] == "red=1 green=0 skipped=0 hang=1"
    assert kept[1:3] == lines


def test_a_failed_step_without_key_lines_keeps_its_last_lines():
    """失敗卻沒有任何關鍵行的一步留下最後 `TAIL_LINES` 行，讓錯誤原因看得到。
    A failed step with no key line keeps its last `TAIL_LINES` lines, so the cause shows."""
    output = "\n".join(f"line {i}" for i in range(50)) + "\nTraceback: boom\n"
    kept = tool.key_lines("mypy", output, failed=True)
    assert len(kept) == tool.TAIL_LINES
    assert kept[-1] == "Traceback: boom"


def test_red_on_base_that_could_not_compare_keeps_its_error():
    """red-on-base 無法比對（沒有任何結果行）時，摘要留下它的錯誤訊息。
    When red-on-base could not compare (no result line), the summary keeps its error message."""
    kept = tool.key_lines("red_on_base", "could not compare: no merge-base\n", failed=True)
    assert kept == ["red=0 green=0 skipped=0 hang=0", "could not compare: no merge-base"]


def test_every_step_passing_exits_zero(tmp_path):
    """每一步都是 0 時結束碼是 0，摘要的最後一行說全部通過。
    When every step exits 0 the exit code is 0 and the summary's last line says so."""
    run, called = _fake_runner({})
    log = tmp_path / "checks.log"
    assert tool.main(["--log", str(log)], repo=str(tmp_path), run=run) == 0
    assert called == list(tool.STEP_NAMES)
    assert log.read_text(encoding="utf-8").splitlines()[-1] == "== all steps exited 0"


def test_a_failing_or_timed_out_step_makes_the_exit_code_non_zero(tmp_path):
    """有一步不是 0、有一步逾時，結束碼是 1，摘要寫出兩者，最後一行點名它們；完整輸出寫進 `.full.log`。
    One step exiting non-zero and one timing out exit 1; the summary names both, its last line lists them, and the
    full output goes to the `.full.log`."""
    run, _ = _fake_runner({"mypy": (1, "Found 2 errors in 1 file\n"), "golden": (None, "partial\n")})
    log = tmp_path / "checks.log"
    assert tool.main(["--log", str(log), "--timeout", "5"], repo=str(tmp_path), run=run) == 1
    summary = log.read_text(encoding="utf-8").splitlines()
    assert "mypy exit=1" in summary and "Found 2 errors in 1 file" in summary
    assert "golden timeout after 5s" in summary
    assert summary[-1] == "== not 0: mypy, golden"
    assert "partial" in (tmp_path / "checks.full.log").read_text(encoding="utf-8")


def test_a_skipped_step_is_not_run_and_the_log_says_so(tmp_path):
    """`--skip` 的步驟不會跑，摘要寫明它被略過，也不算失敗。
    A `--skip` step does not run, the summary says it was skipped, and it does not count as a failure."""
    run, called = _fake_runner({"golden": (1, "1 differing line(s), 1 distinct\n")})
    log = tmp_path / "checks.log"
    assert tool.main(["--log", str(log), "--skip", "golden", "--skip", "red_on_base"], repo=str(tmp_path),
                     run=run) == 0
    assert "golden" not in called and "red_on_base" not in called
    assert "golden skipped (--skip)" in log.read_text(encoding="utf-8").splitlines()


def test_a_command_past_its_timeout_is_stopped_and_reported_as_a_timeout(tmp_path):
    """真的跑一個超過時限的命令：它被停掉，結束碼是 None（逾時），不會當成通過。
    A real command past its time limit is stopped and its exit code is None (a timeout), never a pass."""
    code, _ = tool.run_command([sys.executable, "-c", "import time; time.sleep(60)"], str(tmp_path), 0.5)
    assert code is None


def test_the_log_header_is_written_before_the_first_step_runs(tmp_path):
    """第一步開始跑的時候，摘要 log 與 `.full.log` 已經有檔頭那一行，跑很久的 pytest 期間 log 不是空的；原本檔頭等到
    第一步跑完才寫進檔案（#191）。
    When the first step starts, the summary log and the `.full.log` already hold the header line, so the log is not
    empty during a long pytest run; the header used to reach the files only once the first step finished (#191)."""
    log = tmp_path / "checks.log"
    seen = {}

    def run(cmd, cwd, timeout):
        if not seen:
            seen["summary"] = log.read_text(encoding="utf-8")
            seen["full"] = (tmp_path / "checks.full.log").read_text(encoding="utf-8")
        return 0, "ok\n"

    assert tool.main(["--log", str(log)], repo=str(tmp_path), run=run) == 0
    assert seen["summary"].startswith("== HEAD "), seen
    assert seen["full"].startswith("== HEAD "), seen


def _changing(step, change):
    """跑到 step 那一步時呼叫 change() 改動 repo 的假 runner（其他步驟照常回 0），並記下被呼叫的步驟。
    A fake runner that calls `change()` to alter the repo while running `step` (every other step returns 0),
    recording the steps it was called for."""
    called = []

    def run(cmd, cwd, timeout):
        name = next(n for n, c in tool.steps(sys.executable, "master") if c == list(cmd))
        called.append(name)
        if name == step:
            change()
        return 0, "ok\n"

    return run, called


def test_a_tracked_file_edited_during_a_step_is_could_not_check(git_repo, tmp_path):
    """有一步跑的時候，已追蹤的檔案被改了：後面讀工作目錄的步驟（test_sdist、golden、red_on_base）會讀到改過的
    內容，結果不屬於任何一個狀態。這次執行在那一步停下，摘要點名那一步，最後一行說無法檢查，結束碼 2（#216）。
    A tracked file edited while a step runs: the later steps that read the working tree (test_sdist, golden,
    red_on_base) would read the edited content, so the results belong to no single state. The run stops after that
    step, the summary names it, its last line says could not check, and the exit code is 2 (#216)."""
    root = tmp_path / "repo"
    root.mkdir()
    (root / "calc.py").write_text("x = 1\n", encoding="utf-8", newline="\n")
    git_repo(root)
    run, called = _changing("test_sdist", lambda: (root / "calc.py").write_text("x = 2\n", encoding="utf-8"))
    log = tmp_path / "checks.log"
    code = tool.main(["--log", str(log)], repo=str(root), run=run)
    summary = log.read_text(encoding="utf-8").splitlines()
    assert called[-1] == "test_sdist", called
    assert summary[-1] == "== could not check: the working tree changed during test_sdist", summary
    full = (tmp_path / "checks.full.log").read_text(encoding="utf-8")
    assert "== could not check: the working tree changed during test_sdist" in full, full
    assert code == 2, summary


def test_a_commit_made_during_a_step_is_could_not_check(git_repo, tmp_path):
    """有一步跑的時候提交了一筆改動：工作目錄前後都是乾淨的，只有 HEAD 變了，摘要卻還寫著開始時的 HEAD。同樣停在
    那一步，結束碼 2（#216）。
    A change committed while a step runs: the working tree is clean before and after, only HEAD moved, yet the summary
    still names the HEAD it started at. The run stops after that step too, exit code 2 (#216)."""
    root = tmp_path / "repo"
    root.mkdir()
    (root / "calc.py").write_text("x = 1\n", encoding="utf-8", newline="\n")
    git = git_repo(root)

    def commit():
        (root / "calc.py").write_text("x = 2\n", encoding="utf-8", newline="\n")
        git("commit", "-q", "-am", "meanwhile")

    run, called = _changing("golden", commit)
    log = tmp_path / "checks.log"
    code = tool.main(["--log", str(log)], repo=str(root), run=run)
    summary = log.read_text(encoding="utf-8").splitlines()
    assert called[-1] == "golden", called
    assert summary[-1] == "== could not check: the working tree changed during golden", summary
    assert code == 2, summary


def test_an_untracked_file_whose_content_changes_during_a_step_is_could_not_check(git_repo, tmp_path):
    """還沒提交的新檔案（例如正在寫的測試）在某一步跑的時候內容變了：HEAD、`git diff HEAD` 與未追蹤檔案的清單
    前後都一樣，只有檔案內容不同，red_on_base 這類步驟仍會讀到它。同樣停在那一步，結束碼 2（#216）。
    A new, uncommitted file (such as a test being written) whose content changes while a step runs: HEAD,
    `git diff HEAD` and the list of untracked files read the same before and after, only the content differs, and steps
    such as red_on_base still read it. The run stops after that step too, exit code 2 (#216)."""
    root = tmp_path / "repo"
    root.mkdir()
    (root / "calc.py").write_text("x = 1\n", encoding="utf-8", newline="\n")
    git_repo(root)
    (root / "test_new.py").write_text("def test_a():\n    pass\n", encoding="utf-8", newline="\n")
    run, called = _changing("mypy", lambda: (root / "test_new.py").write_text("def test_b():\n    pass\n",
                                                                               encoding="utf-8", newline="\n"))
    log = tmp_path / "checks.log"
    code = tool.main(["--log", str(log)], repo=str(root), run=run)
    summary = log.read_text(encoding="utf-8").splitlines()
    assert called[-1] == "mypy", called
    assert summary[-1] == "== could not check: the working tree changed during mypy", summary
    assert code == 2, summary


def test_a_run_during_which_nothing_changes_still_exits_zero_in_a_git_repo(git_repo, tmp_path):
    """在 git repo 裡，跑的期間什麼都沒改（只有 git 忽略的 log 寫進 repo）：每一步都跑，結束碼照舊是 0（#216）。
    In a git repo where nothing changes during the run (only a log git ignores is written inside the repo): every
    step runs and the exit code is still 0 (#216)."""
    root = tmp_path / "repo"
    root.mkdir()
    (root / "calc.py").write_text("x = 1\n", encoding="utf-8", newline="\n")
    (root / ".gitignore").write_text("scratch/\n", encoding="utf-8", newline="\n")
    git_repo(root)
    run, called = _changing("golden", lambda: None)
    assert tool.main([], repo=str(root), run=run) == 0
    assert called == list(tool.STEP_NAMES)


def test_a_file_already_modified_at_the_start_and_edited_again_during_a_step_is_could_not_check(git_repo, tmp_path):
    """開始時已經有未提交改動的檔案，在某一步跑的時候又被改了：HEAD 與檔案清單前後都一樣，只有 `git diff HEAD`
    看得出內容又變了。同樣停在那一步，結束碼 2（#216）。
    A file with uncommitted changes at the start, edited again while a step runs: HEAD and the file list read the same
    before and after, and only `git diff HEAD` shows the content moved again. The run stops after that step too, exit
    code 2 (#216)."""
    root = tmp_path / "repo"
    root.mkdir()
    (root / "calc.py").write_text("x = 1\n", encoding="utf-8", newline="\n")
    git_repo(root)
    (root / "calc.py").write_text("x = 2\n", encoding="utf-8", newline="\n")
    run, called = _changing("ruff", lambda: (root / "calc.py").write_text("x = 3\n", encoding="utf-8", newline="\n"))
    log = tmp_path / "checks.log"
    code = tool.main(["--log", str(log)], repo=str(root), run=run)
    summary = log.read_text(encoding="utf-8").splitlines()
    assert called[-1] == "ruff", called
    assert summary[-1] == "== could not check: the working tree changed during ruff", summary
    assert code == 2, summary


def test_a_log_inside_the_repo_at_a_path_git_does_not_ignore_is_no_change(git_repo, tmp_path):
    """`--log` 指到 repo 裡 git 沒忽略的路徑：script 自己寫的摘要與 `.full.log` 是未追蹤檔案，跑的期間一直在變，
    但它們不是讓結果不可信的改動。每一步都跑，結束碼照舊是 0，而不是每次都在第一步誤報「changed during pytest」
    （#216 審查）。
    `--log` pointing inside the repo at a path git does not ignore: the summary and `.full.log` the script writes are
    untracked files that keep changing during the run, but they are no change that makes the results untrustworthy.
    Every step runs and the exit code is still 0, not a false "changed during pytest" on every run (#216 review)."""
    root = tmp_path / "repo"
    root.mkdir()
    (root / "calc.py").write_text("x = 1\n", encoding="utf-8", newline="\n")
    git_repo(root)
    run, called = _changing("golden", lambda: None)
    log = root / "out" / "checks.log"
    code = tool.main(["--log", str(log)], repo=str(root), run=run)
    summary = log.read_text(encoding="utf-8").splitlines()
    assert summary[-1] == "== all steps exited 0", summary
    assert called == list(tool.STEP_NAMES), called
    assert code == 0, summary
