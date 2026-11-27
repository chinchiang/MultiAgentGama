"""`scripts/check_all.py`：依序跑完整檢查，摘要 log 留下每一步的結束碼與關鍵行，失敗、逾時與略過都寫明。
`scripts/check_all.py`: runs the full check in order; the summary log keeps each step's exit code and key lines, and
names failures, timeouts and skipped steps."""

import importlib.util
import os
import subprocess
import sys

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_spec = importlib.util.spec_from_file_location("check_all", os.path.join(REPO_ROOT, "scripts", "check_all.py"))
assert _spec and _spec.loader
tool = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = tool
_spec.loader.exec_module(tool)
# bi_english 的基準要和 `tool.BI_ENGLISH_BASE` 一致；另取一個模組名，不蓋掉 tests/test_bi_english.py 載入的那一份
# bi_english's base must match `tool.BI_ENGLISH_BASE`; loaded under its own name so the copy tests/test_bi_english.py
# loads is left alone
_bi_spec = importlib.util.spec_from_file_location("check_bi_english_for_check_all",
                                                  os.path.join(REPO_ROOT, "scripts", "check_bi_english.py"))
assert _bi_spec and _bi_spec.loader
bi_english = importlib.util.module_from_spec(_bi_spec)
sys.modules[_bi_spec.name] = bi_english
_bi_spec.loader.exec_module(bi_english)

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


@pytest.mark.parametrize("outcome, expected", [("all pass", 0), ("ruff fails", 1), ("tree changes", 2)])
def test_the_summary_ends_with_the_exit_code(git_repo, tmp_path, outcome, expected):
    """摘要的最後一行是 `exit=<結束碼>`：只看 `grep '^exit=' scratch/checks-<sha>.log` 就知道跑完了沒、結果是什麼；
    程序被中斷時沒有這一行。0、1、2 三種結束碼各跑一次。
    The summary's last line is `exit=<exit code>`: `grep '^exit=' scratch/checks-<sha>.log` alone tells whether the
    run is over and how it ended, and an interrupted run has no such line. Each of the exit codes 0, 1 and 2 is run
    once."""
    root = tmp_path / "repo"
    root.mkdir()
    (root / "calc.py").write_text("x = 1\n", encoding="utf-8", newline="\n")
    git_repo(root)
    if outcome == "tree changes":
        run, _ = _changing("golden", lambda: (root / "calc.py").write_text("x = 2\n", encoding="utf-8"))
    else:
        run, _ = _fake_runner({"ruff": (1, "E501\n")} if outcome == "ruff fails" else {})
    log = tmp_path / "checks.log"
    code = tool.main(["--log", str(log)], repo=str(root), run=run)
    summary = log.read_text(encoding="utf-8").splitlines()
    assert summary[-1] == f"exit={expected}", summary[-2:]
    assert code == expected, summary


def test_a_kept_output_line_starting_with_exit_is_indented_so_only_the_last_line_matches(tmp_path):
    """步驟整段保留的輸出（例如 golden）裡有一行以 `exit=` 開頭：摘要照樣留下它，但前面加兩個空白，所以
    `grep '^exit='` 只比對到最後的結束碼那一行，還在跑或被中斷時不會誤判成跑完了。
    A step whose output is kept whole (golden, say) prints a line starting with `exit=`: the summary keeps it,
    indented by two spaces, so `grep '^exit='` matches only the exit-code line at the end, and a run still going or
    interrupted is not taken for finished."""
    run, _ = _fake_runner({"golden": (0, "exit=0\n0 differing line(s), 0 distinct\n")})
    log = tmp_path / "checks.log"
    assert tool.main(["--log", str(log)], repo=str(tmp_path), run=run) == 0
    summary = log.read_text(encoding="utf-8").splitlines()
    matching = [line for line in summary if line.startswith("exit=")]
    assert matching == ["exit=0"], matching
    assert "  exit=0" in summary, summary


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
    """每一步都是 0 時結束碼是 0，摘要的結論行（`exit=` 前一行）說全部通過。
    When every step exits 0 the exit code is 0 and the summary's verdict line (the one before `exit=`) says so."""
    run, called = _fake_runner({})
    log = tmp_path / "checks.log"
    assert tool.main(["--log", str(log)], repo=str(tmp_path), run=run) == 0
    assert called == list(tool.STEP_NAMES)
    assert _verdict(log.read_text(encoding="utf-8").splitlines()) == "== all steps exited 0"


def test_a_failing_or_timed_out_step_makes_the_exit_code_non_zero(tmp_path):
    """有一步不是 0、有一步逾時，結束碼是 1，摘要寫出兩者，結論行點名它們；完整輸出寫進 `.full.log`。
    One step exiting non-zero and one timing out exit 1; the summary names both, its verdict line lists them, and the
    full output goes to the `.full.log`."""
    run, _ = _fake_runner({"mypy": (1, "Found 2 errors in 1 file\n"), "golden": (None, "partial\n")})
    log = tmp_path / "checks.log"
    assert tool.main(["--log", str(log), "--timeout", "5"], repo=str(tmp_path), run=run) == 1
    summary = log.read_text(encoding="utf-8").splitlines()
    assert "mypy exit=1" in summary and "Found 2 errors in 1 file" in summary
    assert "golden timeout after 5s" in summary
    assert _verdict(summary) == "== not 0: mypy, golden"
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


def _changing(step, change, against="master"):
    """跑到 step 那一步時呼叫 change() 改動 repo 的假 runner（其他步驟照常回 0），並記下被呼叫的步驟；against 要和
    傳給 `main` 的 `--against` 相同，才認得出每一步的指令。
    A fake runner that calls `change()` to alter the repo while running `step` (every other step returns 0),
    recording the steps it was called for; `against` must match the `--against` given to `main`, so each step's
    command is recognised."""
    called = []

    def run(cmd, cwd, timeout):
        name = next(n for n, c in tool.steps(sys.executable, against) if c == list(cmd))
        called.append(name)
        if name == step:
            change()
        return 0, "ok\n"

    return run, called


def test_a_tracked_file_edited_during_a_step_is_could_not_check(git_repo, tmp_path):
    """有一步跑的時候，已追蹤的檔案被改了：後面讀工作目錄的步驟（test_sdist、golden、red_on_base）會讀到改過的
    內容，結果不屬於任何一個狀態。這次執行在那一步停下，摘要點名那一步，結論行說無法檢查，結束碼 2（#216）。
    A tracked file edited while a step runs: the later steps that read the working tree (test_sdist, golden,
    red_on_base) would read the edited content, so the results belong to no single state. The run stops after that
    step, the summary names it, its verdict line says could not check, and the exit code is 2 (#216)."""
    root = tmp_path / "repo"
    root.mkdir()
    (root / "calc.py").write_text("x = 1\n", encoding="utf-8", newline="\n")
    git_repo(root)
    run, called = _changing("test_sdist", lambda: (root / "calc.py").write_text("x = 2\n", encoding="utf-8"))
    log = tmp_path / "checks.log"
    code = tool.main(["--log", str(log)], repo=str(root), run=run)
    summary = log.read_text(encoding="utf-8").splitlines()
    assert called[-1] == "test_sdist", called
    assert _verdict(summary) == "== could not check: the working tree changed during test_sdist", summary
    full = (tmp_path / "checks.full.log").read_text(encoding="utf-8")
    assert "== could not check: the working tree changed during test_sdist" in full, full
    assert code == 2, summary


def test_the_against_ref_moving_during_a_step_is_could_not_check(git_repo, tmp_path):
    """有一步跑的時候 `--against` 的 ref（預設 `master`）移動了，例如另一個終端機合併了 PR 再
    `git fetch . origin/master:master`：HEAD 與工作目錄都沒變，但 golden、red_on_base 比對的 merge-base
    跟著變了，前後步驟比的不是同一個基準。停在那一步，結論行點名 ref，結束碼 2（#216 第一輪審查 Spec (c)2）。
    The `--against` ref (`master` by default) moving while a step runs, say when another terminal merges a PR and runs
    `git fetch . origin/master:master`: HEAD and the working tree stay as they were, but the merge-base that
    golden and red_on_base compare against moves with it, so the steps no longer share one base. The run
    stops after that step, its verdict line names the ref, and the exit code is 2 (#216 round-1 review, spec (c)2)."""
    root = tmp_path / "repo"
    root.mkdir()
    (root / "calc.py").write_text("x = 1\n", encoding="utf-8", newline="\n")
    git = git_repo(root)
    git("branch", "-M", "master")
    git("checkout", "-q", "-b", "work")
    (root / "calc.py").write_text("x = 2\n", encoding="utf-8", newline="\n")
    git("commit", "-q", "-am", "work")
    run, called = _changing("golden", lambda: git("branch", "-f", "master", "work"))
    log = tmp_path / "checks.log"
    code = tool.main(["--log", str(log)], repo=str(root), run=run)
    summary = log.read_text(encoding="utf-8").splitlines()
    assert called[-1] == "golden", called
    assert _verdict(summary) == "== could not check: `master` moved during golden", summary
    full = (tmp_path / "checks.full.log").read_text(encoding="utf-8")
    assert "== could not check: `master` moved during golden" in full, full
    assert code == 2, summary


def test_origin_master_moving_during_a_step_is_could_not_check(git_repo, tmp_path):
    """有一步跑的時候 `git fetch` 移動了 `origin/master`：bi_english 一律比對 HEAD 和 `origin/master` 的 merge-base，
    `--against` 是預設的 `master` 也一樣，所以前後步驟比的不是同一個基準。HEAD、工作目錄與 `master` 都沒變，停在
    那一步，結論行點名 `origin/master`，結束碼 2（#216 第一輪審查 Spec (c)2）。
    `git fetch` moving `origin/master` while a step runs: bi_english always compares against the merge-base of HEAD
    and `origin/master`, even with the default `--against master`, so the steps no longer share one base. HEAD, the
    working tree and `master` stay as they were; the run stops after that step, its verdict line names `origin/master`,
    and the exit code is 2 (#216 round-1 review, spec (c)2)."""
    root = tmp_path / "repo"
    root.mkdir()
    (root / "calc.py").write_text("x = 1\n", encoding="utf-8", newline="\n")
    git = git_repo(root)
    git("branch", "-M", "master")
    git("update-ref", "refs/remotes/origin/master", "HEAD")
    fetched = git("commit-tree", "HEAD^{tree}", "-p", "HEAD", "-m", "fetched").stdout.strip()
    run, called = _changing("pytest", lambda: git("update-ref", "refs/remotes/origin/master", fetched))
    log = tmp_path / "checks.log"
    code = tool.main(["--log", str(log)], repo=str(root), run=run)
    summary = log.read_text(encoding="utf-8").splitlines()
    assert called[-1] == "pytest", called
    assert _verdict(summary) == "== could not check: `origin/master` moved during pytest", summary
    full = (tmp_path / "checks.full.log").read_text(encoding="utf-8")
    assert "== could not check: `origin/master` moved during pytest" in full, full
    assert code == 2, summary


def _repo_with_origin_master(git_repo, tmp_path, origin=True):
    """`master` 上有一筆 commit 的 repo，origin 為真時 `origin/master` 也指著它；回傳 (根目錄, git, 另一筆 commit)，
    另一筆 commit 用 `commit-tree` 做出來，HEAD 不動。
    A repo with one commit on `master`, and `origin/master` pointing at it when origin is true; returns (root, git,
    another commit), the other commit made with `commit-tree` so HEAD stays put."""
    root = tmp_path / "repo"
    root.mkdir()
    (root / "calc.py").write_text("x = 1\n", encoding="utf-8", newline="\n")
    git = git_repo(root)
    git("branch", "-M", "master")
    if origin:
        git("update-ref", "refs/remotes/origin/master", "HEAD")
    other = git("commit-tree", "HEAD^{tree}", "-p", "HEAD", "-m", "fetched").stdout.strip()
    return root, git, other


def test_a_ref_moving_with_a_working_tree_change_in_one_step_names_the_working_tree(git_repo, tmp_path):
    """同一步裡工作目錄變了、`origin/master` 也移動了：結論行只寫工作目錄，結束碼 2（#216 第一輪審查 Spec (c)2）。
    The working tree changing and `origin/master` moving in one step: the verdict line names only the working tree, and
    the exit code is 2 (#216 round-1 review, spec (c)2)."""
    root, git, other = _repo_with_origin_master(git_repo, tmp_path)

    def both():
        (root / "calc.py").write_text("x = 2\n", encoding="utf-8", newline="\n")
        git("update-ref", "refs/remotes/origin/master", other)

    run, called = _changing("golden", both)
    log = tmp_path / "checks.log"
    code = tool.main(["--log", str(log)], repo=str(root), run=run)
    summary = log.read_text(encoding="utf-8").splitlines()
    assert _verdict(summary) == "== could not check: the working tree changed during golden", summary
    assert code == 2, summary


def test_against_origin_master_names_origin_master_when_it_moves(git_repo, tmp_path):
    """`--against origin/master` 時 `--against` 和 bi_english 的基準是同一個 ref，只比一次；它移動時結論行點名
    `origin/master`，結束碼 2（#216 第一輪審查 Spec (c)2）。
    With `--against origin/master` the `--against` ref and bi_english's base are one ref, compared once; when it moves
    the verdict line names `origin/master`, and the exit code is 2 (#216 round-1 review, spec (c)2)."""
    root, git, other = _repo_with_origin_master(git_repo, tmp_path)
    run, called = _changing("ruff", lambda: git("update-ref", "refs/remotes/origin/master", other),
                            against="origin/master")
    log = tmp_path / "checks.log"
    code = tool.main(["--log", str(log), "--against", "origin/master"], repo=str(root), run=run)
    summary = log.read_text(encoding="utf-8").splitlines()
    assert called[-1] == "ruff", called
    assert _verdict(summary) == "== could not check: `origin/master` moved during ruff", summary
    assert code == 2, summary


def test_origin_master_created_during_a_step_counts_as_moving(git_repo, tmp_path):
    """開始時還沒有 `origin/master`，跑到一半 `git fetch` 建立了它：被建立也算移動，結論行點名它，結束碼 2
    （#216 第一輪審查 Spec (c)2）。
    No `origin/master` at the start, and a `git fetch` creates it midway: being created counts as moving, so the
    verdict line names it and the exit code is 2 (#216 round-1 review, spec (c)2)."""
    root, git, other = _repo_with_origin_master(git_repo, tmp_path, origin=False)
    run, called = _changing("mypy", lambda: git("update-ref", "refs/remotes/origin/master", other))
    log = tmp_path / "checks.log"
    code = tool.main(["--log", str(log)], repo=str(root), run=run)
    summary = log.read_text(encoding="utf-8").splitlines()
    assert called[-1] == "mypy", called
    assert _verdict(summary) == "== could not check: `origin/master` moved during mypy", summary
    assert code == 2, summary


def test_bi_english_without_a_base_compares_against_bi_english_base(monkeypatch):
    """`steps()` 跑 `scripts/check_bi_english.py` 時沒給 `--base`，它就取 HEAD 和 `origin/master` 的 merge-base；
    `BI_ENGLISH_BASE` 必須是同一個 ref，兩邊有一邊改了，這裡就會紅（#216 第一輪審查 Spec (c)2）。換掉的 `_git`
    記下第一個 git 呼叫後就丟錯結束。
    `steps()` runs `scripts/check_bi_english.py` without `--base`, so it takes the merge-base of HEAD and
    `origin/master`; `BI_ENGLISH_BASE` must be the same ref, and this turns red when either side changes (#216
    round-1 review, spec (c)2). The replaced `_git` records the first git call, then raises to end the run."""
    calls = []

    def fake_git(*args):
        calls.append(args)
        raise subprocess.CalledProcessError(1, ["git", *args], stderr="stopped by the test")

    monkeypatch.setattr(bi_english, "_git", fake_git)
    bi_english.main([])
    assert calls[:1] == [("merge-base", "HEAD", tool.BI_ENGLISH_BASE)], calls


POSIX_USER = pytest.mark.skipif(os.name == "nt" or os.geteuid() == 0,
                                reason="needs POSIX file modes and a user that mode 000 locks out")
POSIX = pytest.mark.skipif(os.name == "nt", reason="needs POSIX symlinks")


def _plain_repo(git_repo, tmp_path):
    """已提交 `calc.py` 的 repo，回傳 (根目錄, git)。
    A repo with `calc.py` committed; returns (root, git)."""
    root = tmp_path / "repo"
    root.mkdir()
    (root / "calc.py").write_text("x = 1\n", encoding="utf-8", newline="\n")
    return root, git_repo(root)


def _verdict(summary):
    """摘要的結論行：最後一行 `exit=<結束碼>` 的前一行。不到兩行或最後一行不是 `exit=` 時直接失敗；結論行的位置
    再變時，讀它的測試只要改這裡。
    The summary's verdict line: the line before the last one, `exit=<exit code>`. Fails at once when the summary has
    fewer than two lines or its last line is not `exit=`; when the verdict line moves again, the tests that read it
    change here alone."""
    assert len(summary) >= 2 and summary[-1].startswith("exit="), summary[-2:]
    return summary[-2]


def _run_main(root, tmp_path, change=lambda: None, step="golden"):
    """在 root 跑 `main`，step 那一步呼叫 change()；回傳 (結束碼, 摘要的每一行, `.full.log` 的內容, 被呼叫的步驟)。
    Runs `main` in root, calling change() during step; returns (exit code, the summary's lines, the `.full.log`
    text, the steps called)."""
    run, called = _changing(step, change)
    log = tmp_path / "checks.log"
    code = tool.main(["--log", str(log)], repo=str(root), run=run)
    full = (tmp_path / "checks.full.log").read_text(encoding="utf-8")
    return code, log.read_text(encoding="utf-8").splitlines(), full, called


@POSIX_USER
def test_an_untracked_file_that_cannot_be_read_stops_before_any_step(git_repo, tmp_path):
    """開始時就有讀不到的未追蹤檔（權限 000）：它的內容不在雜湊裡，途中改了也看不出來，所以一步都不跑，結論行
    點名那個檔案，結束碼 2，摘要最後一行是 `exit=2`（#216 第一輪審查 Standards 第 3 條；原本只雜湊例外名稱，兩次
    都讀不到就算沒變）。
    An untracked file that cannot be read at the start (mode 000): its content is not in the hash, so a change to it
    would go unseen, and no step runs; the verdict line names the file, the exit code is 2 and the summary's last line
    is `exit=2` (#216 round-1 review, standards item 3; it used to hash only the exception's name, so two failed reads
    counted as no change)."""
    root, _ = _plain_repo(git_repo, tmp_path)
    locked = root / "notes.txt"
    locked.write_text("draft\n", encoding="utf-8")
    locked.chmod(0)
    try:
        code, summary, full, called = _run_main(root, tmp_path)
    finally:
        locked.chmod(0o600)
    assert called == [], called
    assert summary[-1] == "exit=2", summary[-2:]
    assert _verdict(summary) == "== could not check: `notes.txt` cannot be read (PermissionError)", summary
    assert "== could not check: `notes.txt` cannot be read (PermissionError)" in full, full
    assert code == 2, summary


@POSIX_USER
def test_two_untracked_files_that_cannot_be_read_name_the_first_and_count_the_rest(git_repo, tmp_path):
    """開始時有兩個讀不到的未追蹤檔：結論行點名第一個（git 列出的順序），後面寫還有幾個（#216 第一輪審查
    Standards 第 3 條）。
    Two untracked files that cannot be read at the start: the verdict line names the first (in git's order) and counts
    the rest (#216 round-1 review, standards item 3)."""
    root, _ = _plain_repo(git_repo, tmp_path)
    locked = [root / "a.txt", root / "b.txt"]
    for path in locked:
        path.write_text("draft\n", encoding="utf-8")
        path.chmod(0)
    try:
        code, summary, _, called = _run_main(root, tmp_path)
    finally:
        for path in locked:
            path.chmod(0o600)
    assert called == [], called
    assert _verdict(summary) == "== could not check: `a.txt` cannot be read (PermissionError) (+1 more)", summary
    assert code == 2, summary


@POSIX
@pytest.mark.parametrize("target", ["missing", "subdir"], ids=["dangling", "to-a-directory"])
def test_an_untracked_symlink_is_hashed_by_its_target_and_does_not_stop_the_run(git_repo, tmp_path, target):
    """未追蹤的 symlink（壞掉的、或指向目錄的）不是讀不到：git 追蹤的是連結的目標文字，所以照雜湊那段文字，每一步
    照常跑（#216 第一輪審查 Standards 第 3 條的第二次審查：`890cffa` 把 `open()` 的錯誤都當成讀不到，誤停）。
    An untracked symlink (dangling, or to a directory) is not unreadable: git tracks the link's target text, so that
    text is hashed and every step runs (second review of #216 round-1 standards item 3: `890cffa` took every `open()`
    error for unreadable and stopped)."""
    root, _ = _plain_repo(git_repo, tmp_path)
    (root / "subdir").mkdir()
    (root / "subdir" / "inner.txt").write_text("x\n", encoding="utf-8")
    os.symlink(target, root / "link")
    code, summary, _, called = _run_main(root, tmp_path)
    assert called[-1:] == ["red_on_base"], summary
    assert code == 0, summary


@POSIX
def test_an_untracked_symlink_pointed_elsewhere_during_a_step_is_could_not_check(git_repo, tmp_path):
    """未追蹤的 symlink 在某一步跑的時候改指到別處：雜湊的是連結的目標文字，所以停在那一步（#216 第一輪審查
    Standards 第 3 條的第二次審查）。
    An untracked symlink pointed elsewhere while a step runs: the link's target text is hashed, so the run stops after
    that step (second review of #216 round-1 standards item 3)."""
    root, _ = _plain_repo(git_repo, tmp_path)
    os.symlink("one", root / "link")

    def repoint():
        os.remove(root / "link")
        os.symlink("two", root / "link")

    code, summary, _, called = _run_main(root, tmp_path, repoint)
    assert called[-1:] == ["golden"], summary
    assert _verdict(summary) == "== could not check: the working tree changed during golden", summary
    assert code == 2, summary


def test_an_untracked_nested_git_repo_is_hashed_by_name_and_does_not_stop_the_run(git_repo, tmp_path):
    """repo 裡沒追蹤的另一個 git repo（例如 clone 或 worktree）：git 把它列成 `nested/`，裡面的改動本來就看不到
    （#216 第一輪審查已判斷可以接受），只雜湊名稱，每一步照常跑（第二次審查：`890cffa` 開它時遇到 IsADirectoryError
    就誤停）。
    Another git repo left untracked inside the repo (a clone or a worktree, say): git lists it as `nested/`, and
    changes inside it go unseen anyway (judged acceptable in the #216 round-1 review), so only its name is hashed and
    every step runs (second review: `890cffa` stopped on the IsADirectoryError from opening it)."""
    root, _ = _plain_repo(git_repo, tmp_path)
    (root / "nested").mkdir()
    (root / "nested" / "inner.py").write_text("y = 1\n", encoding="utf-8")
    git_repo(root / "nested")
    code, summary, _, called = _run_main(root, tmp_path)
    assert called[-1:] == ["red_on_base"], summary
    assert code == 0, summary


@POSIX_USER
def test_an_untracked_directory_git_cannot_list_stops_before_any_step(git_repo, tmp_path):
    """權限 000 的未追蹤目錄：`git ls-files` 列不出裡面的檔案，只在 stderr 警告、結束碼照樣是 0，那些檔案的改動
    看不到。一步都不跑，結論行寫 git 列出未追蹤檔案時有警告並引用那一行，結束碼 2（#216 第一輪審查 Standards
    第 3 條的第二次審查：`890cffa` 照樣跑完）。
    An untracked directory with mode 000: `git ls-files` cannot list the files inside, warns on stderr and still
    exits 0, so changes to them go unseen. No step runs, the verdict line says git warned while listing untracked files
    and quotes the warning, and the exit code is 2 (second review of #216 round-1 standards item 3: `890cffa` ran
    every step)."""
    root, _ = _plain_repo(git_repo, tmp_path)
    (root / "sub").mkdir()
    (root / "sub" / "inner.txt").write_text("x\n", encoding="utf-8")
    (root / "sub").chmod(0)
    try:
        code, summary, full, called = _run_main(root, tmp_path)
    finally:
        (root / "sub").chmod(0o700)
    assert called == [], called
    verdict = _verdict(summary)
    assert verdict.startswith("== could not check: git warned while listing untracked files: "), summary
    assert "sub/" in verdict, summary
    assert verdict in full, full
    assert code == 2, summary


@POSIX_USER
def test_two_untracked_directories_git_cannot_list_count_every_warning(git_repo, tmp_path):
    """兩個權限 000 的未追蹤目錄：git 各印一行警告，每一行各算一個問題，結論行點名 git 印出的第一行，後面寫還有
    幾個（#216 第一輪審查 Standards 第 3 條的第二次審查：`c38bec1` 只取 stderr 的第一行，沒有 `(+1 more)`）。哪個
    目錄排第一跟著 git 讀目錄的順序，這裡不寫死。
    Two untracked directories with mode 000: git prints one warning line for each, each counts as a problem, and the
    verdict line names the first line git printed and counts the rest (second review of #216 round-1 standards item
    3: `c38bec1` kept only the first stderr line, with no "(+1 more)"). Which directory comes first follows git's
    directory order, so it is not fixed here."""
    root, _ = _plain_repo(git_repo, tmp_path)
    dirs = [root / "d1", root / "d2"]
    for path in dirs:
        path.mkdir()
        (path / "inner.txt").write_text("x\n", encoding="utf-8")
        path.chmod(0)
    try:
        code, summary, _, called = _run_main(root, tmp_path)
    finally:
        for path in dirs:
            path.chmod(0o700)
    verdict = _verdict(summary)
    assert verdict.endswith(" (+1 more)"), summary
    assert verdict.startswith("== could not check: git warned while listing untracked files: warning: could not open "
                              "directory 'd"), summary
    assert called == [], called
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
    assert _verdict(summary) == "== could not check: the working tree changed during golden", summary
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
    assert _verdict(summary) == "== could not check: the working tree changed during mypy", summary
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
    assert _verdict(summary) == "== could not check: the working tree changed during ruff", summary
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
    assert _verdict(summary) == "== all steps exited 0", summary
    assert called == list(tool.STEP_NAMES), called
    assert code == 0, summary


def test_a_log_at_a_tracked_file_in_the_repo_is_no_change(git_repo, tmp_path):
    """`--log` 指到 repo 裡已追蹤的檔案：script 覆寫它，`git diff HEAD` 看得到這個改動，但那是 script 自己寫的
    log，不是讓結果不可信的改動。每一步都跑，結束碼照舊是 0；`git diff HEAD` 也要排除 script 自己的 log，只排除
    未追蹤檔案的清單不夠（#216 審查）。
    `--log` pointing at a tracked file in the repo: the script overwrites it and `git diff HEAD` shows that change,
    but it is the script's own log, no change that makes the results untrustworthy. Every step runs and the exit code
    is still 0; `git diff HEAD` has to leave the script's own logs out too, not only the untracked list (#216 review)."""
    root = tmp_path / "repo"
    root.mkdir()
    (root / "calc.py").write_text("x = 1\n", encoding="utf-8", newline="\n")
    (root / "checks.log").write_text("an older summary\n", encoding="utf-8", newline="\n")
    git_repo(root)
    run, called = _changing("golden", lambda: None)
    log = root / "checks.log"
    code = tool.main(["--log", str(log)], repo=str(root), run=run)
    summary = log.read_text(encoding="utf-8").splitlines()
    assert _verdict(summary) == "== all steps exited 0", summary
    assert called == list(tool.STEP_NAMES), called
    assert code == 0, summary
