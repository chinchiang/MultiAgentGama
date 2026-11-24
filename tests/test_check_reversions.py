"""`scripts/check_reversions.py`：把修正一次改回一項，跑測試，列出每一項讓哪些測試變紅，最後把檔案寫回原狀。
`scripts/check_reversions.py`: reverts a fix one item at a time, runs the tests, lists which tests each item turns
red, and writes the file back as it was."""

import importlib.util
import json
import os
import re
import subprocess
import sys

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_spec = importlib.util.spec_from_file_location("check_reversions", os.path.join(REPO_ROOT, "scripts",
                                                                                 "check_reversions.py"))
assert _spec and _spec.loader
tool = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = tool
_spec.loader.exec_module(tool)

CALC = "def add(a, b):\n    return a + b\n"
TESTS = '''\
from calc import add


def test_adding_two_numbers_gives_their_sum():
    assert add(1, 2) == 3
'''


@pytest.fixture
def repo(git_repo, tmp_path):
    """已提交 `calc.py` 與 `tests/test_calc.py` 的 repo，回傳它的根目錄。
    A repo with `calc.py` and `tests/test_calc.py` committed; returns its root."""
    root = tmp_path / "repo"
    (root / "tests").mkdir(parents=True)
    (root / "calc.py").write_text(CALC, encoding="utf-8", newline="\n")
    (root / "tests" / "test_calc.py").write_text(TESTS, encoding="utf-8", newline="\n")
    git_repo(root)
    return root


def _reversions(tmp_path, *items):
    """把 (名稱, 原文, 改壞後) 寫成 repo 外的 JSON 檔，回傳它的路徑。
    Writes (name, old, new) items to a JSON file outside the repo and returns its path."""
    path = tmp_path / "reversions.json"
    path.write_text(json.dumps([{"name": n, "old": o, "new": w} for n, o, w in items]), encoding="utf-8", newline="\n")
    return str(path)


def _clean(root):
    """repo 的工作目錄是乾淨的（git 沒有回報任何改動）。
    The repo's working tree is clean (git reports no change)."""
    out = subprocess.run(["git", "status", "--porcelain"], cwd=root, capture_output=True, text=True).stdout
    return out == ""


def test_a_reversion_that_breaks_the_code_lists_the_tests_it_turns_red(repo, tmp_path, capsys):
    """改回一項會讓測試失敗：列出它讓哪個測試變紅，結束碼 0，檔案寫回原狀，工作目錄是乾淨的。
    A reversion that breaks the code lists the test it turns red, exits 0, and the file is written back with a clean
    working tree."""
    code = tool.main(["calc.py", _reversions(tmp_path, ("subtract", "a + b", "a - b"))], repo=str(repo))
    out = capsys.readouterr().out
    assert code == 0, out
    assert "## subtract: 1 red" in out, out
    assert "tests/test_calc.py::test_adding_two_numbers_gives_their_sum" in out, out
    assert (repo / "calc.py").read_text(encoding="utf-8") == CALC
    assert _clean(repo)


def test_a_reversion_no_test_notices_is_listed_and_exits_1(repo, tmp_path, capsys):
    """改回一項之後沒有任何測試變紅：列成 0 個紅燈，摘要點名它，結束碼 1。
    A reversion that no test notices is listed with 0 red and named in the summary, and the exit code is 1."""
    code = tool.main(["calc.py", _reversions(tmp_path, ("subtract", "a + b", "a - b"), ("swap", "a + b", "b + a"))],
                     repo=str(repo))
    out = capsys.readouterr().out
    assert code == 1, out
    assert "## swap: 0 red" in out, out
    assert "turned nothing red: swap" in out, out
    assert (repo / "calc.py").read_text(encoding="utf-8") == CALC


def test_a_reversion_that_breaks_collection_counts_as_red(repo, tmp_path, capsys):
    """改回一項讓模組無法匯入：收集錯誤也算紅燈。
    A reversion that makes the module fail to import counts its collection error as red."""
    code = tool.main(["calc.py", _reversions(tmp_path, ("syntax", "a + b", "a +"))], repo=str(repo))
    out = capsys.readouterr().out
    assert code == 0, out
    assert "## syntax: 1 red\n   tests/test_calc.py\n" in out, out  # 收集錯誤沒有原因，不印空行 ／ a collection error has no reason, so no blank line
    assert (repo / "calc.py").read_text(encoding="utf-8") == CALC


def test_a_dirty_working_tree_is_refused_before_anything_changes(repo, tmp_path, capsys):
    """工作目錄有還沒 commit 的改動時拒絕執行：結束碼 2，要求先 commit，檔案維持原本（未 commit）的內容。
    A working tree with uncommitted changes is refused: exit code 2, a request to commit first, and the file keeps its
    (uncommitted) content."""
    edited = CALC + "# edited\n"
    (repo / "calc.py").write_text(edited, encoding="utf-8", newline="\n")
    code = tool.main(["calc.py", _reversions(tmp_path, ("subtract", "a + b", "a - b"))], repo=str(repo))
    out = capsys.readouterr().out
    assert code == 2, out
    assert "commit first" in out, out
    assert (repo / "calc.py").read_text(encoding="utf-8") == edited


@pytest.mark.parametrize("old", ["a * b", "a"])
def test_an_old_text_not_found_exactly_once_is_refused(repo, tmp_path, capsys, old):
    """原文在檔案裡不是剛好出現一次（沒有，或不止一次）：結束碼 2，說明是哪一項，什麼都沒改、沒有跑測試。
    An old text that does not occur exactly once (not at all, or more than once) exits 2 naming the item, changes
    nothing and runs no test."""
    code = tool.main(["calc.py", _reversions(tmp_path, ("bad", old, "x"))], repo=str(repo))
    out = capsys.readouterr().out
    assert code == 2, out
    assert "`bad`" in out and "exactly once" in out, out
    assert "## " not in out, out
    assert (repo / "calc.py").read_text(encoding="utf-8") == CALC


def test_the_file_is_written_back_when_pytest_cannot_run(repo, tmp_path, capsys):
    """改回一項讓 pytest 在收集時被中斷（KeyboardInterrupt）：結束碼 2，說出 pytest 的結束碼，檔案照樣寫回原狀。
    原始檔案上的那一次會先擋下找不到的測試檔，所以中斷由改回的那一項造成（#209）。
    A reversion that interrupts pytest during collection (KeyboardInterrupt): the exit code is 2, naming pytest's exit
    code, and the file is still written back. The run on the unmodified file stops a missing test file first, so the
    interruption comes from the reverted item (#209)."""
    code = tool.main(["calc.py", _reversions(tmp_path, ("interrupt", "return a + b\n",
                                                        "return a + b\n\nraise KeyboardInterrupt\n"))],
                     repo=str(repo))
    out = capsys.readouterr().out
    assert code == 2, out
    assert "`interrupt`: pytest exited 2" in out, out
    assert (repo / "calc.py").read_text(encoding="utf-8") == CALC
    assert _clean(repo)


# --- 改壞之前先在原始檔案上跑一次（#209） ------------------------------------------------------
# --- A run on the unmodified file before any reversion (#209) ------------------------------------

def test_a_mistyped_test_id_is_refused_before_any_reversion(repo, tmp_path, capsys):
    """指定的測試 ID 打錯了：在原始檔案上的那一次就找不到它，結束碼 2，點出那個 ID，沒有改回任何一項。原本第一項
    就停下，只說「pytest exited 4 ... no tests ran」，看不出是哪個 ID（#207）。
    A mistyped test id is not found by the run on the unmodified file: exit code 2, the id is named, and no item is
    reverted. It used to stop at the first item saying only "pytest exited 4 ... no tests ran", without the id
    (#207)."""
    typo = "tests/test_calc.py::test_adding_two_number_gives_their_sum"
    code = tool.main(["calc.py", _reversions(tmp_path, ("subtract", "a + b", "a - b")), typo], repo=str(repo))
    out = capsys.readouterr().out
    assert code == 2, out
    # pytest 回報的路徑隨平台不同（Windows 是反斜線的絕對路徑），所以只比對測試名稱
    # pytest reports the path per platform (an absolute backslash path on Windows), so only the test name is matched
    assert "unmodified" in out and "test_adding_two_number_gives_their_sum" in out, out
    assert "## " not in out, out
    assert (repo / "calc.py").read_text(encoding="utf-8") == CALC


def test_each_red_test_shows_its_failure_line(repo, tmp_path, capsys, monkeypatch):
    """每個紅燈測試底下印出它失敗的那一行，不必再跑一次就能確認紅燈的原因是改回的那一項（#205、#207 各寫了一段臨時
    迴圈做這件事）。終端機很窄（`COLUMNS=40`）時原因也不會被截斷；設窄是因為外層的 pytest 可能已經被設成很寬
    （例如本身就在 check_reversions.py 底下執行）。
    Under each red test its failure line is printed, so the cause can be read without running again (#205 and #207
    each wrote an ad-hoc loop for this). A narrow terminal (`COLUMNS=40`) does not cut the reason; it is set narrow
    because the outer pytest may already run wide (under check_reversions.py itself, for one)."""
    monkeypatch.setenv("COLUMNS", "40")
    code = tool.main(["calc.py", _reversions(tmp_path, ("subtract", "a + b", "a - b"))], repo=str(repo))
    out = capsys.readouterr().out
    assert code == 0, out
    assert "   tests/test_calc.py::test_adding_two_numbers_gives_their_sum\n      assert -1 == 3" in out, out


SKIPPING_CALC = "SKIP = False\n\n\ndef add(a, b):\n    return a + b\n"
SKIPPING_TESTS = '''\
import pytest

import calc


def test_adding_two_numbers_gives_their_sum():
    if calc.SKIP:
        pytest.skip("calc asks to skip")
    assert calc.add(1, 2) == 3
'''


def test_a_test_skipped_under_a_reversion_is_listed_as_skipped_not_red(git_repo, tmp_path, capsys):
    """改回一項之後指定的測試被略過：它列成 skipped、不算紅燈，那一項和沒有讓任何測試變紅的一樣，結束碼 1。原本只說
    「0 red」，看不出測試是略過而不是通過（#207 的 Node 測試在 PATH 找不到 node 時就是這樣）（#209）。
    A test skipped under a reversion is listed as skipped and not counted as red, so the item is reported like one
    that turned nothing red, with exit code 1. It used to say only "0 red", not that the test skipped rather than
    passed (as #207's Node test did when PATH had no node) (#209)."""
    root = tmp_path / "repo"
    (root / "tests").mkdir(parents=True)
    (root / "calc.py").write_text(SKIPPING_CALC, encoding="utf-8", newline="\n")
    (root / "tests" / "test_calc.py").write_text(SKIPPING_TESTS, encoding="utf-8", newline="\n")
    git_repo(root)
    code = tool.main(["calc.py", _reversions(tmp_path, ("skip", "SKIP = False", "SKIP = True"))], repo=str(root))
    out = capsys.readouterr().out
    assert code == 1, out
    assert "## skip: 0 red, 1 skipped\n   skipped: tests/test_calc.py::test_adding_two_numbers_gives_their_sum" in out, out
    assert "turned nothing red: skip" in out, out


def _skipping_repo(git_repo, tmp_path):
    """測試在原始檔案上就被略過的 repo（`SKIP = True`） ／ A repo whose test skips on the unmodified file (`SKIP = True`)."""
    root = tmp_path / "repo"
    (root / "tests").mkdir(parents=True)
    (root / "calc.py").write_text(SKIPPING_CALC.replace("SKIP = False", "SKIP = True"), encoding="utf-8", newline="\n")
    (root / "tests" / "test_calc.py").write_text(SKIPPING_TESTS, encoding="utf-8", newline="\n")
    git_repo(root)
    return root


def test_a_test_failing_on_the_unmodified_file_is_refused_before_any_reversion(git_repo, tmp_path, capsys):
    """測試在原始檔案上就失敗：每一項看起來都會「讓它變紅」，什麼都證明不了。結束碼 2，點出那個測試，沒有改回任何
    一項（#209）。
    A test that already fails on the unmodified file would look turned red by every item and prove nothing: exit code
    2, the test is named, and no item is reverted (#209)."""
    root = _repo_with(git_repo, tmp_path, {"test_calc.py": TESTS.replace("== 3", "== 4")})
    code = tool.main(["calc.py", _reversions(tmp_path, ("subtract", "a + b", "a - b"))], repo=str(root))
    out = capsys.readouterr().out
    assert code == 2, out
    assert "unmodified" in out and "test_adding_two_numbers_gives_their_sum" in out, out
    assert "## " not in out, out


def test_a_test_named_by_id_that_skips_on_the_unmodified_file_is_refused(git_repo, tmp_path, capsys):
    """用 node id 指定的測試在原始檔案上就被略過：沒有任何一項能讓它變紅。結束碼 2，點出那個 ID（#209）。
    A test named by its node id that skips on the unmodified file cannot be turned red by any item: exit code 2,
    naming the id (#209)."""
    root = _skipping_repo(git_repo, tmp_path)
    test_id = "tests/test_calc.py::test_adding_two_numbers_gives_their_sum"
    code = tool.main(["calc.py", _reversions(tmp_path, ("subtract", "a + b", "a - b")), test_id], repo=str(root))
    out = capsys.readouterr().out
    assert code == 2, out
    assert f"were not read as passing on the unmodified calc.py, so no item can be checked against them: {test_id} " \
           "(SKIPPED)" in out, out
    assert "## " not in out, out


def test_a_test_reached_through_its_file_that_skips_on_the_unmodified_file_is_a_warning(git_repo, tmp_path, capsys):
    """經由檔案路徑（或整個套件）跑到、在原始檔案上被略過的測試：列成警告後照常逐項改回。整個套件在某些環境一定有
    被略過的測試（Docker、Node），拒絕就沒辦法用（#209）。
    A test reached through its file (or the whole suite) that skips on the unmodified file is listed as a warning, and
    the items are reverted as usual: the whole suite always skips some tests in some environments (Docker, Node), so
    refusing would make it unusable (#209)."""
    root = _skipping_repo(git_repo, tmp_path)
    code = tool.main(["calc.py", _reversions(tmp_path, ("subtract", "a + b", "a - b")), "tests/test_calc.py"],
                     repo=str(root))
    out = capsys.readouterr().out
    assert code == 1, out
    assert ("Skipped on the unmodified calc.py, so no item can turn them red:\n"
            "   skipped: tests/test_calc.py::test_adding_two_numbers_gives_their_sum") in out, out
    assert "## subtract: 0 red, 1 skipped" in out, out


def _repo_with(git_repo, tmp_path, tests, root_files=None):
    """`calc.py`、`tests/` 底下的 tests 與根目錄的 root_files（檔名 -> 內容）都已提交的 repo。檔案在 `git_repo` 提交
    之前寫好：它提交時用自己的身分，測試裡另外跑 `git commit` 在沒有 git 身分的 CI 上會失敗。換行固定是 `\n`，
    Windows 上的原文才找得到。
    A repo with `calc.py`, `tests` under `tests/` and `root_files` at the root (file name -> content) committed. The
    files are written before `git_repo` commits them with its own identity: a separate `git commit` in a test fails on
    CI, which has no git identity. Newlines are fixed to `\n`, so old texts are found on Windows too."""
    root = tmp_path / "repo"
    (root / "tests").mkdir(parents=True)
    (root / "calc.py").write_text(CALC, encoding="utf-8", newline="\n")
    for name, content in tests.items():
        (root / "tests" / name).write_text(content, encoding="utf-8", newline="\n")
    for name, content in (root_files or {}).items():
        (root / name).write_text(content, encoding="utf-8", newline="\n")
    git_repo(root)
    return root


PARAMETRIZED = '''\
import pytest

from calc import add


@pytest.mark.parametrize("a, b, total", [(1, 2, 3), (2, 2, 4)])
def test_sums(a, b, total):
    if a == 2:
        pytest.skip("not today")
    assert add(a, b) == total
'''
WHOLE_MODULE_SKIP = '''\
import pytest

pytest.skip("no runtime here", allow_module_level=True)


def test_never_collected():
    pass
'''


@pytest.mark.parametrize("named", ["tests/test_sums.py::test_sums", "./tests/test_sums.py::test_sums"])
def test_a_parametrized_function_named_without_its_parameters_must_pass_in_every_case(git_repo, tmp_path, capsys,
                                                                                       named):
    """用 node id 指定、沒寫參數的參數化函式：每一個案例都要讀到 PASSED，一個被略過就結束碼 2；`./` 開頭的路徑也
    認得。原本只逐字比對 ID，這兩種寫法都只警告後照常進行（#209 審查第 1 輪）。
    A parametrized function named by node id without its parameters must read PASSED in every case, so one skipped
    case exits 2; a path starting with `./` is read too. It used to match ids verbatim, so both forms only warned and
    went on (#209 review round 1)."""
    root = _repo_with(git_repo, tmp_path, {"test_sums.py": PARAMETRIZED})
    code = tool.main(["calc.py", _reversions(tmp_path, ("subtract", "a + b", "a - b")), named], repo=str(root))
    out = capsys.readouterr().out
    assert code == 2, out
    assert f"{named} (PASSED, SKIPPED)" in out, out
    assert "## " not in out, out


def test_a_test_named_in_a_whole_skipped_module_is_refused(git_repo, tmp_path, capsys):
    """整個模組被略過時，那裡的測試沒有任何結果行：用 node id 指定它，pytest 找不到可收集的項目，結束碼 2 並點出
    那個 ID，什麼都沒改回（#209 審查第 1 輪）。
    A whole skipped module gives its tests no outcome line at all: naming one by node id leaves pytest with nothing to
    collect, so the exit code is 2, the id is named, and nothing is reverted (#209 review round 1)."""
    root = _repo_with(git_repo, tmp_path, {"test_calc.py": TESTS, "test_runtime.py": WHOLE_MODULE_SKIP})
    named = "tests/test_runtime.py::test_never_collected"
    code = tool.main(["calc.py", _reversions(tmp_path, ("subtract", "a + b", "a - b")), named], repo=str(root))
    out = capsys.readouterr().out
    assert code == 2, out
    assert "do not all pass on the unmodified calc.py" in out and "test_never_collected" in out, out
    assert "## " not in out, out


def test_a_named_test_whose_outcome_cannot_be_read_is_refused(repo, tmp_path, capsys, monkeypatch):
    """用 node id 指定的測試讀不到任何結果行（這裡把結果行的格式換成讀不懂的）：無法檢查，結束碼 2，而不是當成通過
    （CODING_STANDARDS 第 8 條；#209 審查第 1 輪）。
    A test named by node id with no outcome line read (the outcome line format is made unreadable here) cannot be
    checked: exit code 2, not taken as passing (CODING_STANDARDS rule 8; #209 review round 1)."""
    # raising=False：在沒有 `_OUTCOME_RE` 的舊版上，紅燈的原因才會是行為本身，不是屬性不存在
    # raising=False: on an older version without `_OUTCOME_RE` the test goes red on the behaviour, not a missing name
    monkeypatch.setattr(tool, "_OUTCOME_RE", re.compile(r"^(never)::(matches)$"), raising=False)
    named = "tests/test_calc.py::test_adding_two_numbers_gives_their_sum"
    code = tool.main(["calc.py", _reversions(tmp_path, ("subtract", "a + b", "a - b")), named], repo=str(repo))
    out = capsys.readouterr().out
    assert code == 2, out
    assert f"{named} (no outcome read)" in out, out


def test_a_whole_skipped_module_reached_through_the_suite_is_listed(git_repo, tmp_path, capsys):
    """整個模組被略過、經由整個套件跑到：它沒有測試 ID，從摘要的略過行列出來，在原始檔案上是警告、每一項底下也列出；
    原本完全不會出現（#209 審查第 1 輪）。
    A whole skipped module reached through the suite has no test id, so it is listed from the summary's skip line: as
    a warning on the unmodified file and under every item. It used to appear nowhere (#209 review round 1)."""
    root = _repo_with(git_repo, tmp_path, {"test_calc.py": TESTS, "test_runtime.py": WHOLE_MODULE_SKIP})
    code = tool.main(["calc.py", _reversions(tmp_path, ("subtract", "a + b", "a - b"))], repo=str(root))
    out = capsys.readouterr().out
    assert code == 0, out
    # 摘要的位置用平台的路徑分隔符號 ／ The summary's location uses the platform's path separator
    line = f"   skipped (no test id): SKIPPED [1] {os.path.join('tests', 'test_runtime.py')}:3: no runtime here"
    assert f"Skipped on the unmodified calc.py, so no item can turn them red:\n{line}" in out, out
    assert "## subtract: 1 red, 1 skipped\n" in out and out.count(line) == 2, out


def test_a_pytest_option_among_the_tests_is_refused(repo, tmp_path, capsys):
    """`--` 之後的測試參數夾著 pytest 選項（`-q` 會蓋掉 `-v`，讓被略過的測試讀不出來）：結束碼 2，什麼都沒跑
    （#209 審查第 1 輪）。
    A pytest option among the tests after `--` (`-q` would cancel `-v` and hide skipped tests) exits 2 before anything
    runs (#209 review round 1)."""
    code = tool.main(["calc.py", _reversions(tmp_path, ("subtract", "a + b", "a - b")), "--", "-q",
                      "tests/test_calc.py"], repo=str(repo))
    out = capsys.readouterr().out
    assert code == 2, out
    assert "not pytest options or @argument files: -q" in out, out
    assert "## " not in out and "unmodified" not in out, out


def test_a_failure_reason_is_cut_after_the_whole_test_id(git_repo, tmp_path, capsys):
    """參數化的 ID 本身含有 ` - `：原因從整個 ID 之後切，不是從第一個 ` - `（#209 審查第 1 輪）。
    A parametrized id that itself contains ` - ` has its reason cut after the whole id, not at the first ` - `
    (#209 review round 1)."""
    tests = TESTS + '''

import pytest


@pytest.mark.parametrize("label", ["a - b"])
def test_labelled_sum(label):
    assert add(2, 2) == 4, label
'''
    root = _repo_with(git_repo, tmp_path, {"test_calc.py": tests})
    code = tool.main(["calc.py", _reversions(tmp_path, ("subtract", "a + b", "a - b"))], repo=str(root))
    out = capsys.readouterr().out
    assert code == 0, out
    assert "   tests/test_calc.py::test_labelled_sum[a - b]\n      AssertionError: a - b\n" in out, out


def test_every_test_failing_on_the_unmodified_file_is_named(git_repo, tmp_path, capsys):
    """原始檔案上失敗的測試全部點名，不只 stdout 最後幾行裡的（#209 審查第 1 輪）。
    Every test failing on the unmodified file is named, not only those in the last lines of stdout (#209 review
    round 1)."""
    tests = "from calc import add\n" + "".join(f"\n\ndef test_wrong_{i}():\n    assert add(1, 1) == {i + 3}\n"
                                              for i in range(8))
    root = _repo_with(git_repo, tmp_path, {"test_calc.py": tests})
    code = tool.main(["calc.py", _reversions(tmp_path, ("subtract", "a + b", "a - b"))], repo=str(root))
    out = capsys.readouterr().out
    assert code == 2, out
    assert all(f"   tests/test_calc.py::test_wrong_{i}\n" in out for i in range(8)), out


SKIPPED_TARGET = TESTS + '''

import pytest


@pytest.mark.skip(reason="not here")
def test_skipped_here():
    pass
'''


@pytest.mark.parametrize("addopts", ["-qq", "-p no:terminal"])
def test_output_the_script_cannot_read_is_could_not_check(git_repo, tmp_path, capsys, addopts):
    """目標 repo 的 pytest 設定改掉了輸出的形狀（`-qq` 沒有結果行也沒有 `===` 統計行；`-p no:terminal` 什麼都不印）：
    讀不到最後的統計行就是無法檢查，結束碼 2，而不是把讀不到的略過當成沒有、把讀不到的紅燈當成「turned nothing
    red」（CODING_STANDARDS 第 8 條；#209 審查第 2 輪）。
    The target repo's pytest config changes the output's shape (`-qq` has no outcome lines and no `===` count line;
    `-p no:terminal` prints nothing): no closing count line read means could not check, exit code 2, rather than
    taking unread skips as none and unread red tests as "turned nothing red" (CODING_STANDARDS rule 8; #209 review
    round 2)."""
    root = _repo_with(git_repo, tmp_path, {"test_calc.py": SKIPPED_TARGET},
                      {"pytest.ini": f"[pytest]\naddopts = {addopts}\n"})
    code = tool.main(["calc.py", _reversions(tmp_path, ("subtract", "a + b", "a - b")), "tests/test_calc.py"],
                     repo=str(root))
    out = capsys.readouterr().out
    assert code == 2, out
    assert "Could not read pytest's output on the unmodified calc.py" in out, out
    assert "## " not in out, out


def test_an_argument_file_among_the_tests_is_refused(repo, tmp_path, capsys):
    """`@檔案` 讓 pytest 從檔案讀參數，裡面的選項與 node id 都躲過檢查：結束碼 2，什麼都沒跑（#209 審查第 2 輪）。
    `@file` makes pytest read arguments from a file, hiding options and node ids from the checks: exit code 2 before
    anything runs (#209 review round 2)."""
    (tmp_path / "args.txt").write_text("-q\ntests/test_calc.py\n", encoding="utf-8", newline="\n")
    code = tool.main(["calc.py", _reversions(tmp_path, ("subtract", "a + b", "a - b")), f"@{tmp_path / 'args.txt'}"],
                     repo=str(repo))
    out = capsys.readouterr().out
    assert code == 2, out
    assert "not pytest options" in out and "args.txt" in out, out
    assert "## " not in out, out


def test_an_item_that_makes_the_output_unreadable_is_could_not_check(git_repo, tmp_path, capsys):
    """原始檔案上讀得懂，改回一項之後讀不懂（這裡改回的就是 pytest.ini 的 `addopts`）：那一項無法檢查，結束碼 2，
    檔案寫回原狀（#209 審查第 2 輪）。
    Readable on the unmodified file but not after an item (the item here is pytest.ini's `addopts` itself): that item
    cannot be checked, exit code 2, and the file is written back (#209 review round 2)."""
    root = _repo_with(git_repo, tmp_path, {"test_calc.py": TESTS}, {"pytest.ini": "[pytest]\naddopts = -ra\n"})
    code = tool.main(["pytest.ini", _reversions(tmp_path, ("quiet", "-ra", "-qq"))], repo=str(root))
    out = capsys.readouterr().out
    assert code == 2, out
    assert "`quiet`: could not read pytest's output" in out, out
    assert (root / "pytest.ini").read_text(encoding="utf-8") == "[pytest]\naddopts = -ra\n"
    assert _clean(root)


def test_failures_reported_but_none_read_is_could_not_check(repo, tmp_path, capsys, monkeypatch):
    """pytest 以 1 結束（有失敗），卻一個失敗都讀不到（這裡讓摘要的解析什麼都讀不到）：無法檢查，結束碼 2，而不是
    「turned nothing red」（CODING_STANDARDS 第 8 條；#209 審查第 2 輪）。
    pytest exits 1 (some failed) but no failure is read (the summary parsing is made to read nothing here): could not
    check, exit code 2, not "turned nothing red" (CODING_STANDARDS rule 8; #209 review round 2)."""
    # 任意參數：舊版的 `_red` 只收一個參數，紅燈的原因才會是行為本身，不是簽章不合
    # Any arguments: an older `_red` takes one, so the test goes red on the behaviour, not on the signature
    monkeypatch.setattr(tool, "_red", lambda *args: [])
    code = tool.main(["calc.py", _reversions(tmp_path, ("subtract", "a + b", "a - b"))], repo=str(repo))
    out = capsys.readouterr().out
    assert code == 2, out
    assert "`subtract`: could not read pytest's output (pytest exited 1)" in out, out
    assert "turned nothing red" not in out, out
