"""`scripts/check_reversions.py`：把修正一次改回一項，跑測試，列出每一項讓哪些測試變紅，最後把檔案寫回原狀。
`scripts/check_reversions.py`: reverts a fix one item at a time, runs the tests, lists which tests each item turns
red, and writes the file back as it was."""

import importlib.util
import json
import os
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
    (root / "calc.py").write_text(CALC, encoding="utf-8")
    (root / "tests" / "test_calc.py").write_text(TESTS, encoding="utf-8")
    git_repo(root)
    return root


def _reversions(tmp_path, *items):
    """把 (名稱, 原文, 改壞後) 寫成 repo 外的 JSON 檔，回傳它的路徑。
    Writes (name, old, new) items to a JSON file outside the repo and returns its path."""
    path = tmp_path / "reversions.json"
    path.write_text(json.dumps([{"name": n, "old": o, "new": w} for n, o, w in items]), encoding="utf-8")
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
    assert "## syntax: 1 red" in out, out
    assert (repo / "calc.py").read_text(encoding="utf-8") == CALC


def test_a_dirty_working_tree_is_refused_before_anything_changes(repo, tmp_path, capsys):
    """工作目錄有還沒 commit 的改動時拒絕執行：結束碼 2，要求先 commit，檔案維持原本（未 commit）的內容。
    A working tree with uncommitted changes is refused: exit code 2, a request to commit first, and the file keeps its
    (uncommitted) content."""
    edited = CALC + "# edited\n"
    (repo / "calc.py").write_text(edited, encoding="utf-8")
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
    assert "unmodified" in out and typo in out, out
    assert "## " not in out, out
    assert (repo / "calc.py").read_text(encoding="utf-8") == CALC


def test_each_red_test_shows_its_failure_line(repo, tmp_path, capsys):
    """每個紅燈測試底下印出它失敗的那一行，不必再跑一次就能確認紅燈的原因是改回的那一項（#205、#207 各寫了一段臨時
    迴圈做這件事）。
    Under each red test its failure line is printed, so the cause can be read without running again (#205 and #207
    each wrote an ad-hoc loop for this)."""
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
    (root / "calc.py").write_text(SKIPPING_CALC, encoding="utf-8")
    (root / "tests" / "test_calc.py").write_text(SKIPPING_TESTS, encoding="utf-8")
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
    (root / "calc.py").write_text(SKIPPING_CALC.replace("SKIP = False", "SKIP = True"), encoding="utf-8")
    (root / "tests" / "test_calc.py").write_text(SKIPPING_TESTS, encoding="utf-8")
    git_repo(root)
    return root


def test_a_test_failing_on_the_unmodified_file_is_refused_before_any_reversion(repo, tmp_path, capsys):
    """測試在原始檔案上就失敗：每一項看起來都會「讓它變紅」，什麼都證明不了。結束碼 2，點出那個測試，沒有改回任何
    一項（#209）。
    A test that already fails on the unmodified file would look turned red by every item and prove nothing: exit code
    2, the test is named, and no item is reverted (#209)."""
    (repo / "tests" / "test_calc.py").write_text(TESTS.replace("== 3", "== 4"), encoding="utf-8")
    subprocess.run(["git", "commit", "-qam", "red"], cwd=repo, check=True, capture_output=True)
    code = tool.main(["calc.py", _reversions(tmp_path, ("subtract", "a + b", "a - b"))], repo=str(repo))
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
    assert "skipped on the unmodified calc.py" in out and test_id in out, out
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
    assert ("Skipped on the unmodified calc.py, so no item can turn them red: "
            "tests/test_calc.py::test_adding_two_numbers_gives_their_sum") in out, out
    assert "## subtract: 0 red, 1 skipped" in out, out
