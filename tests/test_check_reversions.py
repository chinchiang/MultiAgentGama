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
    """pytest 跑不起來時（這裡是找不到測試檔）結束碼 2，說出 pytest 的結束碼，檔案照樣寫回原狀。
    When pytest cannot run (a missing test file here) the exit code is 2, naming pytest's exit code, and the file is
    still written back."""
    code = tool.main(["calc.py", _reversions(tmp_path, ("subtract", "a + b", "a - b")), "tests/missing.py"],
                     repo=str(repo))
    out = capsys.readouterr().out
    assert code == 2, out
    assert "pytest exited 4" in out, out
    assert (repo / "calc.py").read_text(encoding="utf-8") == CALC
    assert _clean(repo)
