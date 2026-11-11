"""`scripts/check_new_tests_red_on_base.py`：分支新增或改動的測試，在基準 revision 的程式碼上要是紅的
（CODING_STANDARDS 第 1 條「a new test that also passes on `master`」；#150）。
`scripts/check_new_tests_red_on_base.py`: the tests a branch adds or changes must be red on the base revision's code
(CODING_STANDARDS rule 1, "a new test that also passes on `master`"; #150)."""

import importlib.util
import os
import subprocess
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_spec = importlib.util.spec_from_file_location(
    "check_new_tests_red_on_base", os.path.join(REPO_ROOT, "scripts", "check_new_tests_red_on_base.py"))
assert _spec and _spec.loader
tool = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = tool
_spec.loader.exec_module(tool)

BUGGY = "def add(a, b):\n    return a - b\n"
FIXED = "def add(a, b):\n    return a + b\n"
BASE_TESTS = '''\
from calc import add


def test_adding_zero_keeps_the_number():
    assert add(5, 0) == 5
'''


def _git(repo, *args):
    subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True)


def _repo(root, calc=BUGGY, tests=BASE_TESTS):
    """在 root 建一個 git repo：一次提交，裡面有 `calc.py` 與 `tests/test_calc.py`；這次提交就是基準。
    Creates a git repo in root with one commit holding `calc.py` and `tests/test_calc.py`; that commit is the base."""
    (root / "tests").mkdir(parents=True, exist_ok=True)
    (root / "calc.py").write_text(calc, encoding="utf-8")
    (root / "tests" / "test_calc.py").write_text(tests, encoding="utf-8")
    _git(root, "init", "-q")
    _git(root, "add", ".")
    _git(root, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "-m", "base")
    return root


def test_a_new_test_that_fails_on_the_base_code_is_listed_as_red(tmp_path, capsys):
    """工作目錄修好 `add` 並新增一個測試：這個測試在基準的程式碼上失敗，所以列成紅的並附上失敗原因，結束碼是 0；
    沒改動的測試不跑。
    The working tree fixes `add` and adds a test: it fails on the base code, so it is listed as red with its failure
    line and the exit code is 0; the unchanged test is not run."""
    repo = _repo(tmp_path / "repo")
    (repo / "calc.py").write_text(FIXED, encoding="utf-8")
    (repo / "tests" / "test_calc.py").write_text(BASE_TESTS + '''

def test_adding_two_numbers_gives_their_sum():
    assert add(1, 2) == 3
''', encoding="utf-8")
    code = tool.main(["--against", "HEAD"], repo=str(repo))
    out = capsys.readouterr().out
    assert code == 0, out
    assert "red    tests/test_calc.py::test_adding_two_numbers_gives_their_sum" in out
    assert "assert -1 == 3" in out
    assert "test_adding_zero_keeps_the_number" not in out


def test_a_new_test_that_passes_on_the_base_code_is_listed_as_green(tmp_path, capsys):
    """新增的測試在基準的程式碼上也通過：它擋不住任何錯，所以列成綠的，結束碼是 1。
    A new test also passes on the base code: it guards against nothing, so it is listed as green and the exit code
    is 1."""
    repo = _repo(tmp_path / "repo")
    (repo / "tests" / "test_calc.py").write_text(BASE_TESTS + '''

def test_adding_zero_to_zero_gives_zero():
    assert add(0, 0) == 0
''', encoding="utf-8")
    code = tool.main(["--against", "HEAD"], repo=str(repo))
    out = capsys.readouterr().out
    assert code == 1, out
    assert "green  tests/test_calc.py::test_adding_zero_to_zero_gives_zero" in out


def test_a_changed_test_is_selected_and_unchanged_or_deleted_tests_are_not(tmp_path, capsys):
    """基準有三個測試：改了內容的那個要跑，沒改的與刪掉的不跑。
    The base has three tests: the one whose body changed runs, the unchanged one and the deleted one do not."""
    repo = _repo(tmp_path / "repo", tests=BASE_TESTS + '''

def test_adding_one_and_one():
    assert add(1, 1) == 0


def test_soon_deleted():
    assert add(2, 2) == 0
''')
    (repo / "calc.py").write_text(FIXED, encoding="utf-8")
    (repo / "tests" / "test_calc.py").write_text(BASE_TESTS + '''

def test_adding_one_and_one():
    assert add(1, 1) == 2
''', encoding="utf-8")
    code = tool.main(["--against", "HEAD"], repo=str(repo))
    out = capsys.readouterr().out
    assert code == 0, out
    assert out.splitlines() == ["red    tests/test_calc.py::test_adding_one_and_one  assert 0 == 2"], out


def test_a_test_red_only_because_its_import_is_missing_on_the_base_shows_the_import_error(tmp_path, capsys):
    """新測試匯入基準還沒有的函式：整個測試檔在基準上收集不到，這個測試仍列成紅的，但失敗原因是 `ImportError`，
    讓人看得出它是因為錯的理由紅，而不是被當成一個好的回歸測試悄悄算過。
    A new test imports a function the base does not have yet: the whole test file fails to collect on the base, and
    the test is still listed as red, but with the `ImportError` as its failure line, so it shows as red for the wrong
    reason instead of quietly counting as a good regression test."""
    repo = _repo(tmp_path / "repo")
    (repo / "calc.py").write_text(FIXED + "\n\ndef sub(a, b):\n    return a - b\n", encoding="utf-8")
    (repo / "tests" / "test_calc.py").write_text(BASE_TESTS.replace("import add", "import add, sub") + '''

def test_subtracting_gives_the_difference():
    assert sub(3, 1) == 2
''', encoding="utf-8")
    code = tool.main(["--against", "HEAD"], repo=str(repo))
    out = capsys.readouterr().out
    assert code == 0, out
    line = next(line for line in out.splitlines() if "test_subtracting_gives_the_difference" in line)
    assert line.startswith("red    ") and "ImportError" in line, out


def test_an_unknown_revision_cannot_compare_and_leaves_no_worktree(tmp_path, capsys, monkeypatch):
    """--against 給了不存在的 revision：結束碼是 2（無法比對，不同於有綠的 1），不留下 worktree 或暫存目錄。
    --against names a revision that does not exist: the exit code is 2 (could not compare, unlike 1 for a green test),
    and no worktree or temporary directory is left."""
    import tempfile

    scratch = tmp_path / "scratch"
    scratch.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(scratch))
    repo = _repo(tmp_path / "repo")
    assert tool.main(["--against", "no-such-rev"], repo=str(repo)) == 2
    assert "could not compare" in capsys.readouterr().err
    worktrees = subprocess.run(["git", "worktree", "list"], cwd=repo, check=True, capture_output=True, text=True)
    assert len(worktrees.stdout.splitlines()) == 1
    assert list(scratch.iterdir()) == []


def test_a_new_test_in_a_class_in_a_subdirectory_is_judged_by_its_own_result(tmp_path, capsys):
    """子目錄裡的測試檔、類別裡的測試：在基準上也通過，所以列成綠的，結束碼是 1。原本 JUnit 報告的 classname
    帶著類別名稱，對不回選到的 node id，類別裡的測試一律落到「沒在基準上跑」而列成紅的，放過了這支 script 要抓的違規。
    A test in a class, in a test file in a subdirectory, also passes on the base, so it is listed as green and the exit
    code is 1. The JUnit report's classname carries the class name, so before, it never matched the selected node id
    and every test in a class fell through to "not run on the base", listed as red: the very violation the script is
    for went through."""
    repo = _repo(tmp_path / "repo")
    (repo / "tests" / "unit").mkdir()
    (repo / "tests" / "unit" / "test_more.py").write_text('''\
from calc import add


class TestAdd:
    def test_adding_zero_to_zero_gives_zero(self):
        assert add(0, 0) == 0
''', encoding="utf-8")
    code = tool.main(["--against", "HEAD"], repo=str(repo))
    out = capsys.readouterr().out
    assert code == 1, out
    assert out.splitlines() == ["green  tests/unit/test_more.py::TestAdd::test_adding_zero_to_zero_gives_zero"], out


PARAMETRIZED = '''

import pytest


@pytest.mark.parametrize("a, b, total", [(1, 2, 3), (0, 0, 0), (2, 2, 4)], ids=["one-two", "zeros", "two-two"])
def test_adding_gives_the_sum(a, b, total):
    assert add(a, b) == total
'''


def test_a_parametrized_test_with_a_case_green_on_the_base_is_green_and_names_that_case(tmp_path, capsys):
    """參數化的測試算一筆：只要有一個 case 在基準上也通過，整筆就是綠的，並列出是哪個 case；原本紅的 case 蓋掉綠的，
    整筆列成紅的。
    A parametrized test counts as one entry: when any case also passes on the base, the entry is green and names that
    case. Before, the red cases hid the green one and the entry was listed as red."""
    repo = _repo(tmp_path / "repo")
    (repo / "calc.py").write_text(FIXED, encoding="utf-8")
    (repo / "tests" / "test_calc.py").write_text(BASE_TESTS + PARAMETRIZED, encoding="utf-8")
    code = tool.main(["--against", "HEAD"], repo=str(repo))
    out = capsys.readouterr().out
    assert code == 1, out
    assert out.splitlines() == ["green  tests/test_calc.py::test_adding_gives_the_sum  green on the base: zeros"], out


def test_a_parametrized_test_red_in_every_case_shows_its_first_failure(tmp_path, capsys):
    """每個 case 在基準上都失敗：整筆是紅的，失敗原因取第一個 case 的（`assert -1 == 3`），不是最後一個的。
    Every case fails on the base: the entry is red, with the first case's failure (`assert -1 == 3`), not the last's."""
    repo = _repo(tmp_path / "repo")
    (repo / "calc.py").write_text(FIXED, encoding="utf-8")
    (repo / "tests" / "test_calc.py").write_text(BASE_TESTS + PARAMETRIZED.replace("(0, 0, 0)", "(3, 1, 4)"),
                                                  encoding="utf-8")
    code = tool.main(["--against", "HEAD"], repo=str(repo))
    out = capsys.readouterr().out
    assert code == 0, out
    assert out.splitlines() == ["red    tests/test_calc.py::test_adding_gives_the_sum  assert -1 == 3"], out


def test_a_new_test_skipped_on_the_base_is_listed_as_skipped_and_counts_like_green(tmp_path, capsys):
    """新測試在基準上被 skip（基準還沒有 `sub`）：它沒有在基準上失敗，沒證明自己擋得住錯，所以列成 skipped 並附上
    skip 的原因，結束碼和有綠的一樣是 1；原本 skip 被當成通過，列成 green。
    A new test is skipped on the base (the base has no `sub` yet): it did not fail there, so it has not shown it
    guards anything; it is listed as skipped with the skip reason, and the exit code is 1, as for a green test.
    Before, a skip counted as a pass and was listed as green."""
    repo = _repo(tmp_path / "repo")
    (repo / "calc.py").write_text(FIXED + "\n\ndef sub(a, b):\n    return a - b\n", encoding="utf-8")
    (repo / "tests" / "test_calc.py").write_text(BASE_TESTS + '''

import calc
import pytest


@pytest.mark.skipif(not hasattr(calc, "sub"), reason="calc has no sub")
def test_subtracting_gives_the_difference():
    assert calc.sub(3, 1) == 2
''', encoding="utf-8")
    code = tool.main(["--against", "HEAD"], repo=str(repo))
    out = capsys.readouterr().out
    assert code == 1, out
    assert out.splitlines() == ["skipped tests/test_calc.py::test_subtracting_gives_the_difference  calc has no sub"], out


def test_a_test_file_that_does_not_parse_cannot_compare(tmp_path, capsys):
    """工作目錄的測試檔有語法錯誤：選不出測試，結束碼是 2（無法比對），而不是丟出 traceback、讓結束碼和「有綠的」一樣。
    A test file in the working tree has a syntax error: no tests can be selected, so the exit code is 2 (could not
    compare), not a traceback whose exit code looks like "some are green"."""
    repo = _repo(tmp_path / "repo")
    (repo / "tests" / "test_calc.py").write_text(BASE_TESTS + "\n\ndef test_broken(:\n    pass\n", encoding="utf-8")
    assert tool.main(["--against", "HEAD"], repo=str(repo)) == 2
    err = capsys.readouterr().err
    assert "could not compare" in err and "tests/test_calc.py" in err, err


def test_a_branch_without_new_or_changed_tests_says_so(tmp_path, capsys):
    """分支只改了程式碼、沒有新增或改動測試：印出說明、結束碼是 0；原本什麼都不印，看起來和「全部是紅的」一樣。
    The branch changes only code, no tests are new or changed: it says so and the exit code is 0. Before, it printed
    nothing, which looked the same as "every test is red"."""
    repo = _repo(tmp_path / "repo")
    (repo / "calc.py").write_text(FIXED, encoding="utf-8")
    assert tool.main(["--against", "HEAD"], repo=str(repo)) == 0
    assert capsys.readouterr().out.splitlines() == ["no new or changed tests under tests/"]


def test_pytest_that_cannot_start_on_the_base_cannot_compare(tmp_path, capsys):
    """基準的 `pytest.ini` 帶著不存在的選項：pytest 在基準上無法啟動、沒寫出報告，結束碼是 2（無法比對），
    不能把沒跑的測試當成任何結果。
    The base's `pytest.ini` carries an option that does not exist: pytest cannot start on the base and writes no
    report, so the exit code is 2 (could not compare); tests that never ran count as no result at all."""
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "pytest.ini").write_text("[pytest]\naddopts = --no-such-option\n", encoding="utf-8")
    _repo(repo)
    (repo / "tests" / "test_calc.py").write_text(BASE_TESTS + '''

def test_adding_two_numbers_gives_their_sum():
    assert add(1, 2) == 3
''', encoding="utf-8")
    assert tool.main(["--against", "HEAD"], repo=str(repo)) == 2
    assert "could not compare" in capsys.readouterr().err
