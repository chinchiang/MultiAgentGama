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
    (root / "tests").mkdir(parents=True)
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
