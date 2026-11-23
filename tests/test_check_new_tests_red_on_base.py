"""`scripts/check_new_tests_red_on_base.py`：分支新增或改動的測試，在基準 revision 的程式碼上要是紅的
（CODING_STANDARDS 第 1 條「a new test that also passes on `master`」；#150）。
`scripts/check_new_tests_red_on_base.py`: the tests a branch adds or changes must be red on the base revision's code
(CODING_STANDARDS rule 1, "a new test that also passes on `master`"; #150)."""

import importlib.util
import os
import sys

import pytest

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


def _base_repo(git_repo, root, calc=BUGGY, tests=BASE_TESTS):
    """用 `git_repo` 夾具在 root 建一個 git repo：一次提交，裡面有 `calc.py` 與 `tests/test_calc.py`；這次提交就是基準。
    回傳 repo 的 git runner。
    Creates, with the `git_repo` fixture, a git repo in root with one commit holding `calc.py` and
    `tests/test_calc.py`; that commit is the base. Returns the repo's git runner."""
    (root / "tests").mkdir(parents=True, exist_ok=True)
    (root / "calc.py").write_text(calc, encoding="utf-8")
    (root / "tests" / "test_calc.py").write_text(tests, encoding="utf-8")
    return git_repo(root)


@pytest.fixture
def make_repo(git_repo):
    """`make_repo(root, calc=..., tests=...)` 用 `_base_repo` 建好基準 repo，回傳 root。
    `make_repo(root, calc=..., tests=...)` builds the base repo with `_base_repo` and returns root."""

    def make(root, calc=BUGGY, tests=BASE_TESTS):
        _base_repo(git_repo, root, calc, tests)
        return root

    return make


def test_a_new_test_that_fails_on_the_base_code_is_listed_as_red(make_repo, tmp_path, capsys):
    """工作目錄修好 `add` 並新增一個測試：這個測試在基準的程式碼上失敗，所以列成紅的並附上失敗原因，結束碼是 0；
    沒改動的測試不跑。
    The working tree fixes `add` and adds a test: it fails on the base code, so it is listed as red with its failure
    line and the exit code is 0; the unchanged test is not run."""
    repo = make_repo(tmp_path / "repo")
    (repo / "calc.py").write_text(FIXED, encoding="utf-8")
    (repo / "tests" / "test_calc.py").write_text(BASE_TESTS + '''

def test_adding_two_numbers_gives_their_sum():
    assert add(1, 2) == 3
''', encoding="utf-8")
    code = tool.main(["--against", "HEAD"], repo=str(repo))
    out, err = capsys.readouterr()
    assert code == 0, out + err
    assert "red    tests/test_calc.py::test_adding_two_numbers_gives_their_sum" in out
    assert "assert -1 == 3" in out
    assert "test_adding_zero_keeps_the_number" not in out


def test_a_failing_global_post_checkout_hook_does_not_stop_the_comparison(make_repo, tmp_path, monkeypatch, request,
                                                                         capsys):
    """開發者的全域 hook 裡有一個一定失敗的 `post-checkout`（即使環境外洩 `GIT_DIR` 或 `GIT_CONFIG_PARAMETERS`）：
    夾具先清掉外洩的 `GIT_*` 讓 Guard 與受測腳本處於同一環境，建基準 worktree 時不跑該 hook，比對照常進行，新的測試列成
    紅的，結束碼是 0。原本 `worktree add` 因為這個 hook 結束碼是 1，整次比對以 2 收場（#158）。
    The developer's global hooks include a `post-checkout` that always fails (even with `GIT_DIR` or
    `GIT_CONFIG_PARAMETERS` leaked into the environment): the fixture clears leaked `GIT_*` so the Guard and the script
    under test share the same environment, adding the base worktree does not run the hook, the comparison goes on, the
    new test is listed as red and the exit code is 0. `worktree add` used to exit 1 because of that hook, ending the
    whole comparison with 2 (#158)."""
    repo = make_repo(tmp_path / "repo")
    monkeypatch.setenv("GIT_DIR", str(tmp_path / "bogus-git-dir"))
    monkeypatch.setenv("GIT_CONFIG_PARAMETERS", f"'core.hooksPath={(tmp_path / 'empty').as_posix()}'")
    request.getfixturevalue("failing_post_checkout")
    assert [k for k in os.environ if k.upper().startswith("GIT_")] == ["GIT_CONFIG_GLOBAL"]
    (repo / "calc.py").write_text(FIXED, encoding="utf-8")
    (repo / "tests" / "test_calc.py").write_text(BASE_TESTS + '''

def test_adding_two_numbers_gives_their_sum():
    assert add(1, 2) == 3
''', encoding="utf-8")
    code = tool.main(["--against", "HEAD"], repo=str(repo))
    captured = capsys.readouterr()
    assert code == 0, captured.out + captured.err
    assert "red    tests/test_calc.py::test_adding_two_numbers_gives_their_sum" in captured.out


def test_a_new_test_that_passes_on_the_base_code_is_listed_as_green(make_repo, tmp_path, capsys):
    """新增的測試在基準的程式碼上也通過：它擋不住任何錯，所以列成綠的，結束碼是 1。
    A new test also passes on the base code: it guards against nothing, so it is listed as green and the exit code
    is 1."""
    repo = make_repo(tmp_path / "repo")
    (repo / "tests" / "test_calc.py").write_text(BASE_TESTS + '''

def test_adding_zero_to_zero_gives_zero():
    assert add(0, 0) == 0
''', encoding="utf-8")
    code = tool.main(["--against", "HEAD"], repo=str(repo))
    out, err = capsys.readouterr()
    assert code == 1, out + err
    assert "green  tests/test_calc.py::test_adding_zero_to_zero_gives_zero" in out


def test_a_changed_test_is_selected_and_unchanged_or_deleted_tests_are_not(make_repo, tmp_path, capsys):
    """基準有三個測試：改了內容的那個要跑，沒改的與刪掉的不跑。
    The base has three tests: the one whose body changed runs, the unchanged one and the deleted one do not."""
    repo = make_repo(tmp_path / "repo", tests=BASE_TESTS + '''

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
    out, err = capsys.readouterr()
    assert code == 0, out + err
    assert out.splitlines() == ["red    tests/test_calc.py::test_adding_one_and_one  assert 0 == 2"], out


def test_a_test_red_only_because_its_import_is_missing_on_the_base_shows_the_import_error(make_repo, tmp_path, capsys):
    """新測試匯入基準還沒有的函式：整個測試檔在基準上收集不到，這個測試仍列成紅的，但失敗原因是 `ImportError`，
    讓人看得出它是因為錯的理由紅，而不是被當成一個好的回歸測試悄悄算過。
    A new test imports a function the base does not have yet: the whole test file fails to collect on the base, and
    the test is still listed as red, but with the `ImportError` as its failure line, so it shows as red for the wrong
    reason instead of quietly counting as a good regression test."""
    repo = make_repo(tmp_path / "repo")
    (repo / "calc.py").write_text(FIXED + "\n\ndef sub(a, b):\n    return a - b\n", encoding="utf-8")
    (repo / "tests" / "test_calc.py").write_text(BASE_TESTS.replace("import add", "import add, sub") + '''

def test_subtracting_gives_the_difference():
    assert sub(3, 1) == 2
''', encoding="utf-8")
    code = tool.main(["--against", "HEAD"], repo=str(repo))
    out, err = capsys.readouterr()
    assert code == 0, out + err
    line = next(line for line in out.splitlines() if "test_subtracting_gives_the_difference" in line)
    assert line.startswith("red    ") and "ImportError" in line, out


def test_an_unknown_revision_cannot_compare_and_leaves_no_worktree(git_repo, tmp_path, capsys, monkeypatch):
    """--against 給了不存在的 revision：結束碼是 2（無法比對，不同於有綠的 1），不留下 worktree 或暫存目錄。
    --against names a revision that does not exist: the exit code is 2 (could not compare, unlike 1 for a green test),
    and no worktree or temporary directory is left."""
    import tempfile

    scratch = tmp_path / "scratch"
    scratch.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(scratch))
    repo = tmp_path / "repo"
    git = _base_repo(git_repo, repo)
    code = tool.main(["--against", "no-such-rev"], repo=str(repo))
    out, err = capsys.readouterr()
    assert code == 2, out + err
    assert "could not compare" in err
    assert len(git("worktree", "list").stdout.splitlines()) == 1
    assert list(scratch.iterdir()) == []


def test_a_new_test_in_a_class_in_a_subdirectory_is_judged_by_its_own_result(make_repo, tmp_path, capsys):
    """子目錄裡的測試檔、類別裡的測試：在基準上也通過，所以列成綠的，結束碼是 1。原本 JUnit 報告的 classname
    帶著類別名稱，對不回選到的 node id，類別裡的測試一律落到「沒在基準上跑」而列成紅的，放過了這支 script 要抓的違規。
    A test in a class, in a test file in a subdirectory, also passes on the base, so it is listed as green and the exit
    code is 1. The JUnit report's classname carries the class name, so before, it never matched the selected node id
    and every test in a class fell through to "not run on the base", listed as red: the very violation the script is
    for went through."""
    repo = make_repo(tmp_path / "repo")
    (repo / "tests" / "unit").mkdir()
    (repo / "tests" / "unit" / "test_more.py").write_text('''\
from calc import add


class TestAdd:
    def test_adding_zero_to_zero_gives_zero(self):
        assert add(0, 0) == 0
''', encoding="utf-8")
    code = tool.main(["--against", "HEAD"], repo=str(repo))
    out, err = capsys.readouterr()
    assert code == 1, out + err
    assert out.splitlines() == ["green  tests/unit/test_more.py::TestAdd::test_adding_zero_to_zero_gives_zero"], out


PARAMETRIZED = '''

import pytest


@pytest.mark.parametrize("a, b, total", [(1, 2, 3), (0, 0, 0), (2, 2, 4)], ids=["one-two", "zeros", "two-two"])
def test_adding_gives_the_sum(a, b, total):
    assert add(a, b) == total
'''


def test_a_parametrized_test_with_a_case_green_on_the_base_is_green_and_names_that_case(make_repo, tmp_path, capsys):
    """參數化的測試算一筆：只要有一個 case 在基準上也通過，整筆就是綠的，並列出是哪個 case；原本紅的 case 蓋掉綠的，
    整筆列成紅的。
    A parametrized test counts as one entry: when any case also passes on the base, the entry is green and names that
    case. Before, the red cases hid the green one and the entry was listed as red."""
    repo = make_repo(tmp_path / "repo")
    (repo / "calc.py").write_text(FIXED, encoding="utf-8")
    (repo / "tests" / "test_calc.py").write_text(BASE_TESTS + PARAMETRIZED, encoding="utf-8")
    code = tool.main(["--against", "HEAD"], repo=str(repo))
    out, err = capsys.readouterr()
    assert code == 1, out + err
    assert out.splitlines() == ["green  tests/test_calc.py::test_adding_gives_the_sum  green on the base: zeros"], out


def test_a_parametrized_test_red_in_every_case_shows_its_first_failure(make_repo, tmp_path, capsys):
    """每個 case 在基準上都失敗：整筆是紅的，失敗原因取第一個 case 的（`assert -1 == 3`），不是最後一個的。
    Every case fails on the base: the entry is red, with the first case's failure (`assert -1 == 3`), not the last's."""
    repo = make_repo(tmp_path / "repo")
    (repo / "calc.py").write_text(FIXED, encoding="utf-8")
    (repo / "tests" / "test_calc.py").write_text(BASE_TESTS + PARAMETRIZED.replace("(0, 0, 0)", "(3, 1, 4)"),
                                                  encoding="utf-8")
    code = tool.main(["--against", "HEAD"], repo=str(repo))
    out, err = capsys.readouterr()
    assert code == 0, out + err
    assert out.splitlines() == ["red    tests/test_calc.py::test_adding_gives_the_sum  assert -1 == 3"], out


def test_a_new_test_skipped_on_the_base_is_listed_as_skipped_and_counts_like_green(make_repo, tmp_path, capsys):
    """新測試在基準上被 skip（基準還沒有 `sub`）：它沒有在基準上失敗，沒證明自己擋得住錯，所以列成 skipped 並附上
    skip 的原因，結束碼和有綠的一樣是 1；原本 skip 被當成通過，列成 green。
    A new test is skipped on the base (the base has no `sub` yet): it did not fail there, so it has not shown it
    guards anything; it is listed as skipped with the skip reason, and the exit code is 1, as for a green test.
    Before, a skip counted as a pass and was listed as green."""
    repo = make_repo(tmp_path / "repo")
    (repo / "calc.py").write_text(FIXED + "\n\ndef sub(a, b):\n    return a - b\n", encoding="utf-8")
    (repo / "tests" / "test_calc.py").write_text(BASE_TESTS + '''

import calc
import pytest


@pytest.mark.skipif(not hasattr(calc, "sub"), reason="calc has no sub")
def test_subtracting_gives_the_difference():
    assert calc.sub(3, 1) == 2
''', encoding="utf-8")
    code = tool.main(["--against", "HEAD"], repo=str(repo))
    out, err = capsys.readouterr()
    assert code == 1, out + err
    assert out.splitlines() == ["skipped tests/test_calc.py::test_subtracting_gives_the_difference  calc has no sub"], out


def test_a_test_file_that_does_not_parse_cannot_compare(make_repo, tmp_path, capsys):
    """工作目錄的測試檔有語法錯誤：選不出測試，結束碼是 2（無法比對），而不是丟出 traceback、讓結束碼和「有綠的」一樣。
    A test file in the working tree has a syntax error: no tests can be selected, so the exit code is 2 (could not
    compare), not a traceback whose exit code looks like "some are green"."""
    repo = make_repo(tmp_path / "repo")
    (repo / "tests" / "test_calc.py").write_text(BASE_TESTS + "\n\ndef test_broken(:\n    pass\n", encoding="utf-8")
    code = tool.main(["--against", "HEAD"], repo=str(repo))
    out, err = capsys.readouterr()
    assert code == 2, out + err
    assert "could not compare" in err and "tests/test_calc.py" in err, err


def test_a_branch_without_new_or_changed_tests_says_so(make_repo, tmp_path, capsys):
    """分支只改了程式碼、沒有新增或改動測試：印出說明、結束碼是 0；原本什麼都不印，看起來和「全部是紅的」一樣。
    The branch changes only code, no tests are new or changed: it says so and the exit code is 0. Before, it printed
    nothing, which looked the same as "every test is red"."""
    repo = make_repo(tmp_path / "repo")
    (repo / "calc.py").write_text(FIXED, encoding="utf-8")
    code = tool.main(["--against", "HEAD"], repo=str(repo))
    out, err = capsys.readouterr()
    assert code == 0, out + err
    assert out.splitlines() == ["no new or changed tests under tests/"]


def test_pytest_that_cannot_start_on_the_base_cannot_compare(git_repo, tmp_path, capsys):
    """基準的 `pytest.ini` 帶著不存在的選項：pytest 在基準上無法啟動、沒寫出報告，結束碼是 2（無法比對），
    不能把沒跑的測試當成任何結果，並附上 pytest 輸出的最後幾行說明原因；這時 worktree 已經建好了，失敗之後照樣移除。
    The base's `pytest.ini` carries an option that does not exist: pytest cannot start on the base and writes no
    report, so the exit code is 2 (could not compare); tests that never ran count as no result at all, and the last
    lines of pytest's output say why. The worktree was already added by then, and it is still removed after the
    failure."""
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "pytest.ini").write_text("[pytest]\naddopts = --no-such-option\n", encoding="utf-8")
    git = _base_repo(git_repo, repo)
    (repo / "tests" / "test_calc.py").write_text(BASE_TESTS + '''

def test_adding_two_numbers_gives_their_sum():
    assert add(1, 2) == 3
''', encoding="utf-8")
    code = tool.main(["--against", "HEAD"], repo=str(repo))
    out, err = capsys.readouterr()
    assert code == 2, out + err
    # 沒有報告時附上 pytest 輸出的最後幾行，看得出它為什麼沒跑（這裡是不認得的選項）
    # Without a report, the last lines of pytest's output show why it did not run (here an unknown option)
    assert "could not compare" in err and "--no-such-option" in err, err
    # 這條路徑已經建了 worktree：失敗之後也要移除
    # This path has already added the worktree: it is removed after the failure too
    worktrees = git("worktree", "list").stdout
    assert len(worktrees.splitlines()) == 1, worktrees


def test_a_selected_test_that_is_not_collected_cannot_compare_and_hides_no_other_result(make_repo, tmp_path, capsys):
    """同一批裡一個綠的新測試，加上一個在基準上收集不到的（類別有 `__init__`，pytest 不收）：綠的照樣列出來，
    收集不到的那個在 stderr 點名，結束碼是 2（無法比對）。原本 pytest 對找不到的 node id 整批不跑，兩個都列成
    「沒在基準上跑」的紅，結束碼 0，綠的被藏起來。
    In one batch, a new green test and one that is not collected on the base (its class has `__init__`, which pytest
    skips): the green one is still listed, the other is named on stderr, and the exit code is 2 (could not compare).
    Before, pytest ran none of the batch for a node id it could not find, both were listed red as "not run on the
    base", the exit code was 0, and the green one was hidden."""
    repo = make_repo(tmp_path / "repo")
    (repo / "tests" / "test_calc.py").write_text(BASE_TESTS + '''

def test_adding_zero_to_zero_gives_zero():
    assert add(0, 0) == 0


class TestHelper:
    def __init__(self):
        pass

    def test_never_collected(self):
        assert True
''', encoding="utf-8")
    code = tool.main(["--against", "HEAD"], repo=str(repo))
    captured = capsys.readouterr()
    assert code == 2, captured.out + captured.err
    assert "green  tests/test_calc.py::test_adding_zero_to_zero_gives_zero" in captured.out.splitlines()
    assert "not collected on the base: tests/test_calc.py::TestHelper::test_never_collected" in captured.err


def test_a_pytest_ini_under_tests_does_not_change_how_results_are_matched(make_repo, tmp_path, capsys):
    """基準在 `tests/` 底下有 `pytest.ini`，pytest 的 rootdir 會落在 `tests/`，JUnit 的 classname 就少了 `tests.`：
    綠的新測試照樣認得出來，列成綠的、結束碼 1，而不是對不上報告。
    The base has a `pytest.ini` under `tests/`, so pytest's rootdir would be `tests/` and the JUnit classname would lack
    `tests.`: a new green test is still recognized, listed as green with exit code 1, instead of missing the report."""
    repo = tmp_path / "repo"
    (repo / "tests").mkdir(parents=True)
    (repo / "tests" / "pytest.ini").write_text("[pytest]\n", encoding="utf-8")
    make_repo(repo)
    (repo / "tests" / "test_calc.py").write_text(BASE_TESTS + '''

def test_adding_zero_to_zero_gives_zero():
    assert add(0, 0) == 0
''', encoding="utf-8")
    code = tool.main(["--against", "HEAD"], repo=str(repo))
    captured = capsys.readouterr()
    assert code == 1, captured.out + captured.err
    assert captured.out.splitlines() == ["green  tests/test_calc.py::test_adding_zero_to_zero_gives_zero"]


def test_a_new_test_that_xfails_on_the_base_is_red(make_repo, tmp_path, capsys):
    """新測試標了 xfail，在基準上確實失敗：它在基準上是紅的，列成紅的並寫明是 xfail，結束碼 0。JUnit 把 xfail 記成
    `<skipped type="pytest.xfail">`，原本被當成 skipped、結束碼 1。
    A new test is marked xfail and does fail on the base: it is red there, so it is listed as red, saying xfail, with
    exit code 0. JUnit records an xfail as `<skipped type="pytest.xfail">`, which used to be taken as skipped, with
    exit code 1."""
    repo = make_repo(tmp_path / "repo")
    (repo / "tests" / "test_calc.py").write_text(BASE_TESTS + '''

import pytest


@pytest.mark.xfail(reason="add subtracts on the base")
def test_adding_two_numbers_gives_their_sum():
    assert add(1, 2) == 3
''', encoding="utf-8")
    code = tool.main(["--against", "HEAD"], repo=str(repo))
    out, err = capsys.readouterr()
    assert code == 0, out + err
    assert out.splitlines() == [
        "red    tests/test_calc.py::test_adding_two_numbers_gives_their_sum  xfail on the base: add subtracts on the base"
    ], out


def test_a_test_file_that_is_not_utf8_cannot_compare(make_repo, tmp_path, capsys):
    """工作目錄的測試檔不是 UTF-8（這裡是一個 Latin-1 的 é）：讀不了，結束碼是 2（無法比對），而不是丟出
    `UnicodeDecodeError`、讓結束碼和「有綠的」一樣。Windows 上 git 的輸出原本用系統編碼解，含中文的測試檔也會這樣。
    A test file in the working tree is not UTF-8 (here a Latin-1 é): it cannot be read, so the exit code is 2 (could
    not compare), not a `UnicodeDecodeError` whose exit code looks like "some are green". On Windows, git's output used
    to be decoded with the system code page, so a test file with Chinese text did the same."""
    repo = make_repo(tmp_path / "repo")
    (repo / "tests" / "test_calc.py").write_bytes(BASE_TESTS.encode() + b"\n\ndef test_caf\xe9():\n    pass\n")
    code = tool.main(["--against", "HEAD"], repo=str(repo))
    out, err = capsys.readouterr()
    assert code == 2, out + err
    assert "could not compare" in err and "utf-8" in err, err


def test_a_test_file_skipped_as_a_whole_on_the_base_lists_its_tests_as_skipped(make_repo, tmp_path, capsys):
    """新測試檔在模組層級 `pytest.importorskip` 一個基準上沒有的模組：整個檔案在基準上被 skip，裡面選到的測試列成
    skipped 並附上原因，結束碼 1。JUnit 把模組層級的 skip 記成 classname 是空的 testcase，原本被當成收集錯誤，
    列成「collection failure」的紅、結束碼 0，放過了一個在基準上根本沒跑的測試。
    A new test file calls `pytest.importorskip` at module level for a module the base lacks: the whole file is skipped
    on the base, so its selected tests are listed as skipped with the reason, exit code 1. JUnit records a module-level
    skip as a testcase with an empty classname, which used to be taken as a collection error: red with "collection
    failure", exit code 0, letting through a test that never ran on the base."""
    repo = make_repo(tmp_path / "repo")
    (repo / "tests" / "test_extra.py").write_text('''\
import pytest

pytest.importorskip("no_such_module_on_the_base")


def test_the_extra_module_is_importable():
    assert True
''', encoding="utf-8")
    code = tool.main(["--against", "HEAD"], repo=str(repo))
    out, err = capsys.readouterr()
    assert code == 1, out + err
    line = next(line for line in out.splitlines() if "test_the_extra_module_is_importable" in line)
    assert line.startswith("skipped ") and "no_such_module_on_the_base" in line, out


def test_a_fail_fast_option_on_the_base_does_not_stop_the_selected_tests(make_repo, tmp_path, capsys):
    """基準的 `pytest.ini` 帶 `-x`，同一個檔案裡排在前面、沒被選到的測試在基準上失敗：選到的測試照樣跑完，
    在基準上通過就列成綠的，結束碼 1。原本 pytest 在第一個失敗就停下，選到的測試被說成「收集不到」、結束碼 2。
    The base's `pytest.ini` carries `-x`, and an unselected test earlier in the same file fails on the base: the
    selected test still runs, is listed as green because it passes there, and the exit code is 1. Before, pytest
    stopped at the first failure and the selected test was reported as "not collected", exit code 2."""
    repo = tmp_path / "repo"
    (repo / "tests").mkdir(parents=True)
    (repo / "pytest.ini").write_text("[pytest]\naddopts = -x\n", encoding="utf-8")
    make_repo(repo, tests=BASE_TESTS + '''

def test_adding_one_and_one():
    assert add(1, 1) == 2
''')
    (repo / "tests" / "test_calc.py").write_text(BASE_TESTS + '''

def test_adding_one_and_one():
    assert add(1, 1) == 2


def test_adding_zero_to_zero_gives_zero():
    assert add(0, 0) == 0
''', encoding="utf-8")
    code = tool.main(["--against", "HEAD"], repo=str(repo))
    captured = capsys.readouterr()
    assert code == 1, captured.out + captured.err
    assert captured.out.splitlines() == ["green  tests/test_calc.py::test_adding_zero_to_zero_gives_zero"]


def test_a_report_that_does_not_read_cannot_compare_with_a_clean_message(make_repo, tmp_path, capsys):
    """基準根目錄的 `conftest.py` 在 pytest 寫完報告之後把它蓋成不是 XML 的內容：報告讀不了，結束碼是 2，訊息只說
    報告讀不了。`ParseError` 是 `SyntaxError` 的子類別，原本走到語法錯誤那一支，多印一行「in None, line None」。
    The base's root `conftest.py` overwrites the report with something that is not XML after pytest writes it: the
    report does not read, so the exit code is 2 and the message says only that. `ParseError` is a subclass of
    `SyntaxError`, so it used to take the syntax-error branch and print an extra "in None, line None"."""
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "conftest.py").write_text('''\
def pytest_unconfigure(config):
    path = config.getoption("xmlpath", None)
    if path:
        with open(path, "w", encoding="utf-8") as f:
            f.write("this is not xml")
''', encoding="utf-8")
    make_repo(repo)
    (repo / "tests" / "test_calc.py").write_text(BASE_TESTS + '''

def test_adding_two_numbers_gives_their_sum():
    assert add(1, 2) == 3
''', encoding="utf-8")
    code = tool.main(["--against", "HEAD"], repo=str(repo))
    out, err = capsys.readouterr()
    assert code == 2, out + err
    assert "could not compare" in err and "in None" not in err, err


def test_a_whole_file_skip_with_a_multi_line_reason_shows_its_first_line(make_repo, tmp_path, capsys):
    """整個檔案以多行的自訂原因被 skip：列出的那一行只帶原因的第一行，和紅的測試只帶失敗的第一行一樣；原本整段原樣
    印出，把一筆結果拆成兩行。
    A whole file is skipped with a multi-line custom reason: its line carries only the reason's first line, as a red
    test carries only its failure's first line. Before, the whole reason was printed as is, splitting one result
    across two lines."""
    repo = make_repo(tmp_path / "repo")
    (repo / "tests" / "test_extra.py").write_text('''\
import pytest

pytest.skip("waits for the extra module\\nsee the issue for details", allow_module_level=True)


def test_the_extra_module_is_importable():
    assert True
''', encoding="utf-8")
    code = tool.main(["--against", "HEAD"], repo=str(repo))
    out, err = capsys.readouterr()
    assert code == 1, out + err
    assert out.splitlines() == [
        "skipped tests/test_extra.py::test_the_extra_module_is_importable  Skipped: waits for the extra module"], out


def test_a_temporary_directory_behind_a_symlink_still_matches_the_results(make_repo, tmp_path, capsys, monkeypatch):
    """暫存目錄經過符號連結（macOS 的 `/var/folders` 指向 `/private/var/folders`）：綠的新測試照樣認得出來，結束碼 1。
    原本 `--rootdir` 拿到沒解開連結的路徑，pytest 卻用解開後的路徑算 node id，classname 對不上，每個測試都成了
    「收集不到」、結束碼 2（PR #152 的 macOS CI）。
    The temporary directory sits behind a symlink (macOS's `/var/folders` points at `/private/var/folders`): a new
    green test is still recognized, exit code 1. Before, `--rootdir` got the unresolved path while pytest computed
    node ids from the resolved one, so no classname matched and every test came out "not collected", exit code 2
    (macOS CI on PR #152)."""
    import tempfile

    import pytest

    (tmp_path / "real").mkdir()
    try:
        (tmp_path / "link").symlink_to(tmp_path / "real", target_is_directory=True)
    except OSError:
        # Windows 沒有開發者模式或系統管理員權限時不能建符號連結
        # Windows cannot create a symlink without developer mode or administrator rights
        pytest.skip("this platform cannot create a symlink")
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path / "link"))
    repo = make_repo(tmp_path / "repo")
    (repo / "tests" / "test_calc.py").write_text(BASE_TESTS + '''

def test_adding_zero_to_zero_gives_zero():
    assert add(0, 0) == 0
''', encoding="utf-8")
    code = tool.main(["--against", "HEAD"], repo=str(repo))
    captured = capsys.readouterr()
    assert code == 1, captured.out + captured.err
    assert captured.out.splitlines() == ["green  tests/test_calc.py::test_adding_zero_to_zero_gives_zero"]


BROKEN_ON_BASE = '''\
from calc import sub


def test_subtracting_gives_the_difference():
    assert sub(3, 1) == 2
'''


def test_a_file_that_fails_to_collect_does_not_hide_another_files_red_test(make_repo, tmp_path, capsys):
    """一個測試檔在基準上匯入失敗、另一個檔案的新測試在基準上失敗：兩個都列成紅的，壞掉的檔案帶著它的匯入錯誤，
    結束碼 0。原本 pytest 遇到收集錯誤就整批中斷，另一個檔案的測試成了「收集不到」、結束碼 2（#183 有 60 個）。
    One test file fails to import on the base and another file's new test fails there: both are listed as red, the
    broken file's test with its import error, exit code 0. Before, pytest stopped the whole run on the collection
    error, so the other file's test came out "not collected", exit code 2 (about 60 tests in #183)."""
    repo = make_repo(tmp_path / "repo")
    (repo / "calc.py").write_text(FIXED + "\n\ndef sub(a, b):\n    return a - b\n", encoding="utf-8")
    (repo / "tests" / "test_sub.py").write_text(BROKEN_ON_BASE, encoding="utf-8")
    (repo / "tests" / "test_calc.py").write_text(BASE_TESTS + '''

def test_adding_two_numbers_gives_their_sum():
    assert add(1, 2) == 3
''', encoding="utf-8")
    code = tool.main(["--against", "HEAD"], repo=str(repo))
    out, err = capsys.readouterr()
    assert code == 0, out + err
    lines = out.splitlines()
    assert "red    tests/test_calc.py::test_adding_two_numbers_gives_their_sum  assert -1 == 3" in lines, out
    broken = next(line for line in lines if "test_subtracting_gives_the_difference" in line)
    assert broken.startswith("red    tests/test_sub.py::") and "ImportError" in broken, out


def test_could_not_compare_names_each_file_that_failed_to_collect(make_repo, tmp_path, capsys):
    """有測試收集不到時，「could not compare」的訊息也逐一點名在基準上收集失敗的檔案，附上錯誤的第一行，看得出
    是哪個檔案壞了；原本只列收集不到的測試（#183 的 60 個測試沒說是 `tests/test_quality_gate.py` 匯入失敗）。
    When a test is not collected, the "could not compare" message also names each file that failed to collect on the
    base with the first line of its error, so the broken file shows; it used to list only the uncollected tests
    (#183's 60 tests did not say that `tests/test_quality_gate.py` failed to import)."""
    repo = make_repo(tmp_path / "repo")
    (repo / "calc.py").write_text(FIXED + "\n\ndef sub(a, b):\n    return a - b\n", encoding="utf-8")
    (repo / "tests" / "test_sub.py").write_text(BROKEN_ON_BASE, encoding="utf-8")
    (repo / "tests" / "test_calc.py").write_text(BASE_TESTS + '''

class TestHelper:
    def __init__(self):
        pass

    def test_never_collected(self):
        assert True
''', encoding="utf-8")
    code = tool.main(["--against", "HEAD"], repo=str(repo))
    captured = capsys.readouterr()
    assert code == 2, captured.out + captured.err
    named = [line for line in captured.err.splitlines() if line.strip().startswith("tests/test_sub.py: ")]
    assert len(named) == 1 and "ImportError: cannot import name 'sub'" in named[0], captured.err


def _alive(pid):
    """這個 pid 的行程還在不在（POSIX 用 signal 0，Windows 問行程的結束碼）。
    Whether the process with this pid is still running (signal 0 on POSIX; the process's exit code on Windows)."""
    if os.name == "nt":
        import ctypes

        kernel32 = ctypes.windll.kernel32
        handle = kernel32.OpenProcess(0x1000, False, pid)  # 只查詢的權限 ／ PROCESS_QUERY_LIMITED_INFORMATION
        if not handle:
            return False
        try:
            code = ctypes.c_ulong()
            kernel32.GetExitCodeProcess(handle, ctypes.byref(code))
            return code.value == 259  # 還在執行 ／ STILL_ACTIVE
        finally:
            kernel32.CloseHandle(handle)
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def test_a_test_that_never_ends_is_reported_as_a_hang_and_its_process_tree_is_stopped(make_repo, tmp_path, capsys):
    """新測試在基準上一直不結束（它自己再開一個子行程）：過了很短的 `--timeout`，這個測試列成 `hang`（不算紅也不算綠），
    結束碼 2，在時限加上餘裕內結束；pytest 與它開的子行程都被停掉，faulthandler 的輸出點名卡住的測試函式。原本
    `subprocess.run` 沒有時限，整個檢查卡住（#183 只好把 FIFO 與 `/dev/zero` 的案例改在判斷函式上測）。
    A new test never ends on the base (and starts a child process of its own): past a short `--timeout` it is listed
    as `hang` (neither red nor green), exit code 2, ending within the timeout plus a margin; pytest and the child it
    started are both stopped, and faulthandler's output names the stuck test function. Before, `subprocess.run` had no
    time limit and the whole check hung (#183 had to test its FIFO and `/dev/zero` cases at the predicate instead)."""
    import time

    pids = tmp_path / "pids"
    repo = make_repo(tmp_path / "repo")
    (repo / "tests" / "test_calc.py").write_text(BASE_TESTS + f'''

def test_waits_forever_on_the_base():
    import os, subprocess, sys, time
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(120)"])
    with open({str(pids)!r}, "w") as f:
        f.write(f"{{os.getpid()}} {{child.pid}}")
    time.sleep(120)
''', encoding="utf-8")
    start = time.monotonic()
    code = tool.main(["--against", "HEAD", "--timeout", "4"], repo=str(repo))
    elapsed = time.monotonic() - start
    captured = capsys.readouterr()
    assert code == 2, captured.out + captured.err
    assert "hang   tests/test_calc.py::test_waits_forever_on_the_base" in captured.out.splitlines(), captured.out
    assert elapsed < 4 + 30, elapsed
    assert "test_waits_forever_on_the_base" in captured.err, captured.err
    deadline = time.monotonic() + 10
    left = [int(p) for p in pids.read_text().split()]
    while any(_alive(p) for p in left) and time.monotonic() < deadline:
        time.sleep(0.2)
    assert [p for p in left if _alive(p)] == [], "pytest or its child is still running"


@pytest.mark.skipif(os.name != "posix", reason="a new session only exists on POSIX")
def test_a_child_that_leaves_the_process_group_cannot_hang_the_check(make_repo, tmp_path, capsys):
    """基準關掉輸出擷取，卡住的測試開了一個用 `start_new_session` 逃出行程群組、還握著 stdout 的子行程：停掉群組之後，script 不再一直
    等那個 pipe，照樣在時限加上餘裕內回報 `hang`、結束碼 2。原本停掉群組後的 `communicate()` 沒有時限，又卡住了。
    The stuck test starts a child that leaves the process group with `start_new_session` and still holds stdout: after
    the group is stopped the script no longer waits on that pipe forever and still reports `hang` with exit code 2
    within the timeout plus a margin. The `communicate()` after stopping the group used to have no time limit and hung
    again."""
    import signal
    import time

    pids = tmp_path / "pids"
    repo = tmp_path / "repo"
    repo.mkdir()
    # 基準關掉輸出擷取（-s）：子行程繼承的是 script 讀的 pipe，不是 pytest 的暫存檔
    # The base turns output capture off (-s): the child inherits the pipe the script reads, not pytest's temp file
    (repo / "pytest.ini").write_text("[pytest]\naddopts = -s\n", encoding="utf-8")
    make_repo(repo)
    (repo / "tests" / "test_calc.py").write_text(BASE_TESTS + f'''

def test_leaves_a_child_outside_the_group():
    import subprocess, sys, time
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(120)"], start_new_session=True)
    with open({str(pids)!r}, "w") as f:
        f.write(str(child.pid))
    time.sleep(120)
''', encoding="utf-8")
    start = time.monotonic()
    try:
        code = tool.main(["--against", "HEAD", "--timeout", "4"], repo=str(repo))
        elapsed = time.monotonic() - start
    finally:
        if pids.is_file():
            try:
                os.kill(int(pids.read_text()), signal.SIGKILL)
            except ProcessLookupError:
                pass
    captured = capsys.readouterr()
    assert code == 2, captured.out + captured.err
    assert "hang   tests/test_calc.py::test_leaves_a_child_outside_the_group" in captured.out.splitlines()
    assert elapsed < 4 + 40, elapsed


def test_tests_that_finished_before_the_timeout_keep_their_result(make_repo, tmp_path, capsys):
    """逾時之前已經跑完的新測試照進度記錄分類：通過的是綠、失敗與 xfail 的是紅、在基準上收集失敗的檔案裡的是紅，
    只有卡住的那個是 `hang`，結束碼 2。
    The new tests that finished before the timeout are sorted from the progress records: a pass is green, a failure
    and an xfail are red, a test in a file that failed to collect on the base is red, and only the stuck one is
    `hang`, exit code 2."""
    repo = make_repo(tmp_path / "repo")
    (repo / "calc.py").write_text(FIXED + "\n\ndef sub(a, b):\n    return a - b\n", encoding="utf-8")
    (repo / "tests" / "test_a_sub.py").write_text(BROKEN_ON_BASE, encoding="utf-8")
    (repo / "tests" / "test_calc.py").write_text(BASE_TESTS + '''

import pytest


def test_adding_zero_to_zero_gives_zero():
    assert add(0, 0) == 0


def test_adding_two_numbers_gives_their_sum():
    assert add(1, 2) == 3


@pytest.mark.xfail(reason="add subtracts on the base")
def test_adding_one_and_one():
    assert add(1, 1) == 2


def test_waits_forever_on_the_base():
    import time
    time.sleep(120)
''', encoding="utf-8")
    code = tool.main(["--against", "HEAD", "--timeout", "4"], repo=str(repo))
    captured = capsys.readouterr()
    assert code == 2, captured.out + captured.err
    statuses = {line.split()[1]: line.split()[0] for line in captured.out.splitlines()}
    assert statuses == {
        "tests/test_a_sub.py::test_subtracting_gives_the_difference": "red",
        "tests/test_calc.py::test_adding_zero_to_zero_gives_zero": "green",
        "tests/test_calc.py::test_adding_two_numbers_gives_their_sum": "red",
        "tests/test_calc.py::test_adding_one_and_one": "red",
        "tests/test_calc.py::test_waits_forever_on_the_base": "hang",
    }, captured.out
