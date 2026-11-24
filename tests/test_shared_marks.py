"""共用的 Node 標記（`tests/node_marks.py`）與 `clean_live.assert_only_gap` 的行為，以 pytester 在子行程跑小測試檔（#210）。
The shared Node markers (`tests/node_marks.py`) and `clean_live.assert_only_gap`, run as small test files in a
pytester subprocess (#210)."""
import os
import sys

import pytest

pytest_plugins = ["pytester"]

_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
_REPO_ROOT = os.path.dirname(_TESTS_DIR)

_MARKED = """
from node_marks import node_only


@node_only
def test_needs_node():
    pass
"""


@pytest.fixture
def path_dir(tmp_path):
    """子行程 PATH 上唯一的目錄，一開始是空的 ／ The only directory on the subprocess's PATH, empty at first."""
    directory = tmp_path / "path-dir"
    directory.mkdir()
    return directory


@pytest.fixture
def repo_pytester(pytester, monkeypatch, path_dir):
    """子行程的 PATH 只有一個空目錄，所以 `detect_node("node")` 找不到 Node；pytester 目錄的 conftest 是
    `tests/conftest.py` 的原文，所以檢查的是 repo 真正的接線，`tests/` 與 repo 根目錄在 PYTHONPATH 上。
    The subprocess's PATH is one empty directory, so `detect_node("node")` finds no Node; the pytester directory's
    conftest is `tests/conftest.py` verbatim, so the repo's real wiring is what is checked, with `tests/` and the repo
    root on PYTHONPATH."""
    monkeypatch.setenv("PATH", str(path_dir))
    monkeypatch.setenv("PYTHONPATH", os.pathsep.join([_TESTS_DIR, _REPO_ROOT]))
    monkeypatch.delenv("VIBEHARNESS_REQUIRE_NODE", raising=False)
    with open(os.path.join(_TESTS_DIR, "conftest.py"), encoding="utf-8") as f:
        pytester.makeconftest(f.read())
    return pytester


@pytest.fixture
def fake_node(repo_pytester, path_dir):
    """PATH 上的空目錄放一個只會印出 `v22.0.0` 的假 `node`（POSIX 是 sh 腳本，Windows 是 .cmd），所以
    `detect_node("node")` 認得到一個可用的 Node。
    The empty PATH directory gets a fake `node` that only prints `v22.0.0` (an sh script on POSIX, a .cmd on Windows),
    so `detect_node("node")` sees a usable Node."""
    script = path_dir / "node"
    script.write_text("#!/bin/sh\necho v22.0.0\n", encoding="utf-8", newline="\n")
    script.chmod(0o755)
    (path_dir / "node.cmd").write_text("@echo v22.0.0\r\n", encoding="utf-8", newline="")
    return repo_pytester


def _run(pytester, *args):
    # 子行程用絕對路徑的直譯器，PATH 是空的也找得到 ／ The subprocess uses the interpreter's absolute path, found with an empty PATH
    assert os.path.isabs(sys.executable)
    return pytester.runpytest_subprocess("-rfEs", "-p", "no:cacheprovider", *args)


def test_a_node_test_fails_when_node_is_required_and_missing(repo_pytester, monkeypatch):
    """VIBEHARNESS_REQUIRE_NODE=1 而且沒有可用的 Node：標了 node_only 的測試是失敗，不是略過，理由寫出偵測到的問題。
    With VIBEHARNESS_REQUIRE_NODE=1 and no usable Node, a node_only test fails instead of skipping, naming the
    detection problem."""
    monkeypatch.setenv("VIBEHARNESS_REQUIRE_NODE", "1")
    repo_pytester.makepyfile(test_marked=_MARKED)
    result = _run(repo_pytester)
    out = result.stdout.str()
    result.assert_outcomes(failed=1)
    assert "VIBEHARNESS_REQUIRE_NODE=1" in out and "no usable Node runtime found" in out, out


def test_a_node_test_is_skipped_with_the_problem_when_node_is_missing(repo_pytester):
    """沒有設定 VIBEHARNESS_REQUIRE_NODE、也沒有可用的 Node：標了 node_only 的測試略過，理由是偵測到的問題。
    Without VIBEHARNESS_REQUIRE_NODE and without a usable Node, a node_only test is skipped with the detection problem
    as the reason."""
    repo_pytester.makepyfile(test_marked=_MARKED)
    result = _run(repo_pytester)
    out = result.stdout.str()
    result.assert_outcomes(skipped=1)
    # 偵測到的問題是雙語的（中文在前）／ The detection problem is bilingual (Chinese first)
    assert "Node unavailable: " in out and "no usable Node runtime found" in out, out


_FEATURE = """
from node_marks import node_feature


@node_feature("Node v20.0.0 lacks the feature")
def test_needs_a_node_feature():
    pass
"""


def test_a_node_feature_test_fails_when_node_is_required_and_missing(repo_pytester, monkeypatch):
    """功能標記在完全沒有 Node 時照共用規則：VIBEHARNESS_REQUIRE_NODE=1 就失敗，不會以「版本太舊」略過。
    With no Node at all a feature marker follows the shared rule: with VIBEHARNESS_REQUIRE_NODE=1 the test fails
    instead of being skipped as "too old"."""
    monkeypatch.setenv("VIBEHARNESS_REQUIRE_NODE", "1")
    repo_pytester.makepyfile(test_feature=_FEATURE)
    result = _run(repo_pytester)
    out = result.stdout.str()
    result.assert_outcomes(failed=1)
    assert "VIBEHARNESS_REQUIRE_NODE=1" in out and "lacks the feature" not in out, out


def test_a_node_feature_test_is_skipped_when_node_lacks_the_feature_even_if_required(fake_node, monkeypatch):
    """有可用的 Node 但缺少那項功能：即使 VIBEHARNESS_REQUIRE_NODE=1 也略過，理由是功能缺少的原因。
    A usable Node that lacks the feature: the test is skipped with the feature's reason, even with
    VIBEHARNESS_REQUIRE_NODE=1."""
    monkeypatch.setenv("VIBEHARNESS_REQUIRE_NODE", "1")
    fake_node.makepyfile(test_feature=_FEATURE)
    result = _run(fake_node)
    out = result.stdout.str()
    result.assert_outcomes(skipped=1)
    assert "Node v20.0.0 lacks the feature" in out, out


_HAS_THE_FEATURE = """
from node_marks import node_feature, node_only


@node_only
def test_needs_node():
    pass


@node_feature(None)
def test_needs_a_node_feature_this_node_has():
    pass
"""


def test_node_tests_run_when_node_has_what_they_need(fake_node, monkeypatch):
    """有可用的 Node：node_only 與這個 Node 具備功能的 node_feature 測試都照常執行，不會被略過或判失敗。
    With a usable Node, a node_only test and a node_feature test whose feature this Node has both run as usual,
    neither skipped nor failed."""
    monkeypatch.setenv("VIBEHARNESS_REQUIRE_NODE", "1")
    fake_node.makepyfile(test_has_feature=_HAS_THE_FEATURE)
    _run(fake_node).assert_outcomes(passed=2)


_GAP_REMOVED = """
from types import SimpleNamespace

from clean_live import assert_only_gap


def test_the_gap_is_gone():
    assert_only_gap(SimpleNamespace(overall_status="READY_TO_SHIP", inconclusive_reasons=[]), "the gap")
"""


def test_assert_only_gap_shows_the_verdict_it_got_when_the_gap_is_gone(repo_pytester):
    """拿掉缺口（如 #205、#207 的逐項改壞）時，`assert_only_gap` 的失敗訊息仍寫出兩邊的判定：conftest 讓 clean_live 的
    assert 經過改寫。
    With the gap removed (as in #205 / #207's reversions), `assert_only_gap` still fails with both Verdicts in the
    message: the conftest has clean_live's asserts rewritten."""
    repo_pytester.makepyfile(test_gap=_GAP_REMOVED)
    result = _run(repo_pytester)
    out = result.stdout.str()
    result.assert_outcomes(failed=1)
    assert "assert 'READY_TO_SHIP' == 'INCONCLUSIVE'" in out, out
