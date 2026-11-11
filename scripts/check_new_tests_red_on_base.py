"""分支新增或改動的測試，在基準 revision 的程式碼上要是紅的（CODING_STANDARDS 第 1 條；#150）。

修正的回歸測試要在修正之前失敗：「a new test that also passes on `master`」是違規。這支 script 找出工作目錄的
`tests/` 裡，相對於與 `--against` 的 merge-base 新增或內容改了的測試函式，把 merge-base 掛成暫時的 detached
worktree、換上工作目錄的 `tests/`，只跑這些測試，再逐一列出它們在基準上是紅、綠還是 skipped。紅的附上失敗原因，
看得出是不是因為錯的理由紅（例如 `ImportError`）；參數化的測試算一筆，有任何 case 通過就是綠的，並列出那些 case；
在基準上被 skip 的列成 skipped（它沒在基準上失敗）。只用在 `fix:` 的分支：`refactor:` 的測試本來就該兩邊都綠。

挑選的範圍：只看 `tests/` 底下的 `test_*.py`，其中最上層的 `test*` 函式，以及最上層 `Test*` 類別裡的 `test*`
方法；「改了」是指函式本身的 AST 不同。只改 fixture、helper 或 `conftest.py` 時，用到它們的測試不會被選到。

結束碼：0 全部是紅的（或沒有新增、改動的測試），1 有綠的或 skipped 的（列出來），2 無法比對（git 失敗、測試檔
解析不了、pytest 在基準上無法啟動）。

用法：
    python scripts/check_new_tests_red_on_base.py --against master

The tests a branch adds or changes must be red on the base revision's code (CODING_STANDARDS rule 1; #150).

A fix's regression test fails before the fix: "a new test that also passes on `master`" is a violation. This script
finds the test functions in the working tree's `tests/` that are new or whose source differs from the merge-base
with `--against`, adds that merge-base as a temporary detached worktree with the working tree's `tests/` in place of
its own, runs only those tests, and lists each one as red, green or skipped on the base. A red one shows its failure
reason, so a test that is red for the wrong reason (an `ImportError`, say) is visible; a parametrized test is one
entry, green when any case passes, naming those cases; one skipped on the base is listed as skipped (it did not fail
there). For `fix:` branches only: a `refactor:` keeps its tests green on both sides on purpose.

What it selects: only `test_*.py` under `tests/`, and in them the top-level `test*` functions and the `test*` methods
of top-level `Test*` classes; "changed" means the function's own AST differs. A change only to a fixture, a helper or
`conftest.py` does not select the tests that use it.

Exit code: 0 every test is red (or no test is new or changed), 1 some are green or skipped (they are listed), 2 could
not compare (git failed, a test file does not parse, pytest could not start on the base).

Usage:
    python scripts/check_new_tests_red_on_base.py --against master
"""

from __future__ import annotations

import argparse
import ast
import os
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _git(repo: str, *args: str) -> str:
    return subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True, text=True).stdout


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


def junit_key(node_id: str) -> tuple[str, str]:
    """一個 node id 在 JUnit 報告裡的 (classname, name)：`tests/a/test_x.py::TestY::test_z` 是
    (`tests.a.test_x.TestY`, `test_z`)。選測試與讀報告共用這條規則，兩邊才不會對不上。
    A node id's (classname, name) in the JUnit report: `tests/a/test_x.py::TestY::test_z` is (`tests.a.test_x.TestY`,
    `test_z`). Selecting tests and reading the report share this rule, so the two always match."""
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


def run_on_base(worktree: Path, node_ids: list[str], report: Path) -> dict[str, tuple[str, str]]:
    """在 worktree 裡只跑 node_ids，回傳每個 node id 在基準上的 (狀態, 說明)。狀態是 `red`、`green` 或
    `skipped`：參數化的測試算一筆，有任何 case 通過就是綠的，說明列出那些 case；沒有通過但有 case 被 skip 是 skipped，
    說明是 skip 的原因（它沒在基準上失敗，結束碼和綠的一樣算）；全部失敗是紅的，說明是第一個 case 的失敗原因。
    收集不到的測試檔，裡面每個選到的測試都帶那個收集錯誤；報告裡完全沒有的測試算紅的（沒在基準上跑），絕不算綠。
    Runs only node_ids in the worktree and returns each node id's (status, detail) on the base. The status is `red`,
    `green` or `skipped`: a parametrized test is one entry, green when any case passes, with those cases as the
    detail; skipped when none passes and a case was skipped, with the skip reason as the detail (it did not fail on
    the base, so the exit code counts it like green); red when all fail, with the first case's failure as the
    detail. Each selected test in a file that failed to collect
    carries that collection error; a test missing from the report counts as red (it did not run on the base), never as
    green."""
    # pytest 的結束碼分不出「無法啟動」與「選到的檔案收集失敗」（兩者都可能是 4），所以只讀報告
    # pytest's exit code cannot tell "could not start" from "a selected file failed to collect" (both can be 4), so
    # only the report is read
    subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", f"--junitxml={report}",
                    *node_ids], cwd=worktree, capture_output=True, text=True)
    passed: dict[str, list[str]] = {}
    skipped: dict[str, str] = {}
    failed: dict[str, str] = {}
    broken_files: dict[str, str] = {}
    by_key = {junit_key(node_id): node_id for node_id in node_ids}
    for case in ET.parse(report).getroot().iter("testcase"):
        problem = case.find("failure")
        if problem is None:
            problem = case.find("error")
        if not case.get("classname"):
            # 模組層級的收集錯誤：name 是模組路徑（tests.test_x）
            # A module-level collection error: name is the module path (tests.test_x)
            reason = _reason(problem) if problem is not None else ""
            broken_files[case.get("name", "").replace(".", "/") + ".py"] = reason or "collection failure"
            continue
        name = case.get("name", "")
        node_id = by_key.get((case.get("classname", ""), name.split("[")[0]))
        if node_id is None:
            continue
        skip = case.find("skipped")
        if problem is not None:
            failed.setdefault(node_id, _reason(problem))
        elif skip is not None:
            skipped.setdefault(node_id, (skip.get("message") or "skipped").splitlines()[0])
        else:
            passed.setdefault(node_id, []).append(name[name.index("[") + 1:-1] if "[" in name else "")
    results: dict[str, tuple[str, str]] = {}
    for node_id in node_ids:
        if node_id in passed:
            cases = [case for case in passed[node_id] if case]
            results[node_id] = ("green", f"green on the base: {', '.join(cases)}" if cases else "")
        elif node_id in skipped:
            results[node_id] = ("skipped", skipped[node_id])
        elif node_id in failed:
            results[node_id] = ("red", failed[node_id])
        else:
            results[node_id] = ("red", broken_files.get(node_id.split("::")[0], "not run on the base"))
    return results


def main(argv: list[str] | None = None, repo: str = _REPO) -> int:
    parser = argparse.ArgumentParser(description="List the new and changed tests that already pass on the base.")
    parser.add_argument("--against", required=True, metavar="REV", help="the revision whose merge-base is the base")
    args = parser.parse_args(argv)
    scratch = Path(tempfile.mkdtemp(prefix="vh_red_on_base_"))
    worktree = scratch / "base"
    try:
        base = _git(repo, "merge-base", args.against, "HEAD").strip()
        node_ids = new_and_changed(repo, base)
        if not node_ids:
            print("no new or changed tests under tests/")
            return 0
        _git(repo, "worktree", "add", "--detach", str(worktree), base)
        # 換上工作目錄的 tests/：要跑的是分支的測試，程式碼是基準的
        # Swap in the working tree's tests/: the branch's tests run against the base's code
        shutil.rmtree(worktree / "tests", ignore_errors=True)
        shutil.copytree(Path(repo, "tests"), worktree / "tests")
        results = run_on_base(worktree, node_ids, scratch / "report.xml")
    except (subprocess.CalledProcessError, OSError, ET.ParseError, SyntaxError) as exc:
        # git 的錯誤在它的 stderr；pytest 沒寫出報告（無法啟動）時讀報告會丟 OSError 或 ParseError；測試檔解析不了是 SyntaxError
        # git's error is in its stderr; when pytest wrote no report (it could not start), reading it raises OSError or
        # ParseError; a test file that does not parse raises SyntaxError
        if isinstance(exc, subprocess.CalledProcessError):
            detail = exc.stderr
        elif isinstance(exc, SyntaxError):
            detail = f"in {exc.filename}, line {exc.lineno}"
        else:
            detail = ""
        print(f"could not compare: {exc}\n{detail or ''}", file=sys.stderr)
        return 2
    finally:
        subprocess.run(["git", "worktree", "remove", "--force", str(worktree)], cwd=repo, capture_output=True)
        subprocess.run(["git", "worktree", "prune"], cwd=repo, capture_output=True)
        shutil.rmtree(scratch, ignore_errors=True)
    for node_id in node_ids:
        status, detail = results[node_id]
        print(f"{status:<6} {node_id}  {detail}".rstrip())
    return 1 if any(status != "red" for status, _ in results.values()) else 0


if __name__ == "__main__":
    sys.exit(main())
