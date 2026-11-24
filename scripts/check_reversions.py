"""把一個檔案裡的修正一次改回一項，跑測試，列出每一項讓哪些測試變紅（測試的敏感度檢查）。

每一項是「名稱、原文、改壞後」，原文在檔案裡要剛好出現一次。script 先確認工作目錄是乾淨的（改壞之前先 commit，
#158 的教訓），再在原始檔案上跑一次測試：有找不到或沒通過的測試、或用 node id 指定的測試被略過，就什麼都不改、
結束碼 2（附上 pytest 的 stderr）；經由檔案、目錄或整個套件跑到而被略過的，列成警告（#209）。之後逐項：把原文
換成改壞後的文字、用固定的 pytest 參數跑測試、從摘要讀出失敗（FAILED）與錯誤（ERROR，例如收集不到）的測試並在
每個底下印出失敗的那一行、列出被略過（skipped，不算紅燈）的測試，最後用記憶體裡的原內容把檔案寫回去，不靠 git。
pytest 的參數是固定的：`-v` 逐一列出每個測試的結果（讀得到被略過的測試 ID），`-rfE` 保證摘要列出失敗與錯誤
（改用 `-rs` 之類的參數會把它們拿掉，讓每一項看起來都沒有紅燈）。

改壞的清單是一個 JSON 檔：`[{"name": "...", "old": "...", "new": "..."}, ...]`；放在 repo 外或 git 忽略的地方，
否則工作目錄就不乾淨。

結束碼：0 每一項都至少讓一個測試變紅，1 有的一項也沒有（摘要點名它們），2 無法檢查（工作目錄不乾淨、清單讀不了、
原文不是剛好出現一次、測試在原始檔案上沒有全部通過、pytest 跑不起來或被中斷、檔案沒能寫回原狀）。

用法：
    python scripts/check_reversions.py <檔案> <清單.json> [pytest 的測試路徑或 node id ...]

Reverts a fix in one file one item at a time, runs the tests, and lists which tests each item turns red (a check of
the tests' sensitivity).

Each item is "name, old text, new text", and the old text must occur exactly once in the file. The script first checks
that the working tree is clean (commit before breaking code, the lesson of #158), then runs the tests once on the
unmodified file: a test that is not found or does not pass, or a test named by its node id that skips, changes
nothing and exits 2 (with pytest's stderr); a test reached through a file, a directory or the whole suite that skips
is listed as a warning (#209). Then for each item: replaces the old text with the new, runs the tests with fixed
pytest arguments, reads the failed (FAILED) and errored (ERROR, such as a collection error) tests from the summary and
prints each one's failure line under it, lists the skipped tests (not counted as red), and writes the file back from
the original content held in memory, not through git. The pytest arguments are fixed: `-v` puts each test's outcome
on its own line (so skipped test ids can be read), and `-rfE` keeps the failures and errors in the summary (an
argument such as `-rs` would drop them, making every item look as if it turned nothing red).

The reversions are a JSON file: `[{"name": "...", "old": "...", "new": "..."}, ...]`; keep it outside the repo or
somewhere git ignores, or the working tree is not clean.

Exit code: 0 every item turned at least one test red, 1 some turned none red (the summary names them), 2 could not
check (the working tree is not clean, the list does not read, an old text does not occur exactly once, the tests do
not all pass on the unmodified file, pytest could not run or was interrupted, the file was not written back as it
was).

Usage:
    python scripts/check_reversions.py <file> <reversions.json> [pytest test paths or node ids ...]
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# 固定的 pytest 參數：逐一列出每個測試的結果（讀得到被略過的測試 ID）、不寫快取、摘要列出失敗與錯誤
# The fixed pytest arguments: each test's outcome on its own line (so skipped test ids can be read), no cache
# written, failures and errors listed in the summary
PYTEST_ARGS = ("-v", "-p", "no:cacheprovider", "-rfE")
# `-v` 的結果行：`<id> SKIPPED (<原因>) [ 50%]` ／ A `-v` outcome line: `<id> SKIPPED (<reason>) [ 50%]`
_SKIPPED_RE = re.compile(r"^(\S.*?::.*?) SKIPPED\b", re.MULTILINE)
# pytest 的結束碼裡表示「跑完了」的：0 全部通過、1 有失敗（2 只在摘要有 ERROR 行時算，見 main）
# The pytest exit codes that mean it ran: 0 all passed, 1 some failed (2 counts only when the summary has ERROR
# lines, see main)
_PYTEST_RAN = (0, 1)


def _dirty(repo: str) -> str:
    """repo 的 `git status --porcelain` 輸出；空字串表示工作目錄是乾淨的。
    The repo's `git status --porcelain` output; an empty string means the working tree is clean."""
    return subprocess.run(["git", "status", "--porcelain"], cwd=repo, check=True, capture_output=True,
                          encoding="utf-8").stdout


def _red(output: str) -> list[tuple[str, str]]:
    """pytest 摘要裡失敗與錯誤的測試與它們的原因（`FAILED <id> - <原因>`、`ERROR <id> - <原因>`）；沒有原因時是空字串。
    The failed and errored tests in pytest's summary with their reasons (`FAILED <id> - <reason>`,
    `ERROR <id> - <reason>`); the reason is empty when there is none."""
    red = []
    for line in output.splitlines():
        for prefix in ("FAILED ", "ERROR "):
            if line.startswith(prefix):
                test, _, reason = line[len(prefix):].partition(" - ")
                red.append((test.strip(), reason.strip()))
    return red


def _skipped(output: str) -> list[str]:
    """`-v` 輸出裡被略過的測試 ID ／ The skipped test ids in `-v` output."""
    return _SKIPPED_RE.findall(output)


def _pytest(repo: str, tests: list[str]) -> subprocess.CompletedProcess[str]:
    """用固定參數在 repo 跑 pytest，擷取 stdout 與 stderr。不寫 bytecode：`__pycache__` 不能讓工作目錄變髒
    （repo 不一定忽略它）；`COLUMNS` 設得夠寬，摘要裡的失敗原因才不會依終端機寬度被截斷。
    Runs pytest in the repo with the fixed arguments, capturing stdout and stderr. No bytecode: `__pycache__` must not
    dirty the working tree (a repo need not ignore it); `COLUMNS` is wide enough that the summary's failure reasons
    are not cut to the terminal width."""
    return subprocess.run([sys.executable, "-m", "pytest", *PYTEST_ARGS, *tests], cwd=repo,
                          env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1", "COLUMNS": "1000"}, capture_output=True,
                          encoding="utf-8", errors="replace")


def _tail(done: subprocess.CompletedProcess[str]) -> str:
    """pytest 的 stderr（例如「ERROR: not found: <id>」）加上 stdout 的最後 5 行。
    pytest's stderr (such as "ERROR: not found: <id>") plus the last 5 lines of its stdout."""
    stdout = "\n".join(done.stdout.strip().splitlines()[-5:])
    return "\n".join(part for part in (done.stderr.strip(), stdout) if part)


def main(argv: list[str] | None = None, repo: str = _REPO) -> int:
    """依參數逐項改回、跑測試並列出紅燈；回傳結束碼。
    Reverts each item, runs the tests and lists what turned red, per the arguments; returns the exit code."""
    parser = argparse.ArgumentParser(description="Revert a fix one item at a time and list the tests each turns red.")
    parser.add_argument("file", help="the file to revert, relative to the repo")
    parser.add_argument("reversions", help='a JSON list of {"name", "old", "new"}')
    parser.add_argument("tests", nargs="*", help="pytest test paths or node ids (default: the whole suite)")
    args = parser.parse_args(argv)

    if _dirty(repo):
        print("The working tree has uncommitted changes: commit first, so a reversion can never take them with it.")
        return 2
    try:
        with open(args.reversions, encoding="utf-8") as f:
            items = json.load(f)
        items = [(str(i["name"]), str(i["old"]), str(i["new"])) for i in items]
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f"Could not read the reversions in {args.reversions}: {error}")
        return 2
    path = os.path.join(repo, args.file)
    with open(path, "rb") as f:
        original = f.read()
    text = original.decode("utf-8")
    for name, old, _new in items:
        count = text.count(old)
        if count != 1:
            print(f"The old text of `{name}` occurs {count} times in {args.file}; it must occur exactly once.")
            return 2

    # 先在原始檔案上跑一次：找不到或沒通過的測試，任何一項改回都證明不了什麼
    # One run on the unmodified file first: a test that is not found or does not pass proves nothing under any item
    baseline = _pytest(repo, args.tests)
    if baseline.returncode != 0:
        print(f"The tests do not all pass on the unmodified {args.file} (pytest exited {baseline.returncode}), so "
              f"nothing was reverted:\n{_tail(baseline)}")
        return 2
    # 用 node id 指定、卻被略過的測試是要檢查的對象本身，拒絕；經由檔案、目錄或整個套件跑到的，只警告：整個套件在
    # 某些環境一定有被略過的測試（Docker、Node）
    # A test named by its node id that skips is the very thing to check, so refuse; one reached through a file, a
    # directory or the whole suite only warns: the whole suite always skips some tests in some environments
    skipped = _skipped(baseline.stdout)
    named = [test for test in skipped if test in args.tests]
    if named:
        print(f"Tests named by id are skipped on the unmodified {args.file}, so no item can turn them red: "
              f"{', '.join(named)}")
        return 2
    if skipped:
        print(f"Skipped on the unmodified {args.file}, so no item can turn them red: {', '.join(skipped)}")

    silent, failed_run = [], None
    try:
        for name, old, new in items:
            with open(path, "wb") as f:
                f.write(text.replace(old, new).encode("utf-8"))
            done = _pytest(repo, args.tests)
            red = _red(done.stdout)
            # 收集錯誤時 pytest 也以 2 結束（和被中斷一樣），但摘要有 ERROR 行：那算紅燈
            # On a collection error pytest exits 2 too (as when interrupted), but the summary has ERROR lines: red
            if done.returncode not in _PYTEST_RAN and not (done.returncode == 2 and red):
                failed_run = f"`{name}`: pytest exited {done.returncode}, so nothing was checked:\n{_tail(done)}"
                break
            skipped = _skipped(done.stdout)
            print(f"## {name}: {len(red)} red" + (f", {len(skipped)} skipped" if skipped else ""))
            for test, reason in red:
                print(f"   {test}")
                if reason:
                    print(f"      {reason}")
            for test in skipped:
                print(f"   skipped: {test}")
            if not red:
                silent.append(name)
    finally:
        with open(path, "wb") as f:
            f.write(original)

    with open(path, "rb") as f:
        restored = f.read() == original
    if not restored or _dirty(repo):
        print(f"{args.file} was not written back as it was; check `git status` and `git diff` before going on.")
        return 2
    if failed_run:
        print(failed_run)
        return 2
    if silent:
        print(f"turned nothing red: {', '.join(silent)}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
