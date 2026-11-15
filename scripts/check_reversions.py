"""把一個檔案裡的修正一次改回一項，跑測試，列出每一項讓哪些測試變紅（測試的敏感度檢查）。

每一項是「名稱、原文、改壞後」，原文在檔案裡要剛好出現一次。script 先確認工作目錄是乾淨的（改壞之前先 commit，
#158 的教訓），再逐項：把原文換成改壞後的文字、用固定的 pytest 參數跑測試、從摘要讀出失敗（FAILED）與錯誤
（ERROR，例如收集不到）的測試，最後用記憶體裡的原內容把檔案寫回去，不靠 git。pytest 的參數是固定的：`-rfE`
保證摘要列出失敗與錯誤（改用 `-rs` 之類的參數會把它們拿掉，讓每一項看起來都沒有紅燈）。

改壞的清單是一個 JSON 檔：`[{"name": "...", "old": "...", "new": "..."}, ...]`；放在 repo 外或 git 忽略的地方，
否則工作目錄就不乾淨。

結束碼：0 每一項都至少讓一個測試變紅，1 有的一項也沒有（摘要點名它們），2 無法檢查（工作目錄不乾淨、清單讀不了、
原文不是剛好出現一次、pytest 跑不起來或被中斷、檔案沒能寫回原狀）。

用法：
    python scripts/check_reversions.py <檔案> <清單.json> [pytest 的測試路徑或 node id ...]

Reverts a fix in one file one item at a time, runs the tests, and lists which tests each item turns red (a check of
the tests' sensitivity).

Each item is "name, old text, new text", and the old text must occur exactly once in the file. The script first checks
that the working tree is clean (commit before breaking code, the lesson of #158), then for each item: replaces the
old text with the new, runs the tests with fixed pytest arguments, reads the failed (FAILED) and errored (ERROR, such
as a collection error) tests from the summary, and writes the file back from the original content held in memory,
not through git. The pytest arguments are fixed: `-rfE` keeps the failures and errors in the summary (an argument such
as `-rs` would drop them, making every item look as if it turned nothing red).

The reversions are a JSON file: `[{"name": "...", "old": "...", "new": "..."}, ...]`; keep it outside the repo or
somewhere git ignores, or the working tree is not clean.

Exit code: 0 every item turned at least one test red, 1 some turned none red (the summary names them), 2 could not
check (the working tree is not clean, the list does not read, an old text does not occur exactly once, pytest could
not run or was interrupted, the file was not written back as it was).

Usage:
    python scripts/check_reversions.py <file> <reversions.json> [pytest test paths or node ids ...]
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# 固定的 pytest 參數：安靜、不寫快取、摘要列出失敗與錯誤
# The fixed pytest arguments: quiet, no cache written, failures and errors listed in the summary
PYTEST_ARGS = ("-q", "-p", "no:cacheprovider", "-rfE")
# pytest 的結束碼裡表示「跑完了」的：0 全部通過、1 有失敗（2 只在摘要有 ERROR 行時算，見 main）
# The pytest exit codes that mean it ran: 0 all passed, 1 some failed (2 counts only when the summary has ERROR
# lines, see main)
_PYTEST_RAN = (0, 1)


def _dirty(repo: str) -> str:
    """repo 的 `git status --porcelain` 輸出；空字串表示工作目錄是乾淨的。
    The repo's `git status --porcelain` output; an empty string means the working tree is clean."""
    return subprocess.run(["git", "status", "--porcelain"], cwd=repo, check=True, capture_output=True,
                          encoding="utf-8").stdout


def _red(output: str) -> list[str]:
    """pytest 摘要裡失敗與錯誤的測試（`FAILED <id> - …`、`ERROR <id> - …`）。
    The failed and errored tests in pytest's summary (`FAILED <id> - …`, `ERROR <id> - …`)."""
    red = []
    for line in output.splitlines():
        for prefix in ("FAILED ", "ERROR "):
            if line.startswith(prefix):
                red.append(line[len(prefix):].split(" - ", 1)[0].strip())
    return red


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

    silent, failed_run = [], None
    try:
        for name, old, new in items:
            with open(path, "wb") as f:
                f.write(text.replace(old, new).encode("utf-8"))
            # 不寫 bytecode：`__pycache__` 不能讓工作目錄變髒（repo 不一定忽略它）
            # No bytecode: `__pycache__` must not dirty the working tree (a repo need not ignore it)
            done = subprocess.run([sys.executable, "-m", "pytest", *PYTEST_ARGS, *args.tests], cwd=repo,
                                  env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}, capture_output=True,
                                  encoding="utf-8", errors="replace")
            red = _red(done.stdout)
            # 收集錯誤時 pytest 也以 2 結束（和被中斷一樣），但摘要有 ERROR 行：那算紅燈
            # On a collection error pytest exits 2 too (as when interrupted), but the summary has ERROR lines: red
            if done.returncode not in _PYTEST_RAN and not (done.returncode == 2 and red):
                tail = "\n".join(done.stdout.strip().splitlines()[-5:])
                failed_run = f"`{name}`: pytest exited {done.returncode}, so nothing was checked:\n{tail}"
                break
            print(f"## {name}: {len(red)} red")
            for test in red:
                print(f"   {test}")
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
