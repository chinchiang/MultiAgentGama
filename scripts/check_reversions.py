"""把一個檔案裡的修正一次改回一項，跑測試，列出每一項讓哪些測試變紅（測試的敏感度檢查）。

每一項是「名稱、原文、改壞後」，原文在檔案裡要剛好出現一次。script 先確認工作目錄是乾淨的（改壞之前先 commit，
#158 的教訓），再在原始檔案上跑一次測試：有找不到或沒通過的測試，或用 node id 指定的測試（class 與沒寫參數的
參數化函式含底下每一個測試）沒有讀到以 PASSED 結束，就什麼都不改、結束碼 2，並點名每一個（附上 pytest 的
stderr）；經由檔案、目錄或整個套件跑到而被略過的，列成警告（#209）。之後逐項：把原文換成改壞後的文字、用固定的
pytest 參數跑測試、從摘要讀出失敗（FAILED）與錯誤（ERROR，例如收集不到）的測試並在每個底下印出失敗的那一行、
列出被略過（skipped，不算紅燈）的測試，最後用記憶體裡的原內容把檔案寫回去，不靠 git。被略過的測試從 `-v` 的
結果行讀 ID；數量對不上最後的統計時（例如整個模組被略過），改列摘要裡的每一行略過。讀不到最後的統計行（目標
repo 的 `addopts = -qq`、`-p no:terminal` 會改掉輸出的形狀），或 pytest 回報有失敗卻讀不到任何一個，都是無法
檢查（結束碼 2）。pytest 的參數是固定的，測試參數裡不接受 pytest 選項與 `@檔案`（`-q` 之類會改掉輸出的形狀）：`-v` 逐一列出每個測試的結果，`-rfEs` 保證摘要列出
失敗、錯誤與略過（改用 `-rs` 之類的參數會把失敗與錯誤拿掉，讓每一項看起來都沒有紅燈）。

改壞的清單是一個 JSON 檔：`[{"name": "...", "old": "...", "new": "..."}, ...]`；放在 repo 外或 git 忽略的地方，
否則工作目錄就不乾淨。

結束碼：0 每一項都至少讓一個測試變紅，1 有的一項也沒有（摘要點名它們），2 無法檢查（工作目錄不乾淨、清單讀不了、
原文不是剛好出現一次、測試參數夾著 pytest 選項或 `@檔案`、讀不懂 pytest 的輸出、測試在原始檔案上沒有全部通過、
pytest 跑不起來或被中斷、檔案沒能寫回原狀）。

用法：
    python scripts/check_reversions.py <檔案> <清單.json> [pytest 的測試路徑或 node id ...]

Reverts a fix in one file one item at a time, runs the tests, and lists which tests each item turns red (a check of
the tests' sensitivity).

Each item is "name, old text, new text", and the old text must occur exactly once in the file. The script first checks
that the working tree is clean (commit before breaking code, the lesson of #158), then runs the tests once on the
unmodified file: a test that is not found or does not pass, or a test named by its node id (a class or a
parametrized function named without its parameters including every test under it) not read as ending PASSED,
changes nothing and exits 2, naming each one (with pytest's stderr); a test reached through a file, a directory or
the whole suite that skips is listed as a warning (#209). Then for each item: replaces the old text with the new,
runs the tests with fixed pytest arguments, reads the failed (FAILED) and errored (ERROR, such as a collection error)
tests from the summary and prints each one's failure line under it, lists the skipped tests (not counted as red), and
writes the file back from the original content held in memory, not through git. Skipped test ids are read from the
`-v` outcome lines; when they do not add up to the closing count (a whole skipped module, for one), every skip line
of the summary is listed instead. No closing count line read (the target repo's `addopts = -qq` or
`-p no:terminal` changes the output's shape), or pytest reporting failures without one being read, is could not
check (exit code 2). The pytest arguments are fixed, and no pytest option or `@file` is accepted among the tests
(`-q` and the like change the output's shape): `-v` puts each test's outcome on its own line, and `-rfEs` keeps the
failures, errors and skips in the summary (an argument such as `-rs` would drop the failures and errors, making every
item look as if it turned nothing red).

The reversions are a JSON file: `[{"name": "...", "old": "...", "new": "..."}, ...]`; keep it outside the repo or
somewhere git ignores, or the working tree is not clean.

Exit code: 0 every item turned at least one test red, 1 some turned none red (the summary names them), 2 could not
check (the working tree is not clean, the list does not read, an old text does not occur exactly once, a pytest
option or `@file` is among the tests, pytest's output does not read, the tests do not all pass on the unmodified
file, pytest could not run or was interrupted, the file was not written back as it was).

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
from dataclasses import dataclass

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# 固定的 pytest 參數：逐一列出每個測試的結果（讀得到每個測試 ID 與它的結果）、不寫快取、摘要列出失敗、錯誤與略過
# （`-rfEs`：沒有逐一結果行的略過，例如整個模組被略過，只出現在摘要）
# The fixed pytest arguments: each test's outcome on its own line (so every test id and its outcome can be read), no
# cache written, failures, errors and skips listed in the summary (`-rfEs`: a skip with no outcome line of its own,
# such as a whole skipped module, appears only there)
PYTEST_ARGS = ("-v", "-p", "no:cacheprovider", "-rfEs")
# `-v` 的結果行：`<id> <結果> (<原因>)   [ 50%]` ／ A `-v` outcome line: `<id> <outcome> (<reason>)   [ 50%]`
_OUTCOME_RE = re.compile(r"^(\S.*::.*?) (PASSED|FAILED|ERROR|SKIPPED|XFAIL|XPASS)(?: \(.*\))?\s+\[\s*\d+%\]\s*$",
                         re.MULTILINE)
# 摘要段的標題；測試在自己裡面跑 pytest 時，內層的摘要也會出現在輸出裡（失敗的擷取輸出），所以只讀最後一段（#214）
# The summary section's header; a test that runs pytest inside itself prints the inner summary into the output too
# (in a failure's captured output), so only the last one is read (#214)
_SUMMARY_HEADER_RE = re.compile(r"^=+ short test summary info =+\s*$", re.MULTILINE)
# 分隔線開頭（例如 pytester 內層執行的 `==== test session starts ====`）：當成原因什麼都沒說
# Starting with a separator (such as a pytester inner run's `==== test session starts ====`): says nothing as a reason
_SEPARATOR_RE = re.compile(r"^([=_-])\1{3,}")
# 摘要裡的略過：`SKIPPED [1] <檔案>:<行>: <原因>` ／ A skip in the summary: `SKIPPED [1] <file>:<line>: <reason>`
_SUMMARY_SKIP_RE = re.compile(r"^SKIPPED \[\d+\] .*$", re.MULTILINE)
# 最後的統計行，例如 `==== 1 failed, 2 passed, 1 skipped in 0.12s ====`
# The closing count line, such as `==== 1 failed, 2 passed, 1 skipped in 0.12s ====`
_SKIP_COUNT_RE = re.compile(r"^=+ .*?\b(\d+) skipped\b.* in [\d.]+s\b.*$", re.MULTILINE)
# 有沒有統計行：讀不到就表示輸出的形狀被改了（目標 repo 的 `addopts = -qq`、`-p no:terminal`），什麼都讀不準
# Whether there is a count line: none means the output's shape was changed (the target repo's `addopts = -qq`,
# `-p no:terminal`), so nothing in it can be read reliably
_COUNT_LINE_RE = re.compile(r"^=+ .* in [\d.]+s\b.*=+$", re.MULTILINE)
# pytest 的結束碼裡表示「跑完了」的：0 全部通過、1 有失敗（2 只在摘要有 ERROR 行時算，見 main）
# The pytest exit codes that mean it ran: 0 all passed, 1 some failed (2 counts only when the summary has ERROR
# lines, see main)
_PYTEST_RAN = (0, 1)


@dataclass
class _Run:
    """一次 pytest 執行讀出來的結果。`outcomes` 是每個測試 ID 的結果（`-v` 的順序）；`red` 是摘要裡失敗與錯誤的
    （ID, 原因）；`unlisted_skips` 是 ID 對不上統計數量時，摘要裡的每一行略過（否則是空的）；`unmatched` 是 `red` 裡
    對不上任何測試的 ID（見 `_unmatched`）；`readable` 是有沒有讀到最後的統計行、沒有對不上的紅燈，pytest 以 1 結束
    （有失敗）時還要讀到失敗。
    What one pytest run reads as. `outcomes` maps each test id to its outcome (in `-v` order); `red` holds the
    (id, reason) pairs of the summary's failures and errors; `unlisted_skips` holds every skip line of the summary when
    the skipped ids do not add up to the count (empty otherwise); `unmatched` holds the ids in `red` that match no test
    (see `_unmatched`); `readable` says whether the closing count line was read with no unmatched red id, and with
    pytest exiting 1 (some failed) whether a failure was read too."""
    done: subprocess.CompletedProcess[str]
    outcomes: dict[str, str]
    red: list[tuple[str, str]]
    unlisted_skips: list[str]
    unmatched: list[str]
    readable: bool

    @property
    def skipped(self) -> list[str]:
        return [test for test, outcome in self.outcomes.items() if outcome == "SKIPPED"]


def _dirty(repo: str) -> str:
    """repo 的 `git status --porcelain` 輸出；空字串表示工作目錄是乾淨的。
    The repo's `git status --porcelain` output; an empty string means the working tree is clean."""
    return subprocess.run(["git", "status", "--porcelain"], cwd=repo, check=True, capture_output=True,
                          encoding="utf-8").stdout


def _summary(output: str) -> str:
    """外層這次執行自己的摘要段（最後一個摘要標題之後）；沒有摘要段時是空字串。
    The outer run's own summary section (after the last summary header); empty when there is none."""
    headers = list(_SUMMARY_HEADER_RE.finditer(output))
    return output[headers[-1].end():] if headers else ""


def _red(output: str, known: list[str]) -> list[tuple[str, str]]:
    """pytest 摘要裡失敗與錯誤的測試與它們的原因（`FAILED <id> - <原因>`、`ERROR <id>[ - <原因>]`）；沒有原因時是空字串。
    只讀外層這次執行自己的摘要段（`_summary`），原因經過 `_meaningful`。
    ID 取 `known` 裡最長的、剛好接在前面的那個（參數化的 ID 本身可能含有 ` - `），沒有時才切在第一個 ` - `。
    The failed and errored tests in pytest's summary with their reasons (`FAILED <id> - <reason>`,
    `ERROR <id>[ - <reason>]`); the reason is empty when there is none. The id is the longest one in `known` that the
    line starts with (a parametrized id may itself contain ` - `), and only without one is the line cut at the first
    ` - `. Only the outer run's own summary section is read (`_summary`), and reasons go through `_meaningful`."""
    red = []
    for line in _summary(output).splitlines():
        for prefix in ("FAILED ", "ERROR "):
            if line.startswith(prefix):
                rest = line[len(prefix):]
                ids = [test for test in known if rest == test or rest.startswith(test + " - ")]
                if ids:
                    test = max(ids, key=len)
                    reason = rest[len(test) + 3:]
                else:
                    test, _, reason = rest.partition(" - ")
                red.append((test.strip(), _meaningful(reason.strip())))
    return red


def _meaningful(reason: str) -> str:
    """原因的內容以分隔線開頭時只留例外名稱：`AssertionError: =====…` 印成 `AssertionError`（#214）。
    A reason whose text starts with a separator keeps the exception name alone: `AssertionError: =====...` prints as
    `AssertionError` (#214)."""
    name, colon, text = reason.partition(": ")
    return name if colon and _SEPARATOR_RE.match(text.strip()) else reason


def _unmatched(red: list[tuple[str, str]], outcomes: dict[str, str], tests: list[str], repo: str) -> list[str]:
    """紅燈 ID 只接受兩種：讀到結果行的測試，或落在傳入的測試路徑底下（沒有傳入時是整個 repo）、沒有 `::` 的收集錯誤；
    其餘的回傳，讓這次執行算成讀不懂（CODING_STANDARDS 第 8 條；#214）。
    A red id is accepted in two forms only: a test whose outcome line was read, or a collection error (no `::`) under
    one of the given test paths (the whole repo when none are given); the rest are returned, so the run counts as
    unreadable (CODING_STANDARDS rule 8; #214)."""
    roots = [_node_id(test, repo).partition("::")[0] for test in tests]
    whole_repo = not roots or "." in roots
    bad = []
    for test, _reason in red:
        if test in outcomes:
            continue
        if "::" not in test and (whole_repo or any(test == root or test.startswith(root.rstrip("/") + "/")
                                                   for root in roots)):
            continue
        bad.append(test)
    return bad


def _read(done: subprocess.CompletedProcess[str], tests: list[str], repo: str) -> _Run:
    """把一次 pytest 執行的輸出讀成 _Run ／ Reads one pytest run's output as a _Run."""
    outcomes = {test: outcome for test, outcome in _OUTCOME_RE.findall(done.stdout)}
    counts = _SKIP_COUNT_RE.findall(done.stdout)
    skip_count = int(counts[-1]) if counts else 0
    listed = sum(1 for outcome in outcomes.values() if outcome == "SKIPPED")
    unlisted = _SUMMARY_SKIP_RE.findall(_summary(done.stdout)) if skip_count != listed else []
    red = _red(done.stdout, list(outcomes))
    unmatched = _unmatched(red, outcomes, tests, repo)
    readable = bool(_COUNT_LINE_RE.search(done.stdout)) and not unmatched and (done.returncode != 1 or bool(red))
    return _Run(done, outcomes, red, unlisted, unmatched, readable)


def _why_unreadable(run: _Run) -> str:
    """讀不懂時補上的原因：對不上任何測試的紅燈 ID ／ What to add when unreadable: the red ids that match no test."""
    return f"; red ids matching no test it ran: {', '.join(run.unmatched)}" if run.unmatched else ""


def _node_id(test: str, repo: str) -> str:
    """把指定的 node id 的路徑部分改寫成 pytest 回報的樣子（相對於 repo、`/` 分隔）。
    Rewrites the path part of a given node id the way pytest reports it (relative to the repo, `/`-separated)."""
    path, sep, rest = test.partition("::")
    full = path if os.path.isabs(path) else os.path.join(repo, path)
    return os.path.relpath(full, repo).replace(os.sep, "/") + sep + rest


def _not_seen_passing(named: list[str], run: _Run, repo: str) -> list[str]:
    """用 node id 指定、卻沒讀到它（或它底下的每個測試：class、沒寫參數的參數化函式）以 PASSED 結束的那些。
    The tests named by node id that were not read as ending PASSED (each test under them included: a class, a
    parametrized function named without its parameters)."""
    bad = []
    for test in named:
        node = _node_id(test, repo)
        seen = [outcome for test_id, outcome in run.outcomes.items()
                if test_id == node or test_id.startswith((node + "::", node + "["))]
        if not seen or any(outcome != "PASSED" for outcome in seen):
            bad.append(f"{test} ({', '.join(sorted(set(seen))) or 'no outcome read'})")
    return bad


def _pytest(repo: str, tests: list[str]) -> subprocess.CompletedProcess[str]:
    """用固定參數在 repo 跑 pytest，擷取 stdout 與 stderr。不寫 bytecode：`__pycache__` 不能讓工作目錄變髒
    （repo 不一定忽略它）；`COLUMNS` 設得夠寬，摘要裡的失敗原因才不會依終端機寬度被截斷。
    Runs pytest in the repo with the fixed arguments, capturing stdout and stderr. No bytecode: `__pycache__` must not
    dirty the working tree (a repo need not ignore it); `COLUMNS` is wide enough that the summary's failure reasons
    are not cut to the terminal width."""
    return subprocess.run([sys.executable, "-m", "pytest", *PYTEST_ARGS, *tests], cwd=repo,
                          env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1", "COLUMNS": "1000"}, capture_output=True,
                          encoding="utf-8", errors="replace")


def _excerpt(done: subprocess.CompletedProcess[str]) -> str:
    """pytest 的 stderr（例如「ERROR: not found: <id>」）加上 stdout 的最後 5 行；`=====` 之類的分隔線縮短，
    `COLUMNS` 很寬時才不會拉成上千個字元。
    pytest's stderr (such as "ERROR: not found: <id>") plus the last 5 lines of its stdout; separator lines such as
    `=====` are shortened, so a wide `COLUMNS` does not stretch them to a thousand characters."""
    lines = [re.sub(r"^([=_!-])\1{3,} ?(.*?) ?\1*$", lambda m: f"== {m.group(2)} ==" if m.group(2) else "==", line)
             for line in done.stdout.strip().splitlines()[-5:]]
    return "\n".join(part for part in (done.stderr.strip(), "\n".join(lines)) if part)


def _print_run(run: _Run) -> None:
    """列出一次執行的紅燈（各附原因）、被略過的測試，以及對不上 ID 的略過摘要。
    Lists one run's red tests (each with its reason), its skipped tests, and the skip summary lines no id accounts
    for."""
    for test, reason in run.red:
        print(f"   {test}")
        if reason:
            print(f"      {reason}")
    for test in run.skipped:
        print(f"   skipped: {test}")
    for line in run.unlisted_skips:
        print(f"   skipped (no test id): {line}")


def main(argv: list[str] | None = None, repo: str = _REPO) -> int:
    """依參數逐項改回、跑測試並列出紅燈；回傳結束碼。
    Reverts each item, runs the tests and lists what turned red, per the arguments; returns the exit code."""
    parser = argparse.ArgumentParser(description="Revert a fix one item at a time and list the tests each turns red.")
    parser.add_argument("file", help="the file to revert, relative to the repo")
    parser.add_argument("reversions", help='a JSON list of {"name", "old", "new"}')
    parser.add_argument("tests", nargs="*", help="pytest test paths or node ids (default: the whole suite); no options")
    args = parser.parse_args(argv)

    # 只接受測試路徑與 node id：pytest 的選項（例如 `-q`）會改掉輸出的形狀，讓結果讀不出來；`@檔案` 從檔案讀參數，
    # 裡面的選項與 node id 都躲過這裡的檢查
    # Only test paths and node ids: a pytest option (such as `-q`) changes the output's shape, so outcomes cannot be
    # read; `@file` reads arguments from a file, hiding its options and node ids from these checks
    options = [test for test in args.tests if test.startswith(("-", "@"))]
    if options:
        print("Only test paths and node ids are accepted after the reversions, not pytest options or @argument files: "
              f"{' '.join(options)}")
        return 2
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
    baseline = _read(_pytest(repo, args.tests), args.tests, repo)
    if not baseline.readable:
        print(f"Could not read pytest's output on the unmodified {args.file} (pytest exited "
              f"{baseline.done.returncode}; an `addopts` or plugin may change its shape){_why_unreadable(baseline)}, "
              "so nothing was reverted:\n"
              f"{_excerpt(baseline.done)}")
        return 2
    if baseline.done.returncode != 0:
        print(f"The tests do not all pass on the unmodified {args.file} (pytest exited {baseline.done.returncode}), "
              "so nothing was reverted:")
        _print_run(baseline)
        print(_excerpt(baseline.done))
        return 2
    # 用 node id 指定的測試是要檢查的對象本身：一定要讀到它以 PASSED 結束，讀不到（被略過、整個模組被略過、
    # 認不出的寫法）就無法檢查。經由檔案、目錄或整個套件跑到而被略過的只警告：整個套件在某些環境一定有被略過的
    # 測試（Docker、Node）
    # A test named by its node id is the very thing to check: it must be read as ending PASSED, and anything else (a
    # skip, a whole skipped module, a form not read) cannot be checked. A skip reached through a file, a directory
    # or the whole suite only warns: the whole suite always skips some tests in some environments (Docker, Node)
    bad = _not_seen_passing([test for test in args.tests if "::" in test], baseline, repo)
    if bad:
        print(f"Tests named by id were not read as passing on the unmodified {args.file}, so no item can be checked "
              f"against them: {'; '.join(bad)}")
        return 2
    if baseline.skipped or baseline.unlisted_skips:
        print(f"Skipped on the unmodified {args.file}, so no item can turn them red:")
        _print_run(baseline)

    silent, failed_run = [], None
    try:
        for name, old, new in items:
            with open(path, "wb") as f:
                f.write(text.replace(old, new).encode("utf-8"))
            run = _read(_pytest(repo, args.tests), args.tests, repo)
            # 收集錯誤時 pytest 也以 2 結束（和被中斷一樣），但摘要有 ERROR 行：那算紅燈
            # On a collection error pytest exits 2 too (as when interrupted), but the summary has ERROR lines: red
            if not run.readable:
                failed_run = f"`{name}`: could not read pytest's output (pytest exited {run.done.returncode})" \
                             f"{_why_unreadable(run)}:\n" \
                             f"{_excerpt(run.done)}"
                break
            if run.done.returncode not in _PYTEST_RAN and not (run.done.returncode == 2 and run.red):
                failed_run = f"`{name}`: pytest exited {run.done.returncode}, so nothing was checked:\n" \
                             f"{_excerpt(run.done)}"
                break
            n_skipped = len(run.skipped) + len(run.unlisted_skips)
            print(f"## {name}: {len(run.red)} red" + (f", {n_skipped} skipped" if n_skipped else ""))
            _print_run(run)
            if not run.red:
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
