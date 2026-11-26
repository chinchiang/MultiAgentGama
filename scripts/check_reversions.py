"""把一個檔案裡的修正一次改回一項，跑測試，列出每一項讓哪些測試變紅（測試的敏感度檢查）。

每一項是「名稱、原文、改壞後」，原文在檔案裡要剛好出現一次。script 先確認工作目錄是乾淨的（改壞之前先 commit，
#158 的教訓），再在原始檔案上跑一次測試：有找不到或沒通過的測試，或用 node id 指定的測試（class 與沒寫參數的
參數化函式含底下每一個測試）沒有讀到以 PASSED 結束，就什麼都不改、結束碼 2，並點名每一個（附上 pytest 的
stderr）；經由檔案、目錄或整個套件跑到而被略過的，列成警告（#209）。之後逐項：把原文換成改壞後的文字、用固定的
pytest 參數跑測試、從摘要讀出失敗（FAILED）與錯誤（ERROR，例如收集不到）的測試並在每個底下印出失敗的那一行、
列出被略過（skipped，不算紅燈）的測試，最後用記憶體裡的原內容把檔案寫回去，不靠 git。被略過的測試從 `-v` 的
結果行讀 ID；數量對不上最後的統計時（例如整個模組被略過），改列摘要裡的每一行略過。讀不到最後的統計行（目標
repo 的 `addopts = -qq`、`-p no:terminal` 會改掉輸出的形狀），pytest 回報有失敗卻讀不到任何一個，或讀到
紅燈，pytest 卻沒有回報失敗（不是以 1 結束，也不是以 2 結束且有 `ERROR` 行），都是無法檢查（結束碼 2）。
結果行、摘要與統計行都只讀外層這次執行自己的：結果行在開頭標題與下一個區段標題之間，摘要在最後
一個摘要標題之後，統計行是輸出的最後一個非空白行；測試在自己裡面跑 pytest 時印進輸出的那些不算。pytest 以
`--force-short-summary` 跑，摘要一個測試一行（不然在 CI 上或 verbose 到 2 時，pytest 把整段多行訊息印進摘要）。
紅燈要和其他部分一致，否則同樣是無法檢查：紅燈 ID 要是結果為 FAILED 或 ERROR 的測試，或 `ERROR` 行上解析後存在、
落在傳入測試路徑（或 repo）底下的收集錯誤；結果為 FAILED 或 ERROR 的測試都要剛好讀到一次；紅燈數量要等於統計行的
`failed` 加 `error`（#214）。pytest 的參數是固定的，測試參數裡不接受 pytest 選項與 `@檔案`（`-q` 之類會改掉
輸出的形狀）：`-v` 逐一列出每個測試的結果，`-rfEs` 保證摘要列出失敗、錯誤與略過（改用 `-rs` 之類的參數會把失敗與
錯誤拿掉，讓每一項看起來都沒有紅燈）。

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
`-p no:terminal` changes the output's shape), pytest reporting failures without one being read, or red tests read while
pytest reported none (it exited neither 1 nor 2 with an `ERROR` line), is could not check (exit code 2). Outcome lines,
the summary and the count line are read from the outer run's own output only: outcome lines between the opening header
and the next section header, the summary after the last summary header, and the count line as the output's last
non-blank line; those a test prints from a pytest run inside it do not count. pytest runs with `--force-short-summary`,
so the summary has one line per test (otherwise, on CI or at verbosity 2, pytest prints a whole multi-line message into
the summary). Red tests must agree with the rest, or it is could not check too: a red id must be a test whose outcome is
FAILED or ERROR, or a collection error (an `ERROR` line) at a path that, once resolved, exists under the given test
paths (or the repo); each test whose outcome is FAILED or ERROR must be read exactly once; and the number of red tests
must equal the count line's `failed` plus `error` (#214). The pytest arguments are fixed, and no pytest option or
`@file` is accepted among the tests (`-q` and the like change the output's shape): `-v` puts each test's outcome on its
own line, and `-rfEs` keeps the failures, errors and skips in the summary (an argument such as `-rs` would drop the
failures and errors, making every item look as if it turned nothing red).

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
import unicodedata
from dataclasses import dataclass

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# 固定的 pytest 參數：逐一列出每個測試的結果（讀得到每個測試 ID 與它的結果）、不寫快取、摘要列出失敗、錯誤與略過
# （`-rfEs`：沒有逐一結果行的略過，例如整個模組被略過，只出現在摘要）、摘要一個測試一行（`--force-short-summary`：
# 在 CI 上或 verbose 到 2 時，例如目標 repo 的 `addopts = -v`，pytest 會把整段多行訊息印進摘要，訊息裡的摘要標題與
# `FAILED` 行就成了摘要的一部分；#214 審查第 3、4 輪）
# The fixed pytest arguments: each test's outcome on its own line (so every test id and its outcome can be read), no
# cache written, failures, errors and skips listed in the summary (`-rfEs`: a skip with no outcome line of its own,
# such as a whole skipped module, appears only there), one summary line per test (`--force-short-summary`: on CI or
# at verbosity 2, such as under a target repo's `addopts = -v`, pytest prints a whole multi-line message into the
# summary, making a summary header or `FAILED` line inside the message part of the summary; #214 review rounds 3 and
# 4)
PYTEST_ARGS = ("-v", "-p", "no:cacheprovider", "-rfEs", "--force-short-summary")
# `-v` 的結果行：`<id> <結果> (<原因>)   [ 50%]` ／ A `-v` outcome line: `<id> <outcome> (<reason>)   [ 50%]`
_OUTCOME_RE = re.compile(r"^(\S.*::.*?) (PASSED|FAILED|ERROR|SKIPPED|XFAIL|XPASS)(?: \(.*\))?\s+\[\s*\d+%\]\s*$",
                         re.MULTILINE)
# 外層的開頭標題，和它之後的下一個區段標題（`==== FAILURES ====` 之類）：結果行只在兩者之間讀，內層用 `-v` 跑時印進
# 失敗擷取輸出的結果行不算（#214 審查第 1 輪）
# The outer run's opening header, and the next section header after it (`==== FAILURES ====` and the like): outcome
# lines are read between the two only, so an inner `-v` run's outcome lines in a failure's captured output do not
# count (#214 review round 1)
_SESSION_HEADER_RE = re.compile(r"^=+ test session starts =+\s*$", re.MULTILINE)
_SECTION_HEADER_RE = re.compile(r"^=+ .* =+\s*$", re.MULTILINE)
# 摘要段的標題；測試在自己裡面跑 pytest 時，內層的摘要也會出現在輸出裡（失敗的擷取輸出），所以只讀最後一段（#214）
# The summary section's header; a test that runs pytest inside itself prints the inner summary into the output too
# (in a failure's captured output), so only the last one is read (#214)
_SUMMARY_HEADER_RE = re.compile(r"^=+ short test summary info =+\s*$", re.MULTILINE)
# 整行分隔線，中間可以有標題（例如 pytester 內層執行的 `==== test session starts ====`）：當成原因什麼都沒說；
# `----- diff` 之類後面還有文字的不算。分隔字元和 `_excerpt` 縮短的一樣（`!` 是 `!!!! Interrupted !!!!`）
# A whole separator line, a title in the middle allowed (such as a pytester inner run's
# `==== test session starts ====`): says nothing as a reason; one with more text after it, such as `----- diff`, is
# not. The separator characters are the ones `_excerpt` shortens (`!` for `!!!! Interrupted !!!!`)
_SEPARATOR_RUN = r"([=_!-])\1{3,}"
_SEPARATOR_RE = re.compile(_SEPARATOR_RUN + r"(?: .* \1{4,})?")
# pytest 把摘要行截到終端機寬度、結尾加 `...`（`--force-short-summary`）：被截斷的看不到結尾，以分隔線開頭就算
# （#214 審查第 2 輪）
# pytest cuts a summary line to the terminal width and ends it with `...` (`--force-short-summary`): a cut one has no
# visible end, so
# starting with a separator is enough (#214 review round 2)
_CUT_SEPARATOR_RE = re.compile(_SEPARATOR_RUN + r"(?: .*)?")
# 摘要裡的略過：`SKIPPED [1] <檔案>:<行>: <原因>` ／ A skip in the summary: `SKIPPED [1] <file>:<line>: <reason>`
_SUMMARY_SKIP_RE = re.compile(r"^SKIPPED \[\d+\] .*$", re.MULTILINE)
# 最後的統計行（輸出的最後一個非空白行），例如 `==== 1 failed, 2 passed, 1 skipped in 0.12s ====`；不是統計行就表示
# 輸出的形狀被改了（目標 repo 的 `addopts = -qq`、`-p no:terminal`），什麼都讀不準。內層執行印出的統計行不在最後，
# 不算（#214 審查第 1 輪）
# The closing count line (the output's last non-blank line), such as
# `==== 1 failed, 2 passed, 1 skipped in 0.12s ====`; anything else there means the output's shape was changed (the
# target repo's `addopts = -qq`, `-p no:terminal`), so nothing in it can be read reliably. An inner run's count line
# is not last, so it does not count (#214 review round 1)
_COUNT_LINE_RE = re.compile(r"=+ .* in [\d.]+s\b.*=+")
_SKIP_COUNT_RE = re.compile(r"\b(\d+) skipped\b")
# 統計行裡失敗與錯誤的數量：要和摘要讀到的紅燈數量一樣，否則是讀錯（#214 審查第 2 輪）
# The count line's failures and errors: they must equal the number of red tests read from the summary, or it is a
# misread (#214 review round 2)
_RED_COUNT_RE = re.compile(r"\b(\d+) (?:failed|errors?)\b")
# pytest 的結束碼裡表示「跑完了」的：0 全部通過、1 有失敗（2 只在摘要有 ERROR 行時算，見 main）
# The pytest exit codes that mean it ran: 0 all passed, 1 some failed (2 counts only when the summary has ERROR
# lines, see main)
_PYTEST_RAN = (0, 1)
# 給 pytest 的終端機寬度：夠寬，摘要裡的失敗原因才幾乎不會被截斷；被截斷的行剛好是這個寬度（見 `_red`）
# The terminal width given to pytest: wide enough that a failure reason in the summary is almost never cut; a cut line
# is exactly this wide (see `_red`)
_COLUMNS = 1000


@dataclass
class _Run:
    """一次 pytest 執行讀出來的結果。`outcomes` 是每個測試 ID 的結果（`-v` 的順序）；`red` 是摘要裡失敗與錯誤的
    （種類, ID, 原因），種類是 `FAILED` 或 `ERROR`；`unlisted_skips` 是 ID 對不上統計數量時，摘要裡的每一行略過
    （否則是空的）；`problems` 是讓這次執行讀不懂的每一個原因（見 `_problems`），沒有時才讀得懂（`readable`）。
    What one pytest run reads as. `outcomes` maps each test id to its outcome (in `-v` order); `red` holds the
    (kind, id, reason) triples of the summary's failures and errors, the kind being `FAILED` or `ERROR`;
    `unlisted_skips` holds every skip line of the summary when the skipped ids do not add up to the count (empty
    otherwise); `problems` holds each reason the run does not read (see `_problems`), and it is `readable` only with
    none."""
    done: subprocess.CompletedProcess[str]
    outcomes: dict[str, str]
    red: list[tuple[str, str, str]]
    unlisted_skips: list[str]
    problems: list[str]

    @property
    def readable(self) -> bool:
        return not self.problems

    @property
    def skipped(self) -> list[str]:
        return [test for test, outcome in self.outcomes.items() if outcome == "SKIPPED"]


def _dirty(repo: str) -> str:
    """repo 的 `git status --porcelain` 輸出；空字串表示工作目錄是乾淨的。
    The repo's `git status --porcelain` output; an empty string means the working tree is clean."""
    return subprocess.run(["git", "status", "--porcelain"], cwd=repo, check=True, capture_output=True,
                          encoding="utf-8").stdout


def _results(output: str) -> str:
    """外層這次執行自己的結果區塊（第一個開頭標題之後、下一個區段標題之前）；沒有開頭標題時是空字串。
    The outer run's own results block (after the first opening header, before the next section header); empty when
    there is no opening header."""
    header = _SESSION_HEADER_RE.search(output)
    if not header:
        return ""
    end = _SECTION_HEADER_RE.search(output, header.end())
    return output[header.end():end.start() if end else len(output)]


def _count_line(output: str) -> str:
    """輸出的最後一個非空白行，是統計行時；否則是空字串。
    The output's last non-blank line when it is the count line; empty otherwise."""
    lines = output.rstrip().split("\n")
    return lines[-1].strip() if _COUNT_LINE_RE.fullmatch(lines[-1].strip()) else ""


def _summary(output: str) -> str:
    """外層這次執行自己的摘要段（最後一個摘要標題之後）；沒有摘要段時是空字串。
    The outer run's own summary section (after the last summary header); empty when there is none."""
    headers = list(_SUMMARY_HEADER_RE.finditer(output))
    return output[headers[-1].end():] if headers else ""


def _red(summary: str, known: list[str]) -> list[tuple[str, str, str]]:
    """外層這次執行自己的摘要段（`_summary`）裡失敗與錯誤的種類、測試與原因（`FAILED <id> - <原因>`、
    `ERROR <id>[ - <原因>]`）；沒有原因時是空字串，原因經過 `_meaningful`。只在 `\n` 切行：pytest 只在那裡換行，
    失敗訊息裡的 form feed、U+2028 之類不是另一行（`str.splitlines` 會在那裡切）。
    ID 取 `known` 裡最長的、剛好接在前面的那個（參數化的 ID 本身可能含有 ` - `），沒有時才切在第一個 ` - `。
    The kind, test and reason of each failure and error in the outer run's own summary section (`_summary`)
    (`FAILED <id> - <reason>`, `ERROR <id>[ - <reason>]`); the reason is empty when there is none, and goes through
    `_meaningful`. Lines are cut at `\n` only: pytest breaks lines there only, so a form feed, U+2028 and the like in
    a failure message do not start another line (`str.splitlines` would cut there). The id is the longest one in
    `known` that the line starts with (a parametrized id may itself contain ` - `), and only without one is the line
    cut at the first ` - `."""
    red = []
    for line in summary.split("\n"):
        for prefix in ("FAILED ", "ERROR "):
            if line.startswith(prefix):
                rest = line[len(prefix):]
                ids = [test for test in known if rest == test or rest.startswith(test + " - ")]
                if ids:
                    test = max(ids, key=len)
                    reason = rest[len(test) + 3:]
                else:
                    test, _, reason = rest.partition(" - ")
                # pytest 截斷的行以 `...` 結尾、剛好是終端機寬度；原因本來就以 `...` 結尾的行比較短
                # A line pytest cut ends with `...` at exactly the terminal width; a reason ending with `...` of its
                # own is shorter
                cut = line.endswith("...") and _width(line) >= _COLUMNS - 1
                red.append((prefix.strip(), test.strip(), _meaningful(reason.strip(), cut)))
    return red


def _width(line: str) -> int:
    """終端機上的寬度：全形（East Asian Wide／Fullwidth）字元算 2 欄，和 pytest 截斷時算的一樣。
    The width on a terminal: a wide (East Asian Wide / Fullwidth) character takes 2 columns, as pytest counts when it
    cuts a line."""
    return sum(2 if unicodedata.east_asian_width(char) in "WF" else 1 for char in line)


def _meaningful(reason: str, cut: bool) -> str:
    """原因的內容是整行分隔線，或什麼都沒有時，只留例外名稱：`AssertionError: ==== test session starts ====`、
    `AssertionError:` 都印成 `AssertionError`；`AssertionError: ----- diff` 原樣印出。被 pytest 截斷的行（cut）看不到
    結尾，以分隔線開頭就算（#214）。
    A reason whose text is a whole separator line, or nothing, keeps the exception name alone:
    `AssertionError: ==== test session starts ====` and `AssertionError:` both print as `AssertionError`, while
    `AssertionError: ----- diff` prints as it is. A line pytest cut (`cut`) has no visible end, so starting with a
    separator is enough (#214)."""
    if reason.endswith(":") and " " not in reason:
        return reason[:-1]
    name, colon, text = reason.partition(": ")
    text = text.strip()
    separator = _CUT_SEPARATOR_RE.fullmatch(text[:-3]) if cut else _SEPARATOR_RE.fullmatch(text)
    return name if colon and separator else reason


def _unmatched(red: list[tuple[str, str, str]], outcomes: dict[str, str], tests: list[str], repo: str) -> list[str]:
    """紅燈 ID 只接受兩種：結果行是 FAILED 或 ERROR 的測試，或 `ERROR` 行上沒有 `::`、是 repo 裡存在的路徑、落在傳入的
    測試路徑底下（沒有傳入時是整個 repo）的收集錯誤；其餘的回傳（讀到結果行的附上它的結果），讓這次執行算成讀不懂
    （CODING_STANDARDS 第 8 條；#214）。
    A red id is accepted in two forms only: a test whose outcome line is FAILED or ERROR, or a collection error (an
    `ERROR` line without `::`) at a path that exists in the repo, under one of the given test paths (the whole repo
    when none are given); the rest are returned (with the outcome read, if any), so the run counts as unreadable
    (CODING_STANDARDS rule 8; #214)."""
    roots = [os.path.realpath(os.path.join(repo, _node_id(test, repo).partition("::")[0])) for test in tests] or \
        [os.path.realpath(repo)]
    bad = []
    for kind, test, _reason in red:
        if test in outcomes:
            if outcomes[test] not in ("FAILED", "ERROR"):
                bad.append(f"{test} ({outcomes[test]})")
            continue
        # 解析過 `..` 與符號連結之後，要落在某個傳入的測試路徑（沒有傳入時是 repo）底下
        # Once `..` and symlinks are resolved, it must lie under one of the given test paths (the repo when none)
        path = os.path.realpath(os.path.join(repo, test))
        if kind == "ERROR" and "::" not in test and os.path.exists(path) and any(_under(path, root) for root in roots):
            continue
        bad.append(test)
    return bad


def _under(path: str, root: str) -> bool:
    """解析過的 path 是不是 root 本身或在它底下；Windows 上不同磁碟機（`commonpath` 丟 ValueError）算不在底下。
    Whether the resolved `path` is `root` or under it; a different drive on Windows (`commonpath` raises ValueError)
    is not under it."""
    try:
        return os.path.commonpath([path, root]) == root
    except ValueError:
        return False


def _read(done: subprocess.CompletedProcess[str], tests: list[str], repo: str) -> _Run:
    """把一次 pytest 執行的輸出讀成 _Run ／ Reads one pytest run's output as a _Run."""
    outcomes = {test: outcome for test, outcome in _OUTCOME_RE.findall(_results(done.stdout))}
    count_line = _count_line(done.stdout)
    counts = _SKIP_COUNT_RE.findall(count_line)
    skip_count = int(counts[0]) if counts else 0
    listed = sum(1 for outcome in outcomes.values() if outcome == "SKIPPED")
    summary = _summary(done.stdout)
    unlisted = _SUMMARY_SKIP_RE.findall(summary) if skip_count != listed else []
    red = _red(summary, list(outcomes))
    return _Run(done, outcomes, red, unlisted, _problems(done, count_line, outcomes, red, tests, repo))


def _problems(done: subprocess.CompletedProcess[str], count_line: str, outcomes: dict[str, str],
              red: list[tuple[str, str, str]], tests: list[str], repo: str) -> list[str]:
    """讓一次執行讀不懂的每一個原因，各是一句可以直接印出的話；規則與訊息只寫在這裡（CODING_STANDARDS 第 8 條；#214）：
    讀不到統計行；紅燈 ID 對不上失敗的測試（`_unmatched`）；紅燈讀到不止一次，或結果是 FAILED 或 ERROR 的測試沒讀到；
    紅燈數量和統計行的 `failed` 加 `error` 不同；pytest 以 1 結束（有失敗）卻沒讀到紅燈；讀到紅燈，pytest 卻不是以 1
    結束，也不是以 2 結束且有 `ERROR` 行（pytest 結束後才印的文字，例如 `atexit`，會成為最後的摘要與最後一行）。
    Each reason a run does not read, each a sentence ready to print; the rules and their messages live here only
    (CODING_STANDARDS rule 8; #214): no count line; a red id matching no failing test (`_unmatched`); a red test read
    more than once, or a test whose outcome is FAILED or ERROR not read; a number of red tests other than the count
    line's `failed` plus `error`; pytest exiting 1 (some failed) with no red test read; red tests read while pytest
    exited neither 1 nor 2 with an `ERROR` line (text printed after pytest finished, such as from `atexit`, becomes the
    last summary and the last line)."""
    problems = []
    if not count_line:
        problems.append("no closing count line as the output's last line (an `addopts` or plugin may change its "
                        "shape)")
    unmatched = _unmatched(red, outcomes, tests, repo)
    if unmatched:
        problems.append(f"red ids not read as failing a test it ran: {', '.join(unmatched)}")
    # 每個紅燈剛好讀到一次：結果行是 FAILED 或 ERROR 的測試都要有紅燈行，同一種類的同一個 ID 不能讀到兩次
    # Every red test read exactly once: each test whose outcome is FAILED or ERROR needs a red line, and the same kind
    # and id may not be read twice
    pairs = [(kind, test) for kind, test, _reason in red]
    twice = sorted({test for kind, test in pairs if pairs.count((kind, test)) > 1})
    if twice:
        problems.append(f"red tests read more than once: {', '.join(twice)}")
    named = {test for _kind, test in pairs}
    not_read = [test for test, outcome in outcomes.items() if outcome in ("FAILED", "ERROR") and test not in named]
    if not_read:
        problems.append(f"failing tests not read as red: {', '.join(not_read)}")
    counted_red = sum(int(n) for n in _RED_COUNT_RE.findall(count_line))
    if count_line and counted_red != len(red):
        problems.append(f"the count line has {counted_red} failed or errored, but {len(red)} red were read")
    if done.returncode == 1 and not red:
        problems.append("pytest exited 1 but no red test was read")
    if red and not (done.returncode == 1 or (done.returncode == 2 and any(kind == "ERROR" for kind, _test in pairs))):
        problems.append(f"pytest exited {done.returncode} but {len(red)} red were read")
    return problems


def _why_unreadable(run: _Run) -> str:
    """讀不懂時補上的原因（`problems`）／ What to add when unreadable (the `problems`)."""
    return "".join(f"; {problem}" for problem in run.problems)


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
                          env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1", "COLUMNS": str(_COLUMNS)},
                          capture_output=True, encoding="utf-8", errors="replace")


def _excerpt(done: subprocess.CompletedProcess[str]) -> str:
    """pytest 的 stderr（例如「ERROR: not found: <id>」）加上 stdout 的最後 5 行；`=====` 之類的分隔線縮短，
    `COLUMNS` 很寬時才不會拉成上千個字元。
    pytest's stderr (such as "ERROR: not found: <id>") plus the last 5 lines of its stdout; separator lines such as
    `=====` are shortened, so a wide `COLUMNS` does not stretch them to a thousand characters."""
    lines = [re.sub("^" + _SEPARATOR_RUN + r" ?(.*?) ?\1*$",
                    lambda m: f"== {m.group(2)} ==" if m.group(2) else "==", line)
             for line in done.stdout.strip().splitlines()[-5:]]
    return "\n".join(part for part in (done.stderr.strip(), "\n".join(lines)) if part)


def _print_run(run: _Run) -> None:
    """列出一次執行的紅燈（各附原因）、被略過的測試，以及對不上 ID 的略過摘要。
    Lists one run's red tests (each with its reason), its skipped tests, and the skip summary lines no id accounts
    for."""
    for _kind, test, reason in run.red:
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
              f"{baseline.done.returncode}){_why_unreadable(baseline)}, so nothing was reverted:\n"
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
