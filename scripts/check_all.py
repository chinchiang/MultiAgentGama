"""依序跑開 PR 前的完整檢查，把每一步的結束碼與關鍵行寫進摘要 log（完整檢查的單一來源）。

步驟與參數在 `STEPS`：pytest 與覆蓋率、ruff、mypy、pip-audit、`scripts/test_sdist.py`、`scripts/check_bi_english.py`、
`scripts/recite_design_refs.py --check`、`scripts/golden/run.py --against <rev>` 與
`scripts/check_new_tests_red_on_base.py --against <rev>`，全部用執行這個 script 的 Python 跑。mypy 與 pytest 覆蓋率
的參數要和 `.github/workflows/tests.yml` 相同（`tests/test_repo_docs.py` 會檢查）。

摘要 log（預設 `scratch/checks-<HEAD 短 SHA>.log`）在每一步跑完就寫入：結束碼，加上該步的關鍵行（pytest 的
`TOTAL` 覆蓋率與通過數、golden 的差異數與每一種差異、red-on-base 的 `red=N green=M skipped=K hang=H` 與每一行結果，
不截斷）；某一步失敗卻沒有任何關鍵行時，留它的最後 20 行。每一步的完整輸出寫在同名的 `.full.log`。

golden、test_sdist 與 red-on-base 都讀工作目錄，跑的時候不要改檔案。每一個有跑的步驟跑完，都比對 HEAD、
`git diff HEAD` 與未追蹤檔案的清單和內容（git 忽略的不算，例如 `scratch/` 裡的 log；script 自己寫的 log 放在哪裡
都不算）；和開始時不同就停在那一步，摘要與 `.full.log` 的最後一行寫出是哪一步跑的時候變的（#216）。比對用的
ref 指到的 commit 也一樣比對：golden 與 red-on-base 比對 `--against` 的 ref，bi_english 一律比對 `origin/master`；
它們移動了（例如另一個終端機 `git fetch` 或 `git fetch . origin/master:master`；被建立或刪除也算），比對的
merge-base 就跟著變，最後一行寫「`<ref>` moved during <步驟>」。同一步裡工作目錄也變了時，只寫工作目錄。

結束碼：0 每一個有跑的步驟都是 0；1 有步驟不是 0 或逾時（red-on-base 有綠燈或略過的測試時也是 1，要讀 log 判斷
那些是不是預期中的守護）；2 跑的期間工作目錄、HEAD、`--against` 的 ref 或 `origin/master` 變了，無法檢查。

用法：
    python scripts/check_all.py [--against master] [--skip STEP ...] [--timeout 1800] [--log PATH]

Runs the full check before a PR in order and writes each step's exit code and key lines to a summary log (the single
source of the full check).

The steps and their arguments are in `STEPS`: pytest with coverage, ruff, mypy, pip-audit, `scripts/test_sdist.py`,
`scripts/check_bi_english.py`, `scripts/recite_design_refs.py --check`, `scripts/golden/run.py --against <rev>` and
`scripts/check_new_tests_red_on_base.py --against <rev>`, all run with the Python running this script. The mypy and
pytest coverage arguments must equal those in `.github/workflows/tests.yml` (`tests/test_repo_docs.py` checks).

The summary log (default `scratch/checks-<short HEAD SHA>.log`) is written as each step finishes: the exit code plus
the step's key lines (pytest's `TOTAL` coverage and counts, golden's difference count and each difference,
red-on-base's `red=N green=M skipped=K hang=H` and every result line, never cut); a failed step with no key line keeps its
last 20 lines. Each step's full output goes to the `.full.log` of the same name.

golden, test_sdist and red-on-base read the working tree: change no file while they run. After each step that
runs, the script compares HEAD, `git diff HEAD` and the list and content of untracked files (not those git ignores,
such as the logs in `scratch/`, nor the logs the script writes, wherever they are) with the start; when they differ it stops after that step, and the last line
of the summary and of the `.full.log` names the step during which the tree changed (#216). The commits the refs
compared against point at are compared too: golden and red-on-base compare against the `--against` ref, bi_english
always against `origin/master`. When one moves (another terminal running `git fetch` or
`git fetch . origin/master:master`, say; being created or deleted counts), the merge-base compared against moves with
it, and the last line reads "`<ref>` moved during <step>". When the working tree changed in the same step, only that
is named.

Exit code: 0 every step that ran exited 0; 1 some step did not or timed out (red-on-base also exits 1 when a test is
green or skipped, so read the log to judge whether those are expected guards); 2 the working tree, HEAD, the
`--against` ref or `origin/master` changed during the run, so it could not check.

Usage:
    python scripts/check_all.py [--against master] [--skip STEP ...] [--timeout 1800] [--log PATH]
"""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import signal
import subprocess
import sys
from typing import Callable, List, Optional, Sequence, Tuple

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# 失敗卻沒有關鍵行時留下的最後幾行 ／ The last lines kept for a failed step with no key line
TAIL_LINES = 20
# 逾時後送 SIGINT，讓子行程的 finally 清掉 worktree，等這麼久再強制結束
# After a timeout SIGINT goes first so the child's finally removes its worktree; this long before a forced kill
_GRACE_SECONDS = 30

# pytest 與 sdist 的關鍵行：失敗與錯誤、覆蓋率總計、最後的計數
# pytest's and the sdist's key lines: failures and errors, the coverage total, the final counts
_PYTEST_KEYS = re.compile(r"^(FAILED|ERROR) |^TOTAL\s|^\d+ (passed|failed|errors?|skipped)\b|Required test coverage")
# 每一步要留在摘要裡的行；None 表示整份輸出都留（輸出本身就是摘要）
# The lines each step keeps in the summary; None keeps the whole output (the output is the summary)
_KEYS = {
    "pytest": _PYTEST_KEYS,
    "ruff": re.compile(r"All checks passed|^Found \d+ error"),
    "mypy": re.compile(r"^Success: |^Found \d+ error"),
    "pip_audit": None,
    "test_sdist": _PYTEST_KEYS,
    "bi_english": None,
    "recite_check": None,
    "golden": None,
    "red_on_base": None,
}
# red-on-base 的每一行結果 ／ red-on-base's result lines
_RED_ON_BASE_LINE = re.compile(r"^(red|green|skipped|hang)\s")


def steps(python: str, against: str) -> List[Tuple[str, List[str]]]:
    """完整檢查的步驟：名稱與要跑的命令，依執行順序。
    The full check's steps: name and command, in run order."""
    return [
        ("pytest", [python, "-m", "pytest", "-q", "--cov=vibeharness", "--cov-fail-under=93", "--cov-precision=2"]),
        ("ruff", [python, "-m", "ruff", "check", "."]),
        ("mypy", [python, "-m", "mypy", "vibeharness/", "main.py"]),
        ("pip_audit", [python, "-m", "pip_audit", "-r", "requirements.lock", "--disable-pip", "--require-hashes"]),
        ("test_sdist", [python, os.path.join("scripts", "test_sdist.py")]),
        ("bi_english", [python, os.path.join("scripts", "check_bi_english.py")]),
        ("recite_check", [python, os.path.join("scripts", "recite_design_refs.py"), "--check"]),
        ("golden", [python, os.path.join("scripts", "golden", "run.py"), "--against", against]),
        ("red_on_base", [python, os.path.join("scripts", "check_new_tests_red_on_base.py"), "--against", against]),
    ]


STEP_NAMES = tuple(name for name, _ in steps(sys.executable, "master"))


def key_lines(name: str, output: str, failed: bool) -> List[str]:
    """一步的輸出裡要寫進摘要的行；red-on-base 另外在最前面加上紅、綠、略過與 hang 的數量。
    The lines of a step's output that go into the summary; red-on-base also gets its red, green, skipped and hang counts
    first."""
    lines = [line.rstrip() for line in output.splitlines() if line.strip()]
    pattern = _KEYS.get(name)
    kept = lines if pattern is None else [line for line in lines if pattern.search(line)]
    if name == "red_on_base":
        statuses = [m.group(1) for m in map(_RED_ON_BASE_LINE.match, lines) if m]
        counts = " ".join(f"{s}={statuses.count(s)}" for s in ("red", "green", "skipped", "hang"))
        kept = [counts, *kept]
    if failed and (not kept or (name == "red_on_base" and len(kept) == 1)):
        kept += lines[-TAIL_LINES:]
    return kept


Runner = Callable[[Sequence[str], str, Optional[float]], Tuple[Optional[int], str]]


def run_command(cmd: Sequence[str], cwd: str, timeout: Optional[float]) -> Tuple[Optional[int], str]:
    """跑一個命令，回傳（結束碼, stdout 與 stderr 合併的輸出）；逾時的結束碼是 None。
    Run a command and return (exit code, stdout and stderr combined); a timeout's exit code is None."""
    posix = os.name == "posix"
    proc = subprocess.Popen(list(cmd), cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            encoding="utf-8", errors="replace", start_new_session=posix)
    try:
        out, _ = proc.communicate(timeout=timeout)
        return proc.returncode, out
    except subprocess.TimeoutExpired:
        # 整個行程群組都要停：golden 與 red-on-base 會再開子行程
        # The whole process group stops: golden and red-on-base start children of their own
        if posix:
            os.killpg(proc.pid, signal.SIGINT)
        else:
            proc.kill()
        try:
            out, _ = proc.communicate(timeout=_GRACE_SECONDS)
        except subprocess.TimeoutExpired:
            if posix:
                os.killpg(proc.pid, signal.SIGKILL)
            else:
                proc.kill()
            out, _ = proc.communicate()
        return None, out


def _short_head(repo: str) -> str:
    """HEAD 的短 SHA；不是 git repo 時回傳 `nohead`。
    HEAD's short SHA; `nohead` outside a git repo."""
    done = subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=repo, capture_output=True, encoding="utf-8")
    return done.stdout.strip() if done.returncode == 0 else "nohead"


def _dirty(repo: str) -> bool:
    """工作目錄有沒有未 commit 的改動。
    Whether the working tree has uncommitted changes."""
    done = subprocess.run(["git", "status", "--porcelain"], cwd=repo, capture_output=True, encoding="utf-8")
    return bool(done.stdout.strip())


def _tree_state(repo: str, own_files: Sequence[str] = ()) -> str:
    """工作目錄目前狀態的雜湊：HEAD、`git diff HEAD`（已追蹤檔案的 staged 與未 staged 改動），以及 git 沒忽略的
    未追蹤檔案的清單與內容。git 忽略的檔案（`.venv/`、快取、`scratch/`）不在其中，那裡的改動看不到；own_files
    （script 自己寫的 log，`--log` 可以指到 repo 裡任何地方）也不算（#216）。不是 git repo 時每次都一樣。不算
    `git status --porcelain`：已追蹤或未被忽略的檔案的每一個改動，這三部分都已看得到，它只多看出不動任何內容的
    `git add`。`git diff` 不用使用者設定的外部 diff 與 textconv，輸出才只取決於內容。
    A hash of the working tree's current state: HEAD, `git diff HEAD` (staged and unstaged changes to tracked files)
    and the list and content of untracked files git does not ignore. Files git ignores (`.venv/`, caches, `scratch/`)
    are not part of it, so a change there goes unseen; `own_files` (the logs the script writes, which `--log` can put
    anywhere in the repo) are left out too (#216). Outside a git repo it reads the same every time.
    `git status --porcelain` is left out: these three parts already see every change to tracked or non-ignored files,
    and it adds only a `git add` that changes no content. `git diff` runs without the user's external diff and
    textconv, so its output depends on the content alone."""
    # 只排除 repo 裡的路徑（Windows 上不同磁碟的路徑沒有相對路徑，也不在 repo 裡）；pathspec 用 literal，
    # 檔名裡的 `*` 之類不會被當成萬用字元
    # Only paths inside the repo are left out (on Windows a path on another drive has no relative path and is not in
    # the repo either); the pathspecs are literal, so a `*` in a file name is no wildcard
    pathspec = ["."]
    for path in own_files:
        try:
            rel = os.path.relpath(path, repo)
        except ValueError:
            continue
        if rel != os.pardir and not rel.startswith(os.pardir + os.sep):
            pathspec.append(f":(exclude,literal){rel}")
    digest = hashlib.sha256()
    for args in (["rev-parse", "HEAD"],
                 ["diff", "HEAD", "--no-ext-diff", "--no-textconv", "--binary", "--", *pathspec],
                 ["ls-files", "-z", "--others", "--exclude-standard", "--", *pathspec]):
        done = subprocess.run(["git", *args], cwd=repo, capture_output=True)
        digest.update(b"%d\0%s\0%s\0" % (done.returncode, done.stdout, done.stderr))
        if args[0] == "ls-files" and done.returncode == 0:
            for name in filter(None, done.stdout.split(b"\0")):
                try:
                    with open(os.path.join(repo, os.fsdecode(name)), "rb") as f:
                        digest.update(name + b"\0" + hashlib.sha256(f.read()).digest())
                except OSError as e:
                    digest.update(name + b"\0" + type(e).__name__.encode())
    return digest.hexdigest()


# `scripts/check_bi_english.py` 沒給 `--base` 時比對的 ref（它的 merge-base 和 HEAD）
# The ref `scripts/check_bi_english.py` compares against when given no `--base` (its merge-base with HEAD)
BI_ENGLISH_BASE = "origin/master"


def _ref_state(repo: str, ref: str) -> str:
    """`ref` 目前指到的 commit（`git rev-parse` 的結束碼、輸出與錯誤）；ref 不存在時每次都一樣。
    The commit `ref` points at now (`git rev-parse`'s exit code, output and error); the same every time when the ref
    does not exist."""
    done = subprocess.run(["git", "rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}"], cwd=repo,
                          capture_output=True, text=True)
    return f"{done.returncode}\0{done.stdout}\0{done.stderr}"


def main(argv: Optional[List[str]] = None, repo: str = _REPO, run: Runner = run_command) -> int:
    """命令列進入點，回傳結束碼。
    Command-line entry point; returns the exit code."""
    parser = argparse.ArgumentParser(description="Run the full check before a PR and write a summary log.")
    parser.add_argument("--against", default="master", metavar="REV",
                        help="the revision golden and red-on-base compare with (default: master)")
    parser.add_argument("--skip", action="append", default=[], choices=STEP_NAMES, metavar="STEP",
                        help=f"leave a step out (repeatable): {', '.join(STEP_NAMES)}")
    parser.add_argument("--timeout", type=float, default=1800, metavar="SECONDS",
                        help="stop a step after this long and report it as timed out (default: 1800)")
    parser.add_argument("--log", metavar="PATH", help="the summary log (default: scratch/checks-<short HEAD>.log)")
    args = parser.parse_args(argv)
    head = _short_head(repo)
    log = args.log or os.path.join(repo, "scratch", f"checks-{head}.log")
    full = os.path.splitext(log)[0] + ".full.log"
    os.makedirs(os.path.dirname(os.path.abspath(log)), exist_ok=True)
    header = f"== HEAD {head} against {args.against}" + (" (uncommitted changes in the working tree)"
                                                          if _dirty(repo) else "")
    failed_steps: List[str] = []
    could_not_check = ""
    own_files = (os.path.abspath(log), os.path.abspath(full))
    start = _tree_state(repo, own_files)
    # golden 與 red-on-base 比對 `--against`，bi_english 一律比對 `origin/master`；同一個 ref 只比一次
    # golden and red-on-base compare against `--against`, bi_english always against `origin/master`; each ref is
    # compared once
    watched = list(dict.fromkeys([args.against, BI_ENGLISH_BASE]))
    refs_start = {ref: _ref_state(repo, ref) for ref in watched}
    with open(log, "w", encoding="utf-8") as summary, open(full, "w", encoding="utf-8") as everything:
        # 檔頭立刻寫進檔案：第一步（pytest）要跑好幾分鐘，這段時間 log 不能看起來是空的（#191）
        # The header reaches the files at once: the first step (pytest) runs for minutes, and the log must not look
        # empty meanwhile (#191)
        for f in (summary, everything):
            f.write(header + "\n")
            f.flush()
        print(header, flush=True)
        for name, cmd in steps(sys.executable, args.against):
            if name in args.skip:
                lines = [f"{name} skipped (--skip)"]
            else:
                code, out = run(cmd, repo, args.timeout)
                status = f"timeout after {args.timeout:g}s" if code is None else f"exit={code}"
                if code != 0:
                    failed_steps.append(name)
                lines = [f"{name} {status}", *key_lines(name, out, code != 0)]
                everything.write(f"== {name} {status}: {' '.join(cmd)}\n{out}\n")
                everything.flush()
            summary.write("\n".join(lines) + "\n")
            summary.flush()
            print(lines[0], flush=True)
            # 讀工作目錄的步驟（test_sdist、golden、red_on_base）會讀到途中的改動：狀態一變就停，
            # 後面的結果不可信（#216）
            # The steps that read the working tree (test_sdist, golden, red_on_base) would read a change made meanwhile:
            # stop as soon as the state differs, as later results could not be trusted (#216)
            # 比對用的 ref 移動了（含被建立或刪除），前後步驟比的就不是同一個基準，也停下；工作目錄也變了時只寫工作目錄
            # （#216 第一輪審查 Spec (c)2）
            # When a ref compared against moves (being created or deleted included), the steps no longer share one
            # base, so the run stops too; when the working tree changed as well, only that is named (#216 round-1
            # review, spec (c)2)
            if name in args.skip:
                continue
            moved = [ref for ref in watched if _ref_state(repo, ref) != refs_start[ref]]
            if _tree_state(repo, own_files) != start:
                could_not_check = f"the working tree changed during {name}"
            elif moved:
                could_not_check = f"`{moved[0]}` moved during {name}"
            if could_not_check:
                break
        if could_not_check:
            verdict = f"== could not check: {could_not_check}"
        else:
            verdict = "== all steps exited 0" if not failed_steps else "== not 0: " + ", ".join(failed_steps)
        summary.write(verdict + "\n")
        if could_not_check:
            everything.write(verdict + "\n")
    print(f"{verdict}\nsummary: {log}\nfull output: {full}")
    if could_not_check:
        return 2
    return 1 if failed_steps else 0


if __name__ == "__main__":
    sys.exit(main())
