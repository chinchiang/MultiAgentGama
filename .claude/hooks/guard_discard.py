#!/usr/bin/env python3
"""Claude Code 的 PreToolUse hook（Bash）：擋下會清掉還沒 commit 的改動的 git 指令。
涵蓋 `git checkout ... -- <路徑>`（以及 `git checkout <存在的路徑>`）、`git restore <路徑>`（只有 `--staged` 的除外）、
`git checkout -f`、`git switch -f`／`--discard-changes`、`git reset --hard` 與 `git reset --merge`。
它問 git 受影響的已追蹤路徑裡，哪些有還沒 commit 的改動（工作目錄或 index 跟 index 或 HEAD 不同；不管指令要還原成
哪個來源），有就擋下並列出它們；git 答不出來時也擋下，附上 git 的錯誤。未追蹤的檔案不算，這些指令不會動到它們。
真的要丟掉時，讓指令裡出現 `# discard-ok`（整行比對字串，不必是真的註解）。
緣由：#158（2026-11-13）的 `git checkout -q -- scripts tests` 清掉了還沒 commit 的修正與測試。
Claude Code PreToolUse hook (Bash): denies git commands that would discard uncommitted changes.
Covers `git checkout ... -- <paths>` (and `git checkout <existing path>`), `git restore <paths>` (unless only
`--staged`), `git checkout -f`, `git switch -f`/`--discard-changes`, `git reset --hard` and `git reset --merge`.
It asks git which of the affected tracked paths have uncommitted changes (the working tree or the index differs from
the index or HEAD, whatever source the command restores from), and denies when any do, listing them; it also denies,
with git's error, when git cannot answer. Untracked files are not counted, as these commands leave them alone.
A command that really means to discard them contains `# discard-ok` (a match on the whole line, not only a real
comment).
Background: on #158 (2026-11-13) `git checkout -q -- scripts tests` wiped an uncommitted fix and its tests."""

import json
import os
import re
import shlex
import subprocess
import sys

OVERRIDE = "# discard-ok"
# 只由這些字元組成的 token 會切開指令：; && || | & ( ) () 與換行
# A token made only of these characters splits commands: ; && || | & ( ) () and newlines
PUNCTUATION = ";&|()\n"
# 出現在 git 前面、要先跳過的 shell 關鍵字與包裝指令
# Shell keywords and wrapper commands in front of git, skipped first
SHELL_PREFIXES = {"{", "}", "then", "do", "else", "elif", "if", "while", "until", "!", "time", "env", "command",
                  "exec", "nohup", "sudo"}
# 包裝指令自己的選項裡，後面帶一個值的那些（其他以 - 開頭的選項單獨跳過）
# The options of wrapper commands that take a value (other options starting with - are skipped on their own)
WRAPPER_VALUE_OPTS = {"env": {"-u", "--unset"}, "sudo": {"-u", "--user", "-g", "--group"}}
# 子指令之前、後面帶一個值的 git 選項
# git options before the subcommand that take a value
GIT_VALUE_OPTS = {"-C", "-c", "--git-dir", "--work-tree", "--namespace"}
# 重導向：可選的檔案描述元數字加上 < 或 >，目標接在後面或是下一個 token
# A redirection: an optional file-descriptor number and < or >, with its target attached or in the next token
REDIRECT = re.compile(r"\d*[<>]+(.*)")


def segments(command):
    """把一行 shell 指令切成各個簡單指令的 token 串列，中間夾著切開它們的分隔符字串（例如 `&&`、`(`）；
    引號解析不了時不回傳任何東西。
    Splits a shell command line into the token lists of its simple commands, with the separator strings between them
    (such as `&&` or `(`); yields nothing when the quoting does not parse."""
    # 反斜線加換行是續行，shell 會把兩者一起拿掉 ／ A backslash-newline continues the line; the shell drops both
    command = command.replace("\\\n", "")
    lexer = shlex.shlex(command, posix=True, punctuation_chars=PUNCTUATION)
    lexer.whitespace = " \t\r"
    lexer.whitespace_split = True
    lexer.commenters = ""
    current = []
    target_next = False
    try:
        for token in lexer:
            if token and all(ch in PUNCTUATION for ch in token):
                if current:
                    yield current
                yield token
                current = []
                target_next = False
            elif target_next:
                target_next = False
            elif redirect := REDIRECT.fullmatch(token):
                # 重導向和它的目標不是指令的參數 ／ A redirection and its target are not arguments of the command
                target_next = not redirect.group(1)
            else:
                current.append(token)
    except ValueError:
        return
    if current:
        yield current


def git_call(tokens, cwd):
    """一個 git 呼叫的 (執行目錄, 子指令, 參數)；不是 git 呼叫時回傳 None。
    The (directory, subcommand, args) of a git invocation, else None."""
    # 先跳過 shell 關鍵字、VAR=value 指派與包裝指令
    # Skip shell keywords, VAR=value assignments and wrapper commands first
    while tokens and (tokens[0] in SHELL_PREFIXES or ("=" in tokens[0] and not tokens[0].startswith("-"))):
        value_opts = WRAPPER_VALUE_OPTS.get(tokens[0], set())
        tokens = tokens[1:]
        # env、sudo 這類包裝指令的選項（例如 `env -i`、`sudo -u 某人`）也跳過
        # Skip the options of wrappers such as env and sudo too (for example `env -i`, `sudo -u someone`)
        while value_opts and tokens and tokens[0].startswith("-"):
            tokens = tokens[2:] if tokens[0] in value_opts else tokens[1:]
    if not tokens or os.path.basename(tokens[0]) != "git":
        return None
    i = 1
    while i < len(tokens) and tokens[i].startswith("-"):
        opt = tokens[i]
        if opt in GIT_VALUE_OPTS and i + 1 < len(tokens):
            if opt == "-C":
                cwd = os.path.join(cwd, tokens[i + 1])
            i += 2
        else:
            i += 1
    if i >= len(tokens):
        return None
    return cwd, tokens[i], tokens[i + 1:]


class GitFailed(Exception):
    """hook 問 git 時 git 失敗；訊息是 git 的 stderr。
    git failed when the hook asked it something; the message is git's stderr."""


def run(cwd, *args):
    """在 cwd 執行 git，回傳 stdout；git 失敗（或 cwd 不存在）時丟出 GitFailed，訊息是 stderr 的第一行。
    Runs git in cwd and returns its stdout; raises GitFailed, carrying the first line of stderr, when git fails (or
    cwd does not exist)."""
    try:
        done = subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True)
    except NotADirectoryError as error:
        raise GitFailed(str(error)) from error
    except FileNotFoundError as error:
        raise GitFailed(f"{cwd}: {error.strerror}") from error
    if done.returncode != 0:
        first = next((line for line in done.stderr.splitlines() if line.strip()), "")
        raise GitFailed(first.strip() or f"git {' '.join(args)} exited {done.returncode}")
    return done.stdout


def dirty(cwd, mode, paths):
    """`paths` 裡（空的時候是全部）有還沒 commit 的改動的已追蹤路徑；git 失敗時丟出 GitFailed。
    The tracked paths among `paths` (all of them when empty) with uncommitted changes; raises GitFailed when git
    fails."""
    spec = ["--", *paths] if paths else []
    if mode == "index":
        # checkout -- 與 restore：工作目錄跟 index 不同、或 index 跟 HEAD 不同的路徑；不看指令指定的來源，
        # 所以只有暫存的改動時 `git restore <路徑>` 也會被擋（它其實不會丟掉那些改動）
        # checkout -- and restore: paths where the working tree differs from the index or the index from HEAD; the
        # source the command names is not consulted, so with only staged changes `git restore <path>` is denied too
        # (it would not actually lose them)
        out = run(cwd, "diff", "--name-only", *spec) + run(cwd, "diff", "--cached", "--name-only", *spec)
    else:
        # reset --hard／--merge 與強制切換：工作目錄或 index 跟 HEAD 不同的路徑
        # reset --hard/--merge and forced switches: paths where the working tree or the index differs from HEAD
        out = run(cwd, "diff", "HEAD", "--name-only", *spec)
    return sorted(set(line for line in out.splitlines() if line))


def forced(args, *longs):
    """參數裡有 `-f`（含 `-qf` 這種合併的短選項）或 longs 其中一個時為真；`--` 之後的不算。
    True when the args carry `-f` (also inside a short-option cluster such as `-qf`) or one of longs; nothing after
    `--` counts."""
    for a in args:
        if a == "--":
            return False
        if a in longs or (a.startswith("-") and not a.startswith("--") and "f" in a[1:]):
            return True
    return False


def affected(cwd, sub, args):
    """這個 git 呼叫可能丟掉改動時回傳 (模式, 路徑)，否則回傳 None。
    (mode, paths) when the git call can discard changes, else None."""
    if sub in ("checkout", "switch") and "--" not in args and forced(args, "--force", "--discard-changes"):
        # 強制切換：工作目錄與 index 的改動都會被丟掉（`checkout -f -- <路徑>` 交給下面只看那些路徑）
        # A forced switch: changes in the working tree and the index are both thrown away (`checkout -f -- <paths>`
        # is left to the branch below, which looks at those paths only)
        return ("head", [])
    if sub == "checkout":
        if "--" in args:
            paths = args[args.index("--") + 1:]
            return ("index", paths) if paths else None
        candidates = [a for a in args if not a.startswith("-")]
        paths = [a for a in candidates if os.path.exists(os.path.join(cwd, a))]
        return ("index", paths) if paths else None
    if sub == "restore":
        staged_only = ("--staged" in args or "-S" in args) and not ("--worktree" in args or "-W" in args)
        if staged_only:
            return None
        paths, skip = [], False
        for a in args:
            if skip:
                skip = False
            elif a in ("-s", "--source"):
                skip = True
            elif a == "--" or a.startswith("-"):
                continue
            else:
                paths.append(a)
        return ("index", paths) if paths else None
    if sub == "reset" and ("--hard" in args or "--merge" in args):
        return ("head", [])
    return None


def main():
    """讀 hook 的 JSON 輸入；有指令會丟掉改動時，印出拒絕的決定與原因。
    Reads the hook's JSON input and, when a command would discard changes, prints a deny decision with its reason."""
    payload = json.load(sys.stdin)
    command = payload.get("tool_input", {}).get("command", "")
    if "git" not in command or OVERRIDE in command:
        return 0
    cwd = payload.get("cwd") or os.getcwd()
    lost, unknown = [], []
    # 進入子 shell 時記下目錄，離開時還原：子 shell 裡的 cd 不影響後面的指令
    # Remember the directory on entering a subshell and restore it on leaving: a cd inside one does not reach later
    # commands
    outer = []
    for tokens in segments(command):
        if isinstance(tokens, str):
            for ch in tokens:
                if ch == "(":
                    outer.append(cwd)
                elif ch == ")" and outer:
                    cwd = outer.pop()
            continue
        if tokens[0] == "cd" and len(tokens) > 1:
            cwd = os.path.join(cwd, tokens[1])
            continue
        call = git_call(tokens, cwd)
        if not call:
            continue
        where, sub, args = call
        hit = affected(where, sub, args)
        if hit:
            try:
                files = dirty(where, *hit)
            except GitFailed as error:
                unknown.append((" ".join(tokens), str(error)))
                continue
            if files:
                lost.append((" ".join(tokens), files))
    if not lost and not unknown:
        return 0
    lines = []
    for cmd, files in lost:
        lines.append(f"`{cmd}` would discard uncommitted changes in: {', '.join(files[:20])}"
                     + (f" (+{len(files) - 20} more)" if len(files) > 20 else ""))
    for cmd, error in unknown:
        lines.append(f"`{cmd}` may discard uncommitted changes, and the hook could not check: git said: {error}")
    reason = ("\n".join(lines) + "\nCommit first (or save a copy and write it back), then retry. "
              f"If discarding these is really intended, add the comment `{OVERRIDE}` to the command.")
    print(json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                                             "permissionDecisionReason": reason}}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
