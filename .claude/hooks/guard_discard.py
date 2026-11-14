#!/usr/bin/env python3
"""Claude Code 的 PreToolUse hook（Bash）：擋下會清掉還沒 commit 的改動的 git 指令。
涵蓋 `git checkout ... -- <路徑>`（以及 `git checkout <存在的路徑>`）、`git restore <路徑>`（只有 `--staged` 的除外）、
`git checkout -f`、`git switch -f`／`--discard-changes`、`git reset --hard` 與 `git reset --merge`。
它問 git 受影響的已追蹤路徑裡，哪些有指令會蓋掉的還沒 commit 的改動，有就擋下並列出它們：沒有來源的 `checkout`
只看工作目錄跟 index 的差異（暫存的改動留得住）；`restore` 與有來源的 `checkout` 也算暫存的改動；`reset` 與強制切換
看跟 HEAD 的差異。它不看指令指定的來源是哪個 commit。git 答不出來時也擋下，附上 git 的錯誤。未追蹤的檔案不算，這些
指令不會動到它們。真的要丟掉時，讓指令裡任何地方出現 `# discard-ok`（對整條指令比對字串，多行指令的任一行都算，
不必是真的註解）。
緣由：#158（2026-11-13）的 `git checkout -q -- scripts tests` 清掉了還沒 commit 的修正與測試。
Claude Code PreToolUse hook (Bash): denies git commands that would discard uncommitted changes.
Covers `git checkout ... -- <paths>` (and `git checkout <existing path>`), `git restore <paths>` (unless only
`--staged`), `git checkout -f`, `git switch -f`/`--discard-changes`, `git reset --hard` and `git reset --merge`.
It asks git which of the affected tracked paths have uncommitted changes the command would overwrite, and denies
when any do, listing them: a `checkout` without a source looks only at the working tree against the index (a staged
change survives it); `restore` and a `checkout` with a source count staged changes too; `reset` and forced switches
look at the difference from HEAD. Which commit a command restores from is not consulted. It also denies, with git's
error, when git cannot answer. Untracked files are not counted, as these commands leave them alone. A command that
really means to discard them contains `# discard-ok` anywhere (a substring match on the whole command, so any line
of a multi-line command counts, and it need not be a real comment).
Background: on #158 (2026-11-13) `git checkout -q -- scripts tests` wiped an uncommitted fix and its tests."""

import json
import os
import re
import shlex
import subprocess
import sys

OVERRIDE = "# discard-ok"
# 只由這些字元組成的 token 會切開指令：; && || | & ( ) () 與換行（`2>&1` 裡的 `&` 也會，切出的 `1` 不是 git 呼叫）
# A token made only of these characters splits commands: ; && || | & ( ) () and newlines (so does the `&` in `2>&1`;
# the `1` it splits off is not a git call)
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
# 含有重導向的 token：前面可以黏著參數（`x>out`）或檔案描述元數字（`2>`），目標接在後面或是下一個 token
# A token holding a redirection: an argument (`x>out`) or a file-descriptor number (`2>`) may be attached in front,
# and the target follows it or is the next token
REDIRECT = re.compile(r"([^<>]*?)[<>]+(.*)")


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
                # 重導向和它的目標不是指令的參數，黏在前面的參數才是（只有數字時是檔案描述元）
                # A redirection and its target are not arguments of the command; an argument attached in front is
                # (unless it is only digits, a file descriptor)
                before, target = redirect.groups()
                if before and not before.isdigit():
                    current.append(before)
                target_next = not target
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
    """在 cwd 執行 git，回傳 stdout；git 失敗時丟出 GitFailed，訊息是 stderr 的第一行；git 或 cwd 找不到時，
    訊息是找不到的那一個。
    Runs git in cwd and returns its stdout; raises GitFailed carrying the first line of stderr when git fails, or
    naming whichever of git and cwd cannot be found."""
    try:
        done = subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True)
    except NotADirectoryError as error:
        raise GitFailed(str(error)) from error
    except FileNotFoundError as error:
        raise GitFailed(f"{error.filename or cwd}: {error.strerror}") from error
    if done.returncode != 0:
        first = next((line for line in done.stderr.splitlines() if line.strip()), "")
        raise GitFailed(first.strip() or f"git {' '.join(args)} exited {done.returncode}")
    return done.stdout


def dirty(cwd, mode, paths):
    """`paths` 裡（空的時候是全部）有還沒 commit 的改動的已追蹤路徑；git 失敗時丟出 GitFailed。
    The tracked paths among `paths` (all of them when empty) with uncommitted changes; raises GitFailed when git
    fails."""
    spec = ["--", *paths] if paths else []
    if mode == "worktree":
        # 沒有來源的 checkout：工作目錄跟 index 不同的路徑；只有暫存的改動留得住
        # A checkout without a source: paths where the working tree differs from the index; a staged-only change
        # survives it
        out = run(cwd, "diff", "--name-only", *spec)
    elif mode == "index":
        # restore 與有來源的 checkout：工作目錄跟 index 不同、或 index 跟 HEAD 不同的路徑；不看指令指定的來源，
        # 所以只有暫存的改動時 `git restore <路徑>` 也會被擋（它其實不會丟掉那些改動）
        # restore and a checkout with a source: paths where the working tree differs from the index or the index
        # from HEAD; the source the command names is not consulted, so with only staged changes `git restore <path>`
        # is denied too (it would not actually lose them)
        out = run(cwd, "diff", "--name-only", *spec) + run(cwd, "diff", "--cached", "--name-only", *spec)
    else:
        # reset --hard／--merge 與強制切換：工作目錄或 index 跟 HEAD 不同的路徑
        # reset --hard/--merge and forced switches: paths where the working tree or the index differs from HEAD
        out = run(cwd, "diff", "HEAD", "--name-only", *spec)
    return sorted(set(line for line in out.splitlines() if line))


def forced(args, *longs):
    """參數裡有 `-f`（含 `-qf` 這種合併的短選項）或 longs 其中一個時為真；`--` 之後的不算，
    帶值的短選項（`-b`、`-B`、`-c`、`-C`）後面黏著的是分支名，也不算（`-bfix` 不是 `-f`）。
    True when the args carry `-f` (also inside a short-option cluster such as `-qf`) or one of longs; nothing after
    `--` counts, nor does a branch name attached to a short option that takes a value (`-b`, `-B`, `-c`, `-C`), so
    `-bfix` is not `-f`."""
    for a in args:
        if a == "--":
            return False
        if a in longs:
            return True
        if a.startswith("-") and not a.startswith("--"):
            for ch in a[1:]:
                if ch == "f":
                    return True
                if ch in "bBcC":
                    break
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
        # 指定了來源（例如 `checkout HEAD -- <路徑>`）時 index 也會被蓋掉；沒有時只把 index 複製回工作目錄
        # With a source (such as `checkout HEAD -- <paths>`) the index is overwritten too; without one only the
        # index is copied back to the working tree
        if "--" in args:
            paths = args[args.index("--") + 1:]
            source = [a for a in args[:args.index("--")] if not a.startswith("-")]
        else:
            candidates = [a for a in args if not a.startswith("-")]
            paths = [a for a in candidates if os.path.exists(os.path.join(cwd, a))]
            source = [a for a in candidates if a not in paths]
        return ("index" if source else "worktree", paths) if paths else None
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
