#!/usr/bin/env python3
"""Claude Code 的 PreToolUse hook（Bash）：擋下會清掉還沒 commit 的改動的 git 指令。
涵蓋 `git checkout ... -- <路徑>`（以及 `git checkout <存在的路徑>`）、`git restore <路徑>`（只有 `--staged` 的除外）
與 `git reset --hard`。它問 git 受影響的已追蹤路徑裡，哪些跟指令要還原成的內容不同，有就擋下並列出它們；
未追蹤的檔案不算，這些指令不會動到它們。真的要丟掉時，在指令裡加上註解 `# discard-ok`。
緣由：#158（2026-11-13）的 `git checkout -q -- scripts tests` 清掉了還沒 commit 的修正與測試。
Claude Code PreToolUse hook (Bash): denies git commands that would discard uncommitted changes.
Covers `git checkout ... -- <paths>` (and `git checkout <existing path>`), `git restore <paths>` (unless only
`--staged`), and `git reset --hard`. It asks git which of the affected tracked paths differ from what the command
restores, and denies when any do, listing them; untracked files are not counted, as these commands leave them alone.
A command that really means to discard them carries the comment `# discard-ok`.
Background: on #158 (2026-11-13) `git checkout -q -- scripts tests` wiped an uncommitted fix and its tests."""

import json
import os
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
# 子指令之前、後面帶一個值的 git 選項
# git options before the subcommand that take a value
GIT_VALUE_OPTS = {"-C", "-c", "--git-dir", "--work-tree", "--namespace"}


def segments(command):
    """把一行 shell 指令切成各個簡單指令的 token 串列；引號解析不了時不回傳任何東西。
    Splits a shell command line into the token lists of its simple commands; yields nothing when the quoting does not
    parse."""
    lexer = shlex.shlex(command, posix=True, punctuation_chars=PUNCTUATION)
    lexer.whitespace = " \t\r"
    lexer.whitespace_split = True
    lexer.commenters = ""
    current = []
    try:
        for token in lexer:
            if token and all(ch in PUNCTUATION for ch in token):
                if current:
                    yield current
                current = []
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
        tokens = tokens[1:]
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


def run(cwd, *args):
    """在 cwd 執行 git，回傳 stdout；git 失敗時回傳空字串。
    Runs git in cwd and returns its stdout, or an empty string when git fails."""
    done = subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True)
    return done.stdout if done.returncode == 0 else ""


def dirty(cwd, mode, paths):
    """`paths` 裡（空的時候是全部）會被指令蓋掉的已追蹤路徑。
    The tracked paths among `paths` (all of them when empty) that the command would overwrite."""
    spec = ["--", *paths] if paths else []
    if mode == "index":
        # checkout -- 與 restore：工作目錄回到 index（或指定的來源），已暫存的改動也算
        # checkout -- and restore: the working tree goes back to the index (or a given source); staged changes count
        out = run(cwd, "diff", "--name-only", *spec) + run(cwd, "diff", "--cached", "--name-only", *spec)
    else:
        # reset --hard：工作目錄與 index 都回到 HEAD
        # reset --hard: the working tree and the index go back to HEAD
        out = run(cwd, "diff", "HEAD", "--name-only", *spec)
    return sorted(set(line for line in out.splitlines() if line))


def affected(cwd, sub, args):
    """這個 git 呼叫可能丟掉改動時回傳 (模式, 路徑)，否則回傳 None。
    (mode, paths) when the git call can discard changes, else None."""
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
    if sub == "reset" and "--hard" in args:
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
    lost = []
    for tokens in segments(command):
        if tokens and tokens[0] == "cd" and len(tokens) > 1:
            cwd = os.path.join(cwd, tokens[1])
            continue
        call = git_call(tokens, cwd)
        if not call:
            continue
        where, sub, args = call
        hit = affected(where, sub, args)
        if hit:
            files = dirty(where, *hit)
            if files:
                lost.append((" ".join(tokens), files))
    if not lost:
        return 0
    lines = []
    for cmd, files in lost:
        lines.append(f"`{cmd}` would discard uncommitted changes in: {', '.join(files[:20])}"
                     + (f" (+{len(files) - 20} more)" if len(files) > 20 else ""))
    reason = ("\n".join(lines) + "\nCommit first (or save a copy and write it back), then retry. "
              f"If discarding these is really intended, add the comment `{OVERRIDE}` to the command.")
    print(json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                                             "permissionDecisionReason": reason}}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
