#!/usr/bin/env python3
"""Claude Code 的 PreToolUse hook（Bash）：PR 的標題或內文還有佔位符時，擋下 `gh pr create`／`gh pr edit`。
佔位符是 `<`、一個大寫字母、再至少兩個大寫字母／數字／底線、`>`，例如 `<FULL_CHECK_3DD1FC6>`：草稿裡等結果出來
再填的段落用這個寫法。指令先剝掉 heredoc 的內文，再照 shell 的規則拆成 token；只有在指令開頭位置的 `gh`（整條
指令的開頭，或 `;`、`&`、`|`、`(`、`)` 之後，前面可以有 `VAR=value`）且之後有 `pr create`／`pr edit` 才算，引號裡
提到的不算。算的時候，hook 掃描整條指令的文字（`--title`、`--body`、heredoc 都在裡面），以及 `--body-file`／`-F`
指到的每一個檔案；有佔位符就擋下並列出它們。
讀不到的內文一律以「無法檢查」擋下：檔案讀不到、路徑裡有 `$` 或反引號（hook 不展開變數與指令替換）、指令前面
有 `cd` 時的相對路徑（hook 不跟著換目錄）、`--body-file -` 卻沒有 heredoc（stdin 從別處來，hook 看不到）、
`--body-file` 沒有值；指令拆不成 token 而文字裡有 `gh` 與 `pr` 時也是。hook 自己出錯時（含讀不懂的輸入）也擋下。
真的要送出時，讓指令裡任何地方出現 `# placeholder-ok`。
已知限制：
- `gh api` 或別的工具建立 PR、`gh` 前面有 `command`、`env`、`sudo` 這類包裝、`bash -c` 的字串裡的 `gh`，都不檢查。
- 小寫或少於三個字元的角括號（`<step>`、`<N>`）不算佔位符。
- 指令裡別處（例如同一條指令寫的另一個檔案的 heredoc）有佔位符時也會擋下。
緣由：#216（2026-11-26）的 PR 草稿裡還有兩個等完整重檢結果的佔位符時，就被要求開 PR。
Claude Code PreToolUse hook (Bash): denies `gh pr create`/`gh pr edit` while the PR's title or body still holds a
placeholder. A placeholder is `<`, an upper-case letter, at least two more upper-case letters, digits or underscores,
then `>`, such as `<FULL_CHECK_3DD1FC6>`: drafts use that form for sections waiting on a result. The command has its
heredoc bodies taken out and is split into tokens by shell rules; only a `gh` in command position (the start, or
after `;`, `&`, `|`, `(` or `)`, past any `VAR=value`) followed by `pr create`/`pr edit` counts, so a mention inside
quotes does not. When one does, the hook scans the whole command's text (`--title`, `--body` and heredocs are all
in it) and every file `--body-file`/`-F` names, and denies when any placeholder is found, listing them.
A body it cannot read is denied as unchecked: a file it cannot read, a path holding `$` or a backtick (the hook does
not expand variables or command substitutions), a relative path after a `cd` earlier in the command (the hook does
not follow it), `--body-file -` without a heredoc (stdin comes from somewhere the hook cannot see), or a
`--body-file` with no value; so is a command that does not split into tokens while its text holds `gh` and `pr`. It
also denies when the hook itself fails (unreadable input included).
A command that really means to send it contains `# placeholder-ok` anywhere.
Known limits:
- A PR created through `gh api` or another tool, a `gh` behind a wrapper such as `command`, `env` or `sudo`, and a
  `gh` inside a `bash -c` string are not checked.
- Angle brackets around lower case or fewer than three characters (`<step>`, `<N>`) are no placeholder.
- A placeholder elsewhere in the command (a heredoc writing another file in the same command, say) is denied too.
Origin: #216 (2026-11-26): opening the PR was asked for while its draft still held two placeholders waiting on the
full check's results."""

import json
import os
import re
import shlex
import sys

OVERRIDE = "# placeholder-ok"
PLACEHOLDER = re.compile(r"<[A-Z][A-Z0-9_]{2,}>")
# heredoc 的開頭（`<<EOF`、`<<'EOF'`、`<<-"EOF"`），不含 here-string 的 `<<<`
# A heredoc's start (`<<EOF`, `<<'EOF'`, `<<-"EOF"`), not a here-string's `<<<`
HEREDOC = re.compile(r"(?<!<)<<(-?)\s*(['\"]?)([A-Za-z_]\w*)\2")
OPERATOR = set("();<>|&")
REDIRECT = re.compile(r"^\d*[<>]")


class Unchecked(Exception):
    """讀不到要檢查的內文 ／ A body the hook cannot read."""


def without_heredocs(command):
    """去掉 heredoc 內文（含結尾那一行）之後的指令，以及它有沒有 heredoc。
    The command with its heredoc bodies (terminator lines included) taken out, and whether it had any heredoc."""
    kept, pending, found = [], [], False
    for line in command.split("\n"):
        if pending:
            strip, word = pending[0]
            if (line.lstrip("\t") if strip else line) == word:
                pending.pop(0)
            continue
        kept.append(line)
        for match in HEREDOC.finditer(line):
            pending.append((bool(match.group(1)), match.group(3)))
            found = True
    return "\n".join(kept), found


def tokens_of(command):
    """照 shell 的規則拆成 token，`;`、`&&`、`|`、`(` 之類各自成一個；換行當成 `;`。
    Splits by shell rules, with `;`, `&&`, `|`, `(` and the like each a token of its own; a newline counts as `;`."""
    lexer = shlex.shlex(command.replace("\n", " ; "), posix=True, punctuation_chars=True)
    lexer.whitespace_split = True
    return list(lexer)


def pr_calls(tokens):
    """每一個在指令開頭位置、之後是 `pr create|edit` 的 `gh`，回傳 `create|edit` 之後到這段指令結束的 token。
    For every `gh` in command position followed by `pr create|edit`, the tokens after `create|edit` up to the end of
    that simple command."""
    calls, start = [], True
    for i, token in enumerate(tokens):
        if token and set(token) <= OPERATOR:
            start = token not in ("<", ">", "<<", ">>")
            continue
        if start and re.fullmatch(r"[A-Za-z_]\w*=.*", token):
            continue
        if start and token == "gh":
            rest = tokens[i + 1:]
            end = next((j for j, t in enumerate(rest) if t and set(t) <= OPERATOR - set("<>")), len(rest))
            rest = rest[:end]
            for j in range(len(rest) - 1):
                if rest[j] == "pr" and rest[j + 1] in ("create", "edit"):
                    calls.append(rest[j + 2:])
                    break
        start = False
    return calls


def body_files(args):
    """`pr create|edit` 之後的參數裡，`--body-file`／`-F` 的每一個值（`--body-file=X`、`-FX` 也算）。
    Every value of `--body-file`/`-F` among the args after `pr create|edit` (`--body-file=X` and `-FX` too)."""
    values = []
    for i, token in enumerate(args):
        if token in ("--body-file", "-F"):
            if i + 1 >= len(args) or (args[i + 1] and set(args[i + 1]) <= OPERATOR):
                raise Unchecked(f"`{token}` has no value")
            values.append(args[i + 1])
        elif token.startswith("--body-file="):
            values.append(token[len("--body-file="):])
        elif token.startswith("-F") and not token.startswith("--"):
            values.append(token[2:])
    return values


def read_body(value, has_heredoc, has_cd, cwd):
    """讀 `--body-file` 的一個值，回傳它的文字；heredoc 的 `-` 回傳 ""（它的文字已在指令裡）。
    Reads one `--body-file` value and returns its text; a `-` fed by a heredoc returns "" (its text is already in the
    command)."""
    if value == "-":
        if has_heredoc:
            return ""
        raise Unchecked("`--body-file -` reads stdin, which comes from outside the command")
    if "$" in value or "`" in value:
        raise Unchecked(f"`{value}` holds a variable or command substitution the hook does not expand")
    path = os.path.expanduser(value)
    if not os.path.isabs(path):
        if has_cd:
            raise Unchecked(f"`{value}` is relative and the command changes directory first")
        path = os.path.join(cwd, path)
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError as error:
        raise Unchecked(f"`{value}` cannot be read ({type(error).__name__}: {error})") from error


def main():
    """讀 hook 的 JSON 輸入；`gh pr create|edit` 的標題或內文有佔位符、或讀不到內文時，印出拒絕的決定與原因。
    Reads the hook's JSON input and, when a `gh pr create|edit` title or body holds a placeholder or cannot be read,
    prints a deny decision with its reason."""
    # stdin 以 UTF-8 讀，不靠 Python 的預設編碼 ／ stdin is read as UTF-8, not with Python's default encoding
    payload = json.loads(sys.stdin.buffer.read().decode("utf-8", errors="replace"))
    command = payload.get("tool_input", {}).get("command", "")
    if "gh" not in command or OVERRIDE in command:
        return 0
    shell, has_heredoc = without_heredocs(command)
    try:
        tokens = tokens_of(shell)
    except ValueError as error:
        if re.search(r"\bgh\b", shell) and re.search(r"\bpr\b", shell):
            deny(f"the PR body could not be checked: the command does not split into tokens ({error})\n"
                 f"If the command opens or edits no PR, or its text is meant to go out as it is, add the comment "
                 f"`{OVERRIDE}` to it.")
        return 0
    calls = pr_calls(tokens)
    if not calls:
        return 0
    cwd = payload.get("cwd") or os.getcwd()
    has_cd = "cd" in tokens
    found, unknown = [], []
    hits = sorted(set(PLACEHOLDER.findall(command)))
    if hits:
        found.append(("the command", hits))
    for args in calls:
        try:
            for value in body_files(args):
                hits = sorted(set(PLACEHOLDER.findall(read_body(value, has_heredoc, has_cd, cwd))))
                if hits:
                    found.append((f"`{value}`", hits))
        except Unchecked as error:
            unknown.append(str(error))
    if not found and not unknown:
        return 0
    lines = [f"{where} still holds placeholders: {', '.join(hits)}" for where, hits in found]
    lines += [f"the PR body could not be checked: {error}" for error in unknown]
    deny("\n".join(lines) + "\nFill them in (or point --body-file at a file the hook can read), then retry. "
         f"If the text is really meant to go out as it is, add the comment `{OVERRIDE}` to the command.")
    return 0


def deny(reason):
    """印出拒絕的決定與原因（ASCII 跳脫的 JSON，不受 stdout 編碼影響）。
    Prints a deny decision with its reason (ASCII-escaped JSON, whatever stdout's encoding)."""
    print(json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                                             "permissionDecisionReason": reason}}))


def guarded_main():
    """執行 main()；main() 裡出錯時擋下指令並附上錯誤，而不是以非 0 結束（Claude Code 會把那當成放行）。
    Runs main(); when main() fails it denies the command with the error, rather than exiting non-zero (which Claude
    Code treats as letting the command run)."""
    try:
        return main()
    except Exception as error:  # 任何錯誤都要擋下 ／ any error must deny
        deny(f"guard_pr_placeholder failed, so the command was not checked: {type(error).__name__}: {error}\n"
             f"If the command is safe, add the comment `{OVERRIDE}` to it.")
        return 0


if __name__ == "__main__":
    sys.exit(guarded_main())
