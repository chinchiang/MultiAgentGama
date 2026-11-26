#!/usr/bin/env python3
"""Claude Code 的 PreToolUse hook（Bash）：PR 的標題或內文還有佔位符時，擋下 `gh pr create`／`gh pr edit`。
佔位符是角括號裡只有大寫字母、數字與底線的字（`<[A-Z0-9_]+>`），例如 `<FULL_CHECK_3DD1FC6>`、`<N>`：草稿裡等結果
出來再填的段落用這個寫法。
規則很粗：指令裡只要有一行（`\\` 續行接起來之後，heredoc 的內文、引號裡的文字也算）依序出現 `gh`、`pr`、`create`
或 `edit` 這幾個字，整條指令就必須是唯一允許的寫法，否則以「無法檢查」擋下：
- 一條指令就是 `gh [-R <repo>] pr create|edit <參數>`，可以用 `\\` 續行，最後可以有 `# 註解`；
- 沒有 `$` 與反引號（hook 不展開變數與指令替換，單引號裡的也一樣不收）、沒有 `;`、`&`、`|`、`(`、`)`、`<`、`>`；
- 內文來自 `--body`／`-b` 的字面文字、`--body-file`／`-F` 或 `--template`／`-T` 指到的檔案（相對路徑以 hook 收到的
  cwd 為準），或是 `--body-file -` 加上指令最後、引號包住結束字（`<<'EOF'`）的 heredoc；
- 短選項不能併在一起（`-dF`），值要接在選項後面或用 `=`。
合乎這個寫法時，hook 掃描每一個參數、每一個內文檔與 heredoc 的內文，有佔位符就擋下並列出它們；檔案讀不到也以
「無法檢查」擋下。hook 自己出錯時（含讀不懂的輸入）也擋下。
真的要照原樣執行時（包括只是提到 `gh pr create` 的 commit 訊息），在 heredoc 內文以外的某一行，以引號外的
`# placeholder-ok` 註解結尾。
已知限制：`gh api` 或別的工具建立 PR，以及指令裡不含這幾個字的寫法（例如把 `gh` 存在變數裡）都不檢查。
緣由：#216（2026-11-26）的 PR 草稿裡還有兩個等完整重檢結果的佔位符時，就被要求開 PR。第一版逐一解析 shell
寫法，第一輪審查就在續行、`$(…)`、`env gh`、`if … then`、heredoc 等處找到放行的缺口，所以改成這個粗規則。
Claude Code PreToolUse hook (Bash): denies `gh pr create`/`gh pr edit` while the PR's title or body still holds a
placeholder. A placeholder is a word of only upper-case letters, digits and underscores in angle brackets
(`<[A-Z0-9_]+>`), such as `<FULL_CHECK_3DD1FC6>` or `<N>`: drafts use that form for sections waiting on a result.
The rule is coarse: when any line of the command (after joining `\\` continuations; heredoc bodies and quoted text
count too) holds the words `gh`, `pr` and `create` or `edit` in that order, the whole command must take the one
allowed form, or it is denied as unchecked:
- a single command `gh [-R <repo>] pr create|edit <args>`, optionally continued with `\\` and ending in a `# comment`;
- no `$` and no backtick (the hook does not expand variables or command substitutions, and refuses them inside single
  quotes too), and no `;`, `&`, `|`, `(`, `)`, `<` or `>`;
- the body comes from the literal text of `--body`/`-b`, from the file named by `--body-file`/`-F` or
  `--template`/`-T` (a relative path is taken from the cwd the hook receives), or from `--body-file -` fed by a heredoc
  at the end of the command whose terminator is quoted (`<<'EOF'`);
- short options are not bundled (`-dF`), and a value follows its option or an `=`.
In that form the hook scans every argument, every body file and the heredoc body, and denies when any placeholder is
found, listing them; a file it cannot read is denied as unchecked too. It also denies when the hook itself fails
(unreadable input included).
A command meant to run as it is (a commit message that only mentions `gh pr create`, say) ends one line outside the
heredoc bodies with the comment `# placeholder-ok`, outside quotes.
Known limit: a PR created through `gh api` or another tool, or written without those words (`gh` kept in a
variable, say), is not checked.
Origin: #216 (2026-11-26): opening the PR was asked for while its draft still held two placeholders waiting on the
full check's results. A first version parsed shell forms one by one, and its first review found forms let through in
continuations, `$(…)`, `env gh`, `if … then` and heredocs, hence this coarse rule."""

import json
import os
import re
import shlex
import sys

OVERRIDE = "placeholder-ok"
PLACEHOLDER = re.compile(r"<[A-Z0-9_]+>")
TRIGGER = re.compile(r"\bgh\b.*\bpr\b.*\b(?:create|edit)\b")
# heredoc 的開頭（`<<EOF`、`<<'EOF'`、`<<-"EOF"`），不含 here-string 的 `<<<`
# A heredoc's start (`<<EOF`, `<<'EOF'`, `<<-"EOF"`), not a here-string's `<<<`
HEREDOC = re.compile(r"(?<!<)<<(?!<)(-?)\s*(['\"]?)([A-Za-z_]\w*)\2")
OPERATOR_CHARS = set("();<>|&")
BODY_FILE_OPTIONS = ("--body-file", "-F", "--template", "-T")
FORM = ("write it as one command `gh [-R <repo>] pr create|edit ...` whose body comes from `--body '<text>'`, "
        "`--body-file <path>` or a quoted heredoc (`<<'EOF'`) fed to `--body-file -`")


class Unchecked(Exception):
    """指令不是唯一允許的寫法，或讀不到內文 ／ The command is not in the one allowed form, or a body cannot be read."""


def split_comment(line):
    """把一行切成 (程式碼, 註解)：註解從引號外、在行首或空白之後的 `#` 開始；沒有註解時是 None。
    Splits a line into (code, comment): a comment starts at a `#` outside quotes, at the start or after whitespace;
    the comment is None when there is none."""
    quote, i = None, 0
    while i < len(line):
        ch = line[i]
        if quote:
            if ch == quote:
                quote = None
            elif ch == "\\" and quote == '"':
                i += 1
        elif ch in "'\"":
            quote = ch
        elif ch == "\\":
            i += 1
        elif ch == "#" and (i == 0 or line[i - 1].isspace()):
            return line[:i], line[i + 1:]
        i += 1
    return line, None


def shell_and_heredocs(command):
    """把指令分成 shell 的行與 heredoc：回傳 (shell 的行, [(開頭所在的 shell 行號, 開頭的 match, 內文, 有沒有結束行)])。
    Splits the command into shell lines and heredocs: returns (shell lines, [(index of the shell line holding the
    start, the start's match, body, whether its terminator was found)])."""
    shell, heredocs, pending, body = [], [], [], []
    for line in command.split("\n"):
        if pending:
            index, match = pending[0]
            if (line.lstrip("\t") if match.group(1) else line) == match.group(3):
                heredocs.append((index, match, "\n".join(body), True))
                pending.pop(0)
                body = []
            else:
                body.append(line)
            continue
        shell.append(line)
        for match in HEREDOC.finditer(split_comment(line)[0]):
            pending.append((len(shell) - 1, match))
    for index, match in pending:
        heredocs.append((index, match, "\n".join(body), False))
        body = []
    return shell, heredocs


def overridden(shell_lines):
    """heredoc 以外有一行以引號外的 `# placeholder-ok` 註解結尾。
    A line outside the heredoc bodies ends with the comment `# placeholder-ok`, outside quotes."""
    return any((split_comment(line)[1] or "").strip() == OVERRIDE for line in shell_lines)


def is_operator(token):
    """token 是 shell 的運算子（`;`、`&&`、`|`、`(`、`<` 之類）。
    The token is a shell operator (`;`, `&&`, `|`, `(`, `<` and the like)."""
    return bool(token) and set(token) <= OPERATOR_CHARS


def pr_args(shell_lines, heredocs):
    """確認指令是唯一允許的寫法，回傳 (`create|edit` 之後的參數, heredoc 的內文或 None)；不是就丟出 Unchecked。
    Checks that the command takes the one allowed form and returns (the args after `create|edit`, the heredoc body or
    None); raises Unchecked otherwise."""
    lines = list(shell_lines)
    while lines and not lines[-1].strip():
        lines.pop()
    heredoc_body = None
    if heredocs:
        if len(heredocs) > 1:
            raise Unchecked("the command holds more than one heredoc")
        index, match, heredoc_body, closed = heredocs[0]
        if not closed or index != len(lines) - 1:
            raise Unchecked("the heredoc is not the last thing in the command")
        if not match.group(2):
            raise Unchecked("the heredoc's terminator is not quoted, so the shell expands `$` in its body")
        code = split_comment(lines[index])[0]
        lines[index] = code[:match.start()] + code[match.end():]
    text = "\n".join(split_comment(line)[0] for line in lines)
    text = re.sub(r"\\\n", " ", text)
    if "\n" in text.strip():
        raise Unchecked("the command spans several lines that are not `\\` continuations")
    if "$" in text or "`" in text:
        raise Unchecked("the command holds `$` or a backtick, which the hook does not expand")
    try:
        lexer = shlex.shlex(text, posix=True, punctuation_chars=True)
        lexer.whitespace_split = True
        lexer.commenters = ""
        tokens = list(lexer)
    except ValueError as error:
        raise Unchecked(f"the command does not split into tokens ({error})") from error
    operators = [t for t in tokens if is_operator(t)]
    if operators:
        raise Unchecked(f"the command holds the shell operator `{operators[0]}`")
    if not tokens or tokens[0] != "gh":
        raise Unchecked("the command does not start with `gh`")
    i = 1
    while i < len(tokens):
        if tokens[i] in ("-R", "--repo"):
            i += 2
        elif tokens[i].startswith("--repo=") or re.fullmatch(r"-R.+", tokens[i]):
            i += 1
        else:
            break
    if tokens[i:i + 1] != ["pr"] or len(tokens) < i + 2 or tokens[i + 1] not in ("create", "edit"):
        raise Unchecked("the command is not `gh [-R <repo>] pr create|edit ...`")
    return tokens[i + 2:], heredoc_body


def body_texts(args, heredoc_body, cwd):
    """參數裡每一個要掃描的文字：(名稱, 文字)。參數本身、內文檔、heredoc 的內文都算。
    Every text to scan among the args, as (name, text): the args themselves, the body files and the heredoc body."""
    texts = [("the command's arguments", "\n".join(args))]
    stdin_used = False
    for i, token in enumerate(args):
        if re.fullmatch(r"-[A-Za-z]{2,}.*", token) and token[:2] not in ("-F", "-T", "-b", "-t", "-R"):
            raise Unchecked(f"`{token}` bundles short options")
        if token in BODY_FILE_OPTIONS:
            if i + 1 >= len(args):
                raise Unchecked(f"`{token}` has no value")
            value = args[i + 1]
        elif token.startswith(("--body-file=", "--template=")):
            value = token.split("=", 1)[1]
        elif token[:2] in ("-F", "-T") and len(token) > 2:
            value = token[2:]
        elif token in ("--body", "-b", "--title", "-t") and i + 1 >= len(args):
            raise Unchecked(f"`{token}` has no value")
        else:
            continue
        if value == "-":
            if heredoc_body is None:
                raise Unchecked(f"`{token} -` reads stdin, and no heredoc at the end of the command feeds it")
            stdin_used = True
            texts.append(("the heredoc body", heredoc_body))
            continue
        path = value if os.path.isabs(os.path.expanduser(value)) else os.path.join(cwd, value)
        try:
            with open(os.path.expanduser(path), encoding="utf-8", errors="replace") as f:
                texts.append((f"`{value}`", f.read()))
        except OSError as error:
            raise Unchecked(f"`{value}` cannot be read ({type(error).__name__}: {error})") from error
    if heredoc_body is not None and not stdin_used:
        raise Unchecked("the heredoc feeds no `--body-file -`")
    return texts


def main():
    """讀 hook 的 JSON 輸入；提到 `gh pr create|edit` 的指令不是允許的寫法、或標題與內文有佔位符時，印出拒絕的
    決定與原因。
    Reads the hook's JSON input and, when a command mentioning `gh pr create|edit` is not in the allowed form or its
    title or body holds a placeholder, prints a deny decision with its reason."""
    # stdin 以 UTF-8 讀，不靠 Python 的預設編碼 ／ stdin is read as UTF-8, not with Python's default encoding
    payload = json.loads(sys.stdin.buffer.read().decode("utf-8", errors="replace"))
    command = payload.get("tool_input", {}).get("command", "")
    joined = re.sub(r"\\\n", " ", command)
    if not any(TRIGGER.search(line) for line in joined.split("\n")):
        return 0
    shell_lines, heredocs = shell_and_heredocs(command)
    if overridden(shell_lines):
        return 0
    try:
        args, heredoc_body = pr_args(shell_lines, heredocs)
        texts = body_texts(args, heredoc_body, payload.get("cwd") or os.getcwd())
    except Unchecked as error:
        deny(f"the PR title or body could not be checked: {error}.\nTo open or edit a PR, {FORM}.")
        return 0
    found = [(name, sorted(set(PLACEHOLDER.findall(text)))) for name, text in texts]
    lines = [f"{name} still holds placeholders: {', '.join(marks)}" for name, marks in found if marks]
    if lines:
        deny("\n".join(lines) + "\nFill them in, then retry.")
    return 0


def deny(reason):
    """印出拒絕的決定與原因，附上照原樣執行的方法（ASCII 跳脫的 JSON，不受 stdout 編碼影響）。
    Prints a deny decision with its reason and the way to run the command as it is (ASCII-escaped JSON, whatever
    stdout's encoding)."""
    reason += f"\nIf the command is meant to run as it is, end its first line with the comment `# {OVERRIDE}`."
    print(json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                                             "permissionDecisionReason": reason}}))


def guarded_main():
    """執行 main()；main() 裡出錯時擋下指令並附上錯誤，而不是以非 0 結束（Claude Code 會把那當成放行）。
    Runs main(); when main() fails it denies the command with the error, rather than exiting non-zero (which Claude
    Code treats as letting the command run)."""
    try:
        return main()
    except Exception as error:  # 任何錯誤都要擋下 ／ any error must deny
        deny(f"guard_pr_placeholder failed, so the command was not checked: {type(error).__name__}: {error}")
        return 0


if __name__ == "__main__":
    sys.exit(guarded_main())
