#!/usr/bin/env python3
"""Claude Code 的 PreToolUse hook（Bash）：PR 的標題或內文還有佔位符時，擋下 `gh pr create`／`gh pr edit`／`gh pr new`。
佔位符是角括號裡只有大寫字母、數字與底線的字（`<[A-Z0-9_]+>`），例如 `<FULL_CHECK_3DD1FC6>`、`<N>`：草稿裡等結果
出來再填的段落用這個寫法。
規則很粗。指令的 `\\` 續行先照 bash 直接接起來（中間不加空白），每一行再拿掉引號與反斜線；只要有一行依序出現
`gh`、`pr` 這兩個字（heredoc 的內文、引號裡的文字也算），就要檢查：
- 每一個 `gh` 後面（只隔著 `-R`／`--repo <repo>`）都緊接 `pr` 與唯讀的子指令（`view`、`list`、`checks`、`diff`、
  `status`、`merge`）時，放行，指令的其他部分不看；
- 否則整條指令必須是唯一允許的寫法，不然以「無法檢查」擋下：
  - 一條指令就是 `gh [-R <repo>] pr <子指令> <參數>`，可以用 `\\` 續行，最後可以有 `# 註解`；子指令是唯讀的就放行，
    是 `create`、`edit`、`new` 的就檢查內文，其他（`comment`、別名等）以「無法檢查」擋下；
  - 沒有 `$` 與反引號（hook 不展開變數與指令替換，單引號裡的也一樣不收）；引號外沒有 `;`、`&`、`|`、`(`、`)`、
    `<`、`>`，也沒有 shell 會展開的 `{`、`}`、`*`、`?`、`[`；
  - 內文來自 `--body`／`-b` 的字面文字、`--body-file`／`-F` 或 `--template`／`-T` 指到的一般檔案（相對路徑以 hook
    收到的 cwd 為準，路徑裡不能有 `~`），或是 `--body-file -` 加上指令最後、引號包住結束字（`<<'EOF'`）的 heredoc；
  - 短選項不能併在一起（`-dF`），值要接在選項後面或用 `=`。
  合乎這個寫法時，hook 掃描每一個參數、每一個內文檔與 heredoc 的內文，有佔位符就擋下並列出它們；檔案讀不到或
  不是一般檔案（`/dev/stdin`、FIFO）也以「無法檢查」擋下。
hook 自己出錯時（含讀不懂的輸入）也擋下。
真的要照原樣執行時（包括只是提到 `gh pr` 的 commit 訊息），讓 heredoc 內文以外的某一行以引號外的
`# placeholder-ok` 註解結尾。
已知限制：`gh api` 或別的工具建立 PR，以及文字裡沒有 `gh` 與 `pr` 這兩個字的寫法（`gh` 的別名、存在變數裡的
`gh`）都不檢查。
緣由：#216（2026-11-26）的 PR 草稿裡還有兩個等完整重檢結果的佔位符時，就被要求開 PR。第一版逐一解析 shell
寫法，第一輪審查就找到續行、`$(…)`、`env gh`、`if … then`、heredoc 等放行的缺口；第二版只在出現 `create`、`edit`
時檢查，第二輪又找到 `gh pr new`、從字中間切開的續行、`/dev/stdin`、大括號展開等缺口，所以觸發條件也改成這個粗規則。
Claude Code PreToolUse hook (Bash): denies `gh pr create`/`gh pr edit`/`gh pr new` while the PR's title or body
still holds a placeholder. A placeholder is a word of only upper-case letters, digits and underscores in angle
brackets (`<[A-Z0-9_]+>`), such as `<FULL_CHECK_3DD1FC6>` or `<N>`: drafts use that form for sections waiting on a
result.
The rule is coarse. The command's `\\` continuations are first joined as bash joins them (with nothing in between),
and each line has its quotes and backslashes taken out; when any line then holds the words `gh` and `pr` in that
order (heredoc bodies and quoted text count too), the command is checked:
- when every `gh` is followed (past only `-R`/`--repo <repo>`) by `pr` and a read-only subcommand (`view`, `list`,
  `checks`, `diff`, `status`, `merge`), it is allowed, and the rest of the command is not looked at;
- otherwise the whole command must take the one allowed form, or it is denied as unchecked:
  - a single command `gh [-R <repo>] pr <subcommand> <args>`, optionally continued with `\\` and ending in a
    `# comment`; a read-only subcommand is allowed, `create`, `edit` and `new` have their body checked, and any other
    (`comment`, an alias) is denied as unchecked;
  - no `$` and no backtick (the hook does not expand variables or command substitutions, and refuses them inside
    single quotes too); outside quotes, no `;`, `&`, `|`, `(`, `)`, `<` or `>`, and none of the `{`, `}`, `*`, `?`
    and `[` the shell expands;
  - the body comes from the literal text of `--body`/`-b`, from the regular file named by `--body-file`/`-F` or
    `--template`/`-T` (a relative path is taken from the cwd the hook receives, and a path may not hold `~`), or
    from `--body-file -` fed by a heredoc at the end of the command whose terminator is quoted (`<<'EOF'`);
  - short options are not bundled (`-dF`), and a value follows its option or an `=`.
  In that form the hook scans every argument, every body file and the heredoc body, and denies when any placeholder
  is found, listing them; a file it cannot read, or one that is not a regular file (`/dev/stdin`, a FIFO), is denied
  as unchecked too.
It also denies when the hook itself fails (unreadable input included).
A command meant to run as it is (a commit message that only mentions `gh pr`, say) ends one line outside the heredoc
bodies with the comment `# placeholder-ok`, outside quotes.
Known limit: a PR created through `gh api` or another tool, or written without the words `gh` and `pr` (a `gh`
alias, a `gh` kept in a variable), is not checked.
Origin: #216 (2026-11-26): opening the PR was asked for while its draft still held two placeholders waiting on the
full check's results. A first version parsed shell forms one by one, and its first review found forms let through in
continuations, `$(…)`, `env gh`, `if … then` and heredocs; a second version checked only when `create` or `edit`
appeared, and its review found `gh pr new`, continuations that split a word, `/dev/stdin` and brace expansion, hence
this coarse trigger too."""

import json
import os
import re
import shlex
import stat
import sys

OVERRIDE = "placeholder-ok"
PLACEHOLDER = re.compile(r"<[A-Z0-9_]+>")
READ_ONLY = ("view", "list", "checks", "diff", "status", "merge")
CHECKED = ("create", "edit", "new")
# 拿掉引號與反斜線之後的一個 `gh`，只隔著 `-R`／`--repo` 接 `pr` 與子指令；group 1 是子指令
# One `gh` with quotes and backslashes taken out, followed past only `-R`/`--repo` by `pr` and a subcommand; group 1
# is the subcommand
GH_PR = re.compile(r"\bgh(?:\s+(?:-R|--repo)(?:=|\s+)\S+|\s+(?:-R\S+|--repo=\S+))*\s+pr(?:\s+([\w-]+))?\b")
# heredoc 開頭的運算子（不含 here-string 的 `<<<`），以及接在它後面的結束字
# A heredoc start's operator (not a here-string's `<<<`), and the terminator that follows it
HEREDOC_START = re.compile(r"(?<!<)<<(?!<)(-?)\s*")
HEREDOC_WORD = re.compile(r"(['\"]?)([A-Za-z_]\w*)\1")
OPERATOR_CHARS = set("();<>|&")
EXPANDING_CHARS = "{}*?["
# `pr` 子指令的選項：值是字面文字（text）、檔案（file）或其他（value）
# Options of the `pr` subcommands: their value is literal text, a file, or something else
OPTIONS = {"--body": "text", "-b": "text", "--title": "text", "-t": "text", "--body-file": "file", "-F": "file",
           "--template": "file", "-T": "file", "--repo": "value", "-R": "value"}
ALLOWED_FORM_HINT = ("write it as one command `gh [-R <repo>] pr create|edit|new ...` whose body comes from "
                     "`--body '<text>'`, `--body-file <path>` or a quoted heredoc (`<<'EOF'`) fed to `--body-file -`")


class Unchecked(Exception):
    """指令不是唯一允許的寫法，或讀不到內文 ／ The command is not in the one allowed form, or a body cannot be read."""


def join_continuations(text):
    """照 bash 把 `\\` 加換行的續行直接接起來，中間不加空白。
    Joins `\\`-newline continuations as bash does, with nothing in between."""
    return re.sub(r"\\\n", "", text)


def mask_quotes(line, quote=None):
    """把引號裡的字（含引號本身）與反斜線跳脫的字換成 `_`，回傳 (遮好的行, 行尾還沒關的引號)；quote 是上一行
    留下來還沒關的引號。
    Replaces quoted characters (the quotes included) and backslash-escaped ones with `_`, returning (the masked line,
    the quote still open at the line's end); quote is the one left open by the line before."""
    out, i = [], 0
    while i < len(line):
        ch = line[i]
        if quote:
            if ch == "\\" and quote == '"' and i + 1 < len(line):
                out.append("__")
                i += 2
                continue
            if ch == quote:
                quote = None
            out.append("_")
        elif ch in "'\"":
            quote = ch
            out.append("_")
        elif ch == "\\" and i + 1 < len(line):
            out.append("__")
            i += 2
            continue
        else:
            out.append(ch)
        i += 1
    return "".join(out), quote


def comment_start(mask):
    """遮好的行裡，註解開始的 `#` 的位置（引號外、在行首或空白之後）；沒有時是 None。
    Where the comment's `#` starts in a masked line (outside quotes, at the start or after whitespace), or None."""
    for i, ch in enumerate(mask):
        if ch == "#" and (i == 0 or mask[i - 1].isspace()):
            return i
    return None


def parse_shell(command):
    """把指令分成 shell 的行與 heredoc。回傳 (shell 的行, 遮好的 shell 的行, heredoc 清單)；每個 heredoc 是
    (開頭所在的 shell 行號, 運算子在行裡的範圍, 結束字有沒有引號, 內文, 有沒有結束行)。
    Splits the command into shell lines and heredocs. Returns (shell lines, masked shell lines, heredocs); each heredoc
    is (index of the shell line holding its start, the operator's span in that line, whether its terminator is
    quoted, its body, whether its terminator line was found)."""
    shell, masks, heredocs, pending = [], [], [], []
    lines, k, quote = command.split("\n"), 0, None
    while k < len(lines):
        line = lines[k]
        k += 1
        mask, quote = mask_quotes(line, quote)
        shell.append(line)
        masks.append(mask)
        end = comment_start(mask)
        for match in HEREDOC_START.finditer(mask[:end]):
            word = HEREDOC_WORD.match(line, match.end())
            if not word:
                raise Unchecked("a heredoc's terminator could not be read")
            pending.append((len(shell) - 1, (match.start(), word.end()), bool(word.group(1)), bool(match.group(1)),
                            word.group(2)))
        if quote:
            continue
        for index, span, quoted, strip, terminator in pending:
            body = []
            while k < len(lines) and (lines[k].lstrip("\t") if strip else lines[k]) != terminator:
                body.append(lines[k])
                k += 1
            closed = k < len(lines)
            k += 1 if closed else 0
            heredocs.append((index, span, quoted, "\n".join(body), closed))
        pending = []
    return shell, masks, heredocs


def overridden(shell, masks):
    """heredoc 以外有一行以引號外的 `# placeholder-ok` 註解結尾。
    A line outside the heredoc bodies ends with the comment `# placeholder-ok`, outside quotes."""
    for line, mask in zip(shell, masks, strict=True):
        start = comment_start(mask)
        if start is not None and line[start + 1:].strip() == OVERRIDE:
            return True
    return False


def all_read_only(command):
    """拿掉引號與反斜線之後，每一行裡每一個後面還有 `pr` 的 `gh`，都只隔著 `-R`／`--repo` 接 `pr` 與唯讀子指令。
    With quotes and backslashes taken out, on every line every `gh` that `pr` follows is followed past only
    `-R`/`--repo` by `pr` and a read-only subcommand."""
    for line in join_continuations(command).split("\n"):
        plain = re.sub(r"['\"\\]", "", line)
        for gh in re.finditer(r"\bgh\b", plain):
            if not re.search(r"\bpr\b", plain[gh.end():]):
                continue
            match = GH_PR.match(plain, gh.start())
            if not match or match.group(1) not in READ_ONLY:
                return False
    return True


def triggered(command):
    """`\\` 續行接起來、拿掉引號與反斜線之後，有一行依序出現 `gh`、`pr` 這兩個字。
    After joining `\\` continuations and taking out quotes and backslashes, some line holds the words `gh` and `pr`
    in that order."""
    return any(re.search(r"\bgh\b.*\bpr\b", re.sub(r"['\"\\]", "", line))
               for line in join_continuations(command).split("\n"))


def is_operator(token):
    """token 是 shell 的運算子（`;`、`&&`、`|`、`(`、`<` 之類）。
    The token is a shell operator (`;`, `&&`, `|`, `(`, `<` and the like)."""
    return bool(token) and set(token) <= OPERATOR_CHARS


def pr_call(shell, masks, heredocs):
    """確認指令是唯一允許的寫法，回傳 (子指令, 它之後的參數, heredoc 的內文或 None)；不是就丟出 Unchecked。
    Checks that the command takes the one allowed form and returns (the subcommand, the args after it, the heredoc
    body or None); raises Unchecked otherwise."""
    lines, masks = list(shell), list(masks)
    while lines and not lines[-1].strip():
        lines.pop()
        masks.pop()
    heredoc_body = None
    if heredocs:
        if len(heredocs) > 1:
            raise Unchecked("the command holds more than one heredoc")
        index, (start, end), quoted, heredoc_body, closed = heredocs[0]
        if not closed or index != len(lines) - 1:
            raise Unchecked("the heredoc is not the last thing in the command")
        if not quoted:
            raise Unchecked("the heredoc's terminator is not quoted, so the shell expands `$` in its body")
        lines[index] = lines[index][:start] + " " * (end - start) + lines[index][end:]
        masks[index] = masks[index][:start] + " " * (end - start) + masks[index][end:]
    cut = [comment_start(mask) for mask in masks]
    text = join_continuations("\n".join(line[:c] for line, c in zip(lines, cut, strict=True)))
    masked = join_continuations("\n".join(mask[:c] for mask, c in zip(masks, cut, strict=True)))
    if "\n" in text.strip():
        raise Unchecked("the command spans several lines that are not `\\` continuations")
    if "$" in text or "`" in text:
        raise Unchecked("the command holds `$` or a backtick, which the hook does not expand")
    expanding = [ch for ch in EXPANDING_CHARS if ch in masked]
    if expanding:
        raise Unchecked(f"the command holds `{expanding[0]}` outside quotes, which the shell expands")
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
    if tokens[i:i + 1] != ["pr"] or len(tokens) < i + 2:
        raise Unchecked("the command is not `gh [-R <repo>] pr <subcommand> ...`")
    sub = tokens[i + 1]
    if sub not in READ_ONLY + CHECKED:
        raise Unchecked(f"`gh pr {sub}` is neither a read-only subcommand nor create, edit or new")
    return sub, tokens[i + 2:], heredoc_body


def read_body_file(value, cwd):
    """讀一個內文檔：只收一般檔案，路徑裡不能有 `~`；不是就丟出 Unchecked。
    Reads one body file: only a regular file, with no `~` in its path; raises Unchecked otherwise."""
    if "~" in value:
        raise Unchecked(f"`{value}` holds `~`, which the hook does not expand")
    path = value if os.path.isabs(value) else os.path.join(cwd, value)
    try:
        if not stat.S_ISREG(os.stat(path).st_mode):
            raise Unchecked(f"`{value}` is not a regular file")
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError as error:
        raise Unchecked(f"`{value}` cannot be read ({type(error).__name__}: {error})") from error


def body_texts(args, heredoc_body, cwd):
    """參數裡每一個要掃描的文字：(名稱, 文字)。參數本身、內文檔、heredoc 的內文都算。
    Every text to scan among the args, as (name, text): the args themselves, the body files and the heredoc body."""
    texts = [("the command's arguments", "\n".join(args))]
    stdin_used = False
    for i, token in enumerate(args):
        if token in OPTIONS:
            if i + 1 >= len(args):
                raise Unchecked(f"`{token}` has no value")
            name, value = token, args[i + 1]
        elif token.startswith("--") and "=" in token and token.split("=", 1)[0] in OPTIONS:
            name, value = token.split("=", 1)
        elif re.fullmatch(r"-[A-Za-z].+", token):
            if token[:2] not in OPTIONS:
                raise Unchecked(f"`{token}` bundles short options")
            name, value = token[:2], token[2:]
        else:
            continue
        if OPTIONS[name] != "file":
            continue
        if value == "-":
            if heredoc_body is None:
                raise Unchecked(f"`{name} -` reads stdin, and no heredoc at the end of the command feeds it")
            stdin_used = True
            texts.append(("the heredoc body", heredoc_body))
        else:
            texts.append((f"`{value}`", read_body_file(value, cwd)))
    if heredoc_body is not None and not stdin_used:
        raise Unchecked("the heredoc feeds no `--body-file -`")
    return texts


def main():
    """讀 hook 的 JSON 輸入；提到 `gh pr` 的指令不是允許的寫法、或標題與內文有佔位符時，印出拒絕的決定與原因。
    Reads the hook's JSON input and, when a command mentioning `gh pr` is not in the allowed form or its title or body
    holds a placeholder, prints a deny decision with its reason."""
    # stdin 以 UTF-8 讀，不靠 Python 的預設編碼 ／ stdin is read as UTF-8, not with Python's default encoding
    payload = json.loads(sys.stdin.buffer.read().decode("utf-8", errors="replace"))
    command = payload.get("tool_input", {}).get("command", "")
    if not triggered(command) or all_read_only(command):
        return 0
    try:
        shell, masks, heredocs = parse_shell(command)
        if overridden(shell, masks):
            return 0
        sub, args, heredoc_body = pr_call(shell, masks, heredocs)
        if sub in READ_ONLY:
            return 0
        texts = body_texts(args, heredoc_body, payload.get("cwd") or os.getcwd())
    except Unchecked as error:
        deny(f"the PR title or body could not be checked: {error}.\nTo open or edit a PR, {ALLOWED_FORM_HINT}.")
        return 0
    found = [(name, sorted(set(PLACEHOLDER.findall(text)))) for name, text in texts]
    report = [f"{name} still holds placeholders: {', '.join(marks)}" for name, marks in found if marks]
    if report:
        deny("\n".join(report) + "\nFill them in, then retry.")
    return 0


def deny(reason):
    """印出拒絕的決定與原因，附上照原樣執行的方法（ASCII 跳脫的 JSON，不受 stdout 編碼影響）。
    Prints a deny decision with its reason and the way to run the command as it is (ASCII-escaped JSON, whatever
    stdout's encoding)."""
    reason += (f"\nIf the command is meant to run as it is, end a line outside the heredoc bodies with the comment "
               f"`# {OVERRIDE}`.")
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
