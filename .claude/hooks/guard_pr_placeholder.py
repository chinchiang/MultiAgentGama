#!/usr/bin/env python3
"""Claude Code 的 PreToolUse hook（Bash）：PR 的標題、內文或合併訊息還有佔位符時，擋下 `gh pr create`／`edit`／`new`／
`merge`。
佔位符是角括號裡只有大寫字母、數字與底線的字（`<[A-Z0-9_]+>`），例如 `<FULL_CHECK_3DD1FC6>`、`<N>`：草稿裡等結果
出來再填的段落用這個寫法。
規則很粗。指令的 `\\` 續行先照 bash 直接接起來（中間不加空白），每一行再拿掉引號與反斜線；只要有一行依序出現
`gh`、`pr` 這兩個字（連字號連著的不算一個字，例如 `chore/gh-pr-x`；heredoc 的內文、引號裡的文字也算），就要檢查：
- 這樣的每一行都沒有 `$` 與反引號，而且每一個 `gh` 後面（只隔著 `-R`／`--repo <repo>`）都緊接 `pr` 與唯讀的子指令
  （`view`、`list`、`checks`、`diff`、`status`）時，放行，指令的其他部分不看；
- 否則整條指令必須是唯一允許的寫法，不然以「無法檢查」擋下：
  - 一條指令就是 `gh [-R <repo>] pr <子指令> <參數>`，可以用 `\\` 續行，最後可以有 `# 註解`；子指令是唯讀的就放行，
    是 `create`、`edit`、`new`、`merge` 的就檢查，其他（`comment`、別名等）以「無法檢查」擋下；
  - 沒有 `$` 與反引號（hook 不展開變數與指令替換，單引號裡的也一樣不收）；引號外沒有 `;`、`&`、`|`、`(`、`)`、
    `<`、`>`，也沒有 shell 會展開的 `{`、`}`、`*`、`?`、`[`；
  - 每個選項都在那個子指令的允許清單（`SUBCOMMAND_OPTIONS`）裡：內文、標題或合併訊息只能來自 `--body`／`-b`、
    `--title`／`-t`、`--subject` 的字面文字，`--body-file`／`-F` 指到的一般檔案（相對路徑以 hook 收到的 cwd 為準，
    路徑裡不能有 `~`），或是 `--body-file -` 加上指令最後、引號包住結束字（`<<'EOF'`）的 heredoc。從別處取內文的
    選項（`--fill`、`--fill-verbose`、`--recover`、`--template`、`--editor`、`--web` 等）不在清單裡；
  - 短選項不能併在一起（`-dF`），值要接在選項後面、用 `=`，或緊接在短選項後面（`-Fx`、`-F=x`）。
  合乎這個寫法時，hook 掃描每一個參數、每一個內文檔與 heredoc 的內文，有佔位符就擋下並列出它們；檔案讀不到或
  不是一般檔案（`/dev/stdin`、FIFO）也以「無法檢查」擋下。
hook 自己出錯時（含讀不懂的輸入）也擋下。
真的要照原樣執行時（包括只是提到 `gh pr` 的 commit 訊息），讓 heredoc 內文以外的某一行以引號外的
`# placeholder-ok` 註解結尾。
已知限制：hook 防的是一般寫法裡不小心帶著佔位符送出，不防刻意拼出來的指令。以下寫法不會觸發檢查：
- `gh api` 或別的工具建立 PR、`gh` 的別名；
- 在觸發的那一行以外把 `gh` 或 `pr` 存進變數；
- 用 `$'…'`、`$"…"` 拼出 `gh` 或 `pr`（`g$'h'`、`p$'r'`、`$'\\x70r'`）；
- 用萬用字元拼出指令名稱（`g?`、`g[h]`、`~/.local/bin/g*`）。
緣由：#216（2026-11-26）的 PR 草稿裡還有兩個等完整重檢結果的佔位符時，就被要求開 PR。第一版逐一解析 shell
寫法，第一輪審查就找到續行、`$(…)`、`env gh`、`if … then`、heredoc 等放行的缺口；第二版只在出現 `create`、`edit`
時檢查，第二輪又找到 `gh pr new`、從字中間切開的續行、`/dev/stdin`、大括號展開等缺口，所以觸發條件也改成粗規則；
第三輪找到沒列入的選項（`--recover`、`--fill`）、會送內文的 `merge` 與觸發行裡的變數，於是選項也改成允許清單。
Claude Code PreToolUse hook (Bash): denies `gh pr create`/`edit`/`new`/`merge` while the PR's title, body or merge
message still holds a placeholder. A placeholder is a word of only upper-case letters, digits and underscores in
angle brackets (`<[A-Z0-9_]+>`), such as `<FULL_CHECK_3DD1FC6>` or `<N>`: drafts use that form for sections waiting
on a result.
The rule is coarse. The command's `\\` continuations are first joined as bash joins them (with nothing in between),
and each line has its quotes and backslashes taken out; when any line then holds the words `gh` and `pr` in that
order (a hyphen joins words, so `chore/gh-pr-x` is not them; heredoc bodies and quoted text count too), the command
is checked:
- when no such line holds `$` or a backtick and every `gh` is followed (past only `-R`/`--repo <repo>`) by `pr` and
  a read-only subcommand (`view`, `list`, `checks`, `diff`, `status`), it is allowed, and the rest of the command is
  not looked at;
- otherwise the whole command must take the one allowed form, or it is denied as unchecked:
  - a single command `gh [-R <repo>] pr <subcommand> <args>`, optionally continued with `\\` and ending in a
    `# comment`; a read-only subcommand is allowed, `create`, `edit`, `new` and `merge` are checked, and any other
    (`comment`, an alias) is denied as unchecked;
  - no `$` and no backtick (the hook does not expand variables or command substitutions, and refuses them inside
    single quotes too); outside quotes, no `;`, `&`, `|`, `(`, `)`, `<` or `>`, and none of the `{`, `}`, `*`, `?`
    and `[` the shell expands;
  - every option is on that subcommand's allow list (`SUBCOMMAND_OPTIONS`): the body, title or merge message comes
    only from the literal text of `--body`/`-b`, `--title`/`-t` or `--subject`, from the regular file named by
    `--body-file`/`-F` (a relative path is taken from the cwd the hook receives, and a path may not hold `~`), or
    from `--body-file -` fed by a heredoc at the end of the command whose terminator is quoted (`<<'EOF'`). Options
    that take the body from elsewhere (`--fill`, `--fill-verbose`, `--recover`, `--template`, `--editor`, `--web` and
    the like) are not on the lists;
  - short options are not bundled (`-dF`), and a value follows its option, an `=`, or the short option itself
    (`-Fx`, `-F=x`).
  In that form the hook scans every argument, every body file and the heredoc body, and denies when any placeholder
  is found, listing them; a file it cannot read, or one that is not a regular file (`/dev/stdin`, a FIFO), is denied
  as unchecked too.
It also denies when the hook itself fails (unreadable input included).
A command meant to run as it is (a commit message that only mentions `gh pr`, say) ends one line outside the heredoc
bodies with the comment `# placeholder-ok`, outside quotes.
Known limits: the hook guards against a placeholder sent by accident in an ordinary command, not against a command
spelled out to dodge it. These do not trigger the check:
- a PR created through `gh api` or another tool, or a `gh` alias;
- `gh` or `pr` kept in a variable set outside the line that triggers;
- `gh` or `pr` spelled with `$'…'` or `$"…"` (`g$'h'`, `p$'r'`, `$'\\x70r'`);
- a command name spelled with a glob (`g?`, `g[h]`, `~/.local/bin/g*`).
Origin: #216 (2026-11-26): opening the PR was asked for while its draft still held two placeholders waiting on the
full check's results. A first version parsed shell forms one by one, and its first review found forms let through in
continuations, `$(…)`, `env gh`, `if … then` and heredocs; a second version checked only when `create` or `edit`
appeared, and its review found `gh pr new`, continuations that split a word, `/dev/stdin` and brace expansion, hence
the coarse trigger; the third review found options not on any list (`--recover`, `--fill`), a `merge` that sends a
body and a variable on the triggering line, hence the option allow lists."""

import json
import os
import re
import shlex
import stat
import sys
from typing import List, NamedTuple, Tuple

OVERRIDE = "placeholder-ok"
PLACEHOLDER = re.compile(r"<[A-Z0-9_]+>")
READ_ONLY = ("view", "list", "checks", "diff", "status")
# 連字號連著的不算一個字（`chore/gh-pr-x`）／ A hyphen joins words (`chore/gh-pr-x`)
GH, PR = r"(?<![\w-])gh(?![\w-])", r"(?<![\w-])pr(?![\w-])"
# 拿掉引號與反斜線之後的一個 `gh`，只隔著 `-R`／`--repo` 接 `pr` 與子指令；group 1 是子指令
# One `gh` with quotes and backslashes taken out, followed past only `-R`/`--repo` by `pr` and a subcommand; group 1
# is the subcommand
GH_PR = re.compile(GH + r"(?:\s+(?:-R|--repo)(?:=|\s+)\S+|\s+(?:-R\S+|--repo=\S+))*\s+pr(?:\s+([\w-]+))?(?![\w-])")
# heredoc 開頭的運算子（不含 here-string 的 `<<<`），以及接在它後面的結束字
# A heredoc start's operator (not a here-string's `<<<`), and the terminator that follows it
HEREDOC_START = re.compile(r"(?<!<)<<(?!<)(-?)\s*")
HEREDOC_WORD = re.compile(r"(['\"]?)([A-Za-z_]\w*)\1")
OPERATOR_CHARS = set("();<>|&")
EXPANDING_CHARS = "{}*?["
# 每個檢查的子指令允許的選項：flag 不帶值，value 帶一個值（照樣掃描），file 帶一個內文檔；`-R`／`--repo` 每個都收
# The options each checked subcommand allows: a flag takes no value, a value option takes one (scanned like any
# argument), a file option takes a body file; `-R`/`--repo` is allowed for each
_BODY = {"--body": "value", "-b": "value", "--body-file": "file", "-F": "file", "--title": "value", "-t": "value",
         "--repo": "value", "-R": "value"}
_CREATE = {**_BODY, "--assignee": "value", "-a": "value", "--base": "value", "-B": "value", "--draft": "flag",
           "-d": "flag", "--dry-run": "flag", "--head": "value", "-H": "value", "--label": "value", "-l": "value",
           "--milestone": "value", "-m": "value", "--no-maintainer-edit": "flag", "--project": "value",
           "-p": "value", "--reviewer": "value", "-r": "value"}
SUBCOMMAND_OPTIONS = {
    "create": _CREATE,
    "new": _CREATE,
    "edit": {**_BODY, "--add-assignee": "value", "--add-label": "value", "--add-project": "value",
             "--add-reviewer": "value", "--base": "value", "-B": "value", "--milestone": "value", "-m": "value",
             "--remove-assignee": "value", "--remove-label": "value", "--remove-milestone": "flag",
             "--remove-project": "value", "--remove-reviewer": "value"},
    "merge": {"--body": "value", "-b": "value", "--body-file": "file", "-F": "file", "--subject": "value",
              "-t": "value", "--repo": "value", "-R": "value", "--admin": "flag", "--author-email": "value",
              "-A": "value", "--auto": "flag", "--delete-branch": "flag", "-d": "flag", "--disable-auto": "flag",
              "--match-head-commit": "value", "--merge": "flag", "-m": "flag", "--rebase": "flag", "-r": "flag",
              "--squash": "flag", "-s": "flag"},
}
ALLOWED_FORM_HINT = ("write it as one command `gh [-R <repo>] pr create|edit|new|merge ...` with only the options the "
                     "hook reads, whose body comes from `--body '<text>'`, `--body-file <path>` or a quoted heredoc "
                     "(`<<'EOF'`) fed to `--body-file -`")


class Unchecked(Exception):
    """指令不是唯一允許的寫法，或讀不到內文 ／ The command is not in the one allowed form, or a body cannot be read."""


class Heredoc(NamedTuple):
    """一個 heredoc：開頭所在的 shell 行號、運算子在那一行的範圍、結束字有沒有引號、內文、有沒有找到結束行。
    One heredoc: the index of the shell line holding its start, the operator's span in that line, whether its
    terminator is quoted, its body, and whether its terminator line was found."""
    index: int
    span: Tuple[int, int]
    quoted: bool
    body: str
    closed: bool


class Shell(NamedTuple):
    """指令拆成 shell 的行（原文與引號遮好的版本）與 heredoc。
    The command split into shell lines (as written and with quotes masked) and heredocs."""
    lines: List[str]
    masks: List[str]
    heredocs: List[Heredoc]


def join_continuations(text):
    """照 bash 把 `\\` 加換行的續行直接接起來，中間不加空白。
    Joins `\\`-newline continuations as bash does, with nothing in between."""
    return re.sub(r"\\\n", "", text)


def plain_lines(command):
    """續行接起來之後的每一行，原文與拿掉引號、反斜線的版本。
    Every line after joining continuations, as written and with quotes and backslashes taken out."""
    return [(line, re.sub(r"['\"\\]", "", line)) for line in join_continuations(command).split("\n")]


def triggered_lines(command):
    """拿掉引號與反斜線之後依序出現 `gh`、`pr` 這兩個字的行，(原文, 拿掉之後)。
    The lines that hold the words `gh` and `pr` in order once quotes and backslashes are taken out, as (written,
    plain)."""
    return [(line, plain) for line, plain in plain_lines(command) if re.search(GH + ".*" + PR, plain)]


def all_read_only(lines):
    """觸發的每一行都沒有 `$` 與反引號，而且每一個後面還有 `pr` 的 `gh` 都只隔著 `-R`／`--repo` 接 `pr` 與唯讀子指令。
    No triggering line holds `$` or a backtick, and on each every `gh` that `pr` follows is followed past only
    `-R`/`--repo` by `pr` and a read-only subcommand."""
    for line, plain in lines:
        if "$" in line or "`" in line:
            return False
        for gh in re.finditer(GH, plain):
            if not re.search(PR, plain[gh.end():]):
                continue
            match = GH_PR.match(plain, gh.start())
            if not match or match.group(1) not in READ_ONLY:
                return False
    return True


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
    """把指令分成 shell 的行與 heredoc；heredoc 的結束字讀不懂時丟出 Unchecked。
    Splits the command into shell lines and heredocs; raises Unchecked when a heredoc's terminator cannot be read."""
    shell = Shell([], [], [])
    pending = []
    lines, k, quote = command.split("\n"), 0, None
    while k < len(lines):
        line = lines[k]
        k += 1
        mask, quote = mask_quotes(line, quote)
        shell.lines.append(line)
        shell.masks.append(mask)
        for match in HEREDOC_START.finditer(mask[:comment_start(mask)]):
            word = HEREDOC_WORD.match(line, match.end())
            if not word:
                raise Unchecked("a heredoc's terminator could not be read")
            # (行號, 範圍, 有沒有引號, `<<-` 去掉 tab, 結束字) ／ (index, span, quoted, `<<-` strips tabs, terminator)
            pending.append((len(shell.lines) - 1, (match.start(), word.end()), bool(word.group(1)),
                            bool(match.group(1)), word.group(2)))
        if quote:
            continue
        for index, span, quoted, strip, terminator in pending:
            body = []
            while k < len(lines) and (lines[k].lstrip("\t") if strip else lines[k]) != terminator:
                body.append(lines[k])
                k += 1
            closed = k < len(lines)
            k += 1 if closed else 0
            shell.heredocs.append(Heredoc(index, span, quoted, "\n".join(body), closed))
        pending = []
    return shell


def overridden(shell):
    """heredoc 以外有一行以引號外的 `# placeholder-ok` 註解結尾。
    A line outside the heredoc bodies ends with the comment `# placeholder-ok`, outside quotes."""
    for line, mask in zip(shell.lines, shell.masks, strict=True):
        start = comment_start(mask)
        if start is not None and line[start + 1:].strip() == OVERRIDE:
            return True
    return False


def is_operator(token):
    """token 是 shell 的運算子（`;`、`&&`、`|`、`(`、`<` 之類）。
    The token is a shell operator (`;`, `&&`, `|`, `(`, `<` and the like)."""
    return bool(token) and set(token) <= OPERATOR_CHARS


def pr_call(shell):
    """確認指令是唯一允許的寫法，回傳 (子指令, 它之後的參數, heredoc 的內文或 None)；不是就丟出 Unchecked。
    Checks that the command takes the one allowed form and returns (the subcommand, the args after it, the heredoc
    body or None); raises Unchecked otherwise."""
    lines, masks = list(shell.lines), list(shell.masks)
    while lines and not lines[-1].strip():
        lines.pop()
        masks.pop()
    heredoc_body = None
    if shell.heredocs:
        if len(shell.heredocs) > 1:
            raise Unchecked("the command holds more than one heredoc")
        heredoc = shell.heredocs[0]
        if not heredoc.closed or heredoc.index != len(lines) - 1:
            raise Unchecked("the heredoc is not the last thing in the command")
        if not heredoc.quoted:
            raise Unchecked("the heredoc's terminator is not quoted, so the shell expands `$` in its body")
        heredoc_body = heredoc.body
        (start, end), i = heredoc.span, heredoc.index
        lines[i] = lines[i][:start] + " " * (end - start) + lines[i][end:]
        masks[i] = masks[i][:start] + " " * (end - start) + masks[i][end:]
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
    if sub not in READ_ONLY and sub not in SUBCOMMAND_OPTIONS:
        raise Unchecked(f"`gh pr {sub}` is neither a read-only subcommand nor create, edit, new or merge")
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


def option_values(sub, args):
    """照子指令的允許清單讀參數，回傳每一個 file 選項的值；清單外的選項、併在一起的短選項、缺值都丟出 Unchecked。
    Reads the args by the subcommand's allow list and returns the value of every file option; an option off the list,
    bundled short options and a missing value raise Unchecked."""
    options, files, i = SUBCOMMAND_OPTIONS[sub], [], 0
    while i < len(args):
        token, value = args[i], None
        i += 1
        if not token.startswith("-") or token == "-":
            continue
        if token.startswith("--"):
            name, _, value = token.partition("=")
            value = value if "=" in token else None
        elif len(token) > 2:
            name, value = token[:2], token[2:]
            if options.get(name) == "flag" or name not in options:
                raise Unchecked(f"`{token}` bundles short options")
            value = value[1:] if value.startswith("=") else value
        else:
            name = token
        if name not in options:
            raise Unchecked(f"`{name}` is not an option the hook reads for `gh pr {sub}`")
        if options[name] == "flag":
            if value is not None:
                raise Unchecked(f"`{token}` gives a value to a flag")
            continue
        if value is None:
            if i >= len(args):
                raise Unchecked(f"`{name}` has no value")
            value = args[i]
            i += 1
        if options[name] == "file":
            files.append((name, value))
    return files


def body_texts(sub, args, heredoc_body, cwd):
    """參數裡每一個要掃描的文字：(名稱, 文字)。參數本身、內文檔、heredoc 的內文都算。
    Every text to scan among the args, as (name, text): the args themselves, the body files and the heredoc body."""
    texts = [("the command's arguments", "\n".join(args))]
    stdin_used = False
    for name, value in option_values(sub, args):
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
    lines = triggered_lines(command)
    if not lines or all_read_only(lines):
        return 0
    try:
        shell = parse_shell(command)
        if overridden(shell):
            return 0
        sub, args, heredoc_body = pr_call(shell)
        if sub in READ_ONLY:
            return 0
        texts = body_texts(sub, args, heredoc_body, payload.get("cwd") or os.getcwd())
    except Unchecked as error:
        deny(f"the PR title or body could not be checked: {error}.\nTo open, edit or merge a PR, {ALLOWED_FORM_HINT}.")
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
