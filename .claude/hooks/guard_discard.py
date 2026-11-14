#!/usr/bin/env python3
"""Claude Code 的 PreToolUse hook（Bash）：擋下會清掉還沒 commit 的改動的 git 指令。
涵蓋 `git checkout ... -- <路徑>`（以及 `git checkout <存在的路徑>`）、`git restore <路徑>`（只有 `--staged` 的除外）、
`git checkout -f`、`git switch -f`／`--discard-changes`、`git reset --hard`、`git reset --merge` 與 `git clean`。
它問 git 受影響的已追蹤路徑裡，哪些有指令會蓋掉的還沒 commit 的改動，有就擋下並列出它們：沒有來源的 `checkout`
只看工作目錄跟 index 的差異（暫存的改動留得住）；`restore` 與有來源的 `checkout` 也算暫存的改動；`reset` 與強制切換
看跟 HEAD 的差異。它不看指令指定的來源是哪個 commit。這些指令不會動到未追蹤的檔案，所以那些不算；`git clean`
例外：參數照原樣接上 `--no-quiet --no-interactive -n` 交給 git 自己的 dry run，列出會刪掉的未追蹤或被忽略的檔案；
本來就是 dry run 的 `git clean -n` 也一樣檢查。git 答不出來時也擋下，附上 git 的錯誤；hook 自己出錯時也擋下。
真的要丟掉時，讓指令裡任何地方出現 `# discard-ok`（對整條指令比對字串，多行指令的任一行都算，不必是真的註解）。
它跟著 `cd`（含 `{`、`then`、`time [-p]`、`command [-p]`、`builtin`、`VAR=value` 之後的，以及 `cd ~`、`cd`、`cd -`）、
`git -C`、`env -C`／`sudo -D`（也在一組短選項裡，例如 `env -iC`）換目錄，`env -S` 的字串拆成指令再看。
hook 跑的每個 git 都用 C 語系（輸出是英文）、不加引號的檔名，並以 UTF-8 解碼。
已知限制：
- 引號裡的 `(`、`)` 會被當成真的括號。
- `cd` 到它不知道的目錄（`cd $VAR`、`cd "$(…)"`）之後，git 答不出來，後面會丟掉改動的指令被擋下而不是被檢查；
  除非之後的 `cd`、`git -C`、`env -C` 或 `sudo -D` 指向絕對路徑。
- 指令裡第一個 `cd -` 回到 hook 收到的 cwd，不一定是 shell 真正的 `OLDPWD`。
- `~` 一律展開，包括 bash 不展開的 `--chdir=~/x`、`-C~` 與引號裡的 `"~"`；展開用的是 Python 的家目錄，
  在 Windows 上是 `USERPROFILE`，Git Bash 的 `cd` 用的卻是 `HOME`。
緣由：#158（2026-11-13）的 `git checkout -q -- scripts tests` 清掉了還沒 commit 的修正與測試。
Claude Code PreToolUse hook (Bash): denies git commands that would discard uncommitted changes.
Covers `git checkout ... -- <paths>` (and `git checkout <existing path>`), `git restore <paths>` (unless only
`--staged`), `git checkout -f`, `git switch -f`/`--discard-changes`, `git reset --hard`, `git reset --merge` and
`git clean`.
It asks git which of the affected tracked paths have uncommitted changes the command would overwrite, and denies
when any do, listing them: a `checkout` without a source looks only at the working tree against the index (a staged
change survives it); `restore` and a `checkout` with a source count staged changes too; `reset` and forced switches
look at the difference from HEAD. Which commit a command restores from is not consulted. These commands leave
untracked files alone, so those do not count. `git clean` is the exception: its args, kept as they are and followed
by `--no-quiet --no-interactive -n`, go to git's own dry run, which lists the untracked or ignored files it would
remove; a `git clean -n` that already is a dry run is checked all the same. It also denies, with git's error, when
git cannot answer, and denies when the hook itself fails. A command that
really means to discard them contains `# discard-ok` anywhere (a substring match on the whole command, so any line
of a multi-line command counts, and it need not be a real comment).
It follows `cd` (also after `{`, `then`, `time [-p]`, `command [-p]`, `builtin` or a `VAR=value`, and `cd ~`, a bare
`cd`, `cd -`), `git -C` and `env -C`/`sudo -D` (also inside a short-option cluster such as `env -iC`) into their
directories, and checks the string of `env -S` as the command. Every git the hook runs uses the C locale (English
output) and unquoted file names, and is decoded as UTF-8.
Known limits:
- A quoted `(` or `)` is taken for a real one.
- After a `cd` to a directory it cannot know (`cd $VAR`, `cd "$(…)"`) git cannot answer, so a following discarding
  command is denied rather than checked, unless a later `cd`, `git -C`, `env -C` or `sudo -D` names an absolute
  directory.
- The first `cd -` in a command goes back to the cwd the hook received, which need not be the shell's `OLDPWD`.
- `~` is always expanded, also where bash would not (`--chdir=~/x`, `-C~`, a quoted `"~"`), and with Python's home
  directory: on Windows that is `USERPROFILE`, while Git Bash's `cd` uses `HOME`.
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
# 包裝指令自己的選項裡帶一個值的那些，以及這個值的作用：value 只是跳過，chdir 是換目錄，split 是把值拆成指令
# （其他以 - 開頭的選項單獨跳過）
# The options of wrapper commands that take a value, and what the value does: value is only skipped, chdir changes
# the directory, split turns the value into the command (other options starting with - are skipped on their own)
WRAPPER_VALUE_OPTS = {
    "env": {"-u": "value", "--unset": "value", "-C": "chdir", "--chdir": "chdir", "-S": "split",
            "--split-string": "split"},
    "sudo": {"-u": "value", "--user": "value", "-g": "value", "--group": "value", "-D": "chdir", "--chdir": "chdir"},
}
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


# 出現在 cd 前面、要先跳過的 shell 關鍵字與前綴（cd 在它們之後仍在目前的 shell 裡生效）；
# 帶選項的前綴（`time -p`、`command -p`），選項也一起跳過
# Shell keywords and prefixes in front of a cd, skipped first (the cd after them still acts in the current shell);
# for the prefixes that take options (`time -p`, `command -p`) the options are skipped too
CD_PREFIXES = {"{", "}", "then", "do", "else", "elif", "if", "while", "until", "!", "time", "command", "builtin"}
CD_PREFIXES_WITH_OPTIONS = {"time", "command"}


def assignment(token):
    """token 是 shell 的 `VAR=value` 指派時為真（不是以 `-` 開頭的選項）。
    True when token is a shell `VAR=value` assignment (not an option starting with `-`)."""
    return "=" in token and not token.startswith("-")


def cd_to(tokens, cwd, previous):
    """tokens 是一個 `cd`（前面可以有 `{`、`then`、`time`、`command`、`builtin` 或 `VAR=value`）時，回傳它換到的目錄，
    否則回傳 None。
    `~` 展開成家目錄，不帶參數時是家目錄，`cd -` 回到 previous（上一個 cd 之前的目錄，一開始是 hook 收到的 cwd）。
    The directory a `cd` moves to when tokens are one (possibly after `{`, `then`, `time`, `command`, `builtin` or a
    `VAR=value`), else None.
    `~` expands to the home directory, a bare `cd` goes home, and `cd -` goes back to previous (the directory before
    the last cd, at first the cwd the hook received)."""
    while tokens and (tokens[0] in CD_PREFIXES or assignment(tokens[0])):
        prefix, tokens = tokens[0], tokens[1:]
        while prefix in CD_PREFIXES_WITH_OPTIONS and tokens and tokens[0].startswith("-"):
            tokens = tokens[1:]
    if not tokens or tokens[0] != "cd":
        return None
    # cd 自己的選項（-L、-P、-e、-@）不是目標 ／ cd's own options (-L, -P, -e, -@) are not the target
    targets = [t for t in tokens[1:] if not (t.startswith("-") and t != "-")]
    if not targets:
        return os.path.expanduser("~")
    if targets[0] == "-":
        return previous
    return os.path.join(cwd, os.path.expanduser(targets[0]))


def wrapper_option(tokens, value_opts):
    """tokens[0] 是 value_opts 裡帶值的選項時，回傳 ((作用, 值), 剩下的 token)；值可以是下一個 token、
    `--選項=值` 或黏在短選項後面，也可以在一組短選項裡（`-C目錄`、`-iC 目錄`）。不是時回傳 (None, tokens)。
    When tokens[0] is a value-taking option from value_opts, returns ((action, value), remaining tokens); the value
    is the next token, follows `--option=` or is attached to a short option, also inside a cluster (`-Cdir`,
    `-iC dir`). Otherwise returns (None, tokens)."""
    token = tokens[0]
    if token.startswith("--") and "=" in token:
        name, value = token.split("=", 1)
        if name in value_opts:
            return (value_opts[name], value), tokens[1:]
    elif token in value_opts and len(tokens) > 1:
        return (value_opts[token], tokens[1]), tokens[2:]
    elif not token.startswith("--"):
        # 一組短選項（`-iC dir`、`-iCdir`）：第一個帶值的選項之後的字元是它的值，沒有時值是下一個 token
        # A short-option cluster (`-iC dir`, `-iCdir`): the characters after its first value-taking option are the
        # value, or the next token when there are none
        for at, letter in enumerate(token[1:], start=1):
            if "-" + letter in value_opts:
                value = token[at + 1:]
                if value:
                    return (value_opts["-" + letter], value), tokens[1:]
                if len(tokens) > 1:
                    return (value_opts["-" + letter], tokens[1]), tokens[2:]
                break
    return None, tokens


def git_call(tokens, cwd):
    """一個 git 呼叫的 (執行目錄, 子指令, 參數)；不是 git 呼叫時回傳 None。
    The (directory, subcommand, args) of a git invocation, else None."""
    # 先跳過 shell 關鍵字、VAR=value 指派與包裝指令
    # Skip shell keywords, VAR=value assignments and wrapper commands first
    while tokens and (tokens[0] in SHELL_PREFIXES or assignment(tokens[0])):
        value_opts = WRAPPER_VALUE_OPTS.get(tokens[0], {})
        tokens = tokens[1:]
        # env、sudo 這類包裝指令的選項（例如 `env -i`、`sudo -u 某人`）也跳過；換目錄的跟著換，`env -S` 的值拆成指令
        # Skip the options of wrappers such as env and sudo too (for example `env -i`, `sudo -u someone`); follow
        # the ones that change directory, and split the value of `env -S` into the command
        while value_opts and tokens and tokens[0].startswith("-"):
            option, rest = wrapper_option(tokens, value_opts)
            if option is None:
                tokens = tokens[1:]
                continue
            action, value = option
            tokens = rest
            if action == "chdir":
                cwd = os.path.join(cwd, os.path.expanduser(value))
            elif action == "split":
                # 拆出來的字串可能還以 env 自己的選項開頭（`env -S "-i git …"`），所以繼續跳過選項
                # The split string may still start with env's own options (`env -S "-i git …"`), so keep skipping
                try:
                    tokens = shlex.split(value) + tokens
                except ValueError:
                    return None
    if not tokens or os.path.basename(tokens[0]) != "git":
        return None
    i = 1
    while i < len(tokens) and tokens[i].startswith("-"):
        opt = tokens[i]
        if opt in GIT_VALUE_OPTS and i + 1 < len(tokens):
            if opt == "-C":
                cwd = os.path.join(cwd, os.path.expanduser(tokens[i + 1]))
            i += 2
        else:
            i += 1
    if i >= len(tokens):
        return None
    return cwd, tokens[i], tokens[i + 1:]


class GitFailed(Exception):
    """hook 問 git 時 git 失敗；訊息是 git 的 stderr。
    git failed when the hook asked it something; the message is git's stderr."""


def os_arg(text):
    """要交給作業系統的參數或路徑：POSIX 上自己以 UTF-8 編成位元組（Python 的檔案系統編碼可能是 ASCII），
    Windows 上照原樣（程序參數本來就是 Unicode）。
    An argument or path for the operating system: on POSIX it is encoded as UTF-8 bytes here (Python's file-system
    encoding may be ASCII), on Windows it stays as it is (process arguments are Unicode there)."""
    return text if os.name == "nt" else text.encode("utf-8", errors="surrogateescape")


def run(cwd, *args):
    """在 cwd 執行 git，回傳 stdout；git 失敗時丟出 GitFailed，訊息是 stderr 的第一行；git 或 cwd 找不到時，
    訊息是找不到的那一個。
    Runs git in cwd and returns its stdout; raises GitFailed carrying the first line of stderr when git fails, or
    naming whichever of git and cwd cannot be found."""
    try:
        # 固定 C 語系：hook 解析 git 的英文輸出（`Would remove`），開發者的語系會讓 git 改說別的語言
        # Pin the C locale: the hook parses git's English output (`Would remove`), and the developer's locale would
        # make git speak another language
        env = {k: v for k, v in os.environ.items() if k != "LANGUAGE"}
        env["LC_ALL"] = "C"
        # 檔名不加引號（`core.quotePath=false`）並以 UTF-8 解碼，不靠 Python 的預設編碼
        # File names unquoted (`core.quotePath=false`) and decoded as UTF-8, not with Python's default encoding
        done = subprocess.run([os_arg(a) for a in ("git", "-c", "core.quotePath=false", *args)], cwd=os_arg(cwd),
                              env=env, capture_output=True, text=True, encoding="utf-8", errors="replace")
    except (NotADirectoryError, FileNotFoundError) as error:
        # 找不到的是 git 或 cwd；路徑以文字寫出，不是 os_arg 編成的位元組
        # What cannot be found is git or cwd; the path is spelt as text, not as the bytes os_arg made
        name = error.filename or cwd
        if isinstance(name, bytes):
            name = name.decode("utf-8", errors="replace")
        raise GitFailed(f"{name}: {error.strerror}") from error
    if done.returncode != 0:
        first = next((line for line in done.stderr.splitlines() if line.strip()), "")
        raise GitFailed(first.strip() or f"git {' '.join(args)} exited {done.returncode}")
    return done.stdout


def dirty(cwd, mode, paths):
    """指令會丟掉的路徑；git 失敗時丟出 GitFailed。clean 以外的模式：`paths` 裡（空的時候是全部）有還沒 commit 的
    改動的已追蹤路徑。clean 模式：`paths` 是 `git clean` 的參數，回傳 git 的 dry run 列出的未追蹤或被忽略的檔案。
    The paths the command would lose; raises GitFailed when git fails. Outside clean mode: the tracked paths among
    `paths` (all of them when empty) with uncommitted changes. In clean mode `paths` are the `git clean` args, and the
    untracked or ignored files git's dry run lists are returned."""
    spec = ["--", *paths] if paths else []
    if mode == "clean":
        # git clean：git 的 dry run 列出的就是會被刪掉的（未追蹤或被忽略的）檔案，paths 是它的參數
        # git clean: what git's dry run lists is what would be removed (untracked or ignored files); paths are its
        # args
        out = run(cwd, "clean", *as_dry_run(paths))
        prefix = "Would remove "
        return sorted(line[len(prefix):] for line in out.splitlines() if line.startswith(prefix))
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


def as_dry_run(args):
    """`git clean` 的參數照原樣保留，在 `--`（沒有時是最後）之前接上 `--no-quiet --no-interactive -n`：git 的選項
    後面的蓋過前面的，所以不論原本怎麼寫（`-q`、縮寫的 `--qui`、`-i`），git 都只做 dry run 並列出會刪掉的檔案。
    `-e` 的值、`-f` 的次數與 pathspec 都由 git 自己解讀。
    Keeps the `git clean` args as they are and puts `--no-quiet --no-interactive -n` before `--` (or at the end when
    there is none): a later git option overrides an earlier one, so however the original is spelt (`-q`, an
    abbreviated `--qui`, `-i`), git only does a dry run and lists what it would remove. The values of `-e`, how many
    times `-f` is given and the pathspecs are left for git to read."""
    at = args.index("--") if "--" in args else len(args)
    return [*args[:at], "--no-quiet", "--no-interactive", "-n", *args[at:]]


def affected(cwd, sub, args):
    """這個 git 呼叫可能丟掉改動時回傳 (模式, 路徑)，clean 模式時第二項是 `git clean` 的參數；否則回傳 None。
    (mode, paths) when the git call can discard changes, the second item being the `git clean` args in clean mode;
    else None."""
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
    if sub == "clean":
        # 一律交給 git 自己的 dry run 列出會刪掉什麼，連本來就是 dry run 的也一樣（判斷它要重寫 git 的選項解析）
        # Always let git's own dry run list what would be removed, even for a call that already is one (telling it
        # apart would mean reimplementing git's option parsing)
        return ("clean", args)
    if sub == "reset" and ("--hard" in args or "--merge" in args):
        return ("head", [])
    return None


def main():
    """讀 hook 的 JSON 輸入；有指令會丟掉改動時，印出拒絕的決定與原因。
    Reads the hook's JSON input and, when a command would discard changes, prints a deny decision with its reason."""
    # stdin 以 UTF-8 讀，不靠 Python 的預設編碼 ／ stdin is read as UTF-8, not with Python's default encoding
    payload = json.loads(sys.stdin.buffer.read().decode("utf-8", errors="replace"))
    command = payload.get("tool_input", {}).get("command", "")
    if "git" not in command or OVERRIDE in command:
        return 0
    cwd = payload.get("cwd") or os.getcwd()
    lost, unknown = [], []
    # 進入子 shell 時記下目錄與上一個目錄，離開時兩個都還原：子 shell 裡的 cd 不影響後面的指令（含 `cd -`）
    # Remember the directory and the previous one on entering a subshell and restore both on leaving: a cd inside
    # one does not reach later commands (`cd -` included)
    outer = []
    # 上一個 cd 之前的目錄，給 `cd -` 用 ／ The directory before the last cd, for `cd -`
    previous = cwd
    for tokens in segments(command):
        if isinstance(tokens, str):
            for ch in tokens:
                if ch == "(":
                    outer.append((cwd, previous))
                elif ch == ")" and outer:
                    cwd, previous = outer.pop()
            continue
        moved = cd_to(tokens, cwd, previous)
        if moved is not None:
            previous, cwd = cwd, moved
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
                lost.append((" ".join(tokens), hit[0], files))
    if not lost and not unknown:
        return 0
    lines = []
    for cmd, mode, files in lost:
        what = "would remove untracked or ignored files" if mode == "clean" else "would discard uncommitted changes in"
        lines.append(f"`{cmd}` {what}: {', '.join(files[:20])}"
                     + (f" (+{len(files) - 20} more)" if len(files) > 20 else ""))
    for cmd, error in unknown:
        lines.append(f"`{cmd}` may discard uncommitted changes, and the hook could not check: git said: {error}")
    reason = ("\n".join(lines) + "\nCommit first (or save a copy and write it back), then retry. "
              f"If discarding these is really intended, add the comment `{OVERRIDE}` to the command.")
    deny(reason)
    return 0


def deny(reason):
    """印出拒絕的決定與原因（ASCII 跳脫的 JSON，不受 stdout 編碼影響）。
    Prints a deny decision with its reason (ASCII-escaped JSON, whatever stdout's encoding)."""
    print(json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                                             "permissionDecisionReason": reason}}))


def guarded_main():
    """執行 main()；hook 自己出錯時擋下指令並附上錯誤，而不是以非 0 結束（Claude Code 會把那當成放行）。
    Runs main(); when the hook itself fails it denies the command with the error, rather than exiting non-zero
    (which Claude Code treats as letting the command run)."""
    try:
        return main()
    except Exception as error:  # noqa: BLE001  任何錯誤都要擋下 ／ any error must deny
        deny(f"guard_discard failed, so the command was not checked: {type(error).__name__}: {error}\n"
             f"If the command is safe, add the comment `{OVERRIDE}` to it.")
        return 0


if __name__ == "__main__":
    sys.exit(guarded_main())
