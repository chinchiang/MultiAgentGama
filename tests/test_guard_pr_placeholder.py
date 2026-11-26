"""`.claude/hooks/guard_pr_placeholder.py`：Claude Code 的 PreToolUse hook，PR 的標題、內文或合併訊息還有佔位符時擋下
`gh pr create`／`edit`／`new`／`merge`，提到 `gh pr` 卻不是唯讀子指令、也不是唯一允許寫法的指令以「無法檢查」擋下。
測試照 Claude Code 呼叫它的方式執行它：stdin 餵 hook 的 JSON，看 stdout 有沒有拒絕的決定。參數化的 id 寫出審查找到
的缺口（`standards-N`、`spec-N` 是第一輪，`round2-`、`round3-` 開頭的是第二、三輪）。
`.claude/hooks/guard_pr_placeholder.py`: the Claude Code PreToolUse hook that denies `gh pr create`/`edit`/`new`/
`merge` while the PR's title, body or merge message still holds a placeholder, and denies as unchecked a command that
mentions `gh pr` with neither a read-only subcommand nor the one allowed form. The tests run it the way Claude Code
does: the hook's JSON on stdin, a deny decision or nothing on stdout. The parametrize ids name the review findings
(`standards-N` and `spec-N` from round 1, those starting `round2-` and `round3-` from rounds 2 and 3)."""

import json
import os
import subprocess
import sys

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HOOK = os.path.join(REPO, ".claude", "hooks", "guard_pr_placeholder.py")
# sdist 不含 .claude/（MANIFEST.in 沒有收），整份略過
# The sdist leaves out .claude/ (MANIFEST.in does not include it), so the whole module skips
if not os.path.isfile(HOOK):
    pytest.skip(".claude/ is not shipped in the sdist", allow_module_level=True)

FILLED = "## Summary\n\nThe `<step>` name and `<n>` stay as they are.\n"
DRAFT = "## Evidence\n\n```text\n<FULL_CHECK_3DD1FC6>\n```\n"
UNCHECKED = "the PR title or body could not be checked: "
POSIX_ONLY = pytest.mark.skipif(os.name == "nt", reason="POSIX device paths")


def _decide(cwd, command, payload_text=None):
    """在 cwd 對 command 執行 hook，拒絕時回傳原因、放行時回傳 None；給了 payload_text 時 stdin 送的是它。
    Runs the hook on command in cwd and returns the deny reason, or None when it allows; payload_text, when given, is
    sent on stdin instead."""
    payload = {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": command},
               "cwd": str(cwd)}
    text = json.dumps(payload, ensure_ascii=False) if payload_text is None else payload_text
    # 逾時和 settings.json 給 hook 的 10 秒一樣：卡住的 hook（例如讀 FIFO）在 Claude Code 裡也會逾時
    # The timeout matches the 10 s settings.json gives the hook: a hook that blocks (reading a FIFO, say) would time
    # out in Claude Code too
    done = subprocess.run([sys.executable, HOOK], input=text, cwd=cwd, capture_output=True, text=True,
                          encoding="utf-8", timeout=10)
    assert done.returncode == 0, f"the hook exited {done.returncode}: {done.stderr}"
    if not done.stdout.strip():
        return None
    output = json.loads(done.stdout)["hookSpecificOutput"]
    assert output["permissionDecision"] == "deny", output
    return output["permissionDecisionReason"]


def _denied(cwd, command, payload_text=None):
    """執行 hook 並回傳拒絕的原因；放行時失敗，訊息寫出被放行的指令。
    Runs the hook and returns the deny reason; fails when it allows, naming the command that was allowed."""
    reason = _decide(cwd, command, payload_text)
    assert reason is not None, f"the command was allowed: {command!r}"
    return reason


@pytest.fixture
def bodies(tmp_path):
    """`draft.md` 有佔位符、`filled.md` 沒有（只有小寫的角括號）；回傳它們所在的目錄。
    `draft.md` holds a placeholder and `filled.md` none (only lower-case angle brackets); returns their directory."""
    (tmp_path / "draft.md").write_text(DRAFT, encoding="utf-8")
    (tmp_path / "filled.md").write_text(FILLED, encoding="utf-8")
    return tmp_path


@pytest.mark.parametrize("command", [
    "gh pr create --base master --head b --title t --body-file draft.md",
    "gh pr create --body-file=draft.md",
    "gh pr edit 217 -F draft.md",
    "gh pr edit 217 -Fdraft.md",
    "gh -R owner/repo pr edit 217 --body-file draft.md",
    "gh --repo=owner/repo pr create -F draft.md",
    pytest.param("gh pr create --title t \\\n  --body-file draft.md", id="spec-1-line-continuation"),
    pytest.param("gh pr new --title t --body-file draft.md", id="round2-standards-1-pr-new-alias"),
    pytest.param("gh pr cre\\\nate --title t --body-file draft.md", id="round2-spec-1-continuation-inside-a-word"),
    pytest.param("g\\\nh pr create --title t --body-file draft.md", id="round2-spec-1-continuation-inside-gh"),
    pytest.param("gh pr cre''ate --title t --body-file draft.md", id="round2-spec-quotes-inside-a-word"),
    pytest.param("gh pr create --title t -F=draft.md", id="round3-spec-short-option-with-equals"),
    pytest.param("gh pr merge 1 --squash --body-file draft.md", id="round3-standards-3-merge-body-file"),
])
def test_a_body_file_with_a_placeholder_is_denied_naming_it(bodies, command):
    """`--body-file`／`-F` 指到的檔案還有佔位符時擋下，原因寫出檔名與佔位符。`\\` 續行（第一輪 Spec 第 1 點）、
    `gh pr new`（第二輪 Standards 第 1 點）、從字中間切開的續行（第二輪 Spec 第 1 點）、字中間的引號、`-F=x`（第三輪
    Spec：第三版讀成 `=x`）與 `gh pr merge` 的內文（第三輪 Standards 第 3 點：第三版把 merge 當成唯讀放行）也一樣。
    A file named by `--body-file`/`-F` that still holds a placeholder is denied, naming the file and the placeholder.
    So is one in a `\\` continuation (round 1, spec item 1), in `gh pr new` (round 2, standards item 1), in a
    continuation that splits a word (round 2, spec item 1), with quotes inside a word, given as `-F=x` (round 3, spec:
    the third version read it as `=x`) and in the body of `gh pr merge` (round 3, standards item 3: the third version
    let merge through as read-only)."""
    reason = _denied(bodies, command)
    assert "`draft.md` still holds placeholders: <FULL_CHECK_3DD1FC6>" in reason, reason


@pytest.mark.parametrize("command", [
    "gh pr create --base master --head b --title t --body-file filled.md",
    "gh pr edit 1 -b 'Done: <step> ran.'",
    "gh pr create --title t --body-file - <<'EOF'\n## Summary\nDone.\nEOF",
    "gh pr create --title 'a; b | c' --body-file filled.md",
    pytest.param("gh pr edit 5 --add-label bug", id="spec-5-edit-without-a-body"),
    pytest.param("gh pr create --title cd --body-file filled.md", id="spec-6-cd-as-an-argument"),
    pytest.param("gh pr create --title t --body 'a <<EOF b' --body-file filled.md",
                 id="round2-spec-heredoc-operator-inside-quotes"),
    pytest.param("gh pr merge 217 --merge", id="round3-merge-without-a-body"),
])
def test_the_allowed_form_without_placeholders_is_allowed(bodies, command):
    """唯一允許的寫法、沒有佔位符時放行：小寫的 `<step>` 不算佔位符；引號裡的 `;`、`|` 不是運算子；沒送內文的
    `gh pr edit`、`gh pr merge` 照樣放行（第一輪 Spec 第 5 點）；參數裡的 `cd` 不是換目錄（第一輪 Spec 第 6 點）；
    引號裡的 `<<EOF` 不是 heredoc（第二輪 Spec：第二版把它當成 heredoc 擋下）。
    The allowed form without placeholders is allowed: a lower-case `<step>` is no placeholder; a quoted `;` or `|` is
    no operator; a `gh pr edit` or `gh pr merge` that sends no body goes through (round 1, spec item 5); a `cd` among
    the args is no change of directory (round 1, spec item 6); a quoted `<<EOF` is no heredoc (round 2, spec: the
    second version denied it as one)."""
    assert _decide(bodies, command) is None


@pytest.mark.parametrize("command", [
    pytest.param("gh pr list --search 'edit'", id="round2-spec-read-only-mentioning-edit"),
    "gh pr view 217 --json body | grep '<RED_ON_BASE>'",
    "gh pr checks 217 2>&1 | tail -3",
    "gh pr view 217 --json state -q .state && gh pr checks 217",
    "gh -R owner/repo pr diff 5",
])
def test_read_only_subcommands_are_allowed_in_any_command(bodies, command):
    """每一個 `gh pr` 都是唯讀子指令時，不管指令的其他部分都放行（第二輪 Spec：第二版擋下 `gh pr list --search 'edit'`）。
    When every `gh pr` takes a read-only subcommand, the command is allowed whatever the rest of it is (round 2, spec:
    the second version denied `gh pr list --search 'edit'`)."""
    assert _decide(bodies, command) is None


def test_an_absolute_body_file_path_is_read(bodies):
    """絕對路徑的內文檔也讀得到。
    A body file at an absolute path is read too."""
    command = f"gh pr edit 1 --body-file '{bodies / 'draft.md'}'"
    reason = _denied(bodies, command)
    assert "<FULL_CHECK_3DD1FC6>" in reason, reason


@pytest.mark.parametrize("command, mark", [
    ("gh pr create --title t --body 'Evidence: <RED_ON_BASE>'", "<RED_ON_BASE>"),
    ("gh pr create --title '<TITLE_TBD>' --body-file filled.md", "<TITLE_TBD>"),
    pytest.param("gh pr create --title 'Fix <AB> parser' --body-file filled.md", "<AB>", id="spec-2-two-letters"),
    pytest.param("gh pr create --title t --body 'see <1ST_RUN>'", "<1ST_RUN>", id="spec-2-starts-with-a-digit"),
    pytest.param("gh pr create --title t --body 'item <N>'", "<N>", id="spec-2-one-letter"),
    pytest.param("gh pr create --title t --body 'item <_X>'", "<_X>", id="spec-2-starts-with-an-underscore"),
    pytest.param("gh pr merge 1 --merge --body '<TODO_X>'", "<TODO_X>", id="round3-standards-3-merge-body"),
    pytest.param("gh pr merge 1 --squash --subject '<TODO_X>'", "<TODO_X>", id="round3-standards-3-merge-subject"),
])
def test_a_placeholder_in_the_arguments_is_denied(bodies, command, mark):
    """標題、`--body` 與合併訊息裡的佔位符擋下；樣式是 spec 的 `<[A-Z0-9_]+>`，數字或底線開頭、少於三個字元的也算
    （第一輪 Spec 第 2 點）；`gh pr merge` 的 `--body`、`--subject` 也掃描（第三輪 Standards 第 3 點）。
    A placeholder in the title, `--body` or the merge message is denied; the pattern is the spec's `<[A-Z0-9_]+>`, so
    one starting with a digit or underscore, or shorter than three characters, counts (round 1, spec item 2); the
    `--body` and `--subject` of `gh pr merge` are scanned too (round 3, standards item 3)."""
    reason = _denied(bodies, command)
    assert f"the command's arguments still holds placeholders: {mark}" in reason, reason


def test_a_placeholder_in_a_heredoc_body_is_denied(bodies):
    """heredoc 送進 `--body-file -` 的內文有佔位符時擋下。
    A heredoc body fed to `--body-file -` holding a placeholder is denied."""
    reason = _denied(bodies, "gh pr create --title t --body-file - <<'EOF'\n## Evidence\n<RED_ON_BASE>\nEOF")
    assert "the heredoc body still holds placeholders: <RED_ON_BASE>" in reason, reason


@pytest.mark.parametrize("command, cause", [
    pytest.param('gh pr create --title t --body "$(cat draft.md)"', "the command holds `$` or a backtick",
                 id="standards-1-command-substitution-in-body"),
    pytest.param('gh pr create --title t --body "$BODY"', "the command holds `$` or a backtick",
                 id="standards-1-variable-in-body"),
    pytest.param('gh pr create --title "$T" --body-file filled.md', "the command holds `$` or a backtick",
                 id="standards-1-variable-in-title"),
    pytest.param("env gh pr create --body-file draft.md", "the command does not start with `gh`",
                 id="standards-2-env"),
    pytest.param("command gh pr create --body-file draft.md", "the command does not start with `gh`",
                 id="standards-2-command"),
    pytest.param("sudo gh pr create --body-file draft.md", "the command does not start with `gh`",
                 id="standards-2-sudo"),
    pytest.param('bash -c "gh pr create --body-file draft.md"', "the command does not start with `gh`",
                 id="standards-2-bash-c"),
    pytest.param("pushd sub && gh pr create -F filled.md", "the command holds the shell operator `&&`",
                 id="standards-3-pushd"),
    pytest.param("python3 - <<'EOF'\nprint(1)\nEOF\ncat draft.md | gh pr create -F -",
                 "the heredoc is not the last thing in the command", id="standards-4-stray-heredoc"),
    pytest.param("gh pr create -dF draft.md", "`-dF` bundles short options", id="standards-5-bundled-shorts"),
    pytest.param("if true; then gh pr create --body-file draft.md; fi", "the command holds the shell operator `;`",
                 id="spec-3-if-then"),
    pytest.param("{ gh pr create --body-file draft.md; }",
                 "the command holds `{` outside quotes, which the shell expands", id="spec-3-braces"),
    pytest.param("`gh pr create --body-file draft.md`", "the command holds `$` or a backtick",
                 id="spec-3-backticks"),
    pytest.param("/usr/bin/gh pr create --body-file draft.md", "the command does not start with `gh`",
                 id="spec-3-full-path"),
    pytest.param("time gh pr create --body-file draft.md", "the command does not start with `gh`",
                 id="spec-3-time"),
    pytest.param("cat <<EOF > /tmp/x\nhi\nEOF\ngh pr create --body-file - < draft.md",
                 "the heredoc is not the last thing in the command", id="spec-4-heredoc-for-another-command"),
    pytest.param('echo "<TODO_ITEM>" >> notes.txt; gh pr edit 5 --add-label bug',
                 "the command holds the shell operator `>>`", id="spec-5-placeholder-in-another-command"),
    pytest.param("ls cd; gh pr create --body-file filled.md", "the command holds the shell operator `;`",
                 id="spec-6-cd-in-another-command"),
    pytest.param("echo it's done; grep gh pr.log", "the command does not split into tokens",
                 id="spec-7-now-a-mention-of-gh-pr"),
    pytest.param("gh pr comment 5 --body-file draft.md",
                 "`gh pr comment` is neither a read-only subcommand nor create, edit, new or merge",
                 id="round2-standards-1-other-subcommand"),
    pytest.param("gh pr create --title t {--body-file,draft.md}",
                 "the command holds `{` outside quotes, which the shell expands", id="round2-spec-2-brace-expansion"),
    pytest.param("gh pr create --body-file draft.*", "the command holds `*` outside quotes, which the shell expands",
                 id="round2-spec-2-glob"),
    pytest.param("gh pr create --body-file '~/draft.md'", "`~/draft.md` holds `~`, which the hook does not expand",
                 id="round2-spec-3-quoted-tilde"),
    pytest.param("gh pr create --body-file=~/draft.md", "`~/draft.md` holds `~`, which the hook does not expand",
                 id="round2-spec-3-tilde-after-equals"),
    pytest.param("gh pr create --title t --recover draft.md",
                 "`--recover` is not an option the hook reads for `gh pr create`", id="round3-standards-1-recover"),
    pytest.param("gh pr create --fill", "`--fill` is not an option the hook reads for `gh pr create`",
                 id="round3-standards-1-fill"),
    pytest.param("gh pr create --fill-verbose", "`--fill-verbose` is not an option the hook reads for `gh pr create`",
                 id="round3-standards-1-fill-verbose"),
    pytest.param("gh pr create --title t --web", "`--web` is not an option the hook reads for `gh pr create`",
                 id="round3-standards-1-web"),
    pytest.param("gh pr create --title t --template filled.md",
                 "`--template` is not an option the hook reads for `gh pr create`", id="round3-spec-template"),
    pytest.param("gh pr create --title t -T filled.md", "`-T` is not an option the hook reads for `gh pr create`",
                 id="round3-spec-template-short"),
    pytest.param("X=pr; gh pr view 1 && gh $X create --title t --body-file draft.md",
                 "the command holds `$` or a backtick", id="round3-spec-3-variable-on-a-read-only-line"),
    pytest.param("gh pr view 1 && gh $SUB --body-file draft.md", "the command holds `$` or a backtick",
                 id="round3-standards-7-variable-subcommand"),
    pytest.param("gh pr create --body-file draft.m?", "the command holds `?` outside quotes, which the shell expands",
                 id="round3-spec-untested-question-mark"),
    pytest.param("gh pr create --body-file draft.[m]d",
                 "the command holds `[` outside quotes, which the shell expands", id="round3-spec-untested-bracket"),
    pytest.param("gh pr create --body-file ~/draft.md", "`~/draft.md` holds `~`, which the hook does not expand",
                 id="round3-spec-untested-bare-tilde"),
    ("gh pr create --draft=true --body-file filled.md", "`--draft=true` gives a value to a flag"),
    ("gh pr merge 217 --merge && gh pr view 217 --json state -q .state", "the command holds the shell operator `&&`"),
    ("gh pr create --body-file missing.md", "`missing.md` cannot be read (FileNotFoundError"),
    ("gh pr create --body-file -", "`--body-file -` reads stdin, and no heredoc at the end of the command feeds it"),
    ("gh pr create --body-file - <<EOF\nDone.\nEOF", "the heredoc's terminator is not quoted"),
    ("gh pr create --title t <<'EOF'\nDone.\nEOF", "the heredoc feeds no `--body-file -`"),
    ("gh pr create --title 'unclosed --body-file filled.md", "the command does not split into tokens"),
    ("gh pr edit 1 -F", "`-F` has no value"),
    ("git commit -F - <<'EOF'\nchore: guard gh pr create\nEOF", "the command does not start with `gh`"),
    ('grep -n "gh pr" notes.log', "the command does not start with `gh`"),
])
def test_a_command_outside_the_allowed_form_is_denied_as_unchecked(bodies, command, cause):
    """提到 `gh pr` 卻不是唯讀子指令、也不是唯一允許寫法的指令，或讀不到的內文，以「無法檢查」擋下，原因寫出是哪一種。
    第一版放行了 `$(…)`、`env gh`、`pushd`、`if … then`、別的指令的 heredoc 等；第二版放行了 `gh pr comment`、大括號
    展開；第三版放行了清單外的選項（`--recover`、`--fill`、`--web`）與觸發行裡的變數，把 `--template` 當成檔案讀。
    只是提到 `gh pr` 的指令被擋、`gh pr merge … && …` 要拆成兩條指令，是粗規則接受的代價。
    A command that mentions `gh pr` with neither a read-only subcommand nor the one allowed form, or a body the hook
    cannot read, is denied as unchecked, naming which kind. The first version let `$(…)`, `env gh`, `pushd`,
    `if … then`, another command's heredoc and the like through; the second let `gh pr comment` and brace expansion
    through; the third let options off the lists (`--recover`, `--fill`, `--web`) and a variable on the triggering
    line through, and read `--template` as a file. Denying a command that only mentions `gh pr`, and splitting
    `gh pr merge … && …` into two commands, are costs the coarse rule accepts."""
    reason = _denied(bodies, command)
    assert UNCHECKED + cause in reason, reason


@POSIX_ONLY
@pytest.mark.parametrize("path", [
    pytest.param("/dev/stdin", id="round2-standards-2-dev-stdin"),
    pytest.param("/dev/null", id="round2-standards-2-device"),
])
def test_a_body_file_that_is_not_a_regular_file_is_denied_as_unchecked(bodies, path):
    """內文檔不是一般檔案（`/dev/stdin`、裝置）時以「無法檢查」擋下（第二輪 Standards 第 2 點：第二版讀到 hook 自己
    已經讀完的 stdin，得到空字串就放行）。
    A body file that is not a regular file (`/dev/stdin`, a device) is denied as unchecked (round 2, standards item 2:
    the second version read the hook's own stdin, already used up, got empty text and allowed)."""
    reason = _denied(bodies, f"gh pr create --title t --body-file {path}")
    assert UNCHECKED + f"`{path}` is not a regular file" in reason, reason


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs os.mkfifo")
def test_a_fifo_body_file_is_denied_without_blocking(bodies):
    """FIFO 的內文檔以「無法檢查」擋下，不會卡住等寫入的一方（第二輪 Standards 第 2 點：第二版開檔就卡到逾時）。
    A FIFO body file is denied as unchecked without waiting for a writer (round 2, standards item 2: the second
    version blocked on opening it until the timeout)."""
    os.mkfifo(bodies / "body.fifo")
    reason = _denied(bodies, "gh pr create --title t --body-file body.fifo")
    assert UNCHECKED + "`body.fifo` is not a regular file" in reason, reason


def test_a_deny_names_the_override_as_the_code_accepts_it(bodies):
    """拒絕的訊息照實寫出跳過標記的用法：heredoc 以外的任何一行，不只第一行（第二輪：第二版寫「第一行」）。
    The deny message describes the override as the code accepts it, any line outside the heredoc bodies rather than
    only the first (round 2: the second version said "first line")."""
    hint = _denied(bodies, "gh pr create --body-file draft.md").splitlines()[-1]
    assert "end a line outside the heredoc bodies with the comment `# placeholder-ok`" in hint, hint


@pytest.mark.parametrize("command", [
    "gh pr create --body-file draft.md  # placeholder-ok",
    "true\ngh pr create --body-file draft.md  # placeholder-ok",
    "git commit -F - <<'EOF'  # placeholder-ok\nchore: guard gh pr create\nEOF",
])
def test_the_override_comment_lets_the_command_through(bodies, command):
    """heredoc 以外的某一行以引號外的 `# placeholder-ok` 結尾時放行。
    A line outside the heredoc bodies ending with `# placeholder-ok`, outside quotes, lets the command through."""
    assert _decide(bodies, command) is None


@pytest.mark.parametrize("command", [
    pytest.param('gh pr create --body-file draft.md --title "# placeholder-ok"', id="spec-scope-override-in-quotes"),
    "gh pr create --title t --body-file - <<'EOF'\n<RED_ON_BASE>\n # placeholder-ok\nEOF",
])
def test_the_override_inside_quotes_or_a_heredoc_body_does_not_count(bodies, command):
    """引號裡或 heredoc 內文裡的 `# placeholder-ok` 不算（第一輪 Spec：第一版在指令任何地方出現都放行）。
    A `# placeholder-ok` inside quotes or a heredoc body does not count (round 1, spec: the first version let it
    through from anywhere in the command)."""
    reason = _denied(bodies, command)
    assert "still holds placeholders" in reason, reason


@pytest.mark.parametrize("command", [
    "cat draft.md",
    "gh issue create --title t --body-file draft.md",
    "echo it's done; grep gh notes.log",
    pytest.param("git checkout -b chore/gh-pr-x", id="round3-spec-hyphenated-branch-name"),
    pytest.param("cat scratch/handoff-gh-pr-notes.md", id="round3-spec-hyphenated-file-name"),
])
def test_commands_that_do_not_mention_gh_pr_are_not_checked(bodies, command):
    """沒有依序提到 `gh`、`pr` 這兩個字的指令不檢查，拆不成 token 的也一樣；連字號連著的 `gh-pr` 不算（第三輪 Spec：
    第三版擋下 `git checkout -b chore/gh-pr-x`）。
    Commands that do not mention the words `gh` and `pr` in order are not checked, even ones that do not split into
    tokens; a hyphenated `gh-pr` is not those words (round 3, spec: the third version denied
    `git checkout -b chore/gh-pr-x`)."""
    assert _decide(bodies, command) is None


def test_unreadable_input_is_denied(tmp_path):
    """讀不懂的輸入（不是 JSON）也擋下，不以非 0 結束讓 Claude Code 放行。
    Unreadable input (not JSON) is denied too, rather than exiting non-zero, which Claude Code would let run."""
    reason = _denied(tmp_path, "", payload_text="not json")
    assert "guard_pr_placeholder failed, so the command was not checked" in reason, reason


def test_settings_run_the_hook_and_ask_before_dropping_a_stash():
    """`.claude/settings.json` 在每個 Bash 指令前跑這個 hook，丟掉 stash 前先問（第二輪 Spec：兩個設定都沒有測試）。
    `.claude/settings.json` runs this hook before every Bash command and asks before dropping a stash (round 2, spec:
    neither entry had a test)."""
    with open(os.path.join(REPO, ".claude", "settings.json"), encoding="utf-8") as f:
        settings = json.load(f)
    commands = [hook["command"] for entry in settings["hooks"]["PreToolUse"] if entry["matcher"] == "Bash"
                for hook in entry["hooks"]]
    assert any("guard_pr_placeholder.py" in c for c in commands), commands
    assert "Bash(git stash drop *)" in settings["permissions"]["ask"], settings["permissions"]["ask"]
