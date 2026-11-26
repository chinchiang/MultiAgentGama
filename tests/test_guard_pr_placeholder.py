"""`.claude/hooks/guard_pr_placeholder.py`：Claude Code 的 PreToolUse hook，PR 的標題或內文還有佔位符時擋下
`gh pr create`／`gh pr edit`，提到它們卻不是唯一允許寫法的指令以「無法檢查」擋下。測試照 Claude Code 呼叫它的方式
執行它：stdin 餵 hook 的 JSON，看 stdout 有沒有拒絕的決定。
`.claude/hooks/guard_pr_placeholder.py`: the Claude Code PreToolUse hook that denies `gh pr create`/`gh pr edit`
while the PR's title or body still holds a placeholder, and denies as unchecked a command that mentions them outside
the one allowed form. The tests run it the way Claude Code does: the hook's JSON on stdin, a deny decision or nothing
on stdout."""

import json
import os
import subprocess
import sys

import pytest

HOOK = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".claude", "hooks",
                    "guard_pr_placeholder.py")
# sdist 不含 .claude/（MANIFEST.in 沒有收），整份略過
# The sdist leaves out .claude/ (MANIFEST.in does not include it), so the whole module skips
if not os.path.isfile(HOOK):
    pytest.skip(".claude/ is not shipped in the sdist", allow_module_level=True)

FILLED = "## Summary\n\nThe `<step>` name and `<n>` stay as they are.\n"
DRAFT = "## Evidence\n\n```text\n<FULL_CHECK_3DD1FC6>\n```\n"
UNCHECKED = "the PR title or body could not be checked: "


def _decide(cwd, command, payload_text=None):
    """在 cwd 對 command 執行 hook，拒絕時回傳原因、放行時回傳 None；給了 payload_text 時 stdin 送的是它。
    Runs the hook on command in cwd and returns the deny reason, or None when it allows; payload_text, when given, is
    sent on stdin instead."""
    payload = {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": command},
               "cwd": str(cwd)}
    text = json.dumps(payload, ensure_ascii=False) if payload_text is None else payload_text
    done = subprocess.run([sys.executable, HOOK], input=text, cwd=cwd, capture_output=True, text=True,
                          encoding="utf-8")
    assert done.returncode == 0, f"the hook exited {done.returncode}: {done.stderr}"
    if not done.stdout.strip():
        return None
    output = json.loads(done.stdout)["hookSpecificOutput"]
    assert output["permissionDecision"] == "deny", output
    return output["permissionDecisionReason"]


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
    "gh --repo=owner/repo pr create -T draft.md",
    "gh pr create --template draft.md",
    pytest.param("gh pr create --title t \\\n  --body-file draft.md", id="spec-1-line-continuation"),
])
def test_a_body_file_with_a_placeholder_is_denied_naming_it(bodies, command):
    """`--body-file`／`-F`／`--template` 指到的檔案還有佔位符時擋下，原因寫出檔名與佔位符；`\\` 續行的指令也一樣
    （Spec 審查第 1 點：第一版把換行當成 `;`，續行那一行的檔案沒讀）。
    A file named by `--body-file`/`-F`/`--template` that still holds a placeholder is denied, naming the file and the
    placeholder; so is one in a command continued with `\\` (spec review, item 1: the first version took the newline
    for `;` and never read the file on the continued line)."""
    reason = _decide(bodies, command)
    assert reason is not None and "`draft.md` still holds placeholders: <FULL_CHECK_3DD1FC6>" in reason, reason


@pytest.mark.parametrize("command", [
    "gh pr create --base master --head b --title t --body-file filled.md",
    "gh pr edit 1 -b 'Done: <step> ran.'",
    "gh pr create --title t --body-file - <<'EOF'\n## Summary\nDone.\nEOF",
    pytest.param("gh pr edit 5 --add-label bug", id="spec-5-edit-without-a-body"),
    pytest.param("gh pr create --title cd --body-file filled.md", id="spec-6-cd-as-an-argument"),
])
def test_the_allowed_form_without_placeholders_is_allowed(bodies, command):
    """唯一允許的寫法、沒有佔位符時放行：小寫的 `<step>` 不算佔位符；沒送內文的 `gh pr edit` 照樣放行（Spec 審查第
    5 點）；參數裡的 `cd` 不是換目錄（Spec 審查第 6 點：第一版只要 token 裡有 `cd` 就擋）。
    The allowed form without placeholders is allowed: a lower-case `<step>` is no placeholder; a `gh pr edit` that
    sends no body goes through (spec review, item 5); a `cd` among the args is no change of directory (spec review,
    item 6: the first version denied any command with a `cd` token)."""
    assert _decide(bodies, command) is None


def test_an_absolute_body_file_path_is_read(bodies):
    """絕對路徑的內文檔也讀得到。
    A body file at an absolute path is read too."""
    reason = _decide(bodies, f"gh pr edit 1 --body-file '{bodies / 'draft.md'}'")
    assert reason is not None and "<FULL_CHECK_3DD1FC6>" in reason, reason


@pytest.mark.parametrize("command, mark", [
    ("gh pr create --title t --body 'Evidence: <RED_ON_BASE>'", "<RED_ON_BASE>"),
    ("gh pr create --title '<TITLE_TBD>' --body-file filled.md", "<TITLE_TBD>"),
    pytest.param("gh pr create --title 'Fix <AB> parser' --body-file filled.md", "<AB>", id="spec-2-two-letters"),
    pytest.param("gh pr create --title t --body 'see <1ST_RUN>'", "<1ST_RUN>", id="spec-2-starts-with-a-digit"),
    pytest.param("gh pr create --title t --body 'item <N>'", "<N>", id="spec-2-one-letter"),
    pytest.param("gh pr create --title t --body 'item <_X>'", "<_X>", id="spec-2-starts-with-an-underscore"),
])
def test_a_placeholder_in_the_arguments_is_denied(bodies, command, mark):
    """標題與 `--body` 裡的佔位符擋下；樣式是 spec 的 `<[A-Z0-9_]+>`，數字或底線開頭、少於三個字元的也算（Spec 審查
    第 2 點：第一版要求大寫字母開頭、至少三個字元）。
    A placeholder in the title or `--body` is denied; the pattern is the spec's `<[A-Z0-9_]+>`, so one starting with
    a digit or underscore, or shorter than three characters, counts (spec review, item 2: the first version required
    an upper-case first letter and three characters)."""
    reason = _decide(bodies, command)
    assert reason is not None and f"the command's arguments still holds placeholders: {mark}" in reason, reason


def test_a_placeholder_in_a_heredoc_body_is_denied(bodies):
    """heredoc 送進 `--body-file -` 的內文有佔位符時擋下。
    A heredoc body fed to `--body-file -` holding a placeholder is denied."""
    reason = _decide(bodies, "gh pr create --title t --body-file - <<'EOF'\n## Evidence\n<RED_ON_BASE>\nEOF")
    assert reason is not None and "the heredoc body still holds placeholders: <RED_ON_BASE>" in reason, reason


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
    pytest.param("cat draft.md | gh pr create -F - ; python3 - <<'EOF'\nprint(1)\nEOF",
                 "the command holds the shell operator `|`", id="standards-4-stray-heredoc"),
    pytest.param("gh pr create -dF draft.md", "`-dF` bundles short options", id="standards-5-bundled-shorts"),
    pytest.param("if true; then gh pr create --body-file draft.md; fi", "the command holds the shell operator `;`",
                 id="spec-3-if-then"),
    pytest.param("{ gh pr create --body-file draft.md; }", "the command holds the shell operator `;`",
                 id="spec-3-braces"),
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
    ("gh pr create --body-file missing.md", "`missing.md` cannot be read (FileNotFoundError"),
    ("gh pr create --body-file -", "`--body-file -` reads stdin, and no heredoc at the end of the command feeds it"),
    ("gh pr create --body-file - <<EOF\nDone.\nEOF", "the heredoc's terminator is not quoted"),
    ("gh pr create --title t <<'EOF'\nDone.\nEOF", "the heredoc feeds no `--body-file -`"),
    ("gh pr create --title 'unclosed --body-file filled.md", "the command does not split into tokens"),
    ("gh pr edit 1 -F", "`-F` has no value"),
    ("git commit -F - <<'EOF'\nchore: guard gh pr create\nEOF", "the command does not start with `gh`"),
])
def test_a_command_outside_the_allowed_form_is_denied_as_unchecked(bodies, command, cause):
    """提到 `gh pr create|edit` 卻不是唯一允許寫法的指令、或讀不到的內文，以「無法檢查」擋下，原因寫出是哪一種。
    參數化的 id 寫出審查找到的缺口：第一版放行了 `$(…)`、`env gh`、`pushd`、`if … then`、別的指令的 heredoc 等，
    或用錯的理由擋下。
    A command that mentions `gh pr create|edit` outside the one allowed form, or a body the hook cannot read, is
    denied as unchecked, naming which kind. The parametrize ids name the review findings: the first version let
    `$(…)`, `env gh`, `pushd`, `if … then`, another command's heredoc and the like through, or denied for the wrong
    reason."""
    reason = _decide(bodies, command)
    assert reason is not None and UNCHECKED + cause in reason, reason


@pytest.mark.parametrize("command", [
    "gh pr create --body-file draft.md  # placeholder-ok",
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
    """引號裡或 heredoc 內文裡的 `# placeholder-ok` 不算（Spec 審查：第一版在指令任何地方出現都放行）。
    A `# placeholder-ok` inside quotes or a heredoc body does not count (spec review: the first version let it
    through from anywhere in the command)."""
    reason = _decide(bodies, command)
    assert reason is not None and "still holds placeholders" in reason, reason


@pytest.mark.parametrize("command", [
    pytest.param("echo it's done; grep gh pr.log", id="spec-7-unbalanced-quote-without-create"),
    "gh pr view 217 --json body | grep '<RED_ON_BASE>'",
    "cat draft.md",
    "gh issue create --title t --body-file draft.md",
])
def test_commands_that_do_not_mention_gh_pr_create_or_edit_are_not_checked(bodies, command):
    """沒有依序提到 `gh`、`pr`、`create|edit` 的指令不檢查，拆不成 token 的也一樣（Spec 審查第 7 點）。
    Commands that do not mention `gh`, `pr` and `create|edit` in order are not checked, even ones that do not split
    into tokens (spec review, item 7)."""
    assert _decide(bodies, command) is None


def test_unreadable_input_is_denied(tmp_path):
    """讀不懂的輸入（不是 JSON）也擋下，不以非 0 結束讓 Claude Code 放行。
    Unreadable input (not JSON) is denied too, rather than exiting non-zero, which Claude Code would let run."""
    reason = _decide(tmp_path, "", payload_text="not json")
    assert reason is not None and "guard_pr_placeholder failed, so the command was not checked" in reason, reason
