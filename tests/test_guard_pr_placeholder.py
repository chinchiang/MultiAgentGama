"""`.claude/hooks/guard_pr_placeholder.py`：Claude Code 的 PreToolUse hook，PR 的標題或內文還有佔位符時擋下
`gh pr create`／`gh pr edit`。測試照 Claude Code 呼叫它的方式執行它：stdin 餵 hook 的 JSON，看 stdout 有沒有拒絕的
決定。
`.claude/hooks/guard_pr_placeholder.py`: the Claude Code PreToolUse hook that denies `gh pr create`/`gh pr edit`
while the PR's title or body still holds a placeholder. The tests run it the way Claude Code does: the hook's JSON on
stdin, a deny decision or nothing on stdout."""

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

FILLED = "## Summary\n\nThe `<step>` name and `<N>` stay as they are.\n"
DRAFT = "## Evidence\n\n```text\n<FULL_CHECK_3DD1FC6>\n```\n"


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
    """`draft.md` 有佔位符、`filled.md` 沒有（只有小寫與短的角括號）；回傳它們所在的目錄。
    `draft.md` holds a placeholder and `filled.md` none (only lower-case and short angle brackets); returns their
    directory."""
    (tmp_path / "draft.md").write_text(DRAFT, encoding="utf-8")
    (tmp_path / "filled.md").write_text(FILLED, encoding="utf-8")
    return tmp_path


@pytest.mark.parametrize("command", [
    "gh pr create --base master --head b --title t --body-file draft.md",
    "gh pr create --body-file=draft.md",
    "gh pr edit 217 -F draft.md",
    "gh pr edit 217 -Fdraft.md",
    "gh -R owner/repo pr edit 217 --body-file draft.md",
    "git push && gh pr create --body-file draft.md",
    "url=$(gh pr create --body-file draft.md)",
    "GH_PAGER= gh pr edit 1 -F draft.md",
])
def test_a_body_file_with_a_placeholder_is_denied_naming_it(bodies, command):
    """`--body-file`／`-F` 指到的檔案還有佔位符時擋下，原因寫出檔名與佔位符。
    A file named by `--body-file`/`-F` that still holds a placeholder is denied, naming the file and the placeholder."""
    reason = _decide(bodies, command)
    assert reason is not None and "`draft.md` still holds placeholders: <FULL_CHECK_3DD1FC6>" in reason, reason


def test_a_filled_body_file_is_allowed(bodies):
    """沒有佔位符的內文放行，小寫的 `<step>` 與短的 `<N>` 不算佔位符。
    A body without placeholders is allowed; a lower-case `<step>` and a short `<N>` are no placeholder."""
    assert _decide(bodies, "gh pr create --base master --head b --title t --body-file filled.md") is None


def test_an_absolute_body_file_path_is_read(bodies):
    """絕對路徑的內文檔也讀得到。
    A body file at an absolute path is read too."""
    reason = _decide(bodies, f"gh pr edit 1 --body-file {bodies / 'draft.md'}")
    assert reason is not None and "<FULL_CHECK_3DD1FC6>" in reason, reason


@pytest.mark.parametrize("command", [
    "gh pr create --title t --body 'Evidence: <RED_ON_BASE>'",
    "gh pr create --title '<TITLE_TBD>' --body-file filled.md",
    "gh pr create --title t --body-file - <<'EOF'\n## Evidence\n<RED_ON_BASE>\nEOF",
])
def test_a_placeholder_in_the_command_text_is_denied(bodies, command):
    """標題、`--body`、heredoc 裡的佔位符都在指令的文字裡，一樣擋下。
    A placeholder in the title, `--body` or a heredoc is in the command's text and is denied as well."""
    reason = _decide(bodies, command)
    assert reason is not None and "the command still holds placeholders: <" in reason, reason


def test_a_heredoc_body_without_placeholders_is_allowed(bodies):
    """heredoc 送進 `--body-file -` 的內文沒有佔位符時放行。
    A heredoc body fed to `--body-file -` without placeholders is allowed."""
    assert _decide(bodies, "gh pr create --title t --body-file - <<'EOF'\n## Summary\nDone.\nEOF") is None


@pytest.mark.parametrize("command, cause", [
    ("gh pr create --body-file missing.md", "`missing.md` cannot be read (FileNotFoundError"),
    ("gh pr create --body-file $BODY", "`$BODY` holds a variable or command substitution"),
    ("cd sub && gh pr create --body-file filled.md", "`filled.md` is relative and the command changes directory"),
    ("cat draft.md | gh pr create --body-file -", "`--body-file -` reads stdin"),
    ("gh pr create --title 'unclosed --body-file filled.md", "the command does not split into tokens"),
    ("gh pr edit 1 -F", "`-F` has no value"),
])
def test_a_body_the_hook_cannot_read_is_denied_as_unchecked(bodies, command, cause):
    """讀不到的內文以「無法檢查」擋下，原因寫出是哪一種。
    A body the hook cannot read is denied as unchecked, naming which kind."""
    reason = _decide(bodies, command)
    assert reason is not None and f"the PR body could not be checked: {cause}" in reason, reason


def test_the_override_comment_lets_a_placeholder_through(bodies):
    """指令裡有 `# placeholder-ok` 時放行。
    A command holding `# placeholder-ok` is allowed."""
    assert _decide(bodies, "gh pr create --body-file draft.md  # placeholder-ok") is None


@pytest.mark.parametrize("command", [
    "echo '<FULL_CHECK_3DD1FC6>' >> notes.md",
    "gh pr view 217 --json body | grep '<RED_ON_BASE>'",
    "cat draft.md",
    "gh issue create --title t --body-file draft.md",
    "git commit -m 'gh pr create --body-file draft.md'",
    "python3 - <<'EOF'\nprint(\"don't gh pr create --body-file draft.md\")\ngh pr create --body-file draft.md\nEOF",
])
def test_commands_other_than_gh_pr_create_or_edit_are_not_checked(bodies, command):
    """`gh pr create`／`gh pr edit` 以外的指令不檢查，即使文字裡有佔位符；引號或 heredoc 內文裡提到的
    `gh pr create` 也不算。
    Commands other than `gh pr create`/`gh pr edit` are not checked, even with a placeholder in their text; nor is a
    `gh pr create` mentioned inside quotes or a heredoc body."""
    assert _decide(bodies, command) is None


def test_unreadable_input_is_denied(tmp_path):
    """讀不懂的輸入（不是 JSON）也擋下，不以非 0 結束讓 Claude Code 放行。
    Unreadable input (not JSON) is denied too, rather than exiting non-zero, which Claude Code would let run."""
    reason = _decide(tmp_path, "", payload_text="not json")
    assert reason is not None and "guard_pr_placeholder failed, so the command was not checked" in reason, reason
