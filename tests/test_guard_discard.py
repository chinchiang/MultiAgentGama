"""`.claude/hooks/guard_discard.py`：Claude Code 的 PreToolUse hook 擋下會清掉還沒 commit 的改動的 git 指令。
測試照 Claude Code 呼叫它的方式執行它：stdin 餵 hook 的 JSON，看 stdout 有沒有拒絕的決定。
`.claude/hooks/guard_discard.py`: the Claude Code PreToolUse hook that denies git commands which would discard
uncommitted changes. The tests run it the way Claude Code does: the hook's JSON on stdin, a deny decision or nothing
on stdout."""

import json
import os
import re
import subprocess
import sys

import pytest

HOOK = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".claude", "hooks",
                    "guard_discard.py")
# sdist 不含 .claude/（MANIFEST.in 沒有收），整份略過
# The sdist leaves out .claude/ (MANIFEST.in does not include it), so the whole module skips
if not os.path.isfile(HOOK):
    pytest.skip(".claude/ is not shipped in the sdist", allow_module_level=True)


@pytest.fixture
def repo(git_repo, tmp_path):
    """已提交 `scripts/a.py`、`tests/t.py`、`README` 的 repo，回傳它的根目錄與夾具的 git runner。
    A repo with `scripts/a.py`, `tests/t.py` and `README` committed; returns its root and the fixture's git runner."""
    root = tmp_path / "repo"
    (root / "scripts").mkdir(parents=True)
    (root / "tests").mkdir()
    (root / "scripts" / "a.py").write_text("a = 1\n", encoding="utf-8")
    (root / "tests" / "t.py").write_text("t = 1\n", encoding="utf-8")
    (root / "README").write_text("r\n", encoding="utf-8")
    return root, git_repo(root)


def _decide(root, command, tmp_path):
    """在 root 對 command 執行 hook，拒絕時回傳原因、放行時回傳 None。hook 自己跑的 git 也不讀開發者的設定。
    Runs the hook on command in root and returns the deny reason, or None when it allows. The git the hook runs
    reads no developer config either."""
    empty_config = tmp_path / "empty-gitconfig"
    empty_config.write_text("", encoding="utf-8")
    env = {k: v for k, v in os.environ.items() if not k.upper().startswith("GIT_")}
    env.update(LC_ALL="C", GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=str(empty_config))
    payload = {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": command},
               "cwd": str(root)}
    done = subprocess.run([sys.executable, HOOK], input=json.dumps(payload), cwd=root, env=env,
                          capture_output=True, text=True, encoding="utf-8")
    assert done.returncode == 0, f"the hook exited {done.returncode}: {done.stderr}"
    if not done.stdout.strip():
        return None
    output = json.loads(done.stdout)["hookSpecificOutput"]
    assert output["permissionDecision"] == "deny"
    return output["permissionDecisionReason"]


def _modify(root):
    """在 `scripts/a.py` 留下一行還沒 commit 的改動。
    Leaves an uncommitted line in `scripts/a.py`."""
    with open(root / "scripts" / "a.py", "a", encoding="utf-8") as f:
        f.write("b = 2\n")


# 這些指令在 `scripts/a.py` 有改動時會丟掉它 ／ These commands discard the change in `scripts/a.py`
DISCARDING = [
    "git checkout -q -- scripts tests",
    "git checkout HEAD -- scripts/a.py",
    "git checkout scripts",
    "git restore scripts/a.py",
    "git restore --staged --worktree scripts/a.py",
    "git reset --hard",
    "git status && git reset --hard HEAD",
    "cd scripts && git checkout -- a.py",
    "run(){ git checkout -q HEAD -- scripts tests; }; run",
    "if true; then git checkout -- scripts; fi",
    "env FOO=1 git reset --hard",
    "git checkout -- scripts > /tmp/out.txt",
    "git checkout -- scripts >/tmp/out.txt 2>&1",
    "git checkout -- scripts 2> /tmp/err.txt",
    "git checkout -- scripts &> /tmp/out.txt",
    "git checkout -- scripts < /dev/null",
    "git checkout -- scripts>/tmp/out.txt",
    "git checkout -- scripts>> /tmp/out.txt",
    "git reset --hard>/tmp/out.txt",
    "git checkout -f",
    "git checkout --force master",
    "git checkout -qf master",
    "git checkout -fbnew",
    "git switch --discard-changes master",
    "git switch -f master",
    "git reset --merge",
    "(cd tests); git checkout -- scripts",
    "(cd tests && ls) && git checkout -- scripts",
    "(cd tests && git checkout -- ../scripts)",
    "git checkout -- \\\nscripts",
    "git checkout \\\n  -- scripts",
    "env -i git reset --hard",
    "env -u HOME FOO=1 git reset --hard",
    "sudo -u someone git reset --hard",
]


@pytest.mark.parametrize("command", DISCARDING)
def test_a_command_that_would_discard_a_change_is_denied_and_names_the_file(repo, tmp_path, command):
    """`scripts/a.py` 有還沒 commit 的改動時，會丟掉它的指令被擋下，原因列出 `scripts/a.py`。
    With an uncommitted change in `scripts/a.py`, a command that would discard it is denied, the reason names
    `scripts/a.py`."""
    root, _ = repo
    _modify(root)
    reason = _decide(root, command, tmp_path)
    assert reason is not None, f"`{command}` was allowed"
    assert "would discard uncommitted changes in: scripts/a.py" in reason, reason


def test_git_minus_c_points_the_check_at_that_repo(repo, tmp_path):
    """`git -C <repo>` 從別的目錄指向 repo 時，hook 檢查的是那個 repo。
    With `git -C <repo>` from another directory, the hook checks that repo."""
    root, _ = repo
    _modify(root)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    reason = _decide(elsewhere, f"git -C {root.as_posix()} checkout -- scripts", tmp_path)
    assert reason is not None and "scripts/a.py" in reason, reason


# 這些指令在 `scripts/a.py` 有改動時不會丟掉它 ／ These commands leave the change in `scripts/a.py` alone
HARMLESS = [
    "git checkout -- tests",
    "git checkout -f -- tests",
    "git checkout master",
    "git checkout -bfix",
    "git checkout -qBfeature-f",
    "git switch -cfix",
    "git switch -Cfeature-f",
    "git restore --staged scripts/a.py",
    "git restore -s HEAD tests",
    "git reset --soft HEAD~1",
    "git log --oneline -- scripts",
    "git diff -- scripts",
    'echo "git checkout -- scripts"',
    "ls",
    "git checkout -q -- scripts tests # discard-ok",
]


@pytest.mark.parametrize("command", HARMLESS)
def test_a_command_that_leaves_the_change_alone_is_allowed(repo, tmp_path, command):
    """`scripts/a.py` 有改動時，碰不到它的指令（以及帶 `# discard-ok` 的指令）被放行。
    With a change in `scripts/a.py`, a command that cannot touch it (and one carrying `# discard-ok`) is allowed."""
    root, _ = repo
    _modify(root)
    assert _decide(root, command, tmp_path) is None


@pytest.mark.parametrize("command", ["git checkout -q -- scripts tests", "git reset --hard", "git checkout -- ."])
def test_on_a_clean_tree_discarding_commands_are_allowed(repo, tmp_path, command):
    """工作目錄乾淨（只有一個未追蹤檔）時，沒有東西會丟，指令被放行。
    On a clean tree (only an untracked file), nothing would be lost and the command is allowed."""
    root, _ = repo
    (root / "new.txt").write_text("n\n", encoding="utf-8")
    assert _decide(root, command, tmp_path) is None


@pytest.mark.parametrize("command", ["git checkout HEAD -- scripts", "git reset --hard"])
def test_a_command_that_resets_the_index_denies_a_staged_only_change(repo, tmp_path, command):
    """改動只在 index（已暫存、工作目錄和 index 一樣）時，把 index 也蓋回 HEAD 的指令會丟掉它，被擋下。
    With a change that is only staged, a command that also resets the index to HEAD would lose it, so it is denied."""
    root, git = repo
    _modify(root)
    git("add", "scripts/a.py")
    reason = _decide(root, command, tmp_path)
    assert reason is not None and "scripts/a.py" in reason, reason


@pytest.mark.parametrize("command", ["git checkout -- scripts", "git checkout scripts"])
def test_checkout_from_the_index_allows_a_staged_only_change(repo, tmp_path, command):
    """改動只在 index 時，`git checkout -- <路徑>` 只把 index 複製回工作目錄，暫存的改動留著，指令被放行。
    With a change that is only staged, `git checkout -- <path>` only copies the index back to the working tree and the
    staged change stays, so the command is allowed."""
    root, git = repo
    _modify(root)
    git("add", "scripts/a.py")
    assert _decide(root, command, tmp_path) is None


def test_when_git_cannot_answer_the_command_is_denied_with_gits_error(repo, tmp_path):
    """hook 問 git 時 git 失敗（路徑在 repo 外），就確認不了會不會丟掉改動：指令被擋下，原因附上 git 的錯誤。
    When git fails to answer the hook (a path outside the repo), it cannot tell whether changes would be lost: the
    command is denied and the reason carries git's error."""
    root, _ = repo
    _modify(root)
    outside = (tmp_path / "outside").as_posix()
    reason = _decide(root, f"git checkout -- scripts {outside}", tmp_path)
    assert reason is not None, "allowed although git could not answer"
    assert re.search(r"could not check: git said: \S", reason), reason


def test_outside_a_repo_a_discarding_command_is_denied(needs_git, tmp_path):
    """不在 git repo 裡時，git 答不出來，`git checkout -- <路徑>` 一樣被擋下。
    Outside a git repo git cannot answer, so `git checkout -- <path>` is denied all the same."""
    plain = tmp_path / "plain"
    plain.mkdir()
    reason = _decide(plain, "git checkout -- f", tmp_path)
    assert reason is not None, "allowed although git could not answer"
    assert re.search(r"could not check: git said: \S", reason), reason
