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
    """已提交 `scripts/a.py`、`tests/t.py`、`README` 與忽略 `*.log` 的 `.gitignore` 的 repo，回傳它的根目錄與夾具的
    git runner。
    A repo with `scripts/a.py`, `tests/t.py`, `README` and a `.gitignore` ignoring `*.log` committed; returns its root
    and the fixture's git runner."""
    root = tmp_path / "repo"
    (root / "scripts").mkdir(parents=True)
    (root / "tests").mkdir()
    (root / "scripts" / "a.py").write_text("a = 1\n", encoding="utf-8")
    (root / "tests" / "t.py").write_text("t = 1\n", encoding="utf-8")
    (root / "README").write_text("r\n", encoding="utf-8")
    (root / ".gitignore").write_text("*.log\n", encoding="utf-8")
    return root, git_repo(root)


def _decide(root, command, tmp_path, home=None, locale="C"):
    """在 root 對 command 執行 hook，拒絕時回傳原因、放行時回傳 None。hook 自己跑的 git 也不讀開發者的設定。
    給了 home 時，它是 hook 看到的家目錄（`HOME` 與 Windows 的 `USERPROFILE`）；locale 是 hook 看到的 `LC_ALL`。
    Runs the hook on command in root and returns the deny reason, or None when it allows. The git the hook runs
    reads no developer config either. When home is given, it is the home directory the hook sees (`HOME`, and
    `USERPROFILE` on Windows); locale is the `LC_ALL` the hook sees."""
    empty_config = tmp_path / "empty-gitconfig"
    empty_config.write_text("", encoding="utf-8")
    env = {k: v for k, v in os.environ.items() if not k.upper().startswith("GIT_")}
    env.update(LC_ALL=locale, GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=str(empty_config))
    if home is not None:
        env.update(HOME=str(home), USERPROFILE=str(home))
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
    "env -C scripts git checkout -- a.py",
    "env --chdir=scripts git checkout -- a.py",
    "env -Cscripts git checkout -- a.py",
    "sudo -D scripts git checkout -- a.py",
    "sudo --chdir=scripts git checkout -- a.py",
    'env -S "git reset --hard"',
    "env --split-string='git checkout -- scripts'",
    'env -S "git checkout --" scripts',
    'env -S "-i git reset --hard"',
    'env -S "-u HOME FOO=1 git reset --hard"',
    "{ cd scripts; git checkout -- a.py; }",
    "if true; then cd scripts; git checkout -- a.py; fi",
    "for d in x; do cd scripts; git checkout -- a.py; done",
    "{ cd scripts; }; git checkout -- a.py",
    "cd scripts && cd - && git checkout -- scripts/a.py",
    "cd scripts; cd ../tests; (cd ..); cd -; git checkout -- a.py",
    "time cd scripts; git checkout -- a.py",
    "command cd scripts; git checkout -- a.py",
    "builtin cd scripts; git checkout -- a.py",
    "FOO=1 cd scripts; git checkout -- a.py",
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
    "env -S 'git reset --hard \"'",
]


@pytest.mark.parametrize("command", HARMLESS)
def test_a_command_that_leaves_the_change_alone_is_allowed(repo, tmp_path, command):
    """`scripts/a.py` 有改動時，碰不到它的指令（以及帶 `# discard-ok` 的指令）被放行。
    With a change in `scripts/a.py`, a command that cannot touch it (and one carrying `# discard-ok`) is allowed."""
    root, _ = repo
    _modify(root)
    reason = _decide(root, command, tmp_path)
    assert reason is None, f"`{command}` was denied: {reason}"


@pytest.mark.parametrize("command", ["git checkout -q -- scripts tests", "git reset --hard", "git checkout -- ."])
def test_on_a_clean_tree_discarding_commands_are_allowed(repo, tmp_path, command):
    """工作目錄乾淨（只有一個未追蹤檔）時，沒有東西會丟，指令被放行。
    On a clean tree (only an untracked file), nothing would be lost and the command is allowed."""
    root, _ = repo
    (root / "new.txt").write_text("n\n", encoding="utf-8")
    reason = _decide(root, command, tmp_path)
    assert reason is None, f"`{command}` was denied: {reason}"


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
    reason = _decide(root, command, tmp_path)
    assert reason is None, f"`{command}` was denied: {reason}"


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


def _untracked(root, *names):
    """在 root 底下建立這些未追蹤（或被忽略）的檔案。
    Creates these untracked (or ignored) files under root."""
    for name in names:
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("u\n", encoding="utf-8")


@pytest.mark.parametrize(("files", "command", "named"), [
    (["new.txt"], "git clean -fd", "new.txt"),
    (["new.txt", "scripts/new.py"], "git clean -f scripts", "scripts/new.py"),
    (["notes.log"], "git clean -fdx", "notes.log"),
    (["notes.log"], "git clean -f -x -d", "notes.log"),
    (["new.txt"], "git clean -i", "new.txt"),
    (["new.txt"], "git clean --force --interactive", "new.txt"),
    (["new.txt"], "git clean -fdq", "new.txt"),
    (["new.txt"], "git clean -f --quiet", "new.txt"),
    (["new.txt"], "git clean -f -e -n", "new.txt"),
    (["new.txt"], "git clean -f --exclude -n", "new.txt"),
    (["new.txt"], "git clean -fd -e -q", "new.txt"),
    (["new.txt", "scripts/new.py"], "git clean -f -e new.txt -- scripts", "scripts/new.py"),
])
def test_git_clean_is_denied_when_its_dry_run_lists_a_file(repo, tmp_path, files, command, named):
    """`git clean` 會刪掉的檔案（由 git 的 dry run 列出）在原因裡被列出，指令被擋下。
    A `git clean` that would remove files (as git's dry run lists them) is denied, and the reason names them."""
    root, _ = repo
    _untracked(root, *files)
    reason = _decide(root, command, tmp_path)
    assert reason is not None, f"`{command}` was allowed"
    assert f"would remove untracked or ignored files: {named}" in reason, reason


@pytest.mark.parametrize(("files", "command"), [
    ([], "git clean -fd"),
    (["new.txt"], "git clean -n"),
    (["new.txt"], "git clean --dry-run -fd"),
    (["new.txt"], "git clean -f tests"),
    (["notes.log"], "git clean -fd"),
    (["new.txt"], "git clean -f -e new.txt"),
    (["new.txt"], "git clean -f -enew.txt"),
    (["new.txt"], "git clean -f --exclude=new.txt"),
    (["new.txt"], "git clean -f --exclude new.txt"),
])
def test_git_clean_is_allowed_when_nothing_would_be_removed(repo, tmp_path, files, command):
    """dry run 什麼都不列（沒有未追蹤檔、pathspec 碰不到它們），或指令本身就是 dry run 時，`git clean` 被放行。
    `git clean` is allowed when the dry run lists nothing (no untracked file, or none the pathspec reaches), or when
    the command is a dry run itself."""
    root, _ = repo
    _untracked(root, *files)
    reason = _decide(root, command, tmp_path)
    assert reason is None, f"`{command}` was denied: {reason}"


@pytest.mark.parametrize("command", ["cd ~ && git reset --hard", "cd && git reset --hard",
                                     "cd ~/scripts && git checkout -- a.py"])
def test_cd_to_home_checks_the_repo_at_home(repo, tmp_path, command):
    """從 repo 外 `cd ~`、`cd ~/…` 或不帶參數的 `cd` 時，hook 檢查家目錄的 repo：乾淨時放行，有改動時擋下並列出檔案。
    After `cd ~`, `cd ~/…` or a bare `cd` from outside a repo, the hook checks the repo at home: allowed while it is
    clean, denied and naming the file once it has a change."""
    root, _ = repo
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    reason = _decide(elsewhere, command, tmp_path, home=root)
    assert reason is None, f"`{command}` was denied on a clean repo at home: {reason}"
    _modify(root)
    reason = _decide(elsewhere, command, tmp_path, home=root)
    assert reason is not None, f"`{command}` was allowed"
    assert "would discard uncommitted changes in: scripts/a.py" in reason, reason


@pytest.mark.parametrize("command", ['cd "$UNKNOWN" && git checkout -- scripts',
                                     'cd "$(pwd)/x" && git checkout -- scripts'])
def test_a_cd_to_an_unknown_directory_still_denies(repo, tmp_path, command):
    """`cd` 到 hook 不知道的目錄（變數、命令替換）之後，git 答不出來，會丟掉改動的指令照樣被擋下。
    After a `cd` to a directory the hook cannot know (a variable, a command substitution), git cannot answer, and a
    discarding command is denied all the same."""
    root, _ = repo
    reason = _decide(root, command, tmp_path)
    assert reason is not None, f"`{command}` was allowed although the directory is unknown"
    assert "could not check" in reason, reason


def test_git_clean_is_checked_whatever_language_git_speaks(repo, tmp_path):
    """開發者的語系讓 git 用別的語言輸出時（這裡是 zh_TW），`git clean` 一樣被檢查、被擋下並列出檔案。
    When the developer's locale makes git speak another language (zh_TW here), `git clean` is still checked, denied
    and the file named."""
    root, _ = repo
    _untracked(root, "new.txt")
    # Guard：這台機器的 git 在 zh_TW 下真的不說英文，否則這個測試什麼也沒證明
    # Guard: git on this machine really does not speak English under zh_TW, else this test proves nothing
    env = {k: v for k, v in os.environ.items() if not k.upper().startswith("GIT_")}
    env.update(LC_ALL="zh_TW.UTF-8", LANGUAGE="zh_TW")
    probe = subprocess.run(["git", "clean", "-n"], cwd=root, env=env, capture_output=True, text=True,
                           encoding="utf-8")
    if "new.txt" not in probe.stdout or "Would remove" in probe.stdout:
        pytest.skip(f"git does not translate its messages to zh_TW here: {probe.stdout!r}")
    reason = _decide(root, "git clean -fd", tmp_path, locale="zh_TW.UTF-8")
    assert reason is not None, "`git clean -fd` was allowed under zh_TW"
    assert "new.txt" in reason, reason


def test_git_clean_with_a_double_force_names_a_nested_repo(git_repo, repo, tmp_path):
    """`git clean -ffd` 連未追蹤的巢狀 repo 也會刪掉；hook 的 dry run 保留兩個 `-f`，所以擋下並列出它。
    `git clean -ffd` also removes an untracked nested repo; the hook's dry run keeps both `-f`, so it is denied and
    names it."""
    root, _ = repo
    nested = root / "sub"
    (nested / "x.txt").parent.mkdir()
    (nested / "x.txt").write_text("x\n", encoding="utf-8")
    git_repo(nested)
    assert _decide(root, "git clean -fd", tmp_path) is None, "a single -f does not remove a nested repo"
    reason = _decide(root, "git clean -ffd", tmp_path)
    assert reason is not None, "`git clean -ffd` was allowed"
    assert "sub/" in reason, reason
