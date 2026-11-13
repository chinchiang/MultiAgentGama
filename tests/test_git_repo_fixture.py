"""共用的 `git_repo` 夾具：測試建的 git repo 不受開發者的全域 git 設定影響（#154）。
The shared `git_repo` fixture: the git repos tests build are not affected by the developer's global git config
(#154)."""

import os
import subprocess


def _hostile_home(home):
    """在 home 寫一份會擋下 commit 的 `~/.gitconfig`：要求簽章但簽章程式一定失敗、hook 一定失敗，還有別人的名字；
    回傳 home。開發者的全域設定就放在這裡，而 `GIT_CONFIG_GLOBAL` 這類 `GIT_*` 變數會被夾具清掉，所以從這裡注入。
    Writes, in home, a `~/.gitconfig` that blocks commits: signing is required but the signing program always fails,
    the hooks always fail, and the user is someone else; returns home. That is where a developer's global config
    lives, and `GIT_*` variables such as `GIT_CONFIG_GLOBAL` are cleared by the fixture, so it is injected here."""
    hooks = home / "hooks"
    hooks.mkdir(parents=True)
    for hook in ("pre-commit", "commit-msg"):
        path = hooks / hook
        path.write_text(f"#!/bin/sh\necho 'hostile {hook} hook' >&2\nexit 1\n", encoding="utf-8")
        path.chmod(0o755)
    (home / ".gitconfig").write_text("[commit]\n\tgpgsign = true\n[gpg]\n\tprogram = false\n"
                      f"[core]\n\thooksPath = {hooks.as_posix()}\n[user]\n\tname = someone-else\n", encoding="utf-8")
    return home


def _unisolated_git(root, *args):
    """不經過夾具、照開發者的環境在 root 執行 git，回傳 CompletedProcess。和開發者的環境只差三點：清掉 `GIT_*`、
    固定英文訊息、補上作者與提交者的 email（敵意設定只給名字，沒有 email 時 git 在跑 hook 與簽章之前就停了）。
    Runs git in root the way the developer's environment would, without the fixture, and returns the
    CompletedProcess. It differs from that environment in three ways only: `GIT_*` is cleared, messages are kept in
    English, and the author and committer e-mail are supplied (the hostile config gives only a name, and without an
    e-mail git stops before it runs the hooks or signs)."""
    env = {k: v for k, v in os.environ.items() if not k.upper().startswith("GIT_")}
    env.update(LC_ALL="C", GIT_AUTHOR_EMAIL="x@x", GIT_COMMITTER_EMAIL="x@x")
    return subprocess.run(["git", *args], cwd=root, env=env, capture_output=True, text=True, encoding="utf-8")


def test_a_hostile_global_git_config_does_not_reach_the_test_repo(git_repo, tmp_path, monkeypatch):
    """開發者的全域 git 設定要求簽章、掛了會失敗的 hook、用別人的名字：`git_repo` 照樣建好 repo 並提交，之後用它回傳的
    runner 再提交一次也一樣，兩次提交的作者都是夾具自己的身分（#154）。
    The developer's global git config requires signing, installs failing hooks and names someone else: `git_repo`
    still builds the repo and commits, a second commit through the runner it returns works too, and both commits carry
    the fixture's own identity (#154)."""
    home = _hostile_home(tmp_path / "home")
    monkeypatch.setenv("HOME", str(home))
    # Guard：不經過夾具時，git 真的讀到這份敵意設定（看 user.name），而且 pre-commit hook、commit-msg hook、簽章
    # 各自都會擋下 commit，否則這個測試什麼也沒證明
    # Guard: without the fixture, git really reads this hostile config (seen in user.name), and the pre-commit hook,
    # the commit-msg hook and the signing each block a commit on their own, else this test proves nothing
    guard = tmp_path / "guard"
    guard.mkdir()
    (guard / "g.txt").write_text("g\n", encoding="utf-8")
    for args in (("init", "-q"), ("add", "-A")):
        assert _unisolated_git(guard, *args).returncode == 0
    assert _unisolated_git(guard, "config", "--global", "user.name").stdout.strip() == "someone-else", \
        "git did not read the hostile ~/.gitconfig"
    hooked = _unisolated_git(guard, "-c", "commit.gpgsign=false", "commit", "-q", "-m", "g")
    assert hooked.returncode != 0 and "hostile pre-commit hook" in hooked.stderr, \
        f"the hostile hook did not block: {hooked}"
    # pre-commit 先失敗、--no-verify 又會跳過 commit-msg，所以暫時移開 pre-commit，commit-msg 才會輪到
    # pre-commit fails first and --no-verify skips commit-msg too, so pre-commit is moved aside for commit-msg to run
    pre_commit = home / "hooks" / "pre-commit"
    parked = pre_commit.rename(home / "pre-commit.parked")
    messaged = _unisolated_git(guard, "-c", "commit.gpgsign=false", "commit", "-q", "-m", "g")
    parked.rename(pre_commit)
    assert messaged.returncode != 0 and "hostile commit-msg hook" in messaged.stderr, \
        f"the hostile commit-msg hook did not block: {messaged}"
    signed = _unisolated_git(guard, "commit", "-q", "--no-verify", "-m", "g")
    assert signed.returncode != 0 and "gpg failed to sign" in signed.stderr, \
        f"the hostile signing did not block: {signed}"
    root = tmp_path / "repo"
    root.mkdir()
    (root / "a.txt").write_text("a\n", encoding="utf-8")
    git = git_repo(root)
    (root / "b.txt").write_text("b\n", encoding="utf-8")
    git("add", "b.txt")
    git("commit", "-q", "-m", "second")
    assert git("log", "--format=%an %s").stdout.splitlines() == ["t second", "t base"]


def test_a_leaked_git_dir_does_not_send_the_commands_to_another_repo(git_repo, tmp_path, monkeypatch):
    """環境裡外洩了指向別的 repo 的 `GIT_DIR`（在 git hook 裡跑測試時 git 會設定它）：`git_repo` 照樣在 root 建自己的
    repo，指令不會跑到那個 repo 去，那個 repo 也沒被動到（#154）。
    A `GIT_DIR` pointing at another repo leaked into the environment (git sets it when tests run inside a git hook):
    `git_repo` still builds its own repo in root, its commands never go to that repo, and that repo is left untouched
    (#154)."""
    (tmp_path / "other").mkdir()
    (tmp_path / "other" / "o.txt").write_text("o\n", encoding="utf-8")
    other = git_repo(tmp_path / "other")
    monkeypatch.setenv("GIT_DIR", str(tmp_path / "other" / ".git"))
    root = tmp_path / "repo"
    root.mkdir()
    (root / "a.txt").write_text("a\n", encoding="utf-8")
    git = git_repo(root)
    assert (root / ".git").is_dir(), "git_repo made no repository in root"
    assert git("ls-files").stdout.splitlines() == ["a.txt"]
    assert other("log", "--format=%s").stdout.splitlines() == ["base"], "the other repo got a commit"
