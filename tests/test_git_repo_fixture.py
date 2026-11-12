"""共用的 `git_repo` 夾具：測試建的 git repo 不受開發者的全域 git 設定影響（#154）。
The shared `git_repo` fixture: the git repos tests build are not affected by the developer's global git config
(#154)."""


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


def test_a_hostile_global_git_config_does_not_reach_the_test_repo(git_repo, tmp_path, monkeypatch):
    """開發者的全域 git 設定要求簽章、掛了會失敗的 hook、用別人的名字：`git_repo` 照樣建好 repo 並提交，之後用它回傳的
    runner 再提交一次也一樣，兩次提交的作者都是夾具自己的身分（#154）。
    The developer's global git config requires signing, installs failing hooks and names someone else: `git_repo` still builds
    the repo and commits, a second commit through the runner it returns works too, and both commits carry the
    fixture's own identity (#154)."""
    monkeypatch.setenv("HOME", str(_hostile_home(tmp_path / "home")))
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
