"""共用夾具：litellm 的替身與依代理回答的模型轉接器，讓「live」程式路徑不需網路或真實金鑰也能執行。
Shared fixtures: a stand-in for litellm and a model transport that answers per agent, so 'live' code paths run
without network or real keys."""
import fnmatch
import json
import os
import shutil
import subprocess
import sys
from types import SimpleNamespace

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from vibeharness.core.transport import ModelReply, ModelRequest  # noqa: E402

_FAKE_KEY_VARS = ("ANTHROPIC_API_KEY", "ZAI_API_KEY", "DEEPSEEK_API_KEY", "GEMINI_API_KEY")


class _FakeLiteLLM:
    """litellm 的替身；`responder(system_prompt, user_prompt)` 回傳模型的原始文字。
    Stands in for litellm; `responder(system_prompt, user_prompt)` returns the raw model text."""

    def __init__(self, responder):
        self.responder = responder
        self.calls = []

    def completion(self, **kwargs):
        self.calls.append(kwargs)
        msgs = kwargs["messages"]
        text = self.responder(msgs[0]["content"], msgs[1]["content"])
        return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=text))])


@pytest.fixture
def fake_live(monkeypatch):
    """設定假的 API 金鑰；呼叫回傳的函式並傳入 responder 以安裝假的 litellm。
    Sets fake API keys; call the returned function with a responder to install the fake litellm."""
    for var in _FAKE_KEY_VARS:
        monkeypatch.setenv(var, "test-key")

    def install(responder):
        fake = _FakeLiteLLM(responder)
        monkeypatch.setattr("vibeharness.core.transport.litellm", fake)
        return fake
    return install


class ScriptedTransport:
    """依 `request.agent_id` 回答的 ModelTransport，並記錄每個 ModelRequest。
    腳本的鍵是代理 id 或 `*` glob（完全相符優先，其次依插入順序比對 glob）；值可以是原始文字、會轉成 JSON 的
    dict／list、例外（在那次嘗試中拋出，就像供應商錯誤），或吃 ModelRequest 並回傳上述任一種的函式。
    沒有腳本的代理會讓測試失敗。
    A ModelTransport that answers by `request.agent_id` and records every ModelRequest.
    Script keys are agent ids or `*` globs (an exact match wins, then globs in insertion order); a value is raw text, a
    dict / list dumped as JSON, an exception (raised in that attempt, like a provider error), or a function taking the
    ModelRequest and returning any of those. An agent without a script fails the test."""

    unavailable_reason = None

    def __init__(self, script):
        self.script = dict(script)
        self.requests = []

    def complete(self, request: ModelRequest) -> ModelReply:
        self.requests.append(request)
        answer = self._answer_for(request.agent_id)
        if callable(answer):
            answer = answer(request)
        if isinstance(answer, BaseException):
            raise answer
        return ModelReply(answer if isinstance(answer, str) else json.dumps(answer))

    def prompts(self, agent_pattern="*"):
        """符合 glob 的代理收到的 (系統提示詞, 使用者提示詞) ／ (system prompt, user prompt) for agents matching the glob."""
        return [(r.messages[0]["content"], r.messages[1]["content"])
                for r in self.requests if fnmatch.fnmatchcase(r.agent_id, agent_pattern)]

    def _answer_for(self, agent_id):
        if agent_id in self.script:
            return self.script[agent_id]
        for pattern, answer in self.script.items():
            if fnmatch.fnmatchcase(agent_id, pattern):
                return answer
        pytest.fail(f"no scripted answer for agent {agent_id!r}")


@pytest.fixture
def scripted(monkeypatch):
    """設定假的 API 金鑰；`scripted({代理 glob: 回答})` 回傳 ScriptedTransport，以 `transport=` 交給閘道或 Commander。
    Sets fake API keys; `scripted({agent_glob: answer})` returns a ScriptedTransport to pass as `transport=` to the
    gateway or the Commander."""
    for var in _FAKE_KEY_VARS:
        monkeypatch.setenv(var, "test-key")
    return ScriptedTransport


# 夾具自己的 git 身分 ／ The fixture's own git identity
_GIT_IDENTITY = {"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t",
                 "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t"}


@pytest.fixture
def needs_git():
    """PATH 上沒有 git 時略過這個測試（#154）。
    Skips the test when git is not on the PATH (#154)."""
    if shutil.which("git") is None:
        pytest.skip("git is not installed")


@pytest.fixture
def git_repo(needs_git, tmp_path_factory):
    """`git_repo(root)` 在 root 建一個 git repo，把裡面的檔案全部提交成 `base`，回傳在 root 執行 git 的
    `git(*args)`：輸出以 UTF-8 文字擷取，失敗時丟出 AssertionError，訊息附上 git 的 stderr 與 stdout。
    這些 git 指令不讀開發者的全域與系統設定（簽章、hook 等都碰不到），外洩的 `GIT_*` 環境變數（例如在 hook 裡跑
    測試時的 `GIT_DIR`）也先清掉，身分由夾具自己給；沒有 git 時略過測試（`needs_git`）（#154）。
    `git_repo(root)` makes root a git repo and commits everything in it as `base`, then returns `git(*args)`, which
    runs git in root: output is captured as UTF-8 text, and a failure raises AssertionError carrying git's stderr and
    stdout. These git commands read neither the developer's global nor system config (signing, hooks and the like
    never reach them), leaked `GIT_*` variables (such as `GIT_DIR` when tests run inside a hook) are cleared first,
    and the fixture supplies its own identity; without git the test is skipped (`needs_git`) (#154)."""
    empty_config = tmp_path_factory.mktemp("git-config") / "gitconfig"
    empty_config.write_text("", encoding="utf-8")

    def make(root):
        root.mkdir(parents=True, exist_ok=True)

        def git(*args):
            env = {k: v for k, v in os.environ.items() if not k.upper().startswith("GIT_")}
            env.update(_GIT_IDENTITY, GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=str(empty_config))
            done = subprocess.run(["git", *args], cwd=root, env=env, capture_output=True, text=True,
                                  encoding="utf-8")
            if done.returncode != 0:
                output = "\n".join(part.strip() for part in (done.stderr, done.stdout) if part.strip())
                raise AssertionError(f"git {' '.join(args)} exited {done.returncode}: {output}")
            return done

        git("init", "-q")
        git("add", "-A")
        git("commit", "-q", "-m", "base")
        return git

    return make


@pytest.fixture
def failing_post_checkout(git_repo, tmp_path_factory, monkeypatch):
    """把開發者的全域 git 設定（`GIT_CONFIG_GLOBAL`）換成一份 `core.hooksPath` 只有一個一定失敗的 `post-checkout` 的
    設定。夾具先證明它真的擋得住：不經過 `git_repo` 時，`git worktree add` 會因為這個 hook 結束碼不是 0（#158）。
    Replaces the developer's global git config (`GIT_CONFIG_GLOBAL`) with one whose `core.hooksPath` holds only a
    `post-checkout` that always fails. The fixture first proves it really blocks: without `git_repo`, `git worktree
    add` exits non-zero because of that hook (#158)."""
    home = tmp_path_factory.mktemp("hostile-git")
    hooks = home / "hooks"
    hooks.mkdir()
    hook = hooks / "post-checkout"
    hook.write_text("#!/bin/sh\necho 'hostile post-checkout hook' >&2\nexit 1\n", encoding="utf-8")
    hook.chmod(0o755)
    config = home / "gitconfig"
    config.write_text(f"[core]\n\thooksPath = {hooks.as_posix()}\n", encoding="utf-8")
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(config))
    # Guard：照開發者的環境執行 worktree add，這個 hook 真的跑了而且擋下來，否則用到它的測試什麼也沒證明
    # Guard: worktree add run the developer's way really runs this hook and is blocked, else a test using it proves
    # nothing
    repo = home / "guard"
    repo.mkdir()
    (repo / "g.txt").write_text("g\n", encoding="utf-8")
    git_repo(repo)
    added = subprocess.run(["git", "worktree", "add", "--detach", str(home / "guard-wt"), "HEAD"], cwd=repo,
                           capture_output=True, text=True, encoding="utf-8")
    assert added.returncode != 0 and "hostile post-checkout hook" in added.stderr, \
        f"the hostile post-checkout hook did not block worktree add: {added}"


def pytest_make_parametrize_id(config, val, argname):
    """長字串參數改用「名稱-長度-雜湊」當測試 ID：pytest 會把測試 ID 寫進 PYTEST_CURRENT_TEST，
    而 Windows 的環境變數上限是 32767 個字元，數十 KB 的惡意輸入會讓整個測試在 setup 就失敗。
    Long string parameters get a "name-length-hash" test id: pytest writes the test id into PYTEST_CURRENT_TEST,
    and Windows caps an environment variable at 32767 characters, so tens of KB of adversarial input would fail
    the test at setup."""
    if isinstance(val, str) and len(val) > 80:
        import hashlib
        return f"{argname}-{len(val)}chars-{hashlib.sha1(val.encode('utf-8', 'surrogatepass')).hexdigest()[:8]}"
    return None
