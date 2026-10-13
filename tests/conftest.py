"""共用夾具：litellm 的替身與依代理回答的模型轉接器，讓「live」程式路徑不需網路或真實金鑰也能執行。
Shared fixtures: a stand-in for litellm and a model transport that answers per agent, so 'live' code paths run
without network or real keys."""
import fnmatch
import json
import os
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
