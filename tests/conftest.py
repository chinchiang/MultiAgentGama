"""共用夾具：litellm 的替身，讓「live」程式路徑不需網路或真實金鑰也能執行。
Shared fixtures: a stand-in for litellm so 'live' code paths run without network or real keys."""
import os
import sys
from types import SimpleNamespace

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)


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
    for var in ("ANTHROPIC_API_KEY", "ZAI_API_KEY", "DEEPSEEK_API_KEY", "GEMINI_API_KEY"):
        monkeypatch.setenv(var, "test-key")

    def install(responder):
        fake = _FakeLiteLLM(responder)
        monkeypatch.setattr("vibeharness.core.transport.litellm", fake)
        return fake
    return install


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
