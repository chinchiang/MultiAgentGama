"""模型呼叫的接縫（core/transport.py）：閘道對每個候選模型送出一個 ModelRequest，轉接器失敗時改試下一個候選模型。
The model-call seam (core/transport.py): the gateway sends one ModelRequest per candidate model and tries the next
candidate when the adapter fails."""
import os
from types import SimpleNamespace

import pytest

from vibeharness.core.llm_gateway import LLMGateway, LLMGatewayError
from vibeharness.core.transport import LiteLLMTransport, ModelReply, ModelRequest

CONFIG = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "vibeharness", "config", "agents_config.yaml")


class _Recording:
    """記錄每個請求；`fail` 裡的模型字串拋出例外 ／ Records every request; model strings in `fail` raise."""

    def __init__(self, text='{"ok": 1}', fail=(), unavailable=None):
        self.text, self.fail, self.requests, self._unavailable = text, set(fail), [], unavailable

    @property
    def unavailable_reason(self):
        return self._unavailable

    def complete(self, request: ModelRequest) -> ModelReply:
        self.requests.append(request)
        if request.model in self.fail:
            raise RuntimeError(f"{request.model} is down")
        return ModelReply(self.text, "stop")


@pytest.fixture
def keys(monkeypatch):
    for var in ("ANTHROPIC_API_KEY", "ZAI_API_KEY", "DEEPSEEK_API_KEY", "GEMINI_API_KEY"):
        monkeypatch.setenv(var, "test-key")


def test_each_attempt_is_one_request_carrying_the_agent(keys):
    transport = _Recording()
    gw = LLMGateway(CONFIG, execution_mode="live", transport=transport)
    resp = gw.generate("whitebox_reviewer_claude", "system", "user", required_keys=["ok"])
    assert resp["ok"] == 1 and not gw.is_simulated(resp)
    (request,) = transport.requests
    model = gw.models_config["claude"]
    assert (request.agent_id, request.model_alias, request.model) == ("whitebox_reviewer_claude", "claude", model["model"])
    assert request.messages == [{"role": "system", "content": request.messages[0]["content"]}, {"role": "user", "content": "user"}]
    assert request.params["api_key"] == "test-key" and request.params["timeout"] == 180 and "messages" not in request.params


def test_a_failed_primary_is_retried_on_the_fallback_model(keys):
    gw = LLMGateway(CONFIG, execution_mode="live")
    primary, fallback = gw.models_config["claude"]["model"], gw.models_config["claude"]["fallback_model"]
    gw.transport = transport = _Recording(fail={primary})
    gw.generate("whitebox_reviewer_claude", "system", "user", required_keys=["ok"])
    assert [r.model for r in transport.requests] == [primary, fallback]
    assert gw.call_log[-1].model_name == fallback and gw.call_log[-1].mode == "live"


def test_an_unavailable_transport_means_simulated_output_or_a_live_failure(keys):
    reason = "the provider SDK is missing"
    hybrid = LLMGateway(CONFIG, execution_mode="hybrid", transport=_Recording(unavailable=reason))
    assert hybrid.is_simulated(hybrid.generate("whitebox_reviewer_claude", "s", "u"))
    assert hybrid.call_log[-1].mode == "simulated" and hybrid.call_log[-1].reason == reason
    live = LLMGateway(CONFIG, execution_mode="live", transport=_Recording(unavailable=reason))
    with pytest.raises(LLMGatewayError, match=reason):
        live.generate("whitebox_reviewer_claude", "s", "u")


def test_litellm_adapter_reads_the_reply(monkeypatch):
    seen = {}

    def completion(**kwargs):
        seen.update(kwargs)
        return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=None), finish_reason=3)])
    monkeypatch.setattr("vibeharness.core.transport.litellm", SimpleNamespace(completion=completion))
    reply = LiteLLMTransport().complete(ModelRequest("a", "x", "m-1", [{"role": "user", "content": "hi"}], {"temperature": 0.2}))
    assert reply == ModelReply("", None)
    assert seen == {"model": "m-1", "messages": [{"role": "user", "content": "hi"}], "temperature": 0.2}
    assert LiteLLMTransport().unavailable_reason is None
    monkeypatch.setattr("vibeharness.core.transport.litellm", None)
    assert "litellm is not installed" in LiteLLMTransport().unavailable_reason


def test_simulated_output_comes_from_the_caller():
    """閘道不再依代理名稱編造模擬輸出：由呼叫端提供，省略時是通用的狀態 dict。
    The gateway no longer makes up Simulated output by agent name: the caller provides it, and a generic status dict
    is used when it is omitted."""
    gw = LLMGateway(CONFIG, execution_mode="mock")
    seen = []

    def simulated(alias):
        seen.append(alias)
        return {"findings": []}
    first = gw.generate("whitebox_reviewer_claude", "s", "u", simulated=simulated)
    second = gw.generate("whitebox_reviewer_claude", "s", "u", simulated=simulated)
    assert seen == ["claude", "claude"] and first is not second
    assert first["findings"] == [] and gw.is_simulated(first) and first["_provenance"]["mode"] == "simulated"
    default = gw.generate("whitebox_reviewer_claude", "s", "u")
    assert set(default) == {"status", "message", "_provenance"} and "whitebox_reviewer_claude" in default["message"]


def test_scripted_answers_by_agent_and_raises_like_a_provider(scripted):
    """`scripted` 夾具：完全相符的代理 id 優先於 glob；腳本裡的例外在那次嘗試中拋出，閘道改試備援模型。
    The `scripted` fixture: an exact agent id wins over a glob; an exception in the script is raised in that attempt and
    the gateway tries the fallback model."""
    attempts = iter([RuntimeError("primary is down"), {"ok": 2}])
    transport = scripted({"whitebox_reviewer_*": {"ok": 1}, "whitebox_reviewer_glm": lambda request: next(attempts)})
    gw = LLMGateway(CONFIG, execution_mode="live", transport=transport)
    assert gw.generate("whitebox_reviewer_claude", "s", "u", required_keys=["ok"])["ok"] == 1
    assert gw.generate("whitebox_reviewer_glm", "s", "u", required_keys=["ok"])["ok"] == 2
    glm = gw.models_config["glm"]
    assert [r.model for r in transport.requests[1:]] == [glm["model"], glm["fallback_model"]]
    assert transport.prompts("whitebox_reviewer_glm") == [(transport.requests[1].messages[0]["content"], "u")] * 2
