"""Shared fixtures: a stand-in for litellm so 'live' code paths run without network or real keys."""
import os
import sys
from types import SimpleNamespace

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)


class _FakeLiteLLM:
    """Stands in for litellm; `responder(system_prompt, user_prompt)` returns the raw model text."""

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
    """Sets fake API keys; call the returned function with a responder to install the fake litellm."""
    for var in ("ANTHROPIC_API_KEY", "NVIDIA_API_KEY", "OPENAI_API_KEY"):
        monkeypatch.setenv(var, "test-key")

    def install(responder):
        fake = _FakeLiteLLM(responder)
        monkeypatch.setattr("core.llm_gateway.litellm", fake)
        return fake
    return install
