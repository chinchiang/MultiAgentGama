"""黑箱代理的回歸測試：模型選的威脅 id、STRIDE 拼法，以及當掉的批次記入 call_log。
Black-box agent regressions: model-chosen threat ids, STRIDE spellings, and crashed batches booked in call_log."""
import json
import os

import pytest

from model_answers import answer
from vibeharness.core.llm_gateway import LLMGateway
from vibeharness.core.models import FindingSeverity, STRIDECategory, ThreatItem

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG = os.path.join(REPO_ROOT, "vibeharness", "config", "agents_config.yaml")

_EVIL_ID = "x` ![t](https://evil.example/leak) `"


def _threat(tid: str) -> ThreatItem:
    return ThreatItem(
        threat_id=tid, stride_category=STRIDECategory.TAMPERING, title="t", description="d",
        asset_at_risk="a", attack_vector="v", trust_boundary_crossed="b", severity=FindingSeverity.HIGH,
        attack_scenario="s", test_verification_goal="g",
    )


# --- 威脅解析：模型選的 id 與 STRIDE 拼法 ---------------------------------------------------------
# --- Threat parsing: model-chosen ids and STRIDE spellings -------------------------------------------

def _modeler_report(fake_live, threats):
    from vibeharness.agents.blackbox.threat_modeler import AutomatedThreatModeler
    fake_live(lambda s, u: json.dumps({"threats": threats}))
    return AutomatedThreatModeler(LLMGateway(CONFIG, execution_mode="live")).model_system("svc", ["api"])


def test_unsafe_threat_ids_are_replaced(fake_live):
    report = _modeler_report(fake_live, [
        {"threat_id": _EVIL_ID, "stride_category": "Tampering", "title": "a", "attack_vector": "x"},
        {"threat_id": "T" * 41, "stride_category": "Tampering", "title": "b", "attack_vector": "y"},
        {"threat_id": " T-ok.1:a_b ", "stride_category": "Tampering", "title": "c", "attack_vector": "z"},
    ])
    assert [t.threat_id for t in report.threats] == ["THREAT-01", "THREAT-02", "T-ok.1:a_b"]


@pytest.mark.parametrize("raw, expected", [
    ("Information disclosure", STRIDECategory.INFORMATION_DISCLOSURE),
    ("DENIAL_OF_SERVICE", STRIDECategory.DENIAL_OF_SERVICE),
    ("Elevation-of-Privilege", STRIDECategory.ELEVATION_OF_PRIVILEGE),
    ("elevation-of-privilege", STRIDECategory.ELEVATION_OF_PRIVILEGE),
    ("  spoofing ", STRIDECategory.SPOOFING),
    ("Sorcery", STRIDECategory.TAMPERING),
    (None, STRIDECategory.TAMPERING),
])
def test_stride_category_spelling_is_normalized(fake_live, raw, expected):
    report = _modeler_report(fake_live, [{"threat_id": "T1", "stride_category": raw, "title": "a", "attack_vector": "x"}])
    assert report.threats[0].stride_category == expected


# --- 當掉的批次會記入 call_log ---------------------------------------------------------------------
# --- Crashed batches are booked in call_log --------------------------------------------------------

def test_crashed_threat_modeling_batch_is_recorded():
    """威脅建模批次在閘道之外當掉時記在 blackbox_threat_modeler 名下（接線測試；扇出本身見 test_fanout.py）。
    A threat-modeling batch that crashes outside the gateway is booked under blackbox_threat_modeler (a wiring test;
    the fan-out itself is in test_fanout.py)."""
    from vibeharness.agents.blackbox.threat_modeler import AutomatedThreatModeler
    gateway = LLMGateway(CONFIG, execution_mode="mock")

    def boom(*args, **kwargs):
        raise RuntimeError("simulated thread crash")
    gateway.generate = boom
    AutomatedThreatModeler(gateway).model_system("svc", ["f"])
    (crashed,) = gateway.invalid_calls
    assert crashed.agent_id == "blackbox_threat_modeler" and "RuntimeError: simulated thread crash" in (crashed.reason or "")

def test_crashed_attack_synthesis_is_recorded():
    """一個威脅的攻擊合成當掉時記在 blackbox_test_synthesizer 名下，其他威脅的測試保留（接線測試；
    扇出本身見 test_fanout.py）。
    A crashed attack synthesis for one threat is booked under blackbox_test_synthesizer and the other threats keep
    their tests (a wiring test; the fan-out itself is in test_fanout.py)."""
    from vibeharness.agents.blackbox.scenario_builder import ThreatScenarioBuilder
    gateway = LLMGateway(CONFIG, execution_mode="mock")

    def crash_t2(agent_id, system, user, **kwargs):
        if "Threat ID: T-2\n" in user:
            raise ValueError("boom")
        return answer({"code": "def test_ok():\n    assert True\n"})
    gateway.generate = crash_t2
    tests = ThreatScenarioBuilder(gateway).build_test_cases_from_threats([_threat("T-1"), _threat("T-2"), _threat("T-3")])
    assert [t.source_ref for t in tests] == ["T-1", "T-3"]
    (crashed,) = gateway.invalid_calls
    assert crashed.agent_id == "blackbox_test_synthesizer" and "ValueError: boom" in (crashed.reason or "")
