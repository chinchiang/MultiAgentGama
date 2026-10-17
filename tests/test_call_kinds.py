"""呼叫紀錄帶著每次呼叫的種類：代理宣告的 kind 經閘道寫進每一筆紀錄與每個送給 transport 的請求，
在閘道之外當掉的呼叫也一樣，JSON 報告與 partial 報告的 agent_calls 都看得到。
The call log carries each call's kind: the kind an agent declares goes through the gateway into every record and
every request sent to the transport, including a call that crashed outside the gateway, and the JSON and partial
reports' agent_calls show it."""
from config_files import CONFIG
from vibeharness.core.harness import VibeHarnessCommander

_APP = "def greet(name):\n    if name is None:\n        raise ValueError('name required')\n    return 'hi ' + name\n"
_VALID_TEST = ("import pytest\nfrom app import greet\n\ndef test_none():\n"
               "    with pytest.raises(ValueError):\n        greet(None)\n")
_THREAT = {
    "threat_id": "T1", "stride_category": "Tampering", "title": "t", "description": "d", "asset_at_risk": "a",
    "attack_vector": "greet", "trust_boundary_crossed": "b", "severity": "HIGH", "attack_scenario": "s",
    "test_verification_goal": "g",
}
# 每個代理的呼叫應有的種類 ／ The kind each agent's calls should carry
_EXPECTED = {
    "whitebox_reviewer_claude": {"reviewer"}, "whitebox_reviewer_deepseek": {"reviewer"},
    "whitebox_reviewer_glm": {"reviewer"}, "whitebox_reviewer_gemini": {"reviewer"},
    "whitebox_verifier_deepseek": {"verifier"}, "whitebox_verifier_glm": {"verifier"},
    "whitebox_verifier_gemini": {"verifier"},
    "whitebox_test_generator": {"test_generator", "heal"},
    "blackbox_threat_modeler": {"threat_modeler"},
    "blackbox_test_synthesizer": {"synthesizer"},
}


def _target(tmp_path):
    target = tmp_path / "app"
    target.mkdir()
    (target / "app.py").write_text(_APP, encoding="utf-8")
    return target


def test_every_record_and_request_carries_its_calls_kind_including_a_heal_and_a_crash(scripted, tmp_path):
    def test_generator(request):
        # 第一次產生的程式碼無效，觸發修復；修復呼叫回有效的程式碼
        # The first generated code is invalid, which triggers a heal; the heal call answers with valid code
        return _VALID_TEST if request.kind == "heal" else {"tests": [{"code": "def test_broken(:\n"}]}

    transport = scripted({
        "whitebox_reviewer_claude": {"findings": [{
            "symbol_name": "greet", "severity": "HIGH", "title": "None crash", "description": "d",
            "root_cause": "r", "suspected_vibe_flaw": "v", "suggested_test_scenario": "call greet(None)",
        }]},
        "whitebox_reviewer_*": {"findings": []},
        "whitebox_verifier_*": {"verdicts": [{"index": 0, "verdict": "confirm", "reason": "real"}]},
        "whitebox_test_generator": test_generator,
        "blackbox_threat_modeler": {"threats": [_THREAT]},
    })
    commander = VibeHarnessCommander(config_path=CONFIG, execution_mode="live", transport=transport)
    generate = commander.gateway.generate

    # 攻擊合成在閘道之外當掉（transport 表達不了），讓 fan_out 以 record_failure 記錄
    # The attack synthesis crashes outside the gateway (the transport cannot express that), so fan_out books it
    # through record_failure
    def crash_synthesis(agent_id, *args, **kwargs):
        if agent_id == "blackbox_test_synthesizer":
            raise RuntimeError("synthesis exploded")
        return generate(agent_id, *args, **kwargs)
    commander.gateway.generate = crash_synthesis

    commander.run_full_pipeline(target_dir=str(_target(tmp_path)), output_report_path=str(tmp_path / "r.md"))

    log = commander.gateway.call_log
    kinds = {}
    for record in log:
        kinds.setdefault(record.agent_id, set()).add(record.kind)
    assert kinds == _EXPECTED
    (crash,) = [r for r in log if r.agent_id == "blackbox_test_synthesizer"]
    assert crash.mode == "invalid" and "synthesis exploded" in (crash.reason or "")
    # 每個送給 transport 的請求都帶著和它的紀錄相同的種類（當掉的合成沒有送出請求）
    # Every request sent to the transport carries the same kind as its record (the crashed synthesis sent none)
    assert {(r.agent_id, r.kind) for r in transport.requests} == \
        {(r.agent_id, r.kind) for r in log if r.agent_id != "blackbox_test_synthesizer"}


def test_the_json_and_partial_reports_show_each_calls_kind(tmp_path, monkeypatch):
    import json

    import pytest

    target = _target(tmp_path)
    commander = VibeHarnessCommander(config_path=CONFIG, execution_mode="mock")
    commander.run_full_pipeline(target_dir=str(target), output_report_path=str(tmp_path / "r.json"),
                                output_format="json")
    calls = json.loads((tmp_path / "r.json").read_text(encoding="utf-8"))["summary"]["agent_calls"]
    assert {(c["agent_id"], c["kind"]) for c in calls} >= {
        ("whitebox_reviewer_claude", "reviewer"), ("blackbox_threat_modeler", "threat_modeler"),
        ("blackbox_test_synthesizer", "synthesizer"),
    }
    assert all(c["kind"] for c in calls)

    crashing = VibeHarnessCommander(config_path=CONFIG, execution_mode="mock")
    monkeypatch.setattr(crashing.threat_modeler, "model_system",
                        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("provider melted")))
    with pytest.raises(RuntimeError):
        crashing.run_full_pipeline(target_dir=str(target), output_report_path=str(tmp_path / "p.md"))
    partial = json.loads((tmp_path / "p.md.partial.json").read_text(encoding="utf-8"))
    # 威脅建模當掉之前只跑了白箱的代理 ／ Only the white-box agents ran before the threat modeler crashed
    assert partial["agent_calls"]
    assert {c["kind"] for c in partial["agent_calls"]} <= {"reviewer", "verifier", "test_generator", "heal"}
