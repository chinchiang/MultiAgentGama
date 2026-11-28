"""強化建議（GLOSSARY：Hardening recommendation；docs/adr/0001）：黑箱測試以自己的斷言失敗，跨模型驗證多數認為它
要求的是目標沒有承諾的防禦時，它不算資安突破，判定結果是 NEEDS_FIXES（#230）。在 `clean_live_run` 上跑整個 pipeline。
Hardening recommendations (GLOSSARY; docs/adr/0001): when a black-box test fails on its own assertion and a
cross-model majority finds it demands a defence the target never promised, it is not a Breach and the Verdict is
NEEDS_FIXES (#230). Runs the whole pipeline on `clean_live_run`."""
import json
import re

from clean_live import respond

# 失敗在自己斷言上的攻擊測試：在 master 上它是資安突破 ／ An attack test failing on its own assertion: a Breach on master
_FAILING_ATTACK = "from calc import add\n\n\ndef test_the_sum_is_audited():\n    assert add(2, 3) == 6, 'no audit trail'\n"


def _responder(votes, attacks=None):
    """乾淨的回答，只換掉攻擊測試（讓它們失敗）與分類呼叫的回答。`votes(alias, test_id)` 回傳那個驗證者模型對那支
    測試的票；`attacks` 是威脅 id -> 攻擊測試的程式碼（預設只有 THREAT-01，以自己的斷言失敗）。
    The clean answers with the attack tests replaced (so they fail) and the classification calls answered.
    `votes(alias, test_id)` returns that verifier model's vote on that test; `attacks` maps threat id to attack test
    code (by default only THREAT-01, failing on its own assertion)."""
    attacks = attacks or {"THREAT-01": _FAILING_ATTACK}

    def answer(system, user):
        if "Threat Modeling Specialist" in system and len(attacks) > 1:
            base = json.loads(respond(system, user))
            threat = base["threats"][0]
            base["threats"] = [dict(threat, threat_id=tid, title=f"{threat['title']} ({tid})") for tid in attacks]
            return json.dumps(base)
        if "Offensive Security" in system:
            tid = next(t for t in attacks if t in user)
            return json.dumps({"test_id": f"BB-TEST-{tid}", "title": f"Attack {tid}", "rationale": "r",
                               "expected_outcome": "e", "code": attacks[tid]})
        if "independent black-box failure classifier" in system:
            alias = re.search(r"\(model: ([^)]+)\)", system).group(1)
            listed = re.findall(r"^\[(\d+)\] (\S+)", user, re.MULTILINE)
            return json.dumps({"verdicts": [{"index": int(i), "verdict": votes(alias, test_id), "reason": "r"}
                                            for i, test_id in listed]})
        return respond(system, user)
    return answer


def _classified(summary):
    """分類呼叫被問到的模型別名（照呼叫紀錄）。 ／ The model aliases the classification calls asked (from the call log)."""
    return sorted(c.model_alias for c in summary.agent_calls if c.kind == "hardening" and c.mode != "retried")


def test_a_majority_of_hardening_votes_makes_the_failure_a_hardening_recommendation_and_the_verdict_needs_fixes(
        clean_live_run):
    """每位被問到的驗證者都投 hardening：那個失敗是強化建議，不是資安突破，判定結果是 NEEDS_FIXES。
    Every verifier asked votes hardening: the failure is a Hardening recommendation, not a Breach, and the Verdict
    is NEEDS_FIXES."""
    summary = clean_live_run(responder=_responder(lambda alias, test_id: "hardening"))
    assert summary.overall_status == "NEEDS_FIXES", (summary.overall_status, summary.inconclusive_reasons)
    assert summary.blackbox_security_breaches == 0
    assert summary.blackbox_hardening_recommendations == 1


def test_a_majority_of_defect_votes_keeps_the_breach(clean_live_run):
    """被問到的驗證者都投 defect：那個失敗仍是資安突破，判定結果是 BLOCKED_CRITICAL_RISK。
    Every verifier asked votes defect: the failure stays a Breach and the Verdict is BLOCKED_CRITICAL_RISK."""
    summary = clean_live_run(responder=_responder(lambda alias, test_id: "defect"))
    assert summary.overall_status == "BLOCKED_CRITICAL_RISK", summary.overall_status
    assert (summary.blackbox_security_breaches, summary.blackbox_hardening_recommendations) == (1, 0)


def test_hardening_short_of_a_strict_majority_keeps_the_breach(clean_live_run):
    """三位被問到的驗證者投 hardening、defect、unsure（一票 hardening 不過半），以及多數投 unsure：都維持資安突破。
    Three verifiers asked vote hardening, defect and unsure (one hardening vote is no strict majority), and a
    majority of unsure: both keep the Breach."""
    split = {"claude": "hardening", "glm": "defect", "gemini": "unsure"}
    for votes in (lambda alias, test_id: split[alias], lambda alias, test_id: "unsure"):
        summary = clean_live_run(responder=_responder(votes))
        assert _classified(summary) == ["claude", "gemini", "glm"]
        assert summary.overall_status == "BLOCKED_CRITICAL_RISK", summary.overall_status
        assert summary.blackbox_hardening_recommendations == 0


def test_a_hardening_recommendation_beside_a_new_breach_still_blocks(clean_live_run):
    """兩支攻擊測試都以自己的斷言失敗，一支被投 hardening、另一支被投 defect：判定結果仍是 BLOCKED_CRITICAL_RISK。
    Two attack tests fail on their own assertions, one voted hardening and the other defect: the Verdict is still
    BLOCKED_CRITICAL_RISK."""
    attacks = {"THREAT-01": _FAILING_ATTACK, "THREAT-02": _FAILING_ATTACK.replace("audited", "checked")}
    votes = {"BB-TEST-THREAT-01": "hardening", "BB-TEST-THREAT-02": "defect"}
    summary = clean_live_run(responder=_responder(lambda alias, test_id: votes[test_id], attacks))
    assert summary.overall_status == "BLOCKED_CRITICAL_RISK", summary.overall_status
    assert (summary.blackbox_security_breaches, summary.blackbox_hardening_recommendations) == (1, 1)


def test_the_attack_synthesizers_model_never_votes_on_its_own_tests(clean_live_run):
    """內建設定裡攻擊合成用 deepseek：分類只問其他三位驗證者（照呼叫紀錄），deepseek 不判斷自己寫的測試。
    The bundled config has attack synthesis on deepseek: classification asks only the other three verifiers (from the
    call log), so deepseek never judges its own tests."""
    summary = clean_live_run(responder=_responder(lambda alias, test_id: "hardening"))
    assert _classified(summary) == ["claude", "gemini", "glm"]


def test_the_summary_json_carries_the_hardening_recommendation_count(clean_live_run):
    """--summary-json 讀得回強化建議的數量。 ／ --summary-json reads back the number of Hardening recommendations."""
    from vibeharness.cli import _summary_json

    summary = clean_live_run(responder=_responder(lambda alias, test_id: "hardening"))
    assert json.loads(_summary_json(summary, "live"))["hardening_recommendations"] == 1
