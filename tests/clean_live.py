"""`clean_live_run` 夾具的乾淨小目標與它專用的假模型回答（responder）。不是測試模組（檔名不以 `test_` 開頭）。
live 模式＋假 litellm 不會有 mock 的 `simulated` 缺口；這裡的回答讓乾淨目標上每一個證據缺口都不成立，所以一次乾淨的
執行是 READY_TO_SHIP（`tests/test_clean_live_run.py` 檢查），建在上面的測試就能斷言判定本身（#200）。
以系統提示詞的角色句子認出 agent（審查者另看 `(Claude)` 模型標籤）；只有驗證者讀使用者提示詞，取其中 `[N]` 開頭的
編號行。乾淨的一次仍有一筆已確認的 LOW 發現（見 _FINDING），沒有阻擋的命中。寫法照 `scripts/golden/fake_llm.py`；
golden 只供開發、不在 sdist 裡，測試不能匯入它，所以這裡另寫一份。
The clean small target of the `clean_live_run` fixture and its own fake model answers (the responder). Not a test
module (the name does not start with `test_`). Live mode with the fake litellm has no `simulated` gap, unlike mock;
these answers make every evidence gap false on the clean target, so one clean run is READY_TO_SHIP (checked by
`tests/test_clean_live_run.py`), and tests built on it can assert the Verdict itself (#200).
The agent is recognised by the system prompt's role sentence (reviewers also by the `(Claude)` model label); only
the verifier reads the user prompt, taking its numbered lines starting `[N]`. A clean run still carries one confirmed
LOW finding (see _FINDING) and no blocking hit. Modelled on `scripts/golden/fake_llm.py`; golden is development-only
and not in the sdist, so tests cannot import it and this is a separate copy."""
import json
import re

# 乾淨目標：一個有 docstring 的純函式 ／ The clean target: one pure function with a docstring
CLEAN_TARGET = {
    "calc.py": 'def add(a, b):\n    """Return the sum of a and b."""\n    return a + b\n',
}

# 一位審查者（Claude）回報一筆 LOW 的發現，其他審查者沒有發現：沒有任何發現時白箱測試產生器不產生測試，
# 「沒有執行任何白箱測試」就成了缺口。這筆發現的測試會通過，所以它只是一個假說，不影響判定
# One reviewer (Claude) reports one LOW finding and the others none: with no finding at all the white-box test
# generator writes no test and "no white-box tests were executed" becomes a gap. This finding's test passes, so it
# stays a hypothesis and does not affect the Verdict
_FINDING = {
    "symbol_name": "add", "severity": "LOW", "title": "Sum of two numbers is never checked",
    "description": "No test checks the sum.", "root_cause": "No test.", "suspected_vibe_flaw": "Happy path only.",
    "suggested_test_scenario": "Add two small numbers.", "owasp_mapping": "",
}
_WHITEBOX_TEST = "from calc import add\n\n\ndef test_two_plus_three_is_five():\n    assert add(2, 3) == 5\n"

# 一個威脅與它會通過的攻擊測試：沒有威脅是 `no_threats` 缺口，威脅沒有可執行的測試是 `untested_threats`
# One threat and its attack test, which passes: no threat is the `no_threats` gap, a threat without an executable test
# is `untested_threats`
_THREAT = {
    "threat_id": "THREAT-01", "stride_category": "Tampering", "owasp_mapping": "", "atlas_mapping": "",
    "title": "A sum could be wrong", "description": "A caller could get a wrong sum.", "asset_at_risk": "results",
    "attack_vector": "function call", "trust_boundary_crossed": "caller to calc", "severity": "LOW",
    "attack_scenario": "Call add with two numbers.", "test_verification_goal": "The sum is right.",
}
_ATTACK_TEST = "from calc import add\n\n\ndef test_the_sum_cannot_be_tampered_with():\n    assert add(2, 3) == 5\n"


def respond(system: str, user: str) -> str:
    """乾淨目標上一次模型呼叫的回答文字。不認得的 agent 會拋出例外：live 模式把它當成那次呼叫失敗，執行中止或記成缺口，
    基準測試因此變紅。
    The answer text of one model call on the clean target. An agent it does not know raises: live mode takes it as
    that call failing, so the run stops or records a gap, and the baseline test turns red."""
    if "white-box AI code auditor" in system:
        return json.dumps({"findings": [_FINDING] if "(Claude)" in system else []})
    if "code-review verifier" in system:
        indices = sorted({int(n) for n in re.findall(r"^\[(\d+)\]", user, re.MULTILINE)})
        return json.dumps({"verdicts": [{"index": i, "verdict": "confirm", "reason": "Plausible."} for i in indices]})
    if "QA Engineer" in system:
        return json.dumps({"test_id": "WB-TEST-01", "title": "The sum is right", "rationale": "Checks the sum.",
                           "expected_outcome": "The assertion holds.", "code": _WHITEBOX_TEST})
    if "Threat Modeling Specialist" in system:
        return json.dumps({"system_description": "A calculator.", "entrypoints": ["add"],
                           "trust_boundaries": ["caller to calc"], "assets": ["results"], "threats": [_THREAT]})
    if "Offensive Security" in system:
        return json.dumps({"test_id": "BB-TEST-THREAT-01", "title": "Attack THREAT-01", "rationale": "Tries the threat.",
                           "expected_outcome": "The attack is refused.", "code": _ATTACK_TEST})
    raise AssertionError("clean_live responder: unknown agent: " + system[:80])
