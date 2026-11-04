"""live 情境用的假 litellm：依系統提示詞的角色句子認出 agent，依使用者提示詞的內容給固定的回答。
不碰網路，回答只取決於提示詞，所以兩次執行、兩個 revision 收到同樣的提示詞就得到同樣的回答。
The fake litellm of the live scenarios: recognises the agent by the role sentence of its system prompt and gives a
fixed answer by the content of the user prompt. No network, and the answer depends on the prompt alone, so the same
prompt gets the same answer on both runs and both revisions."""

import functools
import importlib
import json
import re
import threading
from types import SimpleNamespace

# 審查者：依模型名稱各回報 LIVE_TARGET 裡的一個不同缺陷（相同的發現不會送去交叉驗證）；Gemini 回報沒有缺陷
# Reviewers: each model reports a different defect of LIVE_TARGET (identical findings are not cross-verified);
# Gemini reports none
_FINDINGS = {
    "(Claude)": ("apply_discount", "HIGH", "Discount over 100 percent gives a negative total"),
    "(DeepSeek)": ("safe_quantity", "MEDIUM", "Quantity validation may accept invalid values"),
    "(GLM)": ("lookup_role", "HIGH", "Unknown user raises KeyError"),
}
# LIVE_TARGET_CHANGED 多出的函式：Claude 多回報這一個發現。它的測試會通過：任何發現沒有可執行的測試時，每個函式都會
# 加跑探測，基準線沒有的探測失敗就會跟新的規則命中一起決定判定
# The function LIVE_TARGET_CHANGED adds: Claude reports this one more finding. Its test passes: when any finding has
# no executable test, every function gets a probe, and probe failures the baseline lacks would decide the verdict
# alongside the new rule hit
_CHANGED_MARKER = "def load_model("
_CHANGED_FINDING = ("load_model", "HIGH", "Model file is unpickled without verification")

# 測試產生器：依發現標題給測試。LIVE_TARGET 的三個發現會失敗、會通過、匯入錯誤（未執行）各一
# Test generator: a test per finding title; LIVE_TARGET's three findings get one that fails, one that passes and one
# with an import error (Not run)
_WHITEBOX_TESTS = {
    "Discount over 100 percent gives a negative total":
        "from shop import apply_discount\n\n\ndef test_discount_never_goes_negative():\n"
        "    assert apply_discount(10, 150) >= 0\n",
    "Quantity validation may accept invalid values":
        "import pytest\nfrom shop import safe_quantity\n\n\ndef test_zero_is_rejected():\n"
        "    with pytest.raises(ValueError):\n        safe_quantity(0)\n",
    "Unknown user raises KeyError":
        "from shop import lookup_rol\n\n\ndef test_unknown_user_gets_guest():\n"
        "    assert lookup_rol('mallory') == 'guest'\n",
    "Model file is unpickled without verification":
        "from shop import load_model\n\n\ndef test_load_model_is_defined():\n    assert callable(load_model)\n",
}

_THREATS = [
    ("THREAT-01", "Elevation of Privilege", "CRITICAL", "Any user reads another user's order"),
    ("THREAT-02", "Denial of Service", "HIGH", "Unknown user name crashes the role lookup"),
    ("THREAT-03", "Tampering", "MEDIUM", "Refund of a foreign order"),
    ("THREAT-04", "Repudiation", "MEDIUM", "Actions are not logged"),
]
# 目標有 load_model 時多一個威脅；它的攻擊測試是空的 code（未測試）
# One more threat when the target has load_model; its attack test is an empty code (untested)
_CHANGED_THREAT = ("THREAT-05", "Tampering", "HIGH", "A crafted model file runs code on load")

# 情境產生器：依威脅 id 給攻擊測試。突破、目標內的例外（未分類失敗）、匯入錯誤（未執行）、空的 code（未測試）
# Scenario builder: an attack test per threat id. A Breach, an exception inside the target (Unclassified failure), an
# import error (Not run) and an empty code (untested)
_ATTACK_TESTS = {
    "THREAT-01": "from shop import get_order\n\n\ndef test_foreign_order_is_refused():\n"
                 "    assert get_order(2, 'alice')['owner'] == 'alice'\n",
    "THREAT-02": "from shop import lookup_role\n\n\ndef test_unknown_user_is_handled():\n"
                 "    assert lookup_role('mallory') == 'guest'\n",
    "THREAT-03": "from shop import refund_order\n\n\ndef test_foreign_refund_is_refused():\n"
                 "    assert refund_order(2, 'alice') is None\n",
    "THREAT-04": "",
    "THREAT-05": "",
}


def respond(system: str, user: str) -> str:
    """一次模型呼叫的回答文字。
    The answer text of one model call."""
    if "white-box AI code auditor" in system:
        found = [finding for marker, finding in _FINDINGS.items() if marker in system]
        if "(Claude)" in system and _CHANGED_MARKER in user:
            found.append(_CHANGED_FINDING)
        return json.dumps({"findings": [
            {"symbol_name": symbol, "severity": severity, "title": title, "description": title + ".",
             "root_cause": "Missing check.", "suspected_vibe_flaw": "Happy path only.",
             "suggested_test_scenario": "Call it with the edge case.", "owasp_mapping": ""}
            for symbol, severity, title in found
        ]})
    if "code-review verifier" in system:
        indices = sorted({int(n) for n in re.findall(r"^\[(\d+)\]", user, re.MULTILINE)})
        return json.dumps({"verdicts": [{"index": i, "verdict": "confirm", "reason": "The code has it."} for i in indices]})
    if "QA Engineer" in system:
        title = next((t for t in _WHITEBOX_TESTS if f"Finding Title: {t}" in user), None)
        return json.dumps({"test_id": "WB-TEST-01", "title": title or "No test", "rationale": "Exposes the flaw.",
                           "expected_outcome": "The assertion holds.", "code": _WHITEBOX_TESTS.get(title or "", "")})
    if "Threat Modeling Specialist" in system:
        threats = _THREATS + ([_CHANGED_THREAT] if _CHANGED_MARKER in user else [])
        return json.dumps({
            "system_description": "A small shop.", "entrypoints": ["get_order", "lookup_role"],
            "trust_boundaries": ["caller to shop"], "assets": ["orders"],
            "threats": [
                {"threat_id": tid, "stride_category": stride, "owasp_mapping": "API1:2023 - BOLA", "atlas_mapping": "",
                 "title": title, "description": title + ".", "asset_at_risk": "orders", "attack_vector": "function call",
                 "trust_boundary_crossed": "caller to shop", "severity": severity,
                 "attack_scenario": "Call it as another user.", "test_verification_goal": "The call is refused."}
                for tid, stride, severity, title in threats
            ],
        })
    if "Offensive Security" in system:
        tid = next((t for t in _ATTACK_TESTS if f"Threat ID: {t}\n" in user), "")
        return json.dumps({"test_id": f"BB-TEST-{tid}", "title": f"Attack {tid}", "rationale": "Tries the threat.",
                           "expected_outcome": "The attack is refused.", "code": _ATTACK_TESTS.get(tid, "")})
    raise AssertionError("fake litellm: unknown agent: " + system[:80])


# primary_down：這個模型字串一律失敗，gateway 改呼叫設定裡的 fallback_model
# primary_down: this model string always fails, so the gateway calls the configured fallback_model
_DOWN_MODEL = "deepseek/deepseek-v4-pro"
# invalid_output：重問的提示詞以這句接在原本的使用者提示詞後面（vibeharness/core/llm_gateway.py 的 _RETRY_SUFFIX）
# invalid_output: a re-ask appends this sentence to the original user prompt (_RETRY_SUFFIX in
# vibeharness/core/llm_gateway.py)
_RE_ASK = "Your previous answer could not be used ("
_UNUSABLE = "not json"

# 每個 profile 的注入必須觸發的事件：其中一個從沒發生，表示這一邊的 revision 讓注入失效或變形（模型字串、重問的句子、
# patch 目標的參數形狀改了），verify() 會讓情境當掉（main 回傳 2），不讓它悄悄沒注入就被比對
# The events each profile's injection must trigger: one that never happens means this side's revision disabled or
# warped the injection (a changed model string, re-ask sentence or patch target argument shape), and verify() crashes
# the scenario (main exits 2) rather than letting it be compared without the injection
_REQUIRED = {
    "standard": set(),
    "primary_down": {"primary model blocked"},
    "invalid_output": {"threat modeler re-asked", "Claude reviewer blocked"},
    "crash": {"Gemini reviewer batch crashed"},
}
# 呼叫在 fan_out 的執行緒上並行，記錄要上鎖 ／ Calls run concurrently on fan_out's threads, so recording takes a lock
_lock = threading.Lock()
_fired: set[str] = set()
_profile = ""


def _fire(event: str) -> None:
    """記下注入觸發了 event。
    Records that the injection triggered event."""
    with _lock:
        _fired.add(event)


class _FakeLiteLLM:
    """litellm.completion 的替身，行為依 profile。
    A stand-in for litellm.completion, behaving as its profile."""

    def __init__(self, profile: str) -> None:
        self.profile = profile

    def completion(self, **kwargs):
        if self.profile == "primary_down" and kwargs["model"] == _DOWN_MODEL:
            _fire("primary model blocked")
            raise RuntimeError(f"golden fake: {_DOWN_MODEL} is down")
        messages = kwargs["messages"]
        system, user = messages[0]["content"], messages[1]["content"]
        text = _UNUSABLE if self.profile == "invalid_output" and _unusable(system, user) else respond(system, user)
        return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=text), finish_reason="stop")])


def _unusable(system: str, user: str) -> bool:
    """invalid_output 要回答無法使用的輸出的呼叫：威脅建模只有第一次（重問後才給有效的 JSON），Claude 審查者每一次都是。
    The invalid_output calls answered with unusable output: the threat modeler only the first time (valid JSON once
    re-asked), the Claude reviewer every time."""
    if "Threat Modeling Specialist" in system:
        if _RE_ASK in user:
            _fire("threat modeler re-asked")
            return False
        return True
    if "white-box AI code auditor" in system and "(Claude)" in system:
        _fire("Claude reviewer blocked")
        return True
    return False


# crash：讓 Gemini 審查者的批次在 gateway 之外丟出一般例外（fan_out 把它記成當掉的呼叫）。patch 的是私有方法：
# 另一個 revision 沒有它，或參數形狀改了而從沒觸發，都要讓情境當掉（main 回傳 2），不能悄悄沒注入就跑完
# crash: makes the Gemini reviewer's batch raise an ordinary exception outside the gateway (fan_out books it as a
# crashed call). The patch targets a private method: when another revision lacks it, or a changed argument shape keeps
# it from ever firing, the scenario must crash (main exits 2) rather than quietly run without the injection
_CRASH_TARGET = ("vibeharness.agents.whitebox.multi_reviewer", "HeterogeneousReviewerEnsemble", "_review_batch")
_CRASH_AGENT = "whitebox_reviewer_gemini"


def _install_crash() -> None:
    """把 crash 的 patch 裝到 _CRASH_TARGET 上；目標不存在時丟出例外。
    Installs crash's patch on _CRASH_TARGET; raises when the target is missing."""
    module_name, class_name, method_name = _CRASH_TARGET
    owner = getattr(importlib.import_module(module_name), class_name, None)
    original = getattr(owner, method_name, None)
    if original is None:
        raise RuntimeError(f"golden fake: patch target {'.'.join(_CRASH_TARGET)} is missing on this revision")

    @functools.wraps(original)
    def crashing(self, reviewer, *args, **kwargs):
        if isinstance(reviewer, dict) and reviewer.get("agent_id") == _CRASH_AGENT:
            _fire("Gemini reviewer batch crashed")
            raise RuntimeError(f"golden fake: injected crash in {_CRASH_AGENT}'s batch")
        return original(self, reviewer, *args, **kwargs)

    setattr(owner, method_name, crashing)


PROFILES = tuple(_REQUIRED)


def install(profile: str) -> None:
    """以 profile 的行為把 vibeharness 的 litellm 換成假的；要在 CLI 執行前、vibeharness 匯入後呼叫。
    Replaces vibeharness's litellm with the fake, behaving as profile; call it after vibeharness is imported and
    before the CLI runs."""
    if profile not in PROFILES:
        raise ValueError(f"golden fake: unknown profile {profile!r}")
    import vibeharness.core.transport as transport
    transport.litellm = _FakeLiteLLM(profile)  # type: ignore[assignment]
    if profile == "crash":
        _install_crash()
    global _profile
    _profile = profile


def verify() -> None:
    """CLI 結束後（包括 sys.exit）呼叫：已安裝的 profile 有必須觸發的事件從沒發生就丟出例外，讓情境當掉而不是悄悄沒注入。
    Called after the CLI ends (sys.exit included): raises when an event the installed profile must trigger never
    happened, so the scenario crashes instead of quietly running without the injection."""
    with _lock:
        missing = sorted(_REQUIRED.get(_profile, set()) - _fired)
    if missing:
        raise RuntimeError(f"golden fake: the {_profile} injection never triggered on this revision: {', '.join(missing)}")
