"""模型回答的解析與形狀檢查（core/model_output.py）：`parse_json_object` 與 `check_output` 的表格測試、`mark_cached`，
以及每個代理的模擬輸出都符合它自己宣告的 schema。閘道的重新詢問、快取與各代理的接線在 test_model_output_robustness.py。
Parsing and shape checking of model answers (core/model_output.py): table tests of `parse_json_object` and
`check_output`, `mark_cached`, and every agent's Simulated output fitting the schema it declares. The gateway's re-asks,
the cache and each agent's wiring are in test_model_output_robustness.py."""
import pytest

from vibeharness.core.i18n import bi, en_only, has_cjk, zh_only
from vibeharness.core.model_output import (
    ANY, CACHED_ANSWER_PREFIX, LIST_OF_OBJECTS, OBJECT, REASON_NOT_VALID_JSON, STRING, OutputSchema, check_output,
    mark_cached, parse_json_object,
)


# --- parse_json_object：從原始文字擷取 JSON 物件 ------------------------------------------------------------
# --- parse_json_object: extracting the JSON object from raw text ---------------------------------------------

@pytest.mark.parametrize("text, parsed", [
    ('{"key": "value"}', {"key": "value"}),                                  # 純粹合法的 JSON ／ pure valid JSON
    ('```json\n{"key": 1}\n```', {"key": 1}),                                # 帶 json 標籤的圍欄 ／ fence tagged json
    ('```JSON\n{"key": 2}\n```', {"key": 2}),                                # 大寫標籤 ／ upper-case tag
    ('```\n{"key": 3}\n```', {"key": 3}),                                    # 沒有標籤 ／ no tag
    ('```jsonc\n{"key": 3.5}\n```', {"key": 3.5}),                           # 其他標籤 ／ another tag
    ('Sure! Here is the output:\n{"key": 4}\nHope this helps!', {"key": 4}),  # 對話式包裝 ／ conversational wrapper
    ('Note: {ignore this invalid}\nReal output:\n{"key": 5}', {"key": 5}),    # 前面有非 JSON 的大括號 ／ earlier non-JSON braces
    ('```json\n{"key": 6}\n', {"key": 6}),                                   # 未關閉的圍欄 ／ unclosed fence
    ('Result: {"a": {"b": [1, 2]}} done', {"a": {"b": [1, 2]}}),             # 巢狀物件 ／ nested object
    # 某一條規則的候選無法解碼時改試下一條 ／ when one rule's candidate does not decode, the next rule is tried
    ('```json\n{not json}\n```\nCorrected: {"key": 7}', {"key": 7}),        # 閉合圍欄內不是 JSON ／ a closed fence without JSON
    ('```json\n{"key": broken\n{"key": 8}', {"key": 8}),                     # 未閉合圍欄內不是 JSON ／ an unclosed fence without JSON
    ('{x} and {y} then {"key": 9}', {"key": 9}),                              # 多個非 JSON 的大括號 ／ several non-JSON braces
    ('{"title": "未處理的 KeyError：訂單 id"}', {"title": "未處理的 KeyError：訂單 id"}),  # 中文內容 ／ Chinese content
    # 形狀像解析失敗的 dict 只是普通的 dict ／ a dict shaped like a parse failure is just a dict
    ('{"error": "JSONDecodeError", "raw_content": "hi"}', {"error": "JSONDecodeError", "raw_content": "hi"}),
])
def test_parse_json_object_extracts_the_object(text, parsed):
    assert parse_json_object(text) == parsed


@pytest.mark.parametrize("text", [
    "Sorry, I cannot help with that.",  # 完全不是 JSON：None，而不是可能與模型撞上的哨兵 dict ／ not JSON: None, never a sentinel dict
    "", "   ",
    "[1, 2, 3]",                        # 頂層是清單而不是物件 ／ a top-level list, not an object
    "```json\n[1, 2]\n```",
    "{ not json }",
])
def test_parse_json_object_returns_none_without_an_object(text):
    assert parse_json_object(text) is None


# --- check_output：對照 schema 檢查形狀 --------------------------------------------------------------------
# --- check_output: checking the shape against the schema -----------------------------------------------------

def _usable_title(item):
    return bool(item.get("title"))


_TITLES = LIST_OF_OBJECTS(usable=_usable_title, requirement=bi("每一項都要有 title", "each item needs a title"))


@pytest.mark.parametrize("result, schema, reason", [
    # 基本形狀 ／ the basic shape
    (None, OutputSchema(), REASON_NOT_VALID_JSON),
    ([1, 2], OutputSchema(), "expected a JSON object, got list"),
    ({"a": 1}, OutputSchema(), None),
    # required：全部都要在，ANY 只看鍵是否存在 ／ required: all must be there, ANY only checks presence
    ({"a": 1}, OutputSchema(required={"a": ANY, "b": ANY}), "response is missing required key(s): b"),
    ({"a": 1, "b": None}, OutputSchema(required={"a": ANY, "b": ANY}), None),
    # 字串與物件 ／ STRING and OBJECT
    ({"code": "x"}, OutputSchema(required={"code": STRING}), None),
    ({"code": ""}, OutputSchema(required={"code": STRING}), None),  # 空字串合格 ／ an empty string fits
    ({"code": 42}, OutputSchema(required={"code": STRING}), "field 'code' must be a string (got int)"),
    ({"code": None}, OutputSchema(required={"code": STRING}), "field 'code' must be a string (got null)"),
    ({"meta": {}}, OutputSchema(required={"meta": OBJECT}), None),
    ({"meta": [1]}, OutputSchema(required={"meta": OBJECT}), "field 'meta' must be an object (got list)"),
    # 物件清單 ／ LIST_OF_OBJECTS
    ({"items": []}, OutputSchema(required={"items": _TITLES}), None),  # 「什麼都沒找到」 ／ "nothing found"
    ({"items": [{"title": "t"}, "x", {}]}, OutputSchema(required={"items": _TITLES}), None),  # 部分可用 ／ partly usable
    ({"items": 5}, OutputSchema(required={"items": _TITLES}), "field 'items' must be a list of objects (got int)"),
    ({"items": "x"}, OutputSchema(required={"items": _TITLES}), "field 'items' must be a list of objects (got str)"),
    ({"items": ["x", 1]}, OutputSchema(required={"items": _TITLES}),
     "field 'items' has no usable item (2 item(s)): each item needs a title"),
    ({"items": [{"title": ""}]}, OutputSchema(required={"items": _TITLES}),
     "field 'items' has no usable item (1 item(s)): each item needs a title"),
    # any_of：一個鍵存在且形狀正確就合格 ／ any_of: one key there with the right shape is enough
    ({"tests": [], "code": 1}, OutputSchema(any_of={"tests": _TITLES, "code": STRING}), None),
    ({"tests": "x", "code": "def t(): pass"}, OutputSchema(any_of={"tests": _TITLES, "code": STRING}), None),
    ({"code": "x"}, OutputSchema(any_of={"tests": ANY, "code": ANY}), None),
    ({"oops": 1}, OutputSchema(any_of={"tests": ANY, "code": ANY}), "response has none of the expected key(s): tests, code"),
    # 每個出現的鍵都不合：逐一說明 ／ every present key does not fit: each is explained
    ({"tests": "x", "code": 4}, OutputSchema(any_of={"tests": _TITLES, "code": STRING}),
     "field 'tests' must be a list of objects (got str); field 'code' must be a string (got int)"),
    # required 與 any_of 同時存在 ／ required and any_of together
    ({"code": "x"}, OutputSchema(required={"title": ANY}, any_of={"code": STRING}), "response is missing required key(s): title"),
])
def test_check_output(result, schema, reason):
    problem = check_output(result, schema)
    if reason is None:
        assert problem is None
    else:
        # 原因是雙語的：英文半與預期相同，中文半含 CJK 且指名同一個欄位
        # The reason is bilingual: the English half is the expected one, the Chinese half has CJK and names the same field
        assert en_only(problem) == en_only(reason)
        assert has_cjk(zh_only(problem)) and not has_cjk(en_only(problem))
        for name in ("code", "items", "meta", "tests"):
            assert (f"'{name}'" in zh_only(problem)) == (f"'{name}'" in en_only(problem))


def test_no_schema_only_requires_a_json_object():
    assert check_output({"anything": 1}, None) is None
    assert check_output(None, None) == REASON_NOT_VALID_JSON


def test_mark_cached_names_the_response_cache_in_both_halves():
    reason = check_output({"code": 42}, OutputSchema(required={"code": STRING}))
    marked = mark_cached(reason)
    assert en_only(marked) == f"{en_only(CACHED_ANSWER_PREFIX)}: {en_only(reason)}"
    assert zh_only(marked) == f"{zh_only(CACHED_ANSWER_PREFIX)}：{zh_only(reason)}"
    assert not has_cjk(en_only(marked))


# --- 每個代理的模擬輸出都符合它自己的 schema ／ every agent's Simulated output fits its own schema -------------

def _simulated_outputs():
    from vibeharness.agents.blackbox.scenario_builder import CODE_SCHEMA, _simulated_attack_test
    from vibeharness.agents.blackbox.threat_modeler import THREATS_SCHEMA, _simulated_threat_model
    from vibeharness.agents.whitebox.debater import verdicts_schema
    from vibeharness.agents.whitebox.multi_reviewer import FINDINGS_SCHEMA, _simulated_review
    from vibeharness.agents.whitebox.test_generator import TESTS_SCHEMA
    cases = [(f"reviewer {alias}", _simulated_review(f"whitebox_reviewer_{alias}", alias), FINDINGS_SCHEMA)
             for alias in ("claude", "deepseek", "glm", "gemini", "unknown")]
    return cases + [
        ("threat modeler", _simulated_threat_model("claude"), THREATS_SCHEMA),
        ("verifier", {"verdicts": []}, verdicts_schema(1)),
        ("test generator", {"tests": []}, TESTS_SCHEMA),
        ("attack synthesizer", _simulated_attack_test("deepseek"), CODE_SCHEMA),
    ]


@pytest.mark.parametrize("case", range(9))
def test_every_simulated_output_fits_its_agents_schema(case):
    """模擬輸出是代理在不呼叫模型時給的固定回答；它必須通過代理自己對真實回答的形狀檢查，否則代理讀模擬輸出與讀真實回答的
    方式會不一致。
    Simulated output is the agent's fixed answer given without calling a model; it must pass the agent's own shape
    check for real answers, or the agent would read Simulated output differently from a real answer."""
    name, output, schema = _simulated_outputs()[case]
    assert check_output(output, schema) is None, name
