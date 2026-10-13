"""模型回答的解析與形狀檢查：從模型的原始文字擷取 JSON 物件，並對照代理宣告的 `OutputSchema` 檢查它。

每個代理都宣告它期望的回答形狀（必要的鍵與其型別，或「至少一個」的鍵組），閘道在同一處解析並檢查，不合時以雙語原因重新詢問，
仍不合就記為 `invalid`（證據缺口）。欄位層級的寬容（嚴重度同義詞、字串形式的 index、預設值）仍留在各代理。本模組只有純函式，
不做 I/O、不記錄 log。
Parsing and shape checking of model answers: extracts the JSON object from a model's raw text and checks it against
the `OutputSchema` the agent declared.

Every agent declares the shape of the answer it expects (required keys and their types, or a set of keys of which at
least one must be there); the gateway parses and checks in one place, re-asks with a bilingual reason when it does not
fit, and books it as `invalid` (an evidence gap) when it still does not. Field-level leniency (severity synonyms, an
index given as a string, defaults) stays in the agents. This module is pure functions only: no I/O and no logging."""
import json
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Mapping, Optional

from vibeharness.core.i18n import bi

REASON_NOT_VALID_JSON = bi("回應不是有效的 JSON", "response is not valid JSON")


@dataclass(frozen=True)
class FieldType:
    """一個欄位的型別規則：`problem(value)` 在值不合時回傳雙語原因，合格時為 None。
    The type rule of one field: `problem(value)` returns a bilingual reason when the value does not fit, None when
    it does."""
    name: str
    problem: Callable[[Any], Optional[str]]


# 只要求鍵存在，不檢查型別 ／ Only the key's presence is required; its type is not checked
ANY = FieldType("any", lambda value: None)


@dataclass(frozen=True)
class OutputSchema:
    """代理期望的回答形狀：`required` 的每個鍵都必須存在且符合型別；`any_of` 不為空時，至少要有一個鍵存在且符合型別。
    The shape of the answer an agent expects: every key in `required` must be present and fit its type; when `any_of`
    is not empty, at least one of its keys must be present and fit its type."""
    required: Mapping[str, FieldType] = field(default_factory=dict)
    any_of: Mapping[str, FieldType] = field(default_factory=dict)


def parse_json_object(text: str) -> Optional[Dict[str, Any]]:
    """剝除 markdown 程式碼圍欄並安全地解析 JSON，並提供對話式退回路徑；擷取不到 JSON 物件時為 None。
    Strips markdown code fences and parses JSON safely, with conversational fallback; None when no JSON object can be
    extracted."""
    text = text.strip()
    # 1. 已閉合的 markdown 程式碼圍欄（```json ... ``` 或 ```JSON / ```）
    # 1. Closed markdown code fence (```json ... ``` or ```JSON / ```)
    match = re.search(r"```[\w-]*\s*([\s\S]*?)\s*```", text)
    if match:
        candidate = match.group(1).strip()
        try:
            parsed = json.loads(candidate)
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError:
            pass

    # 2. 直接的 JSON 字串
    # 2. Direct JSON string
    try:
        parsed = json.loads(text)
        if isinstance(parsed, dict):
            return parsed
    except json.JSONDecodeError:
        pass

    # 3. 未閉合的程式碼圍欄（以 ```tag 開頭但缺少結尾的 ```）
    # 3. Unclosed code fence (starts with ```tag but missing closing ```)
    unclosed_match = re.match(r"^\s*```[\w-]*\s*([\s\S]*)$", text)
    if unclosed_match:
        candidate = re.sub(r"```+\s*$", "", unclosed_match.group(1)).strip()
        try:
            parsed = json.loads(candidate)
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError:
            pass

    # 4. 對話式包裹的退回路徑：擷取第一個 '{' 到最後一個 '}' 之間的子字串
    # 4. Conversational wrapping fallback: extract substring between first '{' and last '}'
    first_brace = text.find("{")
    last_brace = text.rfind("}")
    if first_brace != -1 and last_brace > first_brace:
        candidate = text[first_brace:last_brace + 1]
        try:
            parsed = json.loads(candidate)
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError:
            # 若從第一個到最後一個失敗（例如前面有未閉合的非 JSON 大括號），則逐一嘗試每個 '{' 到最後一個 '}'
            # If first-to-last failed (e.g. earlier unclosed non-JSON brace), search each '{' to last '}'
            for m in re.finditer(r"\{", text):
                start = m.start()
                if start == first_brace or start >= last_brace:
                    continue
                try:
                    parsed = json.loads(text[start:last_brace + 1])
                    if isinstance(parsed, dict):
                        return parsed
                except json.JSONDecodeError:
                    continue

    # 回傳 None（而非哨兵 dict）：模型可能正當地回聲出這樣的 dict，
    # 那會與解析失敗無法區分。
    # None (not a sentinel dict): a model could legitimately echo such a dict, which would
    # have been indistinguishable from a parse failure.
    return None


def check_output(result: Any, schema: Optional[OutputSchema]) -> Optional[str]:
    """`result`（`parse_json_object` 的結果）不合 `schema` 時的雙語原因；合格時為 None。
    The bilingual reason `result` (what `parse_json_object` returned) does not fit `schema`; None when it does."""
    schema = schema or OutputSchema()
    if result is None:
        return REASON_NOT_VALID_JSON
    if not isinstance(result, dict):
        return bi(f"預期為 JSON 物件，實際為 {type(result).__name__}", f"expected a JSON object, got {type(result).__name__}")
    missing = [k for k in schema.required if k not in result]
    if missing:
        return bi(f"回應缺少必要鍵：{', '.join(missing)}", f"response is missing required key(s): {', '.join(missing)}")
    for key, kind in schema.required.items():
        problem = kind.problem(result[key])
        if problem is not None:
            return problem
    if schema.any_of and not any(k in result and schema.any_of[k].problem(result[k]) is None for k in schema.any_of):
        return bi(f"回應沒有任何一個預期的鍵：{', '.join(schema.any_of)}",
                  f"response has none of the expected key(s): {', '.join(schema.any_of)}")
    return None
