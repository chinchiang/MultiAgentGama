"""測試用的閘道回答：替換 `gateway.generate` 的假函式用 `answer(...)` 回傳 ModelAnswer，不必自己組來源欄位。不是測試
模組（檔名不以 `test_` 開頭，pytest 不會收集它）。
Gateway answers for tests: fakes standing in for `gateway.generate` return a ModelAnswer through `answer(...)` instead
of assembling the provenance fields themselves. Not a test module (the name does not start with `test_`, so pytest
does not collect it)."""
from typing import Any, Dict, Optional

from vibeharness.core.llm_gateway import ModelAnswer


def answer(data: Optional[Dict[str, Any]] = None, *, mode: str = "live", text: Optional[str] = None,
           reason: Optional[str] = None) -> ModelAnswer:
    """`data` 為回答的 JSON 物件；預設是真實模型（"live"）的回答。
    `data` is the answer's JSON object; by default a real model's ("live") answer."""
    return ModelAnswer(mode=mode, model="test-model", data=dict(data or {}), text=text, reason=reason)
