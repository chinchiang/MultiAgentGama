"""模型呼叫的接縫：一次模型嘗試的請求與回覆，以及預設的 litellm 轉接器。

閘道（core/llm_gateway.py）保有所有政策：模式、預算、回應快取、主要／備援模型的嘗試順序、重新詢問與來源紀錄；
它對每個候選模型呼叫一次 `ModelTransport.complete`。轉接器失敗時直接拋出例外，由閘道改試下一個候選模型。
本模組是唯一知道 litellm 存在的地方。
The model-call seam: the request and reply of one model attempt, and the default litellm adapter.

The gateway (core/llm_gateway.py) keeps all of the policy: the mode, the budget, the response cache, the order of the
primary / fallback model attempts, re-asks and provenance; it calls `ModelTransport.complete` once per candidate model.
An adapter that fails raises, and the gateway tries the next candidate. This module is the only one that knows
litellm exists."""
import os
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Protocol

from vibeharness.core.i18n import bi

# litellm 在匯入時就會以 HTTPS 從 GitHub 抓取模型價格表（失敗還會重試、拖慢啟動），即使是 mock 或 --estimate
# 這種完全不呼叫模型的執行也一樣。改用 litellm 套件內附的本機價格表；使用者自己設定的環境變數優先（setdefault）
# litellm fetches its model cost map from GitHub over HTTPS at import time (and retries on failure, slowing start-up),
# even for a mock or --estimate run that never calls a model. Use the cost map bundled with litellm instead; a value
# the user set in the environment wins (setdefault)
os.environ.setdefault("LITELLM_LOCAL_MODEL_COST_MAP", "True")

try:
    import litellm
except ImportError:  # pragma: no cover - litellm 是選用的執行期相依套件 ／ litellm is an optional runtime dependency
    litellm = None  # type: ignore[assignment]


@dataclass(frozen=True)
class ModelRequest:
    """一次模型嘗試：哪個代理、哪個模型別名、這次嘗試的候選模型字串（主要或備援），以及 litellm 的參數。
    One model attempt: which agent, which model alias, this attempt's candidate model string (primary or fallback),
    and the litellm parameters."""
    agent_id: str
    model_alias: str
    model: str
    messages: List[Dict[str, str]]
    # 原樣的 litellm 參數（temperature、timeout、num_retries、max_tokens、端點與憑證、過濾後的 extra_params）
    # The litellm keyword arguments as is (temperature, timeout, num_retries, max_tokens, endpoint and credentials,
    # the filtered extra_params)
    params: Dict[str, Any]


@dataclass(frozen=True)
class ModelReply:
    text: str
    finish_reason: Optional[str] = None


class ModelTransport(Protocol):
    """閘道與模型供應商之間的接縫。`complete` 失敗時拋出例外；`unavailable_reason` 不是 None 時，閘道改用模擬輸出
    （hybrid）或失敗（live），完全不呼叫 `complete`。
    The seam between the gateway and the model providers. `complete` raises on failure; when `unavailable_reason` is
    not None the gateway uses Simulated output (hybrid) or fails (live) and never calls `complete`."""

    @property
    def unavailable_reason(self) -> Optional[str]: ...

    def complete(self, request: ModelRequest) -> ModelReply: ...


class LiteLLMTransport:
    """預設轉接器：每次嘗試呼叫一次 `litellm.completion`（litellm 自己的重試在 `params["num_retries"]` 內）。
    The default adapter: one `litellm.completion` call per attempt (litellm's own retries are in
    `params["num_retries"]`)."""

    @property
    def unavailable_reason(self) -> Optional[str]:
        return bi("未安裝 litellm", "litellm is not installed") if litellm is None else None

    def complete(self, request: ModelRequest) -> ModelReply:
        response = litellm.completion(model=request.model, messages=request.messages, **request.params)
        choice = response.choices[0]
        finish_reason = getattr(choice, "finish_reason", None)
        return ModelReply(choice.message.content or "", finish_reason if isinstance(finish_reason, str) else None)
