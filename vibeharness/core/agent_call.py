"""代理呼叫：代理宣告一次模型呼叫（回答的形狀、items 在哪裡、怎麼對應成模型），`ask` 組好提示、經閘道呼叫，
交回型別化的 items 與這次呼叫的來源。
Agent calls: an agent declares one model call (the answer's shape, where its items are, how they map to models), and
`ask` assembles the prompt, calls the gateway and hands back typed items with the call's provenance."""
import logging
from dataclasses import dataclass, field, replace
from enum import Enum
from types import MappingProxyType
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Tuple, Union

from vibeharness.core.llm_gateway import LLMGateway
from vibeharness.core.models import CallKind
from vibeharness.core.model_output import OutputSchema
from vibeharness.core.sanitize import (
    UNTRUSTED_CODE_POLICY, UNTRUSTED_MODEL_POLICY, untrusted_block, untrusted_model_block,
)


class Channel(Enum):
    """標示來源的不可信通道；宣告順序就是它們的 policy 接在系統提示詞裡的順序。
    The provenance-labeled untrusted channels; the declaration order is the order of their policies in the system
    prompt."""
    TARGET_CODE = "untrusted_target_code"
    MODEL_OUTPUT = "untrusted_model_output"


class Content(Enum):
    """送給模型的不可信內容種類；每一種走哪個通道由 `_CHANNEL_OF` 決定。
    The kinds of untrusted content sent to a model; `_CHANNEL_OF` decides which channel each one travels in."""
    TARGET_CODE = "target_code"
    # 審查者寫的發現文字可能引用目標裡的注入文字，所以和目標程式碼走同一個通道（0.6.0 的設計）
    # Reviewer-written finding text may quote injected text from the target, so it travels with the target code
    # (the 0.6.0 design)
    REVIEWER_FINDING = "reviewer_finding"
    THREAT_ITEM = "threat_item"


_CHANNEL_OF = {
    Content.TARGET_CODE: Channel.TARGET_CODE,
    Content.REVIEWER_FINDING: Channel.TARGET_CODE,
    Content.THREAT_ITEM: Channel.MODEL_OUTPUT,
}
_POLICY = {Channel.TARGET_CODE: UNTRUSTED_CODE_POLICY, Channel.MODEL_OUTPUT: UNTRUSTED_MODEL_POLICY}
_WRAP = {Channel.TARGET_CODE: untrusted_block, Channel.MODEL_OUTPUT: untrusted_model_block}


@dataclass(frozen=True)
class Untrusted:
    """使用者提示詞裡的一段不可信內容；`ask` 依它的種類包進對應的通道。
    A piece of untrusted content in the user prompt; `ask` wraps it in the channel its kind travels in."""
    kind: Content
    text: str


Part = Union[str, Untrusted]


@dataclass(frozen=True)
class ItemSource:
    """回答裡的 items 在哪裡：某個鍵的物件清單（`key`）；那個鍵沒有可用的項目時，改用整個回答（`key_or_answer`，
    回答本身也要符合同一條可用規則）；或整個回答就是唯一的 item（`answer`）。
    Where an answer's items are: a key's list of objects (`key`); that key's list, or else the whole answer when the
    list has no usable item (`key_or_answer`, the answer itself must pass the same usable rule); or the whole answer as
    the one item (`answer`)."""
    name: Optional[str]
    or_answer: bool = False

    @classmethod
    def key(cls, name: str) -> "ItemSource":
        return cls(name)

    @classmethod
    def key_or_answer(cls, name: str) -> "ItemSource":
        return cls(name, or_answer=True)

    @classmethod
    def answer(cls) -> "ItemSource":
        return cls(None)


@dataclass(frozen=True)
class CallContext:
    """mapper 看得到的這次呼叫：`context` 是代理在 `ask` 時帶進來的資料（例如這一批的符號），`simulated` 表示 items
    來自代理自己的模擬輸出（建構模型時就帶入，不必事後修改）。
    The call as the mapper sees it: `context` is the data the agent passed to `ask` (e.g. this batch's symbols), and
    `simulated` says the items come from the agent's own Simulated output (set when the models are built, never
    patched afterwards)."""
    context: Any
    simulated: bool = False
    # 交給 mapper 的每個 item 在回答的清單裡的位置（從 1 開始，略過的項目也佔位置）；整個回答就是那一個 item 時是 (1,)
    # Where each item handed to the mapper sits in the answer's list (from 1, skipped entries keep their place);
    # (1,) when the whole answer is the one item
    positions: Tuple[int, ...] = ()


@dataclass(frozen=True)
class AgentCall:
    """代理對一種模型呼叫的宣告：回答的 `schema`、items 所在的鍵，以及把這次呼叫的 items 對應成模型的 `mapper`。
    An agent's declaration of one kind of model call: the answer's `schema`, the key its items are under, and the
    `mapper` turning one call's items into models."""
    schema: OutputSchema
    items: ItemSource
    mapper: Callable[[List[Mapping[str, Any]], CallContext], Sequence[Any]]
    # 這種呼叫用到的通道：它們的 policy 依 Channel 的順序插在系統提示詞的 head 與 tail 之間
    # The channels this kind of call uses: their policies go between the system prompt's head and tail, in Channel
    # order
    channels: Tuple[Channel, ...] = ()
    # 有宣告時，每個不可用的物件 item 以代理自己的 logger 記一行 warning
    # When declared, each unusable object item logs one warning with the agent's own logger
    logger: Optional[logging.Logger] = None
    skip_message: Optional[Callable[[CallContext], str]] = None
    # 有宣告時，每個不是物件的 item 以代理自己的 logger 記一行 warning，帶著它在清單裡的位置
    # When declared, each item that is not an object logs one warning with the agent's own logger, with its position
    # in the list
    malformed_message: Optional[Callable[[CallContext, int], str]] = None
    # 沒有呼叫模型時的模擬輸出，依 (agent id, 模型別名) 產生；它也必須符合 `schema`
    # The Simulated output used when no model is called, built from (agent id, model alias); it must fit `schema` too
    simulated: Optional[Callable[[str, str], Dict[str, Any]]] = None
    # 這種呼叫的種類：ask 把它交給閘道，寫進每一筆呼叫紀錄與每個送給 transport 的請求
    # The kind of this call: ask hands it to the gateway, which writes it into every call record and every request
    # sent to the transport
    kind: Optional[CallKind] = None


@dataclass(frozen=True)
class AgentReply:
    """一次代理呼叫的結果：對應好的 `items`、來源 `status`，以及唯讀的 `fields`（回答的頂層欄位，例如威脅模型的
    報告層級欄位）。`status` 是 "live"（真實模型或回應快取）、"simulated"（代理自己的模擬輸出）、"invalid"（重問後
    仍無法使用）或 "none"（根本沒有回答，見 NO_REPLY）。
    The result of one agent call: the mapped `items`, the provenance `status`, and the read-only `fields` (the answer's
    top-level fields, e.g. the threat model's report-level ones). `status` is "live" (a real model or the response
    cache), "simulated" (the agent's own Simulated output), "invalid" (still unusable after the re-asks) or "none" (no
    answer at all, see NO_REPLY)."""
    status: str
    items: Tuple[Any, ...] = ()
    fields: Mapping[str, Any] = field(default_factory=lambda: MappingProxyType({}))

    @property
    def simulated(self) -> bool:
        return self.status == "simulated"

    @property
    def usable(self) -> bool:
        return self.status in ("live", "simulated")


# 沒有拿到回答的呼叫（例如在閘道之外當掉，由 fan_out 記成無效呼叫）：給 fan_out 當 fallback
# A call that got no answer (e.g. it crashed outside the gateway, booked as an invalid call by fan_out): the fallback
# handed to fan_out
NO_REPLY = AgentReply(status="none")


def _system_prompt(call: AgentCall, system: Tuple[str, str]) -> str:
    head, tail = system
    return head + "".join(_POLICY[c] for c in Channel if c in call.channels) + tail


def _user_prompt(prompt: Sequence[Part]) -> str:
    return "".join(_WRAP[_CHANNEL_OF[p.kind]](p.text) if isinstance(p, Untrusted) else p for p in prompt)


def ask(gateway: LLMGateway, call: AgentCall, agent_id: str, system: Tuple[str, str], prompt: Sequence[Part],
        context: Any = None) -> AgentReply:
    """依 `call` 的宣告為 `agent_id` 問一次模型，回傳對應好的 items。
    Asks the model once for `agent_id` as `call` declares it and returns the mapped items."""
    simulated = call.simulated
    answer = gateway.generate(agent_id, _system_prompt(call, system), _user_prompt(prompt), json_output=True,
                              schema=call.schema,
                              simulated=(lambda alias: simulated(agent_id, alias)) if simulated else None,
                              kind=call.kind)
    if not answer.usable:
        # 重問後仍無法使用：閘道已經記成 invalid 呼叫，這裡沒有 items 可對應
        # Still unusable after the re-asks: the gateway booked an invalid call, and there are no items to map
        return AgentReply(status=answer.mode)
    ctx = CallContext(context, simulated=answer.simulated)
    items, positions = _usable_items(call, answer.data, ctx)
    return AgentReply(status=answer.mode, items=tuple(call.mapper(items, replace(ctx, positions=positions))),
                      fields=MappingProxyType(dict(answer.data)))


def _usable_items(call: AgentCall, data: Mapping[str, Any],
                  ctx: CallContext) -> Tuple[List[Mapping[str, Any]], Tuple[int, ...]]:
    name = call.items.name
    if name is None:
        return [data], (1,)
    field_type = call.schema.required.get(name) or call.schema.any_of.get(name)
    usable = field_type.usable if field_type and field_type.usable else (lambda item: True)
    items: List[Mapping[str, Any]] = []
    positions: List[int] = []
    # 閘道的形狀檢查已保證可用回答的這個鍵是清單；不是清單時（例如替換閘道的測試）就當作沒有 items
    # The gateway's shape check already makes this key a list in a usable answer; anything else (e.g. a test replacing
    # the gateway) counts as no items
    raw = data.get(name)
    for position, item in enumerate(raw if isinstance(raw, list) else [], start=1):
        if not isinstance(item, dict):
            if call.logger and call.malformed_message:
                call.logger.warning(call.malformed_message(ctx, position))
            continue
        if not usable(item):
            if call.logger and call.skip_message:
                call.logger.warning(call.skip_message(ctx))
            continue
        items.append(item)
        positions.append(position)
    if not items and call.items.or_answer and usable(data):
        return [data], (1,)
    return items, tuple(positions)


@dataclass(frozen=True)
class TextReply:
    """一次純文字代理呼叫的結果：回答原文 `text`（模擬或無法使用時為空字串）與來源 `status`。
    The result of one plain-text agent call: the raw reply `text` (empty when simulated or unusable) and the provenance
    `status`."""
    status: str
    text: str = ""


def ask_text(gateway: LLMGateway, agent_id: str, system: Tuple[str, str], prompt: Sequence[Part],
             kind: Optional[CallKind] = None) -> TextReply:
    """為 `agent_id` 問一次模型、要純文字回答（不檢查形狀），`kind` 是這次呼叫的種類；它的模擬輸出沒有文字。
    Asks the model once for `agent_id` for a plain-text reply (no shape check), `kind` being the kind of call; its
    Simulated output has no text."""
    head, tail = system
    answer = gateway.generate(agent_id, head + tail, _user_prompt(prompt), json_output=False,
                              simulated=lambda alias: {}, kind=kind)
    return TextReply(status=answer.mode, text=answer.text or "")
