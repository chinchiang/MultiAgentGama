"""代理呼叫與扇出：代理宣告一次模型呼叫（回答的形狀、怎麼把 items 對應成模型），`ask` 組好提示、經閘道呼叫，
交回型別化的 items 與這次呼叫的來源；`ask_batch` 與 `fan_out` 並行執行彼此獨立的呼叫、依呼叫順序收集結果，並由這裡記錄失敗的呼叫。

一般例外（批次在閘道之外當掉）會記錄一行錯誤、以 `record_failure` 記成一次無效呼叫（品質閘門因此把缺少的結果視為證據
缺口），並以呼叫端給的 `fallback` 取代該呼叫的結果，其他呼叫繼續；LLMGatewayError（嚴格的 live 模式）與
KeyboardInterrupt 會在取消尚未開始的呼叫之後往外拋。代理只需要交出呼叫清單，不必記得池、順序、取消或失敗紀錄。
Agent calls and fan-out: an agent declares one model call (the answer's shape and how its items map to models), `ask`
assembles the prompt, calls the gateway and hands back typed items with the call's provenance; `ask_batch` and
`fan_out` run independent calls concurrently, collect the results in call order, and book the calls that fail here.

An ordinary exception (a batch that crashed outside the gateway) logs one error line, is booked with `record_failure`
as an invalid call (so the quality gate sees the missing result as an evidence gap), and the caller's `fallback` takes
that call's place while the others carry on; an LLMGatewayError (strict live mode) and a KeyboardInterrupt propagate
after the calls not started yet are cancelled. An agent only hands over its list of calls and has nothing to remember
about the pool, the order, cancellation or failure booking."""
import logging
import threading
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass, field, replace
from enum import Enum
from types import MappingProxyType
from typing import Any, Callable, Dict, Generic, List, Mapping, Optional, Sequence, Tuple, TypeVar, Union, cast

from vibeharness.core.codecheck import prepare_test_code
from vibeharness.core.i18n import bi, en_only
from vibeharness.core.llm_gateway import LLMGateway, LLMGatewayError
from vibeharness.core.models import CallKind  # 也從這裡匯出 ／ re-exported here too
from vibeharness.core.model_output import OutputSchema
from vibeharness.core.sanitize import (
    UNTRUSTED_CODE_POLICY, UNTRUSTED_MODEL_POLICY, untrusted_block, untrusted_model_block,
)

_T = TypeVar("_T")


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
    GENERATED_TEST = "generated_test"


_CHANNEL_OF = {
    Content.TARGET_CODE: Channel.TARGET_CODE,
    Content.REVIEWER_FINDING: Channel.TARGET_CODE,
    Content.THREAT_ITEM: Channel.MODEL_OUTPUT,
    Content.GENERATED_TEST: Channel.MODEL_OUTPUT,
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
    """代理對一種模型呼叫的宣告：回答的 `schema`（`schema.extract_items` 直接決定 items 從哪裡擷取），以及把這次呼叫的
    items 對應成模型的 `mapper`。
    An agent's declaration of one kind of model call: the answer's `schema` (`schema.extract_items` decides where its
    items are extracted from), and the `mapper` turning one call's items into models."""
    schema: OutputSchema
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
    items, positions, malformed, skipped = call.schema.extract_items(data)
    if call.logger and call.malformed_message:
        for position in malformed:
            call.logger.warning(call.malformed_message(ctx, position))
    if call.logger and call.skip_message:
        for _ in range(skipped):
            call.logger.warning(call.skip_message(ctx))
    return items, positions


@dataclass(frozen=True)
class TextReply:
    """一次純文字代理呼叫的結果：回答原文 `text`（模擬或無法使用時為空字串）與來源 `status`。
    The result of one plain-text agent call: the raw reply `text` (empty when simulated or unusable) and the provenance
    `status`."""
    status: str
    text: str = ""


# 修復提示詞帶的測試程式碼的估計大小（一個典型的測試）；提示詞不截斷，所以這不是上限
# Estimated size of the test code a repair prompt carries (one typical test); the prompt is not truncated, so this is
# not a cap
HEAL_CODE_TOKENS = 1200


def ask_text(gateway: LLMGateway, agent_id: str, system: Tuple[str, str], prompt: Sequence[Part],
             kind: Optional[CallKind] = None, channels: Tuple[Channel, ...] = ()) -> TextReply:
    """為 `agent_id` 問一次模型、要純文字回答（不檢查形狀），`kind` 是這次呼叫的種類；宣告 `channels` 時一併附上對應的
    不可信通道 policy；它的模擬輸出沒有文字。
    Asks the model once for `agent_id` for a plain-text reply (no shape check), `kind` being the kind of call; when
    `channels` are declared, their untrusted-channel policies are included; its Simulated output has no text."""
    head, tail = system
    policies = "".join(_POLICY[c] for c in Channel if c in channels)
    answer = gateway.generate(agent_id, head + policies + tail, _user_prompt(prompt), json_output=False,
                              simulated=lambda alias: {}, kind=kind)
    return TextReply(status=answer.mode, text=answer.text or "")


@dataclass(frozen=True)
class HealSpec:
    """代理對無效測試修復呼叫的靜態宣告：歸屬哪個代理、最多修復幾次、各語言的斷言規則與記錄警告的 logger。
    An agent's static declaration of its invalid-test repair policy: owning agent, repair cap, per-language assertion
    rules and warning logger."""
    agent_id: str
    max_attempts: int
    python_rule: str
    js_rule: str
    logger: logging.Logger

    def plan(self, model_alias: str, opportunities: int) -> "PlannedCalls":
        """無效測試的修復呼叫計畫：每個產生的測試是一個機會，最多修復 `max_attempts` 次（純文字呼叫，不會被重新詢問）。
        Call plan for healing invalid tests: each generated test is one opportunity with at most `max_attempts`
        plain-text repairs (never re-asked)."""
        return PlannedCalls(
            agent_id=self.agent_id, model_alias=model_alias, kind=CallKind.HEAL, calls=opportunities,
            json_output=False, code_tokens=HEAL_CODE_TOKENS, exact=False, conditional=True,
            max_per_call=self.max_attempts,
        )


def heal_invalid_test(
    gateway: LLMGateway,
    spec: HealSpec,
    cleaned_code: str,
    problem: str,
    *,
    subject: Tuple[str, str],
    language: str,
) -> Tuple[str, Optional[str]]:
    """將未通過靜態檢查的測試程式碼與錯誤訊息透過不可信模型輸出通道請模型修復最多 `spec.max_attempts` 次。
    回傳 `(cleaned_code, problem)`（有效時 `problem` 為 `None`）；無法修復的程式碼原樣保留，絕不換成會通過的空測試。
    Asks the model at most `spec.max_attempts` times to repair test code that failed static validation, sending both the
    validation error and the draft through the untrusted model-output channel. Returns `(cleaned_code, problem)` (`None`
    when valid); unrepairable code is kept as is and never swapped for a passing no-op test."""
    zh_subject, en_subject = subject
    current_code = cleaned_code
    current_problem: Optional[str] = problem
    for attempt in range(spec.max_attempts + 1):
        assert current_problem is not None
        spec.logger.warning(bi(
            f"為 {zh_subject} 產生的測試無效（第 {attempt + 1} 次嘗試）：{current_problem}",
            f"Generated test for {en_subject} is invalid (attempt {attempt + 1}): {current_problem}",
        ))
        if attempt == spec.max_attempts:
            break
        if language == "python":
            head = (
                "The following Python pytest code failed static validation.\n"
                "Fix it so it parses and defines at least one module-level test_ function, "
                f"and {spec.python_rule} "
                "Output the corrected Python code only:\n\n"
            )
            heal_system = "Fix Python Test Code"
        else:
            head = (
                "The following node:test module failed static validation.\n"
                "Fix it so it is a valid ES module that defines at least one test() call, "
                f"and {spec.js_rule} "
                "Output the corrected JavaScript code only:\n\n"
            )
            heal_system = "Fix JavaScript Test Code"
        untrusted_draft = f"Validation error: {en_only(current_problem)}\n\n{current_code}"
        reply = ask_text(
            gateway, spec.agent_id, system=(heal_system, ""),
            prompt=[head, Untrusted(Content.GENERATED_TEST, untrusted_draft)],
            kind=CallKind.HEAL, channels=(Channel.MODEL_OUTPUT,),
        )
        fixed, next_problem, _, _ = prepare_test_code(reply.text, language)
        if not fixed:
            break  # 沒有可用來修復的內容（例如模擬引擎） ／ Nothing to repair with (e.g. simulation engine)
        current_code, current_problem = fixed, next_problem
        if current_problem is None:
            return current_code, None
    return current_code, current_problem


@dataclass(frozen=True)
class Call(Generic[_T]):
    """一個代理呼叫：失敗時記在哪個代理名下、錯誤訊息的雙語標籤（中文, 英文）、不帶參數的工作，以及這份工作的
    呼叫種類（當掉時的紀錄帶著它）。
    One agent call: which agent a failure is booked under, the bilingual label (Chinese, English) of the error line,
    the zero-argument work, and the kind of call the work is (a crash's record carries it)."""
    agent_id: str
    label: Tuple[str, str]
    run: Callable[[], _T]
    kind: Optional[CallKind] = None


@dataclass(frozen=True)
class PlannedCalls:
    """一個代理對給定輸入會發出的一組呼叫（`--estimate` 加總它們，不發出任何呼叫）。`calls` 是呼叫數；
    `conditional` 的呼叫只在回答需要時才發生（例如修復無效的測試），這時 `calls` 是機會數，每個機會最多
    `max_per_call` 次。`json_output` 的呼叫在回答無法使用時會被重新詢問；`code_tokens` 是每次呼叫帶上的程式碼
    token 數：`exact` 的計畫是實際的程式碼清單大小，其餘是估算假設的大小（預算上限或典型估計）；`exact` 表示輸入
    在執行前就已知（符號），不是依假設推出的情境（發現、威脅）。
    A set of calls an agent would make for given inputs (`--estimate` adds them up and makes none). `calls` is the
    number of calls; `conditional` calls only happen when an answer needs them (e.g. healing an invalid test), and
    `calls` is then the number of opportunities, each with at most `max_per_call` calls. `json_output` calls are
    re-asked when the answer is unusable; `code_tokens` is the code each call carries, in tokens: the actual code
    listing for `exact` plans, otherwise the size the estimate assumes (a budget cap or a typical size); `exact`
    means the inputs are known before the run (symbols) rather than a scenario from assumptions (findings, threats).
    把項目分派給各次呼叫的代理（驗證者分派發現）另外填 `assigned`（分到的項目數，情境數可能不是整數）與
    `per_call`（每次呼叫最多幾項），`--estimate` 的說明文字讀它們。
    An agent that hands items out to its calls (the verifiers hand out findings) also fills `assigned` (how many it is
    assigned, a scenario count that may not be whole) and `per_call` (the most per call), which `--estimate`'s basis
    text reads."""
    agent_id: str
    model_alias: str
    kind: CallKind
    calls: int
    json_output: bool
    code_tokens: int
    exact: bool
    conditional: bool = False
    max_per_call: int = 1
    assigned: Optional[float] = None
    per_call: Optional[int] = None


@dataclass(frozen=True)
class AgentInput:
    """一次代理呼叫的可變輸入：`system` 的 `(head, tail)`、`prompt` 片段清單與選用的 `context`。
    The per-call inputs of one agent call: the `(head, tail)` system prompt, the user-prompt parts, and the optional
    `context`."""
    system: Tuple[str, str]
    prompt: Sequence[Part]
    context: Any = None


def ask_batch(
    gateway: LLMGateway,
    call: Union[AgentCall, Callable[[_T], AgentCall]],
    items: Sequence[_T],
    prepare: Callable[[_T], AgentInput],
    *,
    agent_id: Union[str, Callable[[_T], str]],
    label: Union[Tuple[str, str], Callable[[_T], Tuple[str, str]]],
) -> List[AgentReply]:
    """對 `items` 裡的每一項建立呼叫輸入並執行 `ask()`，以 `fan_out`（`fallback=NO_REPLY`）並行執行並依序回傳
    `AgentReply` 清單。`call`、`agent_id` 與 `label` 可以是固定值或依 item 計算的函式。
    Prepares inputs and runs `ask()` for each item in `items` concurrently through `fan_out` (`fallback=NO_REPLY`),
    returning the `AgentReply` list in item order. `call`, `agent_id`, and `label` may be constants or per-item
    callables."""
    if not items:
        return []
    calls: List[Call[AgentReply]] = []
    batch_logger: Optional[logging.Logger] = None
    for item in items:
        item_call = call(item) if callable(call) else call
        item_agent = agent_id(item) if callable(agent_id) else agent_id
        if batch_logger is None and item_call.logger is not None:
            batch_logger = item_call.logger

        def _run_one(item: _T = item, ic: AgentCall = item_call, ia: str = item_agent) -> AgentReply:
            inp = prepare(item)
            return ask(gateway, ic, ia, system=inp.system, prompt=inp.prompt, context=inp.context)

        calls.append(Call(
            agent_id=item_agent,
            label=label(item) if callable(label) else label,
            run=_run_one,
            kind=item_call.kind,
        ))
    return fan_out(
        gateway, calls, fallback=NO_REPLY, logger=batch_logger or logging.getLogger("VibeHarness.AgentCall")
    )


def fan_out(gateway: LLMGateway, calls: Sequence[Call[_T]], *, fallback: _T, logger: logging.Logger) -> List[_T]:
    """依呼叫順序回傳每個呼叫的結果；當掉的呼叫記錄一行錯誤（以呼叫端的 logger）、記成無效呼叫，結果換成 `fallback`。
    並行數是閘道的 `max_concurrent_calls`；沒有呼叫時直接回傳空清單。
    Returns each call's result in call order; a call that crashes logs one error line (with the caller's logger), is
    booked as an invalid call, and `fallback` takes its result's place. The concurrency is the gateway's
    `max_concurrent_calls`; no calls means an empty list straight away."""
    if not calls:
        return []
    results: List[_T] = []
    for call, (result, error) in zip(calls, _run_ordered([c.run for c in calls], gateway.max_concurrent_calls), strict=True):
        if error is not None:
            _book(gateway, call, error, logger)
            results.append(fallback)
        else:
            # 成功的呼叫的結果就是 run() 的回傳值（可能本來就是 None）
            # A successful call's result is what run() returned (which may itself be None)
            results.append(cast(_T, result))
    return results


def _book(gateway: LLMGateway, call: "Call[Any]", error: Exception, logger: logging.Logger) -> None:
    zh, en = call.label
    logger.error(bi(f"{zh}失敗：{type(error).__name__}: {error}", f"{en} failed: {type(error).__name__}: {error}"))
    # 記入 call_log，讓品質閘門把缺少的結果視為證據缺口
    # Booked in call_log so the quality gate sees the missing result as an evidence gap
    gateway.record_failure(call.agent_id, f"{type(error).__name__}: {error}", kind=call.kind)


def _run_ordered(calls: List[Callable[[], _T]], max_workers: int) -> List[Tuple[Optional[_T], Optional[Exception]]]:
    """並行執行彼此獨立的呼叫，依呼叫順序回傳每一個的（結果, 例外）。

    一般例外會記成該呼叫的結果，讓其他呼叫繼續；LLMGatewayError（嚴格的 live 模式）與
    KeyboardInterrupt 會中止整批：還沒開始的呼叫被取消、絕不送出，然後才把例外往外拋。
    失敗的工作執行緒在自己的執行緒裡就設下中止旗標，所以它不會再接手佇列中的下一個呼叫。
    Runs independent calls concurrently and returns (result, exception) for each, in call order.

    An ordinary exception becomes that call's result so the others carry on; an LLMGatewayError (strict
    live mode) or a KeyboardInterrupt aborts the batch: calls that have not started are cancelled and never
    sent, then the exception propagates. The failing worker raises the abort flag in its own thread, so it
    never picks up the next queued call.
    """
    abort = threading.Event()

    def guarded(call: Callable[[], _T]) -> _T:
        if abort.is_set():
            raise _Aborted()
        try:
            return call()
        except BaseException as e:
            # 致命的失敗（嚴格 live 模式或中斷）在這個執行緒裡就中止整批，佇列中的下一個呼叫不會開始
            # A fatal failure (strict live mode or an interrupt) aborts the batch right in this thread, so the
            # next queued call never starts
            if isinstance(e, LLMGatewayError) or not isinstance(e, Exception):
                abort.set()
            raise

    results: List[Tuple[Optional[_T], Optional[Exception]]] = []
    with ThreadPoolExecutor(max_workers=max(1, min(max_workers, len(calls) or 1))) as pool:
        futures = [pool.submit(guarded, call) for call in calls]
        try:
            for future in futures:
                try:
                    results.append((future.result(), None))
                except LLMGatewayError:
                    raise
                except _Aborted:
                    # 致命的失敗可能排在後面：等所有呼叫結束後拋出它，而不是拋出中止標記
                    # The fatal failure may come later in call order: raise it once all calls are done,
                    # never the abort marker
                    raise _fatal_error(futures) from None
                except Exception as e:
                    results.append((None, e))
        except BaseException:
            abort.set()
            for future in futures:
                future.cancel()
            raise
    return results


def _fatal_error(futures: "List[Future[Any]]") -> BaseException:
    """已中止的一批呼叫中，第一個致命的例外（LLMGatewayError 或非 Exception 的中斷）。
    The first fatal exception (LLMGatewayError or a non-Exception interrupt) of an aborted batch of calls."""
    for future in futures:
        if future.cancelled():
            continue
        error = future.exception()
        if error is not None and not isinstance(error, _Aborted) and (
                isinstance(error, LLMGatewayError) or not isinstance(error, Exception)):
            return error
    return LLMGatewayError(bi("一批模型呼叫已中止", "a batch of model calls was aborted"))


class _Aborted(Exception):
    """整批已中止後，佇列中尚未開始的呼叫收到的標記例外（從不往外拋給呼叫端）。
    Marker raised by a queued call that starts after the batch was aborted (never surfaces to callers)."""
