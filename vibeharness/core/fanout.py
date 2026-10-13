"""扇出：並行執行一個代理彼此獨立的模型呼叫，依呼叫順序收集結果，並由這裡記錄失敗的呼叫。

一般例外（批次在閘道之外當掉）會記錄一行錯誤、以 `record_failure` 記成一次無效呼叫（品質閘門因此把缺少的結果視為證據
缺口），並以呼叫端給的 `fallback` 取代該呼叫的結果，其他呼叫繼續；LLMGatewayError（嚴格的 live 模式）與
KeyboardInterrupt 會在取消尚未開始的呼叫之後往外拋。代理只需要交出呼叫清單，不必記得池、順序、取消或失敗紀錄。
Fan-out: runs an agent's independent model calls concurrently, collects the results in call order, and books the
calls that fail here.

An ordinary exception (a batch that crashed outside the gateway) logs one error line, is booked with `record_failure`
as an invalid call (so the quality gate sees the missing result as an evidence gap), and the caller's `fallback` takes
that call's place while the others carry on; an LLMGatewayError (strict live mode) and a KeyboardInterrupt propagate
after the calls not started yet are cancelled. An agent only hands over its list of calls and has nothing to remember
about the pool, the order, cancellation or failure booking."""
import logging
import threading
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass
from typing import Any, Callable, Generic, List, Optional, Sequence, Tuple, TypeVar, cast

from vibeharness.core.i18n import bi
from vibeharness.core.llm_gateway import LLMGateway, LLMGatewayError

_T = TypeVar("_T")


@dataclass(frozen=True)
class Call(Generic[_T]):
    """一個代理呼叫：失敗時記在哪個代理名下、錯誤訊息的雙語標籤（中文, 英文），以及不帶參數的工作。
    One agent call: which agent a failure is booked under, the bilingual label (Chinese, English) of the error line,
    and the zero-argument work."""
    agent_id: str
    label: Tuple[str, str]
    run: Callable[[], _T]


def fan_out(gateway: LLMGateway, calls: Sequence[Call[_T]], *, fallback: _T, logger: logging.Logger) -> List[_T]:
    """依呼叫順序回傳每個呼叫的結果；當掉的呼叫記錄一行錯誤（以呼叫端的 logger）、記成無效呼叫，結果換成 `fallback`。
    並行數是閘道的 `max_concurrent_calls`；沒有呼叫時直接回傳空清單。
    Returns each call's result in call order; a call that crashes logs one error line (with the caller's logger), is
    booked as an invalid call, and `fallback` takes its result's place. The concurrency is the gateway's
    `max_concurrent_calls`; no calls means an empty list straight away."""
    if not calls:
        return []
    results: List[_T] = []
    for call, (result, error) in zip(calls, run_ordered([c.run for c in calls], gateway.max_concurrent_calls), strict=True):
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
    gateway.record_failure(call.agent_id, f"{type(error).__name__}: {error}")


def run_ordered(calls: List[Callable[[], _T]], max_workers: int) -> List[Tuple[Optional[_T], Optional[Exception]]]:
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
