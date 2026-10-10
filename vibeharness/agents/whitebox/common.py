"""白箱代理共用的小工具：取消排隊中的模型呼叫。
Small helpers shared by the white-box agents: cancelling queued model calls."""
from concurrent.futures import Future
from typing import Iterable


def cancel_pending(futures: Iterable[Future]) -> None:
    """取消尚未開始的 future（已在執行的呼叫無法中斷，會跑完）。`with ThreadPoolExecutor` 離開時
    只會等待，不會取消，所以重新拋出例外之前必須先呼叫這個函式。
    Cancels the futures that have not started (calls already running cannot be interrupted and finish).
    Leaving a `with ThreadPoolExecutor` block only waits, it does not cancel, so call this before re-raising."""
    for future in futures:
        future.cancel()

