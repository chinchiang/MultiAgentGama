"""白箱代理共用的小工具：取消排隊中的模型呼叫，以及把雙語欄位轉成提示詞用的英文。
Small helpers shared by the white-box agents: cancelling queued model calls, and turning bilingual
fields into prompt English."""
from concurrent.futures import Future
from typing import Iterable

from vibeharness.core.i18n import SEP, en_only, has_cjk


def cancel_pending(futures: Iterable[Future]) -> None:
    """取消尚未開始的 future（已在執行的呼叫無法中斷，會跑完）。`with ThreadPoolExecutor` 離開時
    只會等待，不會取消，所以重新拋出例外之前必須先呼叫這個函式。
    Cancels the futures that have not started (calls already running cannot be interrupted and finish).
    Leaving a `with ThreadPoolExecutor` block only waits, it does not cancel, so call this before re-raising."""
    for future in futures:
        future.cancel()


def prompt_english(text: str) -> str:
    """提示詞用的文字：只有真正的「中文 ／ English」雙語字串（分隔符前有中文、後面沒有）才取英文半。
    模型自己寫的文字若剛好含有 " ／ "（例如 "讀取 ／ 寫入" 或 "path A ／ path B"）會原樣保留，
    而不是像 `en_only` 那樣被截斷成最後一段。
    Text for a prompt: only a genuine "中文 ／ English" bilingual string (CJK before the separator, none
    after it) is reduced to its English half. Model-written text that happens to contain " ／ " (e.g.
    "讀取 ／ 寫入" or "path A ／ path B") is kept whole instead of being truncated to its last segment the
    way `en_only` would."""
    if not text or SEP not in text:
        return text or ""
    head, _sep, tail = text.rpartition(SEP)
    return en_only(text) if has_cjk(head) and not has_cjk(tail) else text
