"""回應快取：可用的模型回答以請求為鍵存在快取目錄，重新執行時直接取用，不呼叫供應商、不扣預算。
閘道（core/llm_gateway.py 的 `generate`）決定什麼時候讀、什麼時候寫（Execution mode、`--cache-only`、重新詢問）；
鍵怎麼算、檔案怎麼讀寫，以及重新詢問的回答要存哪幾把鍵，都在這裡。
The response cache: usable model answers stored in the cache directory keyed by the request, served on a re-run
without a provider call or budget. The gateway (`generate` in core/llm_gateway.py) decides when to read and when to
write (the Execution mode, `--cache-only`, re-asks); how the key is computed, how files are read and written, and
which keys a re-asked answer is stored under, live here."""
import datetime as _dt
import hashlib
import json
import logging
import os
import tempfile
from typing import Any, Dict, Mapping, Optional

from vibeharness.core.i18n import bi

# 與閘道同一個紀錄器名稱：log 格式會印出名稱，搬家不能改變輸出
# The gateway's logger name: the log format prints the name, so the move must not change the output
logger = logging.getLogger("VibeHarness.LLMGateway")

# 屬於端點身分的模型設定：任一個不同就是不同的服務端點，回應快取不得共用
# Model settings that identify the endpoint: if any differs it is a different service, so the response cache must not be shared
_ENDPOINT_IDENTITY_KEYS = ("api_base", "aws_region_name", "aws_profile_name", "api_key_env")


def key(model_alias: str, model_info: Mapping[str, Any], temperature: float, max_output_tokens: int,
        system_prompt: str, user_prompt: str) -> str:
    """一個請求的快取鍵：把模型別名、模型設定（模型、fallback 模型、額外參數、端點身分）、溫度、閘道決定的
    輸出 token 上限，以及兩段提示接在一起，整串算一次 sha256。
    The cache key of a request: the sha256 of the model alias, the model settings (model, fallback model, extra
    parameters, endpoint identity), the temperature, the output-token limit the gateway resolves, and both
    prompts."""
    # 端點身分（api_base、AWS 區域／設定檔、金鑰環境變數）也在鍵內：同一個模型字串
    # 指向另一個端點或帳號時，不得取用前一個端點的回答
    # The endpoint identity (api_base, AWS region / profile, key env var) is part of the key: the same
    # model string pointed at another endpoint or account must not be served the previous endpoint's answer
    endpoint = json.dumps({k: model_info.get(k) for k in _ENDPOINT_IDENTITY_KEYS}, sort_keys=True, default=str)
    parts = "\x00".join([
        model_alias, str(model_info.get("model")), str(model_info.get("fallback_model")), str(temperature),
        str(max_output_tokens),
        json.dumps(model_info.get("extra_params") or {}, sort_keys=True, default=str), endpoint,
        system_prompt, user_prompt,
    ])
    return hashlib.sha256(parts.encode("utf-8")).hexdigest()


def lookup(cache_dir: Optional[str], cache_key: str) -> Optional[Dict[str, Any]]:
    """快取目錄裡這把鍵的項目；沒有快取目錄、沒有檔案、檔案毀損或形狀不對（不是物件、`raw_text` 不是字串）時為 None。
    The entry stored under the key in the cache directory; None without a cache directory, without a file, or for a
    corrupt or wrongly shaped file (not an object, `raw_text` not a string)."""
    if not cache_dir:
        return None
    path = os.path.join(cache_dir, f"{cache_key}.json")
    try:
        with open(path, "r", encoding="utf-8") as f:
            entry = json.load(f)
    except (OSError, ValueError):
        return None
    return entry if isinstance(entry, dict) and isinstance(entry.get("raw_text"), str) else None


def store(cache_dir: Optional[str], cache_key: str, *, agent_id: str, model: str, raw_text: str,
          finish_reason: Optional[str], prompt_sha256: str, reask_key: Optional[str] = None) -> None:
    """把一個可用的回答寫進快取；沒有快取目錄時什麼都不做，寫不進去時只記警告。重新詢問後拿到的回答
    存在重新詢問那次提示的鍵（`reask_key`）下，也存在原始提示的鍵（`cache_key`）下：否則重新執行
    （尤其是 --cache-only）對第一次嘗試永遠未命中，因為重新詢問的提示取決於第一次那個無法使用的回答。
    Stores one usable answer; does nothing without a cache directory and only warns when it cannot write. An
    answer obtained after a re-ask is stored under the re-ask prompt's key (`reask_key`) and also under the
    original prompt's key (`cache_key`): otherwise a re-run (especially --cache-only) always misses the first
    attempt, because the re-ask prompt depends on the unusable first answer."""
    if not cache_dir:
        return
    entry = {
        "agent_id": agent_id, "model": model, "finish_reason": finish_reason, "raw_text": raw_text,
        "prompt_sha256": prompt_sha256, "created_at": _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds"),
    }
    for k in [cache_key] + ([reask_key] if reask_key else []):
        _write(cache_dir, k, entry)


def _write(cache_dir: str, cache_key: str, entry: Dict[str, Any]) -> None:
    tmp: Optional[str] = None
    try:
        # 原子性發佈：並行的代理可能寫入相同的鍵，讀取端絕不能看到寫到一半的檔案
        # Atomic publish: concurrent agents may write the same key, readers must never see a torn file
        fd, tmp = tempfile.mkstemp(prefix=".tmp-", suffix=".json", dir=cache_dir)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(entry, f, ensure_ascii=False)
        os.replace(tmp, os.path.join(cache_dir, f"{cache_key}.json"))
    except OSError as e:
        if tmp is not None:
            # 刪不掉就留著：下面的警告已經回報這次寫入失敗，`lookup` 也從不讀 `.tmp-*.json`（#145）
            # Left in place when it cannot be removed: the warning below already reports the failed write, and
            # `lookup` never reads `.tmp-*.json` (#145)
            try:
                os.unlink(tmp)
            except OSError:
                pass
        logger.warning(bi(f"無法寫入回應快取項目：{e}", f"Could not write the response cache entry: {e}"))
