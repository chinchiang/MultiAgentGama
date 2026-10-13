import datetime as _dt
import hashlib
import os
import json
import tempfile
import logging
import re
import threading
from typing import Dict, Any, Optional, List
# 設定檔的 yaml 在 core/settings.py 才延遲匯入；這裡仍在匯入時載入它，缺少 yaml 的安裝才會在 main() 的防護內被認出是
# 安裝不完整（exit 5 並說明如何重新安裝），而不是在讀設定檔時才當掉
# yaml is imported lazily in core/settings.py; it is still loaded here at import time so an install without yaml is
# recognised as broken inside main()'s guard (exit 5 with reinstall instructions) instead of crashing while reading the config
import yaml  # noqa: F401

from vibeharness.core.models import AgentCallRecord
# 設定檔的預設值、載入與政策都在 core/settings.py；這裡以同名重新匯出 ／ the config defaults, loading and policy live in
# core/settings.py; re-exported here under the same names
from vibeharness.core.settings import (
    GatewaySettings,
    Overrides,
    Settings,
    load_settings,
    prepare_cache_dir,
    DEFAULT_CONFIG_PATH,
    DEFAULT_MAX_CONCURRENT_CALLS as DEFAULT_MAX_CONCURRENT_CALLS,
    DEFAULT_MAX_OUTPUT_TOKENS as DEFAULT_MAX_OUTPUT_TOKENS,
    DEFAULT_TIMEOUT_SECONDS as DEFAULT_TIMEOUT_SECONDS,
    DEFAULT_MAX_RETRIES as DEFAULT_MAX_RETRIES,
    DEFAULT_RETRY_INVALID_OUTPUT as DEFAULT_RETRY_INVALID_OUTPUT,
    DEFAULT_TEMPERATURE,
    UNCONFIGURED_ALIAS,
    _LOOPBACK_HOSTS as _LOOPBACK_HOSTS,
    is_reserved_extra_param,
    _TOKEN_CAP_PARAMS as _TOKEN_CAP_PARAMS,
    ConfigError as ConfigError,
    load_config_file as load_config_file,
    RESERVED_EXTRA_PARAMS as RESERVED_EXTRA_PARAMS,
    _RESERVED_EXTRA_PARAM_RE as _RESERVED_EXTRA_PARAM_RE,
    _TOKEN_NAME_PART_RE as _TOKEN_NAME_PART_RE,
    _COST_NAME_PART_RE as _COST_NAME_PART_RE,
    _KEY_NAME_PART_RE as _KEY_NAME_PART_RE,
    _CACHE_KEY_NAME_PART_RE as _CACHE_KEY_NAME_PART_RE,
    _is_reserved_param_name as _is_reserved_param_name,
    _DISCOVERED_SENSITIVE_GLOBAL_KEYS as _DISCOVERED_SENSITIVE_GLOBAL_KEYS,
    _DISCOVERED_SENSITIVE_GLOBAL_PREFIXES as _DISCOVERED_SENSITIVE_GLOBAL_PREFIXES,
    _BUILTIN_GLOBAL_DEFAULTS as _BUILTIN_GLOBAL_DEFAULTS,
    _DISCOVERED_ALLOWED_GLOBAL_VALUES as _DISCOVERED_ALLOWED_GLOBAL_VALUES,
    _DISCOVERED_SENSITIVE_MODEL_KEYS as _DISCOVERED_SENSITIVE_MODEL_KEYS,
    _DISCOVERED_PINNED_MODEL_KEYS as _DISCOVERED_PINNED_MODEL_KEYS,
    _PREVIOUS_BUNDLED_MODELS as _PREVIOUS_BUNDLED_MODELS,
    _DISCOVERED_COST_LIMIT_KEYS as _DISCOVERED_COST_LIMIT_KEYS,
    _ZERO_MEANS_DEFAULT_KEYS as _ZERO_MEANS_DEFAULT_KEYS,
    _DISCOVERED_REVIEWER_PREFIX as _DISCOVERED_REVIEWER_PREFIX,
    _builtin_cost_default as _builtin_cost_default,
    _effective_cost_limit as _effective_cost_limit,
    _raises_limit as _raises_limit,
    _is_sensitive_global_key as _is_sensitive_global_key,
    _is_sensitive_model_key as _is_sensitive_model_key,
    discovered_config_violations as discovered_config_violations,
    check_discovered_config as check_discovered_config,
    relative_executable_warnings as relative_executable_warnings,
)
from vibeharness.core.i18n import bi, en_only, zh_only
from vibeharness.core.sanitize import clean_model_text, redact_secrets

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

logger = logging.getLogger("VibeHarness.LLMGateway")


# 加到每個回應的鍵，讓呼叫端能分辨模擬輸出與真實模型輸出
# Key added to every response so callers can tell simulated output from real model output
PROVENANCE_KEY = "_provenance"



BUDGET_EXHAUSTED_REASON = bi("max_model_calls 預算已用盡", "max_model_calls budget exhausted")
# --cache-only：快取沒有答案時不發出任何網路呼叫；與預算用盡一樣處理（hybrid 改用模擬、live 失敗），並列為證據缺口
# --cache-only: a call the cache cannot answer makes no network call; handled like an exhausted budget
# (simulation in hybrid, failure in live) and reported as an evidence gap
CACHE_MISS_REASON = bi("--cache-only 模式下回應快取未命中", "cache miss in --cache-only mode")
REASON_NOT_VALID_JSON = bi("回應不是有效的 JSON", "response is not valid JSON")
REASON_CALL_CRASHED = bi("代理呼叫在產生輸出前就當掉", "agent call crashed before producing output")
# 附加到重新詢問的使用者提示之後，讓模型知道第一次回答哪裡有問題
# （模型提示：維持英文；雙語原因會先經過 en_only）
# Appended to the user prompt of a re-ask so the model knows what was wrong with its first answer
# (model prompt: stays English; the bilingual reason goes through en_only first)
_RETRY_SUFFIX = (
    "\n\nYour previous answer could not be used ({reason}). Answer again with ONLY the JSON object described "
    "in the instructions: no prose, no code fence, and include every required key."
)



# 屬於端點身分的模型設定：任一個不同就是不同的服務端點，回應快取不得共用
# Model settings that identify the endpoint: if any differs it is a different service, so the response cache must not be shared
_ENDPOINT_IDENTITY_KEYS = ("api_base", "aws_region_name", "aws_profile_name", "api_key_env")



class LLMGatewayError(RuntimeError):
    """在嚴格的 'live' 模式下，當真實模型呼叫不可能或失敗時拋出。
    Raised in strict 'live' mode when a real model invocation is impossible or fails."""




# 呼叫紀錄的分類：閘道的屬性與品質閘門都用這些函式，原因字串只在這裡比對
# Call-log classification: both the gateway's properties and the quality gate use these, so the reason strings are
# matched in one place
def budget_exhausted_calls(call_log: List[AgentCallRecord]) -> List[AgentCallRecord]:
    return [rec for rec in call_log if rec.reason == BUDGET_EXHAUSTED_REASON]


def cache_miss_calls(call_log: List[AgentCallRecord]) -> List[AgentCallRecord]:
    """--cache-only 模式下快取沒有答案的呼叫（證據缺口；hybrid 改用模擬）。
    Calls the cache could not answer in --cache-only mode (an evidence gap; simulated in hybrid)."""
    return [rec for rec in call_log if rec.reason == CACHE_MISS_REASON]


def simulated_calls(call_log: List[AgentCallRecord]) -> List[AgentCallRecord]:
    return [rec for rec in call_log if rec.mode == "simulated"]


def invalid_calls(call_log: List[AgentCallRecord]) -> List[AgentCallRecord]:
    return [rec for rec in call_log if rec.mode == "invalid"]


class LLMGateway:
    """
    統一閘道，負責協調對異質 LLM 的呼叫（預設為 Claude、GLM、DeepSeek 與 Gemini）。
    執行模式：
    - live：  只做真實 API 呼叫；任何缺少的金鑰或失敗都會拋出 LLMGatewayError。
    - hybrid：可能時做真實 API 呼叫，否則使用離線模擬引擎（記錄為 simulated）。
    - mock：  只使用模擬引擎。
    每次呼叫都記錄在 `call_log` 中，讓報告能揭露哪些結果是模擬的。
    Unified gateway for orchestrating calls to heterogeneous LLMs (by default Claude, GLM, DeepSeek and Gemini).
    Execution modes:
    - live:   real API calls only; any missing key or failure raises LLMGatewayError.
    - hybrid: real API calls when possible, otherwise the offline simulation engine (recorded as simulated).
    - mock:   simulation engine only.
    Every call is recorded in `call_log` so reports can disclose which results are simulated.
    """

    def __init__(self, config_path: str = DEFAULT_CONFIG_PATH, execution_mode: Optional[str] = None, *,
                 settings: Optional[Settings] = None):
        """`settings` 是 load_settings 驗證過的設定；省略時以 `config_path`（視為指定的設定檔）與 `execution_mode` 載入。
        `settings` are the settings load_settings validated; when omitted they are loaded from `config_path` (as an
        Explicit config) and `execution_mode`."""
        if settings is None:
            settings = load_settings(config_path, origin="explicit", overrides=Overrides(execution_mode=execution_mode))
        self.settings: GatewaySettings = settings.gateway
        self.execution_mode = self.settings.execution_mode
        # 唯讀，形狀與設定檔相同 ／ read-only, the same shape as the config file
        self.models_config = self.settings.models
        self.agents_config = self.settings.agents
        self.call_log: List[AgentCallRecord] = []
        # 成本防護：每次執行允許的線上模型呼叫次數（單次呼叫的 litellm 重試／fallback_model
        # 不另外計算）。None 表示不限制。
        # Cost guard: live model invocations allowed per run (litellm retries / fallback_model of one
        # invocation are not counted separately). None means unlimited.
        self.max_model_calls = self.settings.max_model_calls
        # 代理把呼叫分散到最多這麼多個工作者的執行緒池上
        # Agents fan their calls out on a thread pool of at most this many workers
        self.max_concurrent_calls = self.settings.max_concurrent_calls
        self.live_calls_attempted = 0
        self._budget_lock = threading.Lock()
        self.retry_invalid_output = self.settings.retry_invalid_output
        # 以模型 + 提示為鍵、存放可用線上回答的磁碟快取：以相同設定重新執行相同目標
        # 不需任何花費，且得到相同的回答。None 表示停用。
        # On-disk cache of usable live answers keyed by model + prompt: a re-run of the same target with
        # the same config costs nothing and gives the same answers. None disables it.
        self.cache_dir: Optional[str] = self.settings.cache_dir
        # --cache-only：每次模型呼叫都只從回應快取取用，未命中時絕不呼叫供應商（見 CACHE_MISS_REASON）
        # --cache-only: every model call is served from the response cache only; a miss never calls a provider (see CACHE_MISS_REASON)
        self.cache_only = self.settings.cache_only

    def set_cache_dir(self, path: str) -> None:
        """在 `path` 啟用回應快取（不存在時會建立；見 prepare_cache_dir）。
        Enables the response cache in `path` (created if missing; see prepare_cache_dir)."""
        self.cache_dir = prepare_cache_dir(path)

    def _cache_key(self, model_alias: str, model_info: Dict[str, Any], temperature: float, system_prompt: str, user_prompt: str) -> str:
        # 端點身分（api_base、AWS 區域／設定檔、金鑰環境變數）也在鍵內：同一個模型字串
        # 指向另一個端點或帳號時，不得取用前一個端點的回答
        # The endpoint identity (api_base, AWS region / profile, key env var) is part of the key: the same
        # model string pointed at another endpoint or account must not be served the previous endpoint's answer
        endpoint = json.dumps({k: model_info.get(k) for k in _ENDPOINT_IDENTITY_KEYS}, sort_keys=True, default=str)
        parts = "\x00".join([
            model_alias, str(model_info.get("model")), str(model_info.get("fallback_model")), str(temperature),
            str(self._max_output_tokens(model_info)),
            json.dumps(model_info.get("extra_params") or {}, sort_keys=True, default=str), endpoint,
            system_prompt, user_prompt,
        ])
        return hashlib.sha256(parts.encode("utf-8")).hexdigest()

    def _cache_read(self, key: str) -> Optional[Dict[str, Any]]:
        if not self.cache_dir:
            return None
        path = os.path.join(self.cache_dir, f"{key}.json")
        try:
            with open(path, "r", encoding="utf-8") as f:
                entry = json.load(f)
        except (OSError, ValueError):
            return None
        return entry if isinstance(entry, dict) and isinstance(entry.get("raw_text"), str) else None

    def _cache_write(self, key: str, agent_id: str, model_name: str, raw_text: str, finish_reason: Optional[str], prompt_sha256: str) -> None:
        if not self.cache_dir:
            return
        entry = {
            "agent_id": agent_id, "model": model_name, "finish_reason": finish_reason, "raw_text": raw_text,
            "prompt_sha256": prompt_sha256, "created_at": _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds"),
        }
        try:
            # 原子性發佈：並行的代理可能寫入相同的鍵，讀取端絕不能看到寫到一半的檔案
            # Atomic publish: concurrent agents may write the same key, readers must never see a torn file
            fd, tmp = tempfile.mkstemp(prefix=".tmp-", suffix=".json", dir=self.cache_dir)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(entry, f, ensure_ascii=False)
            os.replace(tmp, os.path.join(self.cache_dir, f"{key}.json"))
        except OSError as e:
            logger.warning(bi(f"無法寫入回應快取項目：{e}", f"Could not write the response cache entry: {e}"))

    @staticmethod
    def _safe_reason(text: str) -> str:
        """可供記錄或列入報告的供應商錯誤文字：憑證已遮蔽（HTTP 用戶端
        可能回聲出帶有 API 金鑰的請求 URL 或標頭），控制字元已移除。
        Provider error text as it may be logged or reported: credentials redacted (an HTTP client
        can echo a request URL or header carrying the API key), control characters removed."""
        return clean_model_text(redact_secrets(str(text)))

    def _reserve_live_call(self) -> bool:
        """從預算中認領一次線上呼叫（執行緒安全）；預算用盡時為 False。
        Claims one live invocation from the budget (thread-safe); False when it is exhausted."""
        with self._budget_lock:
            if self.max_model_calls is not None and self.live_calls_attempted >= self.max_model_calls:
                return False
            self.live_calls_attempted += 1
            return True

    @property
    def budget_exhausted_calls(self) -> List[AgentCallRecord]:
        return budget_exhausted_calls(self.call_log)

    @property
    def cache_miss_calls(self) -> List[AgentCallRecord]:
        return cache_miss_calls(self.call_log)

    @property
    def used_simulation(self) -> bool:
        return bool(simulated_calls(self.call_log))

    @property
    def invalid_calls(self) -> List[AgentCallRecord]:
        return invalid_calls(self.call_log)

    @property
    def retried_calls(self) -> List[AgentCallRecord]:
        """回答無法使用而被重新詢問的首次嘗試（會揭露，但不是證據缺口）。
        First attempts whose answer was unusable and that were re-asked (disclosed, not an evidence gap)."""
        return [rec for rec in self.call_log if rec.mode == "retried"]

    @staticmethod
    def is_simulated(resp: Dict[str, Any]) -> bool:
        return resp.get(PROVENANCE_KEY, {}).get("mode") == "simulated"

    @staticmethod
    def is_usable(resp: Dict[str, Any]) -> bool:
        """模型有回答但其輸出無法使用時為 False。
        False when the model answered but its output could not be used."""
        return resp.get(PROVENANCE_KEY, {}).get("mode") != "invalid"

    def is_live_configured(self, model_alias: str) -> bool:
        """檢查所要求的模型是否具備憑證：其 API 金鑰，或 AWS 設定檔
        （Bedrock 透過 AWS 憑證鏈驗證，而非 API 金鑰）。
        Checks whether the requested model has credentials: its API key, or an AWS profile
        (Bedrock authenticates through the AWS credential chain, not an API key)."""
        model_info = self.models_config.get(model_alias) or {}
        if model_info.get("aws_profile_name"):
            return True
        env_var = model_info.get("api_key_env")
        return bool(env_var and os.getenv(env_var))

    def generate(
        self,
        agent_id: str,
        system_prompt: str,
        user_prompt: str,
        json_output: bool = True,
        required_keys: Optional[List[str]] = None,
        required_keys_any: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        針對指定代理所設定的 LLM 執行提示。
        線上回應若不是有效的 JSON，或缺少 `required_keys` 中的任一鍵（全部都必須
        存在）或 `required_keys_any`（至少要有一個存在），會以 mode "invalid" 記錄，
        回傳只含 PROVENANCE_KEY（mode "invalid"、model、reason）的 dict，讓呼叫端與品質閘門絕不會把無法使用的回答
        誤認為真正的空結果（以 is_usable() 判斷）。
        Executes a prompt targeting the designated agent's configured LLM.
        A live response that is not valid JSON or lacks any of `required_keys` (all must be
        present) or `required_keys_any` (at least one must be present) is recorded with
        mode "invalid" and returned as a dict holding only PROVENANCE_KEY (mode "invalid", model, reason), so
        callers and the quality gate never mistake an unusable answer for a genuine empty result (check is_usable()).
        """
        agent_meta = self.agents_config.get(agent_id) or {}
        model_alias = agent_meta.get("model_alias") or UNCONFIGURED_ALIAS
        # null 與省略相同（預設值）：None 絕不會送進 litellm 或快取鍵 ／ null means omitted (the default): None never reaches litellm or the cache key
        raw_temperature = agent_meta.get("temperature")
        temperature = DEFAULT_TEMPERATURE if raw_temperature is None else raw_temperature
        model_info = self.models_config.get(model_alias) or {}
        model_name = model_info.get("model") or f"(no model configured for alias '{model_alias}')"
        # 重新詢問一律從主要模型開始：model_name 之後會改成實際回答的模型（可能是 fallback），
        # 若拿它當下一次的主要模型，主要模型會被跳過、fallback 被呼叫兩次
        # A re-ask always starts from the primary: model_name later becomes the model that actually answered
        # (possibly the fallback); using it as the next primary would skip the primary and call the fallback twice
        primary_model = model_name
        prompt_hash = hashlib.sha256(f"{system_prompt}\x00{user_prompt}".encode("utf-8")).hexdigest()

        # 決定要呼叫線上 API 還是模擬引擎
        # Decide whether to invoke live API or mock engine
        fallback_reason: Optional[str] = None
        if self.execution_mode == "mock":
            fallback_reason = bi("execution_mode 為 'mock'", "execution_mode is 'mock'")
        elif self.cache_only:
            # 只讀快取不需要 litellm 或金鑰：命中直接取用，未命中在下方登記為 CACHE_MISS_REASON
            # Reading the cache needs neither litellm nor a key: a hit is served, a miss is booked below as CACHE_MISS_REASON
            pass
        elif litellm is None:
            fallback_reason = bi("未安裝 litellm", "litellm is not installed")
        elif not self.is_live_configured(model_alias):
            env_var = model_info.get("api_key_env") or "<no api_key_env configured>"
            fallback_reason = bi(f"未設定 API 金鑰環境變數 {env_var}", f"API key env var {env_var} is not set")
        cached: Optional[Dict[str, Any]] = None
        cache_key = ""
        # 這次邏輯呼叫的第幾次詢問，登記在每筆紀錄上，讓 sorted_call_log 保留時間順序
        # Which ask of this logical call is current, booked on every record so sorted_call_log keeps the chronology
        attempt = 0
        if fallback_reason is None:
            cache_key = self._cache_key(model_alias, model_info, temperature, system_prompt, user_prompt)
            cached = self._cache_read(cache_key)
            if cached is None and self.cache_only:
                # 不呼叫網路、不扣預算；之後與預算用盡相同：live 拋出 LLMGatewayError，hybrid 改用模擬
                # No network call and no budget spent; then the same as an exhausted budget: live raises LLMGatewayError, hybrid simulates
                fallback_reason = CACHE_MISS_REASON
            elif cached is None and not self._reserve_live_call():
                fallback_reason = BUDGET_EXHAUSTED_REASON

        if fallback_reason is None:
            logger.info(bi(f"將 [{agent_id}] 派送至線上 LLM：{model_name}（別名：{model_alias}）",
                           f"Dispatching [{agent_id}] to Live LLM: {model_name} (Alias: {model_alias})"))
            # 無法使用的回答（以散文取代 JSON、缺少鍵、安全過濾器造成的空白回應）
            # 會在登記為 `invalid` 之前，附上問題說明重新詢問最多 retry_invalid_output 次：
            # 在線上執行中，多數這類回答只是一次性的格式失誤，而過去每一筆都會讓
            # 整次執行變成 INCONCLUSIVE。重新詢問是計入預算的真實呼叫。
            # An unusable answer (prose instead of JSON, a missing key, an empty response from a safety
            # filter) is re-asked up to retry_invalid_output times, naming the problem, before it is
            # booked as `invalid`: in live runs most such answers are one-off format slips, and each
            # one used to turn the whole run INCONCLUSIVE. Re-asks are real calls against the budget.
            prompt_text = user_prompt
            while True:
                messages = [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": prompt_text}
                ]
                try:
                    if cached is not None and attempt == 0:
                        raw_text, model_name = cached["raw_text"], str(cached.get("model") or model_name)
                        finish_reason = cached.get("finish_reason") if isinstance(cached.get("finish_reason"), str) else None
                        logger.info(bi(f"[{agent_id}] 回答取自回應快取（{model_name}）",
                                       f"[{agent_id}] answer served from the response cache ({model_name})"))
                    else:
                        raw_text, model_name, finish_reason = self._complete(model_info, primary_model, messages, temperature)
                except Exception as e:
                    fallback_reason = f"{bi('線上呼叫失敗', 'live invocation failed')}: {self._safe_reason(str(e))}"
                    if self.execution_mode == "live":
                        raise LLMGatewayError(f"[{agent_id}] {model_name}: {fallback_reason}") from e
                    logger.warning(bi(f"{agent_id}（{model_name}）線上呼叫失敗：{fallback_reason}。改用模擬邏輯。",
                                      f"Live invocation failed for {agent_id} ({model_name}): {fallback_reason}. "
                                      "Falling back to simulation logic."))
                    break
                # 上方只防護網路呼叫：解析／驗證／登記中的錯誤
                # 必須明確失敗，而不是被掩蓋成退回模擬。
                # Only the network call is guarded above: a bug in parsing/validation/booking
                # must fail loudly instead of being masked as a fallback to simulation.
                result = self._clean_and_parse_json(raw_text) if json_output else {"raw": raw_text}
                problem = self._validate_output(result, json_output, required_keys, required_keys_any)
                if problem is None and result is not None:
                    from_cache = cached is not None and attempt == 0
                    if not from_cache:
                        # 重新詢問後的可用回答也存到原始提示的鍵下：否則重新執行（尤其是 --cache-only）
                        # 對第一次嘗試永遠未命中，因為重新詢問的提示取決於第一次那個無法使用的回答
                        # A usable answer after a re-ask is also stored under the original prompt's key: otherwise a
                        # re-run (especially --cache-only) always misses the first attempt, because the re-ask
                        # prompt depends on the unusable first answer
                        keys = [cache_key] if attempt == 0 else [cache_key, self._cache_key(
                            model_alias, model_info, temperature, system_prompt, prompt_text
                        )]
                        for key in keys:
                            self._cache_write(key, agent_id, model_name, raw_text, finish_reason, prompt_hash)
                    self._record(agent_id, model_alias, model_name, "live", prompt_sha256=prompt_hash, cached=from_cache,
                                 attempt=attempt)
                    result[PROVENANCE_KEY] = {"mode": "live", "model": model_name, "cached": from_cache}
                    return result
                reason = problem or REASON_NOT_VALID_JSON
                if not raw_text.strip():
                    # 例如供應商的安全過濾器阻擋了攻擊測試程式碼；finish reason 會說明是哪一種
                    # e.g. a provider safety filter blocking attack-test code; the finish reason says which
                    reason = bi(f"模型回傳空白回應（finish_reason: {finish_reason or 'unknown'}）",
                                f"model returned an empty response (finish_reason: {finish_reason or 'unknown'})")
                if finish_reason == "length":
                    # 推理模型會把部分預算花在思考上；要說明這點，而不是歸咎於格式
                    # Reasoning models spend part of the budget thinking; say so instead of blaming the format
                    limit = self._max_output_tokens(model_info)
                    reason = bi(
                        f"輸出在 max_output_tokens 上限（{limit}）被截斷；{zh_only(reason)}。"
                        "請提高此模型的 max_output_tokens（推理 token 也計入此上限）",
                        f"output truncated at the max_output_tokens limit ({limit}); "
                        f"{en_only(reason)}. Raise max_output_tokens for this model (reasoning tokens count against it)"
                    )
                # --cache-only 絕不重新詢問：重新詢問是網路呼叫
                # --cache-only never re-asks: a re-ask is a network call
                if (not self.cache_only and json_output and attempt < self.retry_invalid_output
                        and self._reserve_live_call()):
                    self._record(agent_id, model_alias, model_name, "retried", reason, prompt_sha256=prompt_hash, attempt=attempt)
                    attempt += 1
                    logger.warning(bi(f"[{agent_id}] {model_name} 回傳無法使用的輸出（{reason}）；重新詢問（{attempt}/{self.retry_invalid_output}）",
                                      f"[{agent_id}] {model_name} returned unusable output ({reason}); re-asking ({attempt}/{self.retry_invalid_output})"))
                    # 提示維持英文：只有原因的英文部分會送達模型
                    # The prompt stays English: only the English half of the reason reaches the model
                    prompt_text = user_prompt + _RETRY_SUFFIX.format(reason=en_only(reason))
                    continue
                logger.error(bi(f"[{agent_id}] {model_name} 回傳無法使用的輸出：{reason}",
                                f"[{agent_id}] {model_name} returned unusable output: {reason}"))
                self._record(agent_id, model_alias, model_name, "invalid", reason, prompt_sha256=prompt_hash, attempt=attempt)
                return {PROVENANCE_KEY: {"mode": "invalid", "model": model_name, "reason": reason}}
        elif self.execution_mode == "live":
            raise LLMGatewayError(f"[{agent_id}] {bi(f'無法以 {model_name} 執行線上模式', f'cannot run live with {model_name}')}: {fallback_reason}")

        # 離線／模擬退回路徑
        # Offline / Mock Fallback
        logger.info(bi(f"將 [{agent_id}] 派送至模擬引擎（模型別名：{model_alias}；原因：{fallback_reason}）",
                       f"Dispatching [{agent_id}] to Simulation Engine (Model Alias: {model_alias}; reason: {fallback_reason})"))
        self._record(agent_id, model_alias, model_name, "simulated", fallback_reason, prompt_sha256=prompt_hash, attempt=attempt)
        result = self._generate_simulated_response(agent_id, model_alias, user_prompt)
        result[PROVENANCE_KEY] = {"mode": "simulated", "model": model_name, "reason": fallback_reason}
        return result

    def _complete(self, model_info: Dict[str, Any], model_name: str, messages: List[Dict[str, str]], temperature: float):
        """
        呼叫主要模型（含 litellm 自身的重試），主要模型失敗時再呼叫一次 `fallback_model`。
        API 金鑰會明確傳入，因此 litellm 預設環境變數與 `api_key_env` 不同的供應商
        （例如 GLM 的 Z.AI）仍能通過驗證。
        回傳 (text, model_actually_used, finish_reason)；finish_reason 為 "length" 表示 token 上限截斷了輸出。
        Calls the primary model (with litellm's own retries), then `fallback_model` once if the primary fails.
        The API key is passed explicitly, so providers whose litellm default env var differs from
        `api_key_env` (e.g. Z.AI for GLM) still authenticate.
        Returns (text, model_actually_used, finish_reason); finish_reason "length" means the token limit cut it off.
        """
        if self.cache_only:
            # 縱深防禦：generate 在 --cache-only 下不會走到這裡；萬一走到，也絕不發出網路呼叫
            # Defense in depth: generate never gets here under --cache-only; if it ever did, no network call is made
            raise LLMGatewayError(bi("--cache-only 模式下不允許網路呼叫", "network calls are not allowed in --cache-only mode"))
        env_var = model_info.get("api_key_env")
        aws_profile = model_info.get("aws_profile_name")
        if not env_var and not aws_profile:
            # 以可採取行動的訊息失敗，而不是讓下方的設定查詢拋出 KeyError
            # Fail with an actionable message instead of a KeyError from the config lookup below
            raise LLMGatewayError(bi(
                f"模型 '{model_name}' 未設定 'api_key_env'（Bedrock 則為 'aws_profile_name'）；"
                "請在代理設定檔的 models 區段設定後才能進行線上呼叫。",
                f"Model '{model_name}' has no 'api_key_env' (or 'aws_profile_name' for Bedrock) configured; "
                "set it in the models section of the agents config to make live calls."
            ))
        kwargs: Dict[str, Any] = {
            "messages": messages,
            "temperature": temperature,
            # 較新的模型會拒絕取樣參數（Bedrock 上的 Claude Opus 5.5 只接受 temperature=1；
            # Gemini 3 正在棄用它們）：捨棄模型不支援的參數，而不是讓呼叫失敗
            # Newer models reject sampling knobs (Claude Opus 5.5 on Bedrock accepts only temperature=1;
            # Gemini 3 is deprecating them): drop what a model does not support rather than failing the call
            "drop_params": True,
            # null 已在載入設定時換成預設值：timeout=None 對 litellm 代表不限時，絕不傳出
            # null was already replaced by the default when the settings were loaded: timeout=None means no limit to litellm and is never passed
            "timeout": self.settings.timeout_seconds,
            "num_retries": self.settings.max_retries,
            "max_tokens": self._max_output_tokens(model_info),
        }
        if env_var:
            kwargs["api_key"] = os.getenv(env_var)
        if aws_profile:
            kwargs["aws_profile_name"] = aws_profile
            if model_info.get("aws_region_name"):
                kwargs["aws_region_name"] = model_info["aws_region_name"]
        if model_info.get("api_base"):
            kwargs["api_base"] = model_info["api_base"]
        # 逐模型的 litellm 直通參數，例如 {thinking: {type: disabled}} 或 {reasoning_effort: low}，
        # 讓推理模型不會把整個輸出預算花在思考上（啟動時驗證為對應表）
        # Per-model litellm passthrough, e.g. {thinking: {type: disabled}} or {reasoning_effort: low} so a
        # reasoning model does not spend the whole output budget thinking (validated as a mapping at start-up)
        # 保留參數（端點、憑證、逾時、重試、請求內容）已在啟動時拒絕；這裡再過濾一次作為縱深防禦
        # Reserved parameters (endpoint, credentials, timeout, retries, request content) are rejected at
        # start-up; they are filtered again here as defense in depth
        kwargs.update({k: v for k, v in (model_info.get("extra_params") or {}).items() if not is_reserved_extra_param(k)})

        candidates = [model_name] + ([model_info["fallback_model"]] if model_info.get("fallback_model") else [])
        last_error: Optional[Exception] = None
        for candidate in candidates:
            try:
                response = litellm.completion(model=candidate, **kwargs)
                choice = response.choices[0]
                finish_reason = getattr(choice, "finish_reason", None)
                return choice.message.content or "", candidate, finish_reason if isinstance(finish_reason, str) else None
            except Exception as e:
                last_error = e
                logger.warning(bi(f"模型 {candidate} 失敗：{self._safe_reason(str(e))}",
                                  f"Model {candidate} failed: {self._safe_reason(str(e))}"))
        if last_error is None:
            # 實務上不會執行到：candidates 絕不會是空的，但絕不拋出 Optional
            # Unreachable in practice: candidates is never empty, but never raise an Optional
            raise LLMGatewayError(bi(f"模型 {model_name}：沒有任何候選模型可以嘗試",
                                     f"Model {model_name}: no candidate model could be attempted"))
        raise last_error

    def _max_output_tokens(self, model_info: Dict[str, Any]) -> int:
        """逐模型的 `max_output_tokens` 會覆寫全域設定：推理模型（GLM、DeepSeek、
        Gemini 3）會把思考 token 計入此上限，因此需要較大的預算。
        Per-model `max_output_tokens` overrides the global one: reasoning models (GLM, DeepSeek,
        Gemini 3) count thinking tokens against this limit and need a larger budget.
        逐模型值省略或為 null 時採用全域值；全域值省略或為 null 時採用 DEFAULT_MAX_OUTPUT_TOKENS。
        A per-model value that is omitted or null falls back to the global one; an omitted or null global
        value falls back to DEFAULT_MAX_OUTPUT_TOKENS."""
        value = model_info.get("max_output_tokens")
        if value is None:
            value = self.settings.max_output_tokens
        return int(value)

    @staticmethod
    def _validate_output(
        result: Any, json_output: bool,
        required_keys: Optional[List[str]], required_keys_any: Optional[List[str]] = None
    ) -> Optional[str]:
        if not json_output:
            return None
        if result is None:
            return REASON_NOT_VALID_JSON
        if not isinstance(result, dict):
            return bi(f"預期為 JSON 物件，實際為 {type(result).__name__}", f"expected a JSON object, got {type(result).__name__}")
        missing = [k for k in (required_keys or []) if k not in result]
        if missing:
            return bi(f"回應缺少必要鍵：{', '.join(missing)}", f"response is missing required key(s): {', '.join(missing)}")
        if required_keys_any and not any(k in result for k in required_keys_any):
            return bi(f"回應沒有任何一個預期的鍵：{', '.join(required_keys_any)}",
                      f"response has none of the expected key(s): {', '.join(required_keys_any)}")
        return None

    def record_failure(self, agent_id: str, reason: str) -> None:
        """登記一次在閘道能回答之前就當掉的代理呼叫（例如呼叫端執行緒池批次中的
        例外）。記錄為 `invalid` 呼叫，讓品質閘門把缺少的結果視為證據缺口，
        而不是把沉默誤認為「沒有發現」。
        Books an agent call that crashed before the gateway could answer (e.g. an exception in
        the caller's thread-pool batch). Recorded as an `invalid` call so the quality gate sees the
        missing result as an evidence gap instead of mistaking silence for "nothing found"."""
        agent_meta = self.agents_config.get(agent_id) or {}
        model_alias = agent_meta.get("model_alias") or UNCONFIGURED_ALIAS
        model_info = self.models_config.get(model_alias) or {}
        model_name = model_info.get("model") or f"(no model configured for alias '{model_alias}')"
        self._record(agent_id, model_alias, model_name, "invalid", f"{REASON_CALL_CRASHED}: {reason}")

    def _record(
        self, agent_id: str, model_alias: str, model_name: str, mode: str,
        reason: Optional[str] = None, prompt_sha256: Optional[str] = None, cached: bool = False, attempt: int = 0
    ):
        self.call_log.append(AgentCallRecord(
            agent_id=agent_id, model_alias=model_alias, model_name=model_name, mode=mode,
            reason=self._safe_reason(reason) if reason is not None else None,
            prompt_sha256=prompt_sha256, cached=cached, attempt=attempt
        ))

    @property
    def cached_calls(self) -> List[AgentCallRecord]:
        return [rec for rec in self.call_log if rec.cached]

    def _clean_and_parse_json(self, text: str) -> Optional[Dict[str, Any]]:
        """剝除 markdown 程式碼圍欄並安全地解析 JSON，並提供對話式退回路徑。
        Strips markdown code fences and parses JSON safely, with conversational fallback."""
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

        logger.error(bi(f"JSON 解析錯誤：無法擷取有效的 JSON。原始內容：{text[:200]}",
                        f"JSON parsing error: could not extract valid JSON. Raw content: {text[:200]}"))
        # 回傳 None（而非哨兵 dict）：模型可能正當地回聲出這樣的 dict，
        # 那會與解析失敗無法區分。
        # None (not a sentinel dict): a model could legitimately echo such a dict, which would
        # have been indistinguishable from a parse failure.
        return None

    def _generate_simulated_response(self, agent_id: str, model_alias: str, prompt: str) -> Dict[str, Any]:
        """
        反映各審查者關注重點的高擬真領域專屬退回邏輯：
        - Claude：狀態轉換、缺少的 null 檢查、邊界情況邏輯。
        - DeepSeek：邊界限制、輸入消毒、防禦性守衛。
        - GLM：合約規格、API 合規性、參數驗證。
        - Gemini：AI/LLM 整合（OWASP Top 10 for LLM Applications 2026）。
        審查者樣板依模型別名選取，退而以代理 id 的字尾選取。
        注意：回應是與目標程式碼無關的固定樣板；它們的存在是為了讓
        流程能離線演練，且在報告中一律標示為 simulated。
        High-fidelity domain-specific fallback logic reflecting each reviewer's focus:
        - Claude: state transitions, missing null checks, edge-case logic.
        - DeepSeek: boundary limits, input sanitization, defensive guards.
        - GLM: contract specifications, API compliance, parameter validation.
        - Gemini: AI/LLM integration (OWASP Top 10 for LLM Applications 2026).
        Reviewer templates are chosen by model alias, falling back to the agent id's suffix.
        NOTE: responses are fixed templates independent of the target code; they exist so the
        pipeline can be exercised offline and are always flagged as simulated in reports.
        """
        if "reviewer_" in agent_id:
            template = _SIMULATED_REVIEWS.get(model_alias) or _SIMULATED_REVIEWS.get(agent_id.rsplit("_", 1)[-1])
            return {"findings": [dict(template)] if template else []}

        if "verifier" in agent_id:
            # 樣板無法評判針對目標的發現；辯論者會略過模擬的裁決
            # A template cannot judge target-specific findings; the debater ignores simulated verdicts
            return {"verdicts": []}

        elif "threat_modeler" in agent_id:
            return {
                "system_description": bi("Vibe coding 產出的網頁應用程式與 API 服務。", "Vibe-coded web application and API service."),
                "entrypoints": [bi("REST API 路由", "REST API routes"), bi("驗證標頭", "Auth headers"),
                                bi("使用者註冊／管理端點", "User registration / management endpoints")],
                "trust_boundaries": [bi("用戶端／網際網路到公開閘道", "Client / Internet to Public Gateway"),
                                     bi("公開閘道到內部資料庫", "Public Gateway to Internal DB")],
                "assets": [bi("使用者憑證", "User credentials"), bi("客戶資料紀錄", "Customer data records"),
                           bi("資料庫連線字串", "Database connection strings")],
                "threats": [
                    {
                        "threat_id": "THREAT-01",
                        "stride_category": "Elevation of Privilege",
                        "owasp_mapping": "API1:2023 - Broken Object Level Authorization (BOLA)",
                        "title": bi("資源更新的 BOLA / IDOR", "BOLA / IDOR on Resource Updates"),
                        "description": bi("已驗證的使用者只要竄改 URL 路徑或酬載中的物件 ID，就能修改其他使用者的物件。",
                                          "An authenticated user can modify other users' objects by simply tampering with the object ID in the URL path or payload."),
                        "asset_at_risk": bi("使用者帳號與私人紀錄", "User accounts & private records"),
                        "attack_vector": "HTTP PUT/PATCH /api/users/{foreign_id}",
                        "trust_boundary_crossed": bi("使用者 A 的邊界跨入使用者 B 的資料領域", "User A boundary into User B data domain"),
                        "severity": "CRITICAL",
                        "attack_scenario": bi("以使用者 A 登入，對使用者 B 的資源 ID 發出 PUT 請求。",
                                              "Login as User A, issue a PUT request targeting User B's resource ID."),
                        "test_verification_goal": bi("確認狀態碼為 403 Forbidden 或 404 Not Found，絕不可為 200 OK。",
                                                     "Ensure status code is 403 Forbidden or 404 Not Found, never 200 OK.")
                    },
                    {
                        "threat_id": "THREAT-02",
                        "stride_category": "Tampering",
                        "owasp_mapping": "API3:2023 - Broken Object Property Level Authorization",
                        "title": bi("管理員／敏感欄位的大量指派", "Mass Assignment of Admin / Sensitive Fields"),
                        "description": bi("更新端點接受原始 JSON 本文並直接套用到資料庫模型，沒有嚴格的允許清單，使用者因此能注入 is_admin=true。",
                                          "The update endpoint accepts raw JSON body and applies it to the DB model without a strict whitelist, allowing users to inject is_admin=true."),
                        "asset_at_risk": bi("系統授權完整性", "System authorization integrity"),
                        "attack_vector": "HTTP POST/PUT with extra 'is_admin': true in payload",
                        "trust_boundary_crossed": bi("無特權用戶端到特權角色", "Unprivileged client to privileged role"),
                        "severity": "HIGH",
                        "attack_scenario": bi("在更新個人資料時送出酬載 {'name': 'test', 'is_admin': true}。",
                                              "Send payload {'name': 'test', 'is_admin': true} during profile update."),
                        "test_verification_goal": bi("確認 is_admin 維持 false，且無法透過公開端點更改。",
                                                     "Ensure is_admin remains false and cannot be altered through public endpoint.")
                    },
                    {
                        "threat_id": "THREAT-03",
                        "stride_category": "Information Disclosure",
                        "owasp_mapping": "API8:2023 - Security Misconfiguration",
                        "title": bi("格式錯誤輸入導致堆疊追蹤與資料庫錯誤外洩", "Stack Trace & Database Error Leakage on Malformed Input"),
                        "description": bi("送出無效的 JSON 或語法字元會造成未處理的 500 錯誤，外洩內部資料庫細節與檔案路徑。",
                                          "Sending invalid JSON or syntax characters causes unhandled 500 error leaking internal database details and file paths."),
                        "asset_at_risk": bi("內部系統架構細節", "Internal system architecture details"),
                        "attack_vector": "HTTP POST with malformed syntax / SQL injection characters",
                        "trust_boundary_crossed": bi("內部錯誤日誌流到外部 HTTP 回應", "Internal error logs to external HTTP response"),
                        "severity": "MEDIUM",
                        "attack_scenario": bi("送出格式錯誤的酬載，並檢查 HTTP 回應本文是否含有追蹤記錄。",
                                              "Send malformed payload and inspect HTTP response body for tracebacks."),
                        "test_verification_goal": bi("確認回應只含一般性的錯誤訊息，沒有檔案路徑或 SQL 關鍵字。",
                                                     "Ensure response contains generic error message without file paths or SQL keywords.")
                    }
                ]
            }

        elif "test_synthesizer" in agent_id or "test_generator" in agent_id:
            # 模擬引擎無法撰寫針對目標的測試；呼叫端會退回
            # 確定性、由目標推導的探測（白箱），或把威脅記為未測試（黑箱）。
            # The simulation engine cannot write target-specific tests; callers fall back to
            # deterministic, target-derived probes (whitebox) or mark the threat as untested (blackbox).
            return {"tests": []}

        return {"status": "ok", "message": bi(f"{agent_id} 的模擬輸出", f"Simulated output for {agent_id}")}


# 逐模型別名的固定離線審查樣板（見 LLMGateway._generate_simulated_response）
# Fixed offline review templates per model alias (see LLMGateway._generate_simulated_response)
_SIMULATED_REVIEWS: Dict[str, Dict[str, str]] = {
    "claude": {
        "severity": "HIGH",
        "title": bi("處理函式中未檢查的空值／隱含的狀態假設", "Unchecked Null / Implicit State Assumption in Handler"),
        "description": bi("Vibe coding 產出的邏輯假設實體存在且狀態轉換有效，卻未驗證資料庫查詢結果，導致未處理的 NoneType / NullPointer 例外。",
                          "The vibe-coded logic assumes entities exist and state transitions are valid without verifying database fetch outcomes, leading to unhandled NoneType / NullPointer exceptions."),
        "root_cause": bi("存取屬性前缺少防禦性的空值檢查。", "Absence of defensive null-check before property traversal."),
        "suspected_vibe_flaw": bi("Vibe coding 常假設一定找得到紀錄的「理想路徑」。",
                                  "Vibe coding commonly assumes the 'happy path' where records are always found."),
        "suggested_test_scenario": bi("以不存在的 ID 或空酬載呼叫端點／函式，並斷言回傳正確的錯誤狀態（404/400）而不是 500 當機。",
                                      "Invoke the endpoint/function with a non-existent ID or empty payload and assert proper error status (404/400) instead of a 500 crash."),
    },
    "deepseek": {
        "severity": "CRITICAL",
        "title": bi("缺少輸入清理與無上限的資源配置", "Missing Input Sanitization & Unbounded Resource Allocation"),
        "description": bi("邏輯未對查詢或資料陣列限制輸入長度與數值範圍，可能造成記憶體耗盡、ReDoS 或未驗證的大量酬載。",
                          "The logic lacks input length and numerical range clamping on queries or data arrays, allowing memory exhaustion and ReDoS or unvalidated bulk payloads."),
        "root_cause": bi("直接把不可信的輸入餵入下游的迭代與記憶體結構。",
                         "Directly feeding untrusted input into downstream iteration and memory structures."),
        "suspected_vibe_flaw": bi("AI 程式助理常略過明確的大小檢查與分頁上限。",
                                  "AI coding assistants frequently skip explicit size checks and pagination limits."),
        "suggested_test_scenario": bi("提供 10MB 的酬載或超過 1,000,000 的整數值，確認以 HTTP 413 或 422 妥善拒絕。",
                                      "Supply a 10MB payload or integer values exceeding 1,000,000 and verify graceful rejection with HTTP 413 or 422."),
    },
    "glm": {
        "severity": "MEDIUM",
        "title": bi("API 契約規格漂移與結構描述不一致", "API Contract Specification Drift & Schema Inconsistency"),
        "description": bi("缺少參數型別強制檢查，且預期的回應結構描述與實際序列化的字典欄位不一致。",
                          "Missing parameter type enforcement and inconsistency between expected response schema and actual serialized dictionary fields."),
        "root_cause": bi("隱含的結構描述轉型，沒有嚴格的 Pydantic/dataclass 結構描述驗證。",
                         "Implicit schema casting without strict Pydantic/dataclass schema validation."),
        "suspected_vibe_flaw": bi("Vibe coding 的快速原型常臨時更改回應結構，卻未更新契約定義。",
                                  "Quick prototyping in vibe coding often changes response structures on the fly without updating contract definitions."),
        "suggested_test_scenario": bi("斷言回應結構描述在所有欄位型別上都與預期的 OpenAPI/JSON 契約完全一致。",
                                      "Assert response schema matches the expected OpenAPI/JSON contract exactly across all field types."),
    },
    "gemini": {
        "severity": "HIGH",
        "title": bi("不可信的輸入進入提示詞，且模型輸出未經驗證就被使用",
                    "Untrusted Input Reaches the Prompt and Model Output Is Used Unvalidated"),
        "description": bi("使用者控制或擷取的文字被串接進模型提示詞，而模型輸出未經嚴格的結構描述檢查就驅動決策或下游呼叫。",
                          "User-controlled or retrieved text is concatenated into model prompts, and model output drives decisions or downstream calls without a strict schema check."),
        "root_cause": bi("指令與資料之間沒有信任邊界，模型輸出也沒有確定性的驗證（OWASP LLM01:2026 / LLM10:2026）。",
                         "No trust boundary between instructions and data, and no deterministic validation of model output (OWASP LLM01:2026 / LLM10:2026)."),
        "suspected_vibe_flaw": bi("Vibe coding 產出的 AI 功能因為示範提示詞看起來正常，就把模型直接接進業務邏輯。",
                                  "Vibe-coded AI features wire the model straight into business logic because the demo prompt behaved."),
        "suggested_test_scenario": bi("餵入含有指令覆寫與不可見 Unicode 的輸入，並斷言輸出經過結構描述驗證，絕不會進入 eval/SQL/HTML 或特權操作。",
                                      "Feed input containing an instruction override and invisible Unicode, and assert the output is schema-validated and never reaches eval/SQL/HTML or a privileged action."),
        "owasp_mapping": "LLM01:2026",
    },
}
