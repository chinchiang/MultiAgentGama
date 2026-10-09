import datetime as _dt
import hashlib
import os
import json
import tempfile
import logging
import re
import threading
import urllib.parse
from typing import Dict, Any, Optional, List
import yaml

from vibeharness.core.models import AgentCallRecord
from vibeharness.core.i18n import SEP, bi, en_only
from vibeharness.core.sanitize import clean_model_text, redact_secrets

try:
    import litellm
except ImportError:  # pragma: no cover - litellm is an optional runtime dependency
    litellm = None  # type: ignore[assignment]

logger = logging.getLogger("VibeHarness.LLMGateway")

DEFAULT_CONFIG_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "config", "agents_config.yaml"
)

# Key added to every response so callers can tell simulated output from real model output
PROVENANCE_KEY = "_provenance"

DEFAULT_MAX_CONCURRENT_CALLS = 6
# A cap, not a spend: threat-model JSON and reasoning models' thinking tokens both overflowed 4096 in live runs
DEFAULT_MAX_OUTPUT_TOKENS = 16384


BUDGET_EXHAUSTED_REASON = bi("max_model_calls 預算已用盡", "max_model_calls budget exhausted")
REASON_NOT_VALID_JSON = bi("回應不是有效的 JSON", "response is not valid JSON")
REASON_CALL_CRASHED = bi("代理呼叫在產生輸出前就當掉", "agent call crashed before producing output")
# How many times an unusable live answer (not JSON, missing keys, empty) is re-asked before it is
# booked as `invalid`; each re-ask is a real call that counts against max_model_calls
DEFAULT_RETRY_INVALID_OUTPUT = 1
# Appended to the user prompt of a re-ask so the model knows what was wrong with its first answer
# (model prompt: stays English; the bilingual reason goes through en_only first)
_RETRY_SUFFIX = (
    "\n\nYour previous answer could not be used ({reason}). Answer again with ONLY the JSON object described "
    "in the instructions: no prose, no code fence, and include every required key."
)

# Agents missing from the config resolve to this alias, which has no model and no key: hybrid mode
# simulates them and live mode fails loudly, instead of silently routing them to some real provider
UNCONFIGURED_ALIAS = "unconfigured"

_LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1"}


def _zh_only(text: str) -> str:
    """雙語字串的中文半（最後一個分隔符之前）；沒有分隔符就原樣回傳。
    The Chinese half of a bilingual string (before the last separator); unchanged when there is none."""
    head, sep, _tail = text.rpartition(SEP)
    return head if sep else text


class LLMGatewayError(RuntimeError):
    """Raised in strict 'live' mode when a real model invocation is impossible or fails."""


class ConfigError(ValueError):
    """Raised when the agent configuration file is missing or unparseable.

    Subclasses ValueError so code (and tests) that guard against bad config values keeps working.
    vibeharness/cli.py maps this to a dedicated 'harness misconfigured' exit code so it can never be
    mistaken for a NEEDS_FIXES verdict about the audited target.
    """


class LLMGateway:
    """
    Unified gateway for orchestrating calls to heterogeneous LLMs (by default Claude, GLM, DeepSeek and Gemini).
    Execution modes:
    - live:   real API calls only; any missing key or failure raises LLMGatewayError.
    - hybrid: real API calls when possible, otherwise the offline simulation engine (recorded as simulated).
    - mock:   simulation engine only.
    Every call is recorded in `call_log` so reports can disclose which results are simulated.
    """

    def __init__(self, config_path: str = DEFAULT_CONFIG_PATH, execution_mode: Optional[str] = None):
        self.config = self._load_config(config_path)
        self.execution_mode = execution_mode or self.config.get("global", {}).get("execution_mode", "hybrid")
        if self.execution_mode not in ("live", "hybrid", "mock"):
            raise ValueError(bi(f"未知的 execution_mode '{self.execution_mode}'（應為 live、hybrid 或 mock）",
                                   f"Unknown execution_mode '{self.execution_mode}' (expected live, hybrid or mock)"))
        self.models_config = self.config.get("models") or {}
        self.agents_config = self.config.get("agents") or {}
        self.call_log: List[AgentCallRecord] = []
        global_cfg = self.config.get("global") or {}
        # Cost guard: live model invocations allowed per run (litellm retries / fallback_model of one
        # invocation are not counted separately). None or 0 means unlimited.
        self.max_model_calls = self._positive_int(global_cfg.get("max_model_calls"), "max_model_calls")
        # Agents fan their calls out on a thread pool of at most this many workers
        self.max_concurrent_calls = self._positive_int(
            global_cfg.get("max_concurrent_calls", DEFAULT_MAX_CONCURRENT_CALLS), "max_concurrent_calls"
        ) or DEFAULT_MAX_CONCURRENT_CALLS
        self.live_calls_attempted = 0
        self._budget_lock = threading.Lock()
        retries = global_cfg.get("retry_invalid_output", DEFAULT_RETRY_INVALID_OUTPUT)
        self.retry_invalid_output = 0 if retries is None else retries
        # On-disk cache of usable live answers keyed by model + prompt: a re-run of the same target with
        # the same config costs nothing and gives the same answers. None disables it.
        self.cache_dir: Optional[str] = None
        if global_cfg.get("cache_dir"):
            self.set_cache_dir(str(global_cfg["cache_dir"]))
        self._validate_endpoints()
        self._validate_settings()

    def _validate_endpoints(self) -> None:
        """Every custom api_base must be https (plain http only to loopback): target source code and
        prompts travel to these endpoints, so a typo or a hostile config must not send them in clear
        text to an arbitrary host (OWASP LLM04:2026; allow-listed model endpoints)."""
        for alias, info in self.models_config.items():
            base = info.get("api_base") if isinstance(info, dict) else None
            if not base:
                continue
            try:
                parts = urllib.parse.urlsplit(str(base))
                host = (parts.hostname or "").lower()
            except ValueError as e:
                raise ConfigError(bi(f"models.{alias}.api_base 不是有效的 URL：{base!r}",
                                     f"models.{alias}.api_base is not a valid URL: {base!r}")) from e
            if parts.scheme == "https" and host:
                continue
            if parts.scheme == "http" and host in _LOOPBACK_HOSTS:
                continue
            raise ConfigError(bi(
                f"models.{alias}.api_base 必須是 https:// URL（只有回送位址可用 http://），目前為 {base!r}",
                f"models.{alias}.api_base must be an https:// URL (http:// only for loopback hosts), got {base!r}"
            ))

    def set_cache_dir(self, path: str) -> None:
        """Enables the response cache in `path` (created if missing). The directory holds raw model
        answers, which can quote the audited code: treat it like the reports."""
        target = os.path.abspath(path)
        try:
            os.makedirs(target, exist_ok=True)
        except OSError as e:
            raise ConfigError(bi(f"cache_dir {path!r} 無法建立：{e}", f"cache_dir {path!r} cannot be created: {e}")) from e
        if not os.access(target, os.W_OK):
            raise ConfigError(bi(f"cache_dir {path!r} 不可寫入", f"cache_dir {path!r} is not writable"))
        self.cache_dir = target

    def _cache_key(self, model_alias: str, model_info: Dict[str, Any], temperature: float, system_prompt: str, user_prompt: str) -> str:
        parts = "\x00".join([
            model_alias, str(model_info.get("model")), str(model_info.get("fallback_model")), str(temperature),
            str(self._max_output_tokens(model_info)), json.dumps(model_info.get("extra_params") or {}, sort_keys=True),
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
            # Atomic publish: concurrent agents may write the same key, readers must never see a torn file
            fd, tmp = tempfile.mkstemp(prefix=".tmp-", suffix=".json", dir=self.cache_dir)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(entry, f, ensure_ascii=False)
            os.replace(tmp, os.path.join(self.cache_dir, f"{key}.json"))
        except OSError as e:
            logger.warning(bi(f"無法寫入回應快取項目：{e}", f"Could not write the response cache entry: {e}"))

    def _validate_settings(self) -> None:
        """Numeric settings are checked once at start-up. They used to be read only when a call was
        made, so a typo such as `timeout_seconds: "abc"` reached litellm, failed there, and in hybrid
        mode was booked as "live invocation failed" and silently replaced by the simulation engine."""
        global_cfg = self.config.get("global") or {}
        self._number(global_cfg.get("timeout_seconds", 180), "global.timeout_seconds", minimum=1)
        self._number(global_cfg.get("max_retries", 2), "global.max_retries", minimum=0, integer=True)
        self._number(global_cfg.get("max_output_tokens", DEFAULT_MAX_OUTPUT_TOKENS), "global.max_output_tokens",
                     minimum=1, integer=True)
        for alias, info in self.models_config.items():
            if isinstance(info, dict) and info.get("max_output_tokens") is not None:
                self._number(info["max_output_tokens"], f"models.{alias}.max_output_tokens", minimum=1, integer=True)
        for agent_id, meta in self.agents_config.items():
            if isinstance(meta, dict) and meta.get("temperature") is not None:
                self._number(meta["temperature"], f"agents.{agent_id}.temperature", minimum=0, maximum=2)
        self._number(self.retry_invalid_output, "global.retry_invalid_output", minimum=0, maximum=5, integer=True)
        for alias, info in self.models_config.items():
            for key in ("price_per_million_input", "price_per_million_output"):
                if isinstance(info, dict) and info.get(key) is not None:
                    self._number(info[key], f"models.{alias}.{key}", minimum=0)
            extra = info.get("extra_params") if isinstance(info, dict) else None
            if extra is not None and (not isinstance(extra, dict) or not all(isinstance(k, str) for k in extra)):
                raise ConfigError(bi(f"models.{alias}.extra_params 必須是 litellm 參數名稱的對應表，目前為 {extra!r}",
                                     f"models.{alias}.extra_params must be a mapping of litellm parameter names, got {extra!r}"))

    @staticmethod
    def _number(value: Any, key: str, minimum: float, maximum: Optional[float] = None, integer: bool = False) -> None:
        ok = isinstance(value, (int, float)) and not isinstance(value, bool) and (not integer or isinstance(value, int))
        if not ok or value < minimum or (maximum is not None and value > maximum):
            kind = "an integer" if integer else "a number"
            kind_zh = "整數" if integer else "數值"
            bounds = f">= {minimum}" if maximum is None else f"between {minimum} and {maximum}"
            bounds_zh = f">= {minimum}" if maximum is None else f"介於 {minimum} 與 {maximum} 之間"
            raise ConfigError(bi(f"{key} 必須是 {bounds_zh} 的{kind_zh}，目前為 {value!r}",
                                 f"{key} must be {kind} {bounds}, got {value!r}"))

    @staticmethod
    def _safe_reason(text: str) -> str:
        """Provider error text as it may be logged or reported: credentials redacted (an HTTP client
        can echo a request URL or header carrying the API key), control characters removed."""
        return clean_model_text(redact_secrets(str(text)))

    @staticmethod
    def _positive_int(value: Any, key: str) -> Optional[int]:
        """An optional positive integer setting; None/0 mean "not set"."""
        if value is None or value == 0:
            return None
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ConfigError(bi(f"global.{key} 必須是非負整數，目前為 {value!r}",
                                 f"global.{key} must be a non-negative integer, got {value!r}"))
        return value

    def _reserve_live_call(self) -> bool:
        """Claims one live invocation from the budget (thread-safe); False when it is exhausted."""
        with self._budget_lock:
            if self.max_model_calls is not None and self.live_calls_attempted >= self.max_model_calls:
                return False
            self.live_calls_attempted += 1
            return True

    @property
    def budget_exhausted_calls(self) -> List[AgentCallRecord]:
        return [rec for rec in self.call_log if rec.reason == BUDGET_EXHAUSTED_REASON]

    @property
    def used_simulation(self) -> bool:
        return any(rec.mode == "simulated" for rec in self.call_log)

    @property
    def invalid_calls(self) -> List[AgentCallRecord]:
        return [rec for rec in self.call_log if rec.mode == "invalid"]

    @property
    def retried_calls(self) -> List[AgentCallRecord]:
        """First attempts whose answer was unusable and that were re-asked (disclosed, not an evidence gap)."""
        return [rec for rec in self.call_log if rec.mode == "retried"]

    @staticmethod
    def is_simulated(resp: Dict[str, Any]) -> bool:
        return resp.get(PROVENANCE_KEY, {}).get("mode") == "simulated"

    @staticmethod
    def is_usable(resp: Dict[str, Any]) -> bool:
        """False when the model answered but its output could not be used."""
        return resp.get(PROVENANCE_KEY, {}).get("mode") != "invalid"

    def _load_config(self, path: str) -> Dict[str, Any]:
        # A missing or unparseable config would silently drop every model/agent mapping, so
        # fail loudly with ConfigError instead of leaking raw FileNotFoundError/YAMLError
        if not os.path.exists(path):
            raise ConfigError(bi(f"找不到代理設定檔：{path}", f"Agent config not found: {path}"))
        try:
            with open(path, "r", encoding="utf-8") as f:
                return yaml.safe_load(f) or {}
        except yaml.YAMLError as e:
            raise ConfigError(bi(f"代理設定檔不是有效的 YAML（{path}）：{e}",
                                 f"Agent config is not valid YAML ({path}): {e}")) from e

    def is_live_configured(self, model_alias: str) -> bool:
        """Checks whether the requested model has credentials: its API key, or an AWS profile
        (Bedrock authenticates through the AWS credential chain, not an API key)."""
        model_info = self.models_config.get(model_alias, {})
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
        Executes a prompt targeting the designated agent's configured LLM.
        A live response that is not valid JSON or lacks any of `required_keys` (all must be
        present) or `required_keys_any` (at least one must be present) is recorded with
        mode "invalid" (and returned as {}), so callers and the quality gate never mistake an
        unusable answer for a genuine empty result.
        """
        agent_meta = self.agents_config.get(agent_id) or {}
        model_alias = agent_meta.get("model_alias") or UNCONFIGURED_ALIAS
        temperature = agent_meta.get("temperature", 0.2)
        model_info = self.models_config.get(model_alias) or {}
        model_name = model_info.get("model") or f"(no model configured for alias '{model_alias}')"
        prompt_hash = hashlib.sha256(f"{system_prompt}\x00{user_prompt}".encode("utf-8")).hexdigest()

        # Decide whether to invoke live API or mock engine
        fallback_reason: Optional[str] = None
        if self.execution_mode == "mock":
            fallback_reason = bi("execution_mode 為 'mock'", "execution_mode is 'mock'")
        elif litellm is None:
            fallback_reason = bi("未安裝 litellm", "litellm is not installed")
        elif not self.is_live_configured(model_alias):
            env_var = model_info.get("api_key_env") or "<no api_key_env configured>"
            fallback_reason = bi(f"未設定 API 金鑰環境變數 {env_var}", f"API key env var {env_var} is not set")
        cached: Optional[Dict[str, Any]] = None
        cache_key = ""
        if fallback_reason is None:
            cache_key = self._cache_key(model_alias, model_info, temperature, system_prompt, user_prompt)
            cached = self._cache_read(cache_key)
            if cached is None and not self._reserve_live_call():
                fallback_reason = BUDGET_EXHAUSTED_REASON

        if fallback_reason is None:
            logger.info(bi(f"將 [{agent_id}] 派送至線上 LLM：{model_name}（別名：{model_alias}）",
                           f"Dispatching [{agent_id}] to Live LLM: {model_name} (Alias: {model_alias})"))
            # An unusable answer (prose instead of JSON, a missing key, an empty response from a safety
            # filter) is re-asked up to retry_invalid_output times, naming the problem, before it is
            # booked as `invalid`: in live runs most such answers are one-off format slips, and each
            # one used to turn the whole run INCONCLUSIVE. Re-asks are real calls against the budget.
            attempt = 0
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
                        raw_text, model_name, finish_reason = self._complete(model_info, model_name, messages, temperature)
                except Exception as e:
                    fallback_reason = f"{bi('線上呼叫失敗', 'live invocation failed')}: {self._safe_reason(str(e))}"
                    if self.execution_mode == "live":
                        raise LLMGatewayError(f"[{agent_id}] {model_name}: {fallback_reason}") from e
                    logger.warning(bi(f"{agent_id}（{model_name}）線上呼叫失敗：{fallback_reason}。改用模擬邏輯。",
                                      f"Live invocation failed for {agent_id} ({model_name}): {fallback_reason}. "
                                      "Falling back to simulation logic."))
                    break
                # Only the network call is guarded above: a bug in parsing/validation/booking
                # must fail loudly instead of being masked as a fallback to simulation.
                result = self._clean_and_parse_json(raw_text) if json_output else {"raw": raw_text}
                problem = self._validate_output(result, json_output, required_keys, required_keys_any)
                if problem is None and result is not None:
                    from_cache = cached is not None and attempt == 0
                    if not from_cache:
                        self._cache_write(cache_key if attempt == 0 else self._cache_key(
                            model_alias, model_info, temperature, system_prompt, prompt_text
                        ), agent_id, model_name, raw_text, finish_reason, prompt_hash)
                    self._record(agent_id, model_alias, model_name, "live", prompt_sha256=prompt_hash, cached=from_cache)
                    result[PROVENANCE_KEY] = {"mode": "live", "model": model_name, "cached": from_cache}
                    return result
                reason = problem or REASON_NOT_VALID_JSON
                if not raw_text.strip():
                    # e.g. a provider safety filter blocking attack-test code; the finish reason says which
                    reason = bi(f"模型回傳空白回應（finish_reason: {finish_reason or 'unknown'}）",
                                f"model returned an empty response (finish_reason: {finish_reason or 'unknown'})")
                if finish_reason == "length":
                    # Reasoning models spend part of the budget thinking; say so instead of blaming the format
                    limit = self._max_output_tokens(model_info)
                    reason = bi(
                        f"輸出在 max_output_tokens 上限（{limit}）被截斷；{_zh_only(reason)}。"
                        "請提高此模型的 max_output_tokens（推理 token 也計入此上限）",
                        f"output truncated at the max_output_tokens limit ({limit}); "
                        f"{en_only(reason)}. Raise max_output_tokens for this model (reasoning tokens count against it)"
                    )
                if json_output and attempt < self.retry_invalid_output and self._reserve_live_call():
                    attempt += 1
                    logger.warning(bi(f"[{agent_id}] {model_name} 回傳無法使用的輸出（{reason}）；重新詢問（{attempt}/{self.retry_invalid_output}）",
                                      f"[{agent_id}] {model_name} returned unusable output ({reason}); re-asking ({attempt}/{self.retry_invalid_output})"))
                    self._record(agent_id, model_alias, model_name, "retried", reason, prompt_sha256=prompt_hash)
                    # The prompt stays English: only the English half of the reason reaches the model
                    prompt_text = user_prompt + _RETRY_SUFFIX.format(reason=en_only(reason))
                    continue
                logger.error(bi(f"[{agent_id}] {model_name} 回傳無法使用的輸出：{reason}",
                                f"[{agent_id}] {model_name} returned unusable output: {reason}"))
                self._record(agent_id, model_alias, model_name, "invalid", reason, prompt_sha256=prompt_hash)
                return {PROVENANCE_KEY: {"mode": "invalid", "model": model_name, "reason": reason}}
        elif self.execution_mode == "live":
            raise LLMGatewayError(f"[{agent_id}] {bi(f'無法以 {model_name} 執行線上模式', f'cannot run live with {model_name}')}: {fallback_reason}")

        # Offline / Mock Fallback
        logger.info(bi(f"將 [{agent_id}] 派送至模擬引擎（模型別名：{model_alias}；原因：{fallback_reason}）",
                       f"Dispatching [{agent_id}] to Simulation Engine (Model Alias: {model_alias}; reason: {fallback_reason})"))
        self._record(agent_id, model_alias, model_name, "simulated", fallback_reason, prompt_sha256=prompt_hash)
        result = self._generate_simulated_response(agent_id, model_alias, user_prompt)
        result[PROVENANCE_KEY] = {"mode": "simulated", "model": model_name, "reason": fallback_reason}
        return result

    def _complete(self, model_info: Dict[str, Any], model_name: str, messages: List[Dict[str, str]], temperature: float):
        """
        Calls the primary model (with litellm's own retries), then `fallback_model` once if the primary fails.
        The API key is passed explicitly, so providers whose litellm default env var differs from
        `api_key_env` (e.g. Z.AI for GLM) still authenticate.
        Returns (text, model_actually_used, finish_reason); finish_reason "length" means the token limit cut it off.
        """
        global_cfg = self.config.get("global") or {}
        env_var = model_info.get("api_key_env")
        aws_profile = model_info.get("aws_profile_name")
        if not env_var and not aws_profile:
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
            # Newer models reject sampling knobs (Claude Opus 5.5 on Bedrock accepts only temperature=1;
            # Gemini 3 is deprecating them): drop what a model does not support rather than failing the call
            "drop_params": True,
            "timeout": global_cfg.get("timeout_seconds", 180),
            "num_retries": global_cfg.get("max_retries", 2),
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
        # Per-model litellm passthrough, e.g. {thinking: {type: disabled}} or {reasoning_effort: low} so a
        # reasoning model does not spend the whole output budget thinking (validated as a mapping at start-up)
        kwargs.update(model_info.get("extra_params") or {})

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
            # Unreachable in practice: candidates is never empty, but never raise an Optional
            raise LLMGatewayError(bi(f"模型 {model_name}：沒有任何候選模型可以嘗試",
                                     f"Model {model_name}: no candidate model could be attempted"))
        raise last_error

    def _max_output_tokens(self, model_info: Dict[str, Any]) -> int:
        """Per-model `max_output_tokens` overrides the global one: reasoning models (GLM, DeepSeek,
        Gemini 3) count thinking tokens against this limit and need a larger budget."""
        value = model_info.get("max_output_tokens") or (self.config.get("global") or {}).get(
            "max_output_tokens", DEFAULT_MAX_OUTPUT_TOKENS
        )
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
        """Books an agent call that crashed before the gateway could answer (e.g. an exception in
        the caller's thread-pool batch). Recorded as an `invalid` call so the quality gate sees the
        missing result as an evidence gap instead of mistaking silence for "nothing found"."""
        agent_meta = self.agents_config.get(agent_id) or {}
        model_alias = agent_meta.get("model_alias") or UNCONFIGURED_ALIAS
        model_info = self.models_config.get(model_alias) or {}
        model_name = model_info.get("model") or f"(no model configured for alias '{model_alias}')"
        self._record(agent_id, model_alias, model_name, "invalid", f"{REASON_CALL_CRASHED}: {reason}")

    def _record(
        self, agent_id: str, model_alias: str, model_name: str, mode: str,
        reason: Optional[str] = None, prompt_sha256: Optional[str] = None, cached: bool = False
    ):
        self.call_log.append(AgentCallRecord(
            agent_id=agent_id, model_alias=model_alias, model_name=model_name, mode=mode,
            reason=self._safe_reason(reason) if reason is not None else None,
            prompt_sha256=prompt_sha256, cached=cached
        ))

    @property
    def cached_calls(self) -> List[AgentCallRecord]:
        return [rec for rec in self.call_log if rec.cached]

    def _clean_and_parse_json(self, text: str) -> Optional[Dict[str, Any]]:
        """Strips markdown code fences and parses JSON safely, with conversational fallback."""
        text = text.strip()
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

        # 2. Direct JSON string
        try:
            parsed = json.loads(text)
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError:
            pass

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
        # None (not a sentinel dict): a model could legitimately echo such a dict, which would
        # have been indistinguishable from a parse failure.
        return None

    def _generate_simulated_response(self, agent_id: str, model_alias: str, prompt: str) -> Dict[str, Any]:
        """
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
            # The simulation engine cannot write target-specific tests; callers fall back to
            # deterministic, target-derived probes (whitebox) or mark the threat as untested (blackbox).
            return {"tests": []}

        return {"status": "ok", "message": bi(f"{agent_id} 的模擬輸出", f"Simulated output for {agent_id}")}


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
