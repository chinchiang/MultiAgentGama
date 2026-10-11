import datetime as _dt
import hashlib
import os
import json
import tempfile
import logging
import re
import threading
import urllib.parse
from typing import Dict, Any, FrozenSet, Optional, List
import yaml

from vibeharness.core.models import AgentCallRecord
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

DEFAULT_CONFIG_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "config", "agents_config.yaml"
)

# 加到每個回應的鍵，讓呼叫端能分辨模擬輸出與真實模型輸出
# Key added to every response so callers can tell simulated output from real model output
PROVENANCE_KEY = "_provenance"

DEFAULT_MAX_CONCURRENT_CALLS = 6
# 這是上限而非花費：威脅模型 JSON 與推理模型的思考 token 在線上執行時都曾超過 4096
# A cap, not a spend: threat-model JSON and reasoning models' thinking tokens both overflowed 4096 in live runs
DEFAULT_MAX_OUTPUT_TOKENS = 16384
# 單次 LLM 請求的逾時（秒）與 litellm 層級的重試次數；設定為 null 時也採用這些值
# Per-request LLM timeout (seconds) and litellm-level retry count; a null setting also means these values
DEFAULT_TIMEOUT_SECONDS = 180
DEFAULT_MAX_RETRIES = 2


BUDGET_EXHAUSTED_REASON = bi("max_model_calls 預算已用盡", "max_model_calls budget exhausted")
# --cache-only：快取沒有答案時不發出任何網路呼叫；與預算用盡一樣處理（hybrid 改用模擬、live 失敗），並列為證據缺口
# --cache-only: a call the cache cannot answer makes no network call; handled like an exhausted budget
# (simulation in hybrid, failure in live) and reported as an evidence gap
CACHE_MISS_REASON = bi("--cache-only 模式下回應快取未命中", "cache miss in --cache-only mode")
REASON_NOT_VALID_JSON = bi("回應不是有效的 JSON", "response is not valid JSON")
REASON_CALL_CRASHED = bi("代理呼叫在產生輸出前就當掉", "agent call crashed before producing output")
# 無法使用的線上回答（非 JSON、缺少鍵、空白）在登記為 `invalid` 之前
# 會被重新詢問的次數；每次重新詢問都是真實呼叫，會計入 max_model_calls
# How many times an unusable live answer (not JSON, missing keys, empty) is re-asked before it is
# booked as `invalid`; each re-ask is a real call that counts against max_model_calls
DEFAULT_RETRY_INVALID_OUTPUT = 1
# agents.<id>.temperature 省略或為 null 時的取樣溫度 ／ sampling temperature when agents.<id>.temperature is omitted or null
DEFAULT_TEMPERATURE = 0.2
# 附加到重新詢問的使用者提示之後，讓模型知道第一次回答哪裡有問題
# （模型提示：維持英文；雙語原因會先經過 en_only）
# Appended to the user prompt of a re-ask so the model knows what was wrong with its first answer
# (model prompt: stays English; the bilingual reason goes through en_only first)
_RETRY_SUFFIX = (
    "\n\nYour previous answer could not be used ({reason}). Answer again with ONLY the JSON object described "
    "in the instructions: no prose, no code fence, and include every required key."
)

# 設定檔中缺少的代理會解析為此別名，它沒有模型也沒有金鑰：hybrid 模式
# 會模擬它們，而 live 模式會明確失敗，而不是悄悄地把它們導向某個真實供應商
# Agents missing from the config resolve to this alias, which has no model and no key: hybrid mode
# simulates them and live mode fails loudly, instead of silently routing them to some real provider
UNCONFIGURED_ALIAS = "unconfigured"

_LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1"}

# `extra_params` 不得覆寫的 litellm 參數：端點與憑證（會繞過 api_base 的 https 檢查，
# 把目標原始碼送到任意主機）、harness 自己設定的請求內容與重試／逾時控制，以及會讓
# 回應解析失效的 stream。這些都有專用的設定鍵（或由 harness 決定），放進 extra_params 即為 ConfigError。
# litellm parameters `extra_params` must not override: endpoints and credentials (they would bypass
# the https check on api_base and send the target source code to an arbitrary host), the request
# content and the retry / timeout controls the harness sets itself, and stream, which would break
# response parsing. Each has a dedicated setting (or is the harness's call); in extra_params it is a ConfigError.
RESERVED_EXTRA_PARAMS = frozenset({
    "model", "messages", "api_base", "base_url", "api_key", "api_version", "timeout", "request_timeout",
    "num_retries", "max_retries", "fallbacks", "stream", "aws_profile_name", "aws_region_name",
    "aws_access_key_id", "aws_secret_access_key", "aws_session_token", "aws_bedrock_runtime_endpoint",
    "aws_role_name", "aws_web_identity_token", "custom_llm_provider",
    # 輸出 token 上限只能用 max_output_tokens 設定：這些鍵會覆寫它，--estimate 與快取鍵也會看錯上限
    # The output-token cap is set only through max_output_tokens: these keys would override it, and
    # --estimate and the cache key would see the wrong cap
    "max_tokens", "max_completion_tokens", "max_output_tokens",
    # litellm 的罐頭回應鍵：完全不連網就回傳 mock_completion 的假答案，模擬的輸出會被登記成 live 證據
    # litellm's canned-response keys: they return mock_completion's fake answer with no network call at all,
    # so simulated output would be booked as live evidence
    "mock_response", "mock_tool_calls", "mock_timeout", "mock_delay",
    # TLS 驗證只能維持開啟：關掉後 api_base 的 https 檢查就失去意義
    # TLS verification stays on: turning it off would make the https check on api_base meaningless
    "ssl_verify",
    # litellm 其他會改變目的地或憑證的參數（依 litellm 的 completion() 與各 provider 讀取的鍵整理）：
    # 別名式的金鑰與端點、Azure／Vertex／watsonx／OCI／GigaChat 等雲端憑證與專案、代理與部署路由、
    # 可覆寫 Authorization 的標頭，以及自備的 HTTP 用戶端
    # Other litellm parameters that change the destination or the credentials (collected from litellm's
    # completion() and the keys its providers read): alias spellings of the key and the endpoint, Azure / Vertex /
    # watsonx / OCI / GigaChat cloud credentials and projects, proxy and deployment routing, headers that could
    # override Authorization, and a caller-supplied HTTP client
    "apikey", "token", "model_list", "deployment_id", "engine", "organization", "extra_headers", "headers",
    "provider_specific_header", "client", "shared_session", "use_litellm_proxy", "use_xai_oauth",
    "use_psc_endpoint_format", "use_bearer_for_custom_base", "tenant_id", "client_id", "client_secret",
    "azure_ad_token", "azure_ad_token_provider", "azure_username", "azure_password", "azure_scope",
    "vertex_project", "vertex_location", "vertex_credentials", "vertex_ai_project", "vertex_ai_location",
    "vertex_ai_credentials", "vertex_count_tokens_location", "watsonx_project", "watsonx_credentials", "project_id",
    "account_id", "predibase_tenant_id", "gigachat_access_token", "gigachat_auth_url", "gigachat_scope",
    "aws_external_id", "aws_session_name", "aws_session_tags", "aws_sts_endpoint", "aws_bedrock_project_id",
    "aws_bedrock_client", "sagemaker_base_url", "custom_endpoint", "deployment_url", "oci_endpoint_id", "oci_region",
    "oci_key", "oci_key_file", "zen_api_key", "gemini_api_key", "_litellm_internal_model_credentials",
    "litellm_logging_obj", "logger_fn", "proxy_server_request",
    # litellm 的記錄／callback 參數（litellm 1.103 的 StandardCallbackDynamicParams、
    # initialize_dynamic_callback_params 與 Logging 讀取的 kwargs）：它們會把完整的提示與回答（也就是受稽核的原始碼）
    # 轉送給第三方的觀測服務（Langfuse、LangSmith、Datadog、GCS／S3 bucket、Slack webhook……）。
    # metadata／litellm_metadata 也在內：litellm 會從其中讀取同一組 callback 參數（例如 metadata.langfuse_host）
    # litellm's logging / callback parameters (the kwargs litellm 1.103 reads through StandardCallbackDynamicParams,
    # initialize_dynamic_callback_params and Logging): they forward the full prompt and answer (that is, the audited
    # source code) to third-party observability services (Langfuse, LangSmith, Datadog, GCS / S3 buckets, a Slack
    # webhook, ...). metadata / litellm_metadata are included: litellm reads the same callback parameters from them
    # (e.g. metadata.langfuse_host)
    "callbacks", "success_callback", "failure_callback", "_async_success_callback", "_async_failure_callback",
    "litellm_disabled_callbacks", "litellm_trusted_callback_vars", "metadata", "litellm_metadata", "litellm_params",
    "lunary_public_key", "litellm_request_debug", "verbose",
    # 會改寫請求內容或改送到別的模型的參數：litellm 的提示管理（從第三方服務取回提示）、系統提示注入、
    # 模型別名對應、context window 的備援模型、路由與重試策略，以及其他逾時控制
    # Parameters that rewrite the request or reroute it to another model: litellm's prompt management (fetches the
    # prompt from a third-party service), system-prompt injection, model alias mapping, the context-window fallback
    # model, routing and retry policies, and other timeout controls
    "prompt_id", "prompt_variables", "prompt_version", "prompt_environment", "litellm_system_prompt",
    "model_alias_map", "custom_prompt_dict", "context_window_fallback_dict", "routing_strategy", "_router_weights",
    "retry_policy", "retry_strategy", "force_timeout", "client_side_timeout", "azure", "data_residency",
})
# 名單之外的同類鍵（litellm 新版本或少見的 provider）以名稱樣式保留：雲端憑證與觀測服務整合的前綴，以及含有金鑰、
# 密碼、憑證、端點、URL、代理、標頭、callback、webhook、主機或 bucket 字樣的名稱
# Keys of the same kind outside the list (newer litellm versions or rare providers) are reserved by name
# pattern: cloud credential and observability-integration prefixes, and names containing key, secret, password,
# credential, endpoint, URL, proxy, header, callback, webhook, host or bucket parts
_RESERVED_EXTRA_PARAM_RE = re.compile(
    r"^(?:aws|azure|vertex|oci|watsonx|gigachat"
    r"|langfuse|langsmith|gcs|s3|dd|datadog|helicone|lunary|humanloop|arize|posthog|braintrust|slack|newrelic"
    r"|wandb|weave|otel|opik|mlflow|logfire|sentry|phoenix|galileo|athina|literalai|openmeter|greenscale|traceloop)_"
    r"|callback"
    r"|(?:^|_)(?:api_?key|secret|password|credentials?|endpoint|url|api_base|base_url|proxy|headers?|webhook|host|bucket)(?:$|_)",
    re.IGNORECASE,
)
# 名稱含有 token 的部分另外判斷：access_token、api_token、id_token、token 等都是憑證而保留；只改價格的成本覆寫
# （input_cost_per_token、cache_read_input_token_cost……）不改變目的地，允許
# A `token` name part is judged separately: access_token, api_token, id_token, token and the like are credentials and
# reserved; cost overrides (input_cost_per_token, cache_read_input_token_cost, ...) only change the price, not the
# destination, so they are allowed
_TOKEN_NAME_PART_RE = re.compile(r"(?:^|_)token(?:$|_)", re.IGNORECASE)
_COST_NAME_PART_RE = re.compile(r"(?:^|_)cost(?:$|_)", re.IGNORECASE)


def _is_reserved_param_name(name: str) -> bool:
    """名稱符合端點／憑證／callback 樣式（不看 RESERVED_EXTRA_PARAMS 名單）。
    The name matches an endpoint / credential / callback pattern (without consulting RESERVED_EXTRA_PARAMS)."""
    if _RESERVED_EXTRA_PARAM_RE.search(name):
        return True
    return bool(_TOKEN_NAME_PART_RE.search(name)) and not _COST_NAME_PART_RE.search(name)


def is_reserved_extra_param(name: str) -> bool:
    """`extra_params` 不得設定的 litellm 參數：在 RESERVED_EXTRA_PARAMS 裡，或名稱符合端點／憑證／callback 樣式。
    A litellm parameter `extra_params` must not set: listed in RESERVED_EXTRA_PARAMS, or named like an endpoint,
    a credential or a callback."""
    return name in RESERVED_EXTRA_PARAMS or _is_reserved_param_name(name)
# 上面屬於輸出 token 上限的保留鍵；錯誤訊息會指向 max_output_tokens
# The reserved keys above that are the output-token cap; the error message points at max_output_tokens
_TOKEN_CAP_PARAMS = frozenset({"max_tokens", "max_completion_tokens", "max_output_tokens"})

# 屬於端點身分的模型設定：任一個不同就是不同的服務端點，回應快取不得共用
# Model settings that identify the endpoint: if any differs it is a different service, so the response cache must not be shared
_ENDPOINT_IDENTITY_KEYS = ("api_base", "aws_region_name", "aws_profile_name", "api_key_env")



class LLMGatewayError(RuntimeError):
    """在嚴格的 'live' 模式下，當真實模型呼叫不可能或失敗時拋出。
    Raised in strict 'live' mode when a real model invocation is impossible or fails."""


class ConfigError(ValueError):
    """代理設定檔缺少或無法解析時拋出。

    繼承自 ValueError，使防範錯誤設定值的程式碼（與測試）得以繼續運作。
    vibeharness/cli.py 會把它對應到專用的「harness 設定錯誤」結束碼，因此絕不會
    被誤認為針對受稽核目標的 NEEDS_FIXES 判定結果。
    Raised when the agent configuration file is missing or unparseable.

    Subclasses ValueError so code (and tests) that guard against bad config values keeps working.
    vibeharness/cli.py maps this to a dedicated 'harness misconfigured' exit code so it can never be
    mistaken for a NEEDS_FIXES verdict about the audited target.
    """


def load_config_file(path: str) -> Dict[str, Any]:
    """讀取並檢查代理設定檔的結構；缺少、無法解析或結構錯誤時拋出 ConfigError。
    Reads an agent config file and checks its structure; raises ConfigError when it is missing, unparseable or malformed."""
    # 缺少或無法解析的設定檔會悄悄地丟掉所有模型／代理對應，因此
    # 以 ConfigError 明確失敗，而不是外洩原始的 FileNotFoundError/YAMLError
    # A missing or unparseable config would silently drop every model/agent mapping, so
    # fail loudly with ConfigError instead of leaking raw FileNotFoundError/YAMLError
    if not os.path.exists(path):
        raise ConfigError(bi(f"找不到代理設定檔：{path}", f"Agent config not found: {path}"))
    try:
        with open(path, "r", encoding="utf-8") as f:
            config = yaml.safe_load(f)
    except yaml.YAMLError as e:
        raise ConfigError(bi(f"代理設定檔不是有效的 YAML（{path}）：{e}",
                             f"Agent config is not valid YAML ({path}): {e}")) from e
    except (OSError, UnicodeDecodeError) as e:
        # 例如把目錄、無法讀取的檔案或二進位檔當成 --config 傳入
        # e.g. a directory, an unreadable file or a binary file passed as --config
        raise ConfigError(bi(f"無法讀取代理設定檔（{path}）：{e}",
                             f"Agent config cannot be read ({path}): {e}")) from e
    if config is None:
        return {}
    if not isinstance(config, dict):
        raise ConfigError(bi(f"代理設定檔的最上層必須是 YAML 對應表，目前為 {type(config).__name__}（{path}）",
                             f"Agent config must be a YAML mapping at the top level, got {type(config).__name__} ({path})"))
    for section in ("global", "models", "agents"):
        value = config.get(section)
        if value is not None and not isinstance(value, dict):
            raise ConfigError(bi(f"代理設定檔的 '{section}' 區段必須是對應表，目前為 {type(value).__name__}（{path}）",
                                 f"Agent config section '{section}' must be a mapping, got {type(value).__name__} ({path})"))
    # 每個模型與代理項目本身也必須是對應表（或留空）：否則之後的 .get() 會在執行中途當掉
    # Every model and agent entry must itself be a mapping (or empty): otherwise a later .get() crashes mid-run
    for section in ("models", "agents"):
        for name, entry in (config.get(section) or {}).items():
            if entry is not None and not isinstance(entry, dict):
                raise ConfigError(bi(f"{section}.{name} 必須是對應表，目前為 {type(entry).__name__}（{path}）",
                                     f"{section}.{name} must be a mapping, got {type(entry).__name__} ({path})"))
    return config


# 自動發現的設定檔（目前目錄的 ./vibeharness.yaml、./.vibeharness.yaml，沒有以 --config 明確指定）可能來自
# 不可信的 checkout（例如 PR）。它不得設定下列安全敏感的 global 鍵：可執行檔路徑（*_bin，啟動時就會被執行）、
# 沙盒的選擇與 docker／node 設定，以及回應快取（預先放好的快取項目會被當成 live 回答）。除非值與套件內的預設相同
# A discovered config (./vibeharness.yaml or ./.vibeharness.yaml in the current directory, not passed with --config)
# may come from an untrusted checkout (e.g. a PR). It must not set these security-sensitive global keys: executable
# paths (*_bin, run at start-up), the sandbox choice and its docker / node settings, and the response cache
# (pre-planted cache entries would be served as live answers). Unless the value equals the bundled default
_DISCOVERED_SENSITIVE_GLOBAL_KEYS = frozenset({
    "sandbox_provider", "sandbox_node_provider", "cache_dir",
})
_DISCOVERED_SENSITIVE_GLOBAL_PREFIXES = ("docker_", "node_")
# 套件內的預設設定沒寫、但 harness 有內建預設值的鍵 ／ keys the bundled config omits but the harness defaults
_BUILTIN_GLOBAL_DEFAULTS: Dict[str, Any] = {"docker_bin": "docker", "node_bin": "node", "sandbox_provider": "local_subprocess"}
# 除了預設值以外也允許的值：改用 docker 沙盒只會更嚴格（映像與 docker_bin 仍必須是預設值）
# Values allowed besides the default: switching to the docker sandbox only makes it stricter (the image and
# docker_bin must still be the defaults)
_DISCOVERED_ALLOWED_GLOBAL_VALUES: Dict[str, Any] = {
    "sandbox_provider": ("local_subprocess", "docker"), "sandbox_node_provider": ("local_subprocess", "docker"),
}
# models.<alias> 裡決定目的地或憑證的鍵：端點、金鑰環境變數、AWS 設定檔／區域，以及原樣傳給 litellm 的 extra_params
# Keys of models.<alias> that decide the destination or the credentials: the endpoint, the key's environment
# variable, the AWS profile / region, and extra_params, which is passed straight to litellm
_DISCOVERED_SENSITIVE_MODEL_KEYS = frozenset({"api_base", "base_url", "api_key_env", "aws_profile_name", "aws_region_name",
                                              "extra_params"})
# models.<alias> 裡決定「送到哪個模型」的鍵：litellm 的模型字串本身就帶供應商路由（例如 openai/...），換掉它就能把
# 套件內設定的金鑰送到另一家供應商，所以自動發現的設定檔只能沿用同一別名的內建值
# Keys of models.<alias> that decide which model is called: a litellm model string carries the provider routing itself
# (e.g. openai/...), so swapping it could send a bundled key to another provider; a discovered config may only keep
# the bundled value of the same alias
_DISCOVERED_PINNED_MODEL_KEYS = frozenset({"model", "fallback_model"})
# 先前版本內建設定曾經使用過、但目前版本已換掉的 models.<alias> 值（依每個 v* tag 的
# vibeharness/config/agents_config.yaml 與舊路徑 config/agents_config.yaml 整理；tests/test_r5_gateway_harness.py 會
# 逐一比對每個 tag）。自動發現的設定檔若是舊版 --init-config 寫出的覆本，同一別名的這些值也接受：它們都曾是內建值，
# 不會把金鑰送到別家供應商；新版本換掉內建模型字串時，請把舊值加進這裡
# models.<alias> values a previous release's bundled config used and the current one has replaced (collected from
# vibeharness/config/agents_config.yaml, and the old path config/agents_config.yaml, at every v* tag;
# tests/test_r5_gateway_harness.py checks each tag). A discovered config that is a copy written by an older
# --init-config may keep these values for the same alias: each was a bundled value, so none sends a key to another
# provider. When a release replaces a bundled model string, add the old value here
_PREVIOUS_BUNDLED_MODELS: Dict[str, Dict[str, FrozenSet[str]]] = {
    "claude": {"model": frozenset({"claude-sonnet-5"})},  # v0.1.0 至 v0.2.0 的內建值 ／ bundled in v0.1.0 to v0.2.0
}
# 會增加花費的 global 數值上限：自動發現的設定檔只能把它們調低（或保持內建值），不能調高。值為 null 或省略時
# 採用 harness 的預設值；這些鍵的 0 也代表預設值（max_model_calls 的 0／null 是不限制）
# Global numeric limits that raise spend: a discovered config may only lower them (or keep the bundled value), never
# raise them. null or omitted means the harness default; for these keys 0 means the default too (0 / null is
# unlimited for max_model_calls)
_DISCOVERED_COST_LIMIT_KEYS = ("max_model_calls", "max_concurrent_calls", "max_output_tokens", "retry_invalid_output",
                               "max_retries", "max_files", "max_file_bytes")
_ZERO_MEANS_DEFAULT_KEYS = frozenset({"max_model_calls", "max_concurrent_calls", "max_files", "max_file_bytes"})
# 每個 whitebox_reviewer_* 代理都會審查每個符號，新增一個就多一整輪付費呼叫；驗證者則依模型別名去重，數量有上限
# Every whitebox_reviewer_* agent reviews every symbol, so a new one adds a whole round of paid calls; verifiers are
# de-duplicated per model alias, so their number is bounded
_DISCOVERED_REVIEWER_PREFIX = "whitebox_reviewer_"


def _builtin_cost_default(key: str) -> Optional[int]:
    """`_DISCOVERED_COST_LIMIT_KEYS` 的 harness 內建預設值；None 表示不限制。
    The harness's built-in default for a `_DISCOVERED_COST_LIMIT_KEYS` key; None means unlimited."""
    # 延遲匯入：ast_extractor 只依賴 models 與 i18n，但閘道不需要在匯入時就載入它
    # Lazy import: ast_extractor depends only on models and i18n, but the gateway need not load it at import time
    from vibeharness.agents.whitebox.ast_extractor import DEFAULT_MAX_FILE_BYTES, DEFAULT_MAX_FILES
    defaults: Dict[str, Optional[int]] = {
        "max_model_calls": None, "max_concurrent_calls": DEFAULT_MAX_CONCURRENT_CALLS,
        "max_output_tokens": DEFAULT_MAX_OUTPUT_TOKENS, "retry_invalid_output": DEFAULT_RETRY_INVALID_OUTPUT,
        "max_retries": DEFAULT_MAX_RETRIES, "max_files": DEFAULT_MAX_FILES, "max_file_bytes": DEFAULT_MAX_FILE_BYTES,
    }
    return defaults[key]


def _effective_cost_limit(key: str, value: Any) -> Any:
    """設定值實際代表的上限：null（以及 _ZERO_MEANS_DEFAULT_KEYS 的 0）換成內建預設值；None 表示不限制。
    非數值原樣回傳，由啟動時的驗證回報。
    The limit a setting actually means: null (and 0 for _ZERO_MEANS_DEFAULT_KEYS) becomes the built-in default;
    None means unlimited. A non-number is returned as is, for the start-up validation to report."""
    if value is None or (value == 0 and not isinstance(value, bool) and key in _ZERO_MEANS_DEFAULT_KEYS):
        return _builtin_cost_default(key)
    return value


def _raises_limit(value: Any, reference: Any) -> bool:
    """`value` 比 `reference` 寬鬆（None 表示不限制）；非數值不在這裡判斷，交給啟動時的驗證。
    `value` is looser than `reference` (None means unlimited); non-numbers are left to the start-up validation."""
    if reference is None:
        return False
    if value is None:
        return True
    numeric = (int, float)
    if isinstance(value, bool) or not isinstance(value, numeric) or isinstance(reference, bool) or not isinstance(reference, numeric):
        return False
    return value > reference


def _is_sensitive_global_key(key: str) -> bool:
    """自動發現的設定檔不得自訂的 global 鍵 ／ A global key a discovered config must not customize."""
    return key in _DISCOVERED_SENSITIVE_GLOBAL_KEYS or key.endswith("_bin") or key.startswith(_DISCOVERED_SENSITIVE_GLOBAL_PREFIXES)


def _is_sensitive_model_key(key: str) -> bool:
    """自動發現的設定檔不得自訂的 models.<alias> 鍵 ／ A models.<alias> key a discovered config must not customize."""
    return key in _DISCOVERED_SENSITIVE_MODEL_KEYS or _is_reserved_param_name(key)


def discovered_config_violations(config: Dict[str, Any], reference: Dict[str, Any]) -> List[str]:
    """自動發現的 `config` 中設定了安全敏感鍵的位置（例如 "global.docker_bin"），依序排列；空清單表示可以採用。
    與 `reference`（套件內的預設設定）相同的值、null 以及省略都允許，所以 --init-config 寫出的覆本照樣可用。
    models 區段只能使用預設設定裡已有的別名（新別名記為 "models.<alias>"）；每個別名的 model、fallback_model、
    api_key_env 與端點鍵都必須與預設設定中「同一個別名」的值相同，或是先前版本內建設定的同一別名值
    （_PREVIOUS_BUNDLED_MODELS；不能把 ANTHROPIC_API_KEY 接到別的供應商）。agent 仍可在內建別名之間重新指派，
    但不能新增 whitebox_reviewer_* 代理。花費相關的設定只能調低：execution_mode 不能是 live，
    _DISCOVERED_COST_LIMIT_KEYS 與 models.<alias>.max_output_tokens 的實際值（省略或 null 即 harness 預設值）不能高於預設設定。
    The places where the discovered `config` sets a security-sensitive key (e.g. "global.docker_bin"), sorted;
    an empty list means the config may be used. A value equal to `reference` (the bundled default), null and
    omission are allowed, so a copy written by --init-config still works. The models section may only use aliases
    the default config has (a new alias is reported as "models.<alias>"); each alias's model, fallback_model,
    api_key_env and endpoint keys must equal the default config's value for the same alias, or a previous release's
    bundled value for that alias (_PREVIOUS_BUNDLED_MODELS; so ANTHROPIC_API_KEY cannot be wired to another
    provider). Agents may still be reassigned among the bundled aliases, but no whitebox_reviewer_* agent may be
    added. Cost-related settings may only be lowered: execution_mode must not be live, and neither the
    _DISCOVERED_COST_LIMIT_KEYS nor models.<alias>.max_output_tokens may exceed the default config in effect (omitted or
    null means the harness default)."""
    problems: List[str] = []
    ref_global = reference.get("global") or {}
    cfg_global = config.get("global") or {}
    for key, value in cfg_global.items():
        key = str(key)
        if key == "execution_mode":
            # 只能維持內建模式或改成 mock：live 在缺金鑰或呼叫失敗時也不會退回模擬，只會繼續付費呼叫或失敗
            # Only the bundled mode or mock: live never falls back to simulation, it keeps making paid calls or fails
            if value is not None and value != ref_global.get(key) and value != "mock":
                problems.append(f"global.{key}")
            continue
        if key in _DISCOVERED_COST_LIMIT_KEYS:
            continue
        if value is None or not _is_sensitive_global_key(key):
            continue
        if value != ref_global.get(key, _BUILTIN_GLOBAL_DEFAULTS.get(key)) and value not in _DISCOVERED_ALLOWED_GLOBAL_VALUES.get(key, ()):
            problems.append(f"global.{key}")
    # 自動發現的設定檔是整份取代內建設定（不會合併），所以省略的上限代表 harness 預設值，也要比較
    # A discovered config replaces the bundled one as a whole (no merge), so an omitted limit means the harness
    # default and is compared too
    for key in _DISCOVERED_COST_LIMIT_KEYS:
        if _raises_limit(_effective_cost_limit(key, cfg_global.get(key)), _effective_cost_limit(key, ref_global.get(key))):
            problems.append(f"global.{key}")
    ref_models = reference.get("models") or {}
    cfg_output_cap = _effective_cost_limit("max_output_tokens", cfg_global.get("max_output_tokens"))
    ref_output_cap = _effective_cost_limit("max_output_tokens", ref_global.get("max_output_tokens"))
    for alias, info in (config.get("models") or {}).items():
        if alias not in ref_models:
            problems.append(f"models.{alias}")
            continue
        ref_info = ref_models.get(alias) or {}
        previous = _PREVIOUS_BUNDLED_MODELS.get(str(alias), {})
        for key, value in (info or {}).items():
            key = str(key)
            if key == "max_output_tokens":
                # 逐模型的上限省略時跟隨 global；與預設設定中同一別名的實際上限比較
                # A per-model cap that is omitted follows global; compare with the same alias's actual cap in the default config
                ref_cap = ref_output_cap if ref_info.get(key) is None else ref_info.get(key)
                if _raises_limit(cfg_output_cap if value is None else value, ref_cap):
                    problems.append(f"models.{alias}.{key}")
                continue
            if value is None or not (key in _DISCOVERED_PINNED_MODEL_KEYS or _is_sensitive_model_key(key)):
                continue
            if value == ref_info.get(key) or (isinstance(value, str) and value in previous.get(key, frozenset())):
                continue
            problems.append(f"models.{alias}.{key}")
    ref_agents = reference.get("agents") or {}
    for agent_id in (config.get("agents") or {}):
        if str(agent_id).startswith(_DISCOVERED_REVIEWER_PREFIX) and agent_id not in ref_agents:
            problems.append(f"agents.{agent_id}")
    return sorted(problems)


def check_discovered_config(path: str, reference_path: str = DEFAULT_CONFIG_PATH) -> None:
    """自動發現的設定檔設定了安全敏感鍵時拋出 ConfigError（CLI 以 exit 5 結束），訊息列出那些鍵並說明：
    信任這個檔案就以 --config 明確指定；若是其他版本寫出的覆本，就以 --init-config --force 重新產生。
    Raises ConfigError (the CLI exits 5) when a discovered config sets a security-sensitive key; the message
    names those keys and says to pass the file explicitly with --config if it is trusted, or to regenerate it with
    --init-config --force if another version wrote it."""
    problems = discovered_config_violations(load_config_file(path), load_config_file(reference_path))
    if problems:
        names = ", ".join(problems)
        raise ConfigError(bi(
            f"自動發現的設定檔 {path} 設定了安全敏感的鍵：{names}。自動發現的設定檔可能來自不可信的 checkout，"
            "不得設定可執行檔路徑、沙盒／docker／node 設定、回應快取、新的模型別名或 whitebox_reviewer_* 代理、"
            "模型的 model／fallback_model、端點、金鑰環境變數與 extra_params（必須與內建設定的同一別名相同），"
            "也不得調高花費（execution_mode: live，或高於內建值的 max_model_calls、max_concurrent_calls、max_output_tokens、"
            "retry_invalid_output、max_retries、max_files、max_file_bytes）。"
            "這個檔案是較舊或較新版本的 VibeHarness 寫出的嗎？如果信任這個檔案，請以 "
            f"--config {path} 明確指定；否則請以 vibeharness --init-config {path} --force 重新產生",
            f"the discovered config {path} sets security-sensitive key(s): {names}. A discovered config may come "
            "from an untrusted checkout, so it must not set executable paths, sandbox / docker / node settings, the "
            "response cache, new model aliases or whitebox_reviewer_* agents, or a model's model / fallback_model, "
            "endpoint, key environment variable or extra_params (they must equal the bundled config's same alias), "
            "and it must not raise spend (execution_mode: live, or max_model_calls, max_concurrent_calls, "
            "max_output_tokens, retry_invalid_output, max_retries, max_files or max_file_bytes above the bundled "
            "value). Was this file written by an older or newer VibeHarness version? If you trust this file, pass "
            f"it explicitly with --config {path}; otherwise regenerate it with vibeharness --init-config {path} --force",
        ))


def relative_executable_warnings(config: Dict[str, Any]) -> List[str]:
    """global.*_bin 是相對路徑（含目錄分隔字元但不是絕對路徑，例如 ./node）時的警告：它會相對於目前目錄
    （通常是受稽核的 checkout）解析並在啟動時執行。請用絕對路徑，或在 PATH 上解析的裸名稱。
    Warnings for a global.*_bin that is a relative path (has a directory separator but is not absolute, e.g.
    ./node): it resolves against the current directory (usually the audited checkout) and runs at start-up.
    Use an absolute path, or a bare name resolved on PATH."""
    warnings: List[str] = []
    for key, value in sorted((config.get("global") or {}).items(), key=lambda kv: str(kv[0])):
        if not str(key).endswith("_bin") or not isinstance(value, str):
            continue
        has_sep = "/" in value or (os.sep in value) or bool(os.altsep and os.altsep in value)
        if has_sep and not os.path.isabs(value):
            warnings.append(bi(
                f"global.{key} 是相對路徑 {value!r}：它相對於目前目錄解析並會被執行；請改用絕對路徑或 PATH 上的名稱",
                f"global.{key} is a relative path {value!r}: it resolves against the current directory and is "
                "executed; use an absolute path or a name on PATH",
            ))
    return warnings


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

    def __init__(self, config_path: str = DEFAULT_CONFIG_PATH, execution_mode: Optional[str] = None):
        self.config = self._load_config(config_path)
        # 空的 `global:` 會載入成 None：當成空對應表，而不是在 .get() 時拋出 AttributeError
        # An empty `global:` loads as None: treat it as an empty mapping instead of raising AttributeError on .get()
        global_cfg = self.config.get("global") or {}
        self.execution_mode = execution_mode or global_cfg.get("execution_mode") or "hybrid"
        if self.execution_mode not in ("live", "hybrid", "mock"):
            raise ValueError(bi(f"未知的 execution_mode '{self.execution_mode}'（應為 live、hybrid 或 mock）",
                                   f"Unknown execution_mode '{self.execution_mode}' (expected live, hybrid or mock)"))
        self.models_config = self.config.get("models") or {}
        self.agents_config = self.config.get("agents") or {}
        self.call_log: List[AgentCallRecord] = []
        # 成本防護：每次執行允許的線上模型呼叫次數（單次呼叫的 litellm 重試／fallback_model
        # 不另外計算）。None 或 0 表示不限制。
        # Cost guard: live model invocations allowed per run (litellm retries / fallback_model of one
        # invocation are not counted separately). None or 0 means unlimited.
        self.max_model_calls = self._positive_int(global_cfg.get("max_model_calls"), "max_model_calls")
        # 代理把呼叫分散到最多這麼多個工作者的執行緒池上
        # Agents fan their calls out on a thread pool of at most this many workers
        self.max_concurrent_calls = self._positive_int(
            global_cfg.get("max_concurrent_calls", DEFAULT_MAX_CONCURRENT_CALLS), "max_concurrent_calls"
        ) or DEFAULT_MAX_CONCURRENT_CALLS
        self.live_calls_attempted = 0
        self._budget_lock = threading.Lock()
        # null 與未設定相同，都用預設值（與 timeout_seconds、max_retries 一致）；只有明確的 0 才關閉
        # null means the same as unset, the default (consistent with timeout_seconds, max_retries); only an explicit 0 disables
        retries = global_cfg.get("retry_invalid_output")
        self.retry_invalid_output = DEFAULT_RETRY_INVALID_OUTPUT if retries is None else retries
        # 以模型 + 提示為鍵、存放可用線上回答的磁碟快取：以相同設定重新執行相同目標
        # 不需任何花費，且得到相同的回答。None 表示停用。
        # On-disk cache of usable live answers keyed by model + prompt: a re-run of the same target with
        # the same config costs nothing and gives the same answers. None disables it.
        self.cache_dir: Optional[str] = None
        # --cache-only：每次模型呼叫都只從回應快取取用，未命中時絕不呼叫供應商（見 CACHE_MISS_REASON）
        # --cache-only: every model call is served from the response cache only; a miss never calls a provider (see CACHE_MISS_REASON)
        self.cache_only = False
        if global_cfg.get("cache_dir"):
            self.set_cache_dir(str(global_cfg["cache_dir"]))
        self._validate_endpoints()
        self._validate_settings()

    def _validate_endpoints(self) -> None:
        """每個自訂的 api_base 都必須是 https（純 http 只允許連到 loopback）：目標原始碼與
        提示會傳送到這些端點，因此打錯字或惡意設定不得把它們以明文送到任意主機
        （OWASP LLM04:2026；允許清單內的模型端點）。
        Every custom api_base must be https (plain http only to loopback): target source code and
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
        """在 `path` 啟用回應快取（不存在時會建立）。該目錄存放原始的模型回答，
        其中可能引用受稽核的程式碼：請把它當成報告一樣看待。
        Enables the response cache in `path` (created if missing). The directory holds raw model
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

    def _validate_settings(self) -> None:
        """數值設定在啟動時檢查一次。過去它們只在發出呼叫時才被讀取，
        因此像 `timeout_seconds: "abc"` 這樣的錯字會傳到 litellm、在那裡失敗，而在 hybrid
        模式下被登記為「線上呼叫失敗」並悄悄地由模擬引擎取代。
        Numeric settings are checked once at start-up. They used to be read only when a call was
        made, so a typo such as `timeout_seconds: "abc"` reached litellm, failed there, and in hybrid
        mode was booked as "live invocation failed" and silently replaced by the simulation engine."""
        # null 與省略相同，都採用預設值（與其他數值設定一致）；0 或負數仍是 ConfigError
        # null means the same as omitted, the default (consistent with the other numeric settings); 0 or a negative value is still a ConfigError
        self._number(self._global_setting("timeout_seconds", DEFAULT_TIMEOUT_SECONDS), "global.timeout_seconds", minimum=1)
        self._number(self._global_setting("max_retries", DEFAULT_MAX_RETRIES), "global.max_retries", minimum=0, integer=True)
        self._number(self._global_setting("max_output_tokens", DEFAULT_MAX_OUTPUT_TOKENS), "global.max_output_tokens",
                     minimum=1, integer=True)
        for alias, info in self.models_config.items():
            # 每個模型項目都必須有 litellm 模型字串：否則指向它的 agent 會悄悄改用模擬（hybrid）或在 live 中途失敗
            # Every model entry needs a litellm model string: otherwise an agent pointing at it silently simulates
            # (hybrid) or fails mid-run (live)
            info = info if isinstance(info, dict) else {}
            model = info.get("model")
            if not isinstance(model, str) or not model.strip():
                raise ConfigError(bi(f"models.{alias}.model 必須是非空的 litellm 模型字串，目前為 {model!r}",
                                     f"models.{alias}.model must be a non-empty litellm model string, got {model!r}"))
            fallback = info.get("fallback_model")
            if fallback is not None and (not isinstance(fallback, str) or not fallback.strip()):
                raise ConfigError(bi(f"models.{alias}.fallback_model 必須是非空字串或 null，目前為 {fallback!r}",
                                     f"models.{alias}.fallback_model must be a non-empty string or null, got {fallback!r}"))
            # 檢查的是去掉前後空白的值，保存的也必須是它：否則 " claude-sonnet-5-5" 會原樣送進 litellm 與快取鍵
            # The check is on the stripped value, so the stripped value is what is kept: otherwise " claude-sonnet-5-5"
            # would reach litellm and the cache key as written
            info["model"] = model.strip()
            if fallback is not None:
                info["fallback_model"] = fallback.strip()
            # base_url 不會被讀取（端點是 api_base）：留著它會讓使用者以為呼叫送到了自訂端點
            # base_url is never read (the endpoint is api_base): keeping it would make users think calls go to a custom endpoint
            if info.get("base_url") is not None:
                raise ConfigError(bi(f"models.{alias}.base_url 不會被讀取；自訂端點請改用 models.{alias}.api_base",
                                     f"models.{alias}.base_url is not read; use models.{alias}.api_base for a custom endpoint"))
            if info.get("max_output_tokens") is not None:
                self._number(info["max_output_tokens"], f"models.{alias}.max_output_tokens", minimum=1, integer=True)
        for agent_id, meta in self.agents_config.items():
            # 打錯字的 model_alias 過去會悄悄解析成 unconfigured：hybrid 改用模擬，live 則在已付費的呼叫之後才中途失敗。
            # 省略或 null 仍是刻意的 unconfigured；明確寫出的別名必須存在於 models
            # A misspelled model_alias used to resolve silently to unconfigured: hybrid simulated it, live failed mid-run
            # after paid calls. Omitted or null is still a deliberate unconfigured; an alias that is written must exist in models
            alias = meta.get("model_alias") if isinstance(meta, dict) else None
            if alias is not None and alias != UNCONFIGURED_ALIAS and (not isinstance(alias, str) or alias not in self.models_config):
                known = ", ".join(sorted(str(a) for a in self.models_config)) or "-"
                raise ConfigError(bi(
                    f"agents.{agent_id}.model_alias {alias!r} 不在 models 區段中（已定義：{known}）",
                    f"agents.{agent_id}.model_alias {alias!r} is not defined in the models section (defined: {known})",
                ))
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
            reserved = sorted(k for k in (extra or {}) if is_reserved_extra_param(k))
            if reserved and set(reserved) <= _TOKEN_CAP_PARAMS:
                names = ", ".join(reserved)
                raise ConfigError(bi(
                    f"models.{alias}.extra_params 不可設定輸出 token 上限：{names}"
                    f"（請改用 models.{alias}.max_output_tokens 或 global.max_output_tokens）",
                    f"models.{alias}.extra_params must not set the output-token cap: {names} "
                    f"(use models.{alias}.max_output_tokens or global.max_output_tokens instead)"
                ))
            if reserved:
                names = ", ".join(reserved)
                raise ConfigError(bi(
                    f"models.{alias}.extra_params 不可設定保留的 litellm 參數：{names}"
                    "（端點、憑證、逾時與重試請用 models.<alias> 或 global 的專用設定鍵；輸出 token 上限請用 max_output_tokens）",
                    f"models.{alias}.extra_params must not set reserved litellm parameter(s): {names} "
                    "(use the dedicated models.<alias> / global settings for endpoints, credentials, timeouts and "
                    "retries, and max_output_tokens for the output-token cap)"
                ))

    def _global_setting(self, key: str, default: Any) -> Any:
        """`global.<key>` 的值；省略或為 null 時回傳 `default`，因此絕不會把 None 傳給 litellm。
        The value of `global.<key>`; `default` when it is omitted or null, so None never reaches litellm."""
        value = (self.config.get("global") or {}).get(key)
        return default if value is None else value

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
        """可供記錄或列入報告的供應商錯誤文字：憑證已遮蔽（HTTP 用戶端
        可能回聲出帶有 API 金鑰的請求 URL 或標頭），控制字元已移除。
        Provider error text as it may be logged or reported: credentials redacted (an HTTP client
        can echo a request URL or header carrying the API key), control characters removed."""
        return clean_model_text(redact_secrets(str(text)))

    @staticmethod
    def _positive_int(value: Any, key: str) -> Optional[int]:
        """選用的正整數設定；None/0 表示「未設定」。
        An optional positive integer setting; None/0 mean "not set"."""
        if value is None or value == 0:
            return None
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ConfigError(bi(f"global.{key} 必須是非負整數，目前為 {value!r}",
                                 f"global.{key} must be a non-negative integer, got {value!r}"))
        return value

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
        return [rec for rec in self.call_log if rec.reason == BUDGET_EXHAUSTED_REASON]

    @property
    def cache_miss_calls(self) -> List[AgentCallRecord]:
        """--cache-only 模式下快取沒有答案的呼叫（證據缺口；hybrid 改用模擬）。
        Calls the cache could not answer in --cache-only mode (an evidence gap; simulated in hybrid)."""
        return [rec for rec in self.call_log if rec.reason == CACHE_MISS_REASON]

    @property
    def used_simulation(self) -> bool:
        return any(rec.mode == "simulated" for rec in self.call_log)

    @property
    def invalid_calls(self) -> List[AgentCallRecord]:
        return [rec for rec in self.call_log if rec.mode == "invalid"]

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

    def _load_config(self, path: str) -> Dict[str, Any]:
        """見 load_config_file ／ See load_config_file."""
        return load_config_file(path)

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
            # null 已由 _global_setting 換成預設值：timeout=None 對 litellm 代表不限時，絕不傳出
            # null is already replaced by the default in _global_setting: timeout=None means no limit to litellm and is never passed
            "timeout": self._global_setting("timeout_seconds", DEFAULT_TIMEOUT_SECONDS),
            "num_retries": self._global_setting("max_retries", DEFAULT_MAX_RETRIES),
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
            value = self._global_setting("max_output_tokens", DEFAULT_MAX_OUTPUT_TOKENS)
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
