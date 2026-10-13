"""設定：載入一次、套用預設一次、驗證一次。

`load_settings` 讀取代理設定檔（global、models、agents），依來源套用政策（探索到的設定檔只能調低花費、不得設定安全敏感的鍵），
套用預設值、依啟動時的順序驗證每個鍵，再套用 CLI 已檢查過的覆寫值，回傳凍結的 `Settings`。每個預設值都在這裡定義；
舊位置（閘道、harness、擷取器、突變測試、沙盒）以同名重新匯出。本模組在匯入時不載入任何第三方套件（yaml 延遲匯入）。
Settings: load once, default once, validate once.

`load_settings` reads the agent config file (global, models, agents), applies its origin's policy (a discovered config
may only lower spend and may set no security-sensitive key), applies the defaults, validates every key in start-up
order, then applies the overrides the CLI has already checked, and returns a frozen `Settings`. Every default is defined
here; the old locations (the gateway, the harness, the extractor, mutation testing, the sandbox) re-export it under the
same name. This module loads no third-party package at import time (yaml is imported lazily)."""
import math
import os
import re
import urllib.parse
from dataclasses import dataclass, field, replace
from typing import Any, Dict, FrozenSet, List, Literal, Mapping, NoReturn, Optional, Tuple

from vibeharness.core.i18n import bi

DEFAULT_CONFIG_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "config", "agents_config.yaml"
)

DEFAULT_MAX_CONCURRENT_CALLS = 6
# 這是上限而非花費：威脅模型 JSON 與推理模型的思考 token 在線上執行時都曾超過 4096
# A cap, not a spend: threat-model JSON and reasoning models' thinking tokens both overflowed 4096 in live runs
DEFAULT_MAX_OUTPUT_TOKENS = 16384
# 單次 LLM 請求的逾時（秒）與 litellm 層級的重試次數；設定為 null 時也採用這些值
# Per-request LLM timeout (seconds) and litellm-level retry count; a null setting also means these values
DEFAULT_TIMEOUT_SECONDS = 180
DEFAULT_MAX_RETRIES = 2

# 無法使用的線上回答（非 JSON、缺少鍵、空白）在登記為 `invalid` 之前
# 會被重新詢問的次數；每次重新詢問都是真實呼叫，會計入 max_model_calls
# How many times an unusable live answer (not JSON, missing keys, empty) is re-asked before it is
# booked as `invalid`; each re-ask is a real call that counts against max_model_calls
DEFAULT_RETRY_INVALID_OUTPUT = 1
# agents.<id>.temperature 省略或為 null 時的取樣溫度 ／ sampling temperature when agents.<id>.temperature is omitted or null
DEFAULT_TEMPERATURE = 0.2

# 沙盒與 Node 沙盒共用的預設值 ／ defaults shared by the sandbox and the Node sandbox
# local_subprocess 沙盒的位址空間上限（MB）；0 表示停用
# Address-space cap for the local_subprocess sandbox (MB); 0 disables
DEFAULT_SANDBOX_MEMORY_MB = 2048
# 突變測試的預設值：變異體上限與低於幾分（百分比）算證據缺口 ／ mutation-testing defaults: the mutant cap and the score (percent) below which an evidence gap is added
DEFAULT_MUTATION_MAX_MUTANTS = 20
DEFAULT_MUTATION_MIN_SCORE = 70.0
# 沙盒逾時與 docker 程序數上限的預設值 ／ defaults for the sandbox timeouts and the docker process limit
DEFAULT_SANDBOX_TIMEOUT_SECONDS = 120
DEFAULT_PER_TEST_TIMEOUT_SECONDS = 30
DEFAULT_DOCKER_PIDS_LIMIT = 256
DEFAULT_SANDBOX_PROVIDER = "local_subprocess"
DEFAULT_DOCKER_IMAGE = "vibeharness-sandbox:latest"
DEFAULT_DOCKER_NODE_IMAGE = "vibeharness-sandbox-node:latest"
# 複本大小上限（MB）：單一檔案目標會以所在目錄為工作目錄，可能很大；超過就略過並記原因
# Size cap (MB) of the scratch copy: a single-file target uses its whole directory, which may be large;
# above it the step is skipped with a reason
DEFAULT_MAX_COPY_MB = 200

DEFAULT_MAX_FILES = 50
# 單一原始碼檔案超過此大小就略過（回報為證據缺口）：壓縮過的 bundle 與
# 產生的程式碼無法審查，而且 JS/TS 詞法分析器是逐字元的 Python 迴圈
# A single source file above this size is skipped (reported as an evidence gap): minified bundles and
# generated code are not reviewable, and the JS/TS lexer is a character-by-character Python loop
DEFAULT_MAX_FILE_BYTES = 1_000_000

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
    r"|wandb|weave|otel|opik|mlflow|logfire|sentry|phoenix|galileo|athina|literalai|openmeter|greenscale|traceloop|signoz)_"
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
# 名稱含有 key 的部分同樣另外判斷：signoz_ingestion_key（litellm 1.105）、public_key 等都是憑證而保留；只指名快取項目的
# cache_key（prompt_cache_key）不改變目的地，允許
# A `key` name part is judged the same way: signoz_ingestion_key (litellm 1.105), public_key and the like are
# credentials and reserved; cache_key (prompt_cache_key) only names a cache entry, not a destination, so it is allowed
_KEY_NAME_PART_RE = re.compile(r"(?:^|_)key(?:$|_)", re.IGNORECASE)
_CACHE_KEY_NAME_PART_RE = re.compile(r"(?:^|_)cache_key(?:$|_)", re.IGNORECASE)


def _is_reserved_param_name(name: str) -> bool:
    """名稱符合端點／憑證／callback 樣式（不看 RESERVED_EXTRA_PARAMS 名單）。
    The name matches an endpoint / credential / callback pattern (without consulting RESERVED_EXTRA_PARAMS)."""
    if _RESERVED_EXTRA_PARAM_RE.search(name):
        return True
    if _KEY_NAME_PART_RE.search(name) and not _CACHE_KEY_NAME_PART_RE.search(name):
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
    # 延遲匯入：只匯入常數的模組（擷取器、沙盒）不必載入 yaml
    # Lazy import: modules that only import constants (the extractor, the sandbox) need not load yaml
    import yaml
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
        raise ConfigError(_discovered_config_message(path, problems))


def _discovered_config_message(path: str, problems: List[str]) -> str:
    """列出安全敏感鍵並說明如何處理 ／ Names the security-sensitive keys and says what to do about them."""
    names = ", ".join(problems)
    return bi(
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
    )


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


# --- 唯讀的 models／agents ／ read-only models / agents --------------------------------------------

def _read_only(*args: Any, **kwargs: Any) -> NoReturn:
    raise TypeError(bi("設定在載入後是唯讀的", "settings are read-only once loaded"))


class FrozenDict(dict):
    """載入後不可修改的 dict：與 dict 同型（json.dumps、isinstance(x, dict)、**展開都照常），但任何修改都是 TypeError。
    A dict that cannot be changed once loaded: the same type as dict (json.dumps, isinstance(x, dict) and ** unpacking
    keep working), but any change is a TypeError."""
    __setitem__ = __delitem__ = clear = pop = popitem = setdefault = update = __ior__ = _read_only  # type: ignore[assignment]

    def __reduce__(self) -> Tuple[Any, ...]:
        return (FrozenDict, (dict(self),))


class FrozenList(list):
    """載入後不可修改的 list（例如 extra_params 裡的 stop 序列）／ A list that cannot be changed once loaded (e.g. stop
    sequences in extra_params)."""
    __setitem__ = __delitem__ = __iadd__ = __imul__ = append = extend = insert = pop = remove = clear = sort = reverse = _read_only  # type: ignore[assignment]

    def __reduce__(self) -> Tuple[Any, ...]:
        return (FrozenList, (list(self),))


def freeze(value: Any) -> Any:
    """把巢狀的 dict／list 換成唯讀版本 ／ Replaces nested dicts / lists with read-only versions."""
    if isinstance(value, dict):
        return FrozenDict({k: freeze(v) for k, v in value.items()})
    if isinstance(value, list):
        return FrozenList(freeze(v) for v in value)
    return value


# --- 驗證規則 ／ validation rules -------------------------------------------------------------------

def positive_int(value: Any, key: str) -> Optional[int]:
    """選用的正整數設定；None/0 表示「未設定」。
    An optional positive integer setting; None/0 mean "not set"."""
    if value is None or value == 0:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ConfigError(bi(f"global.{key} 必須是非負整數，目前為 {value!r}",
                             f"global.{key} must be a non-negative integer, got {value!r}"))
    return value


def number(value: Any, key: str, minimum: float, maximum: Optional[float] = None, integer: bool = False) -> None:
    ok = isinstance(value, (int, float)) and not isinstance(value, bool) and (not integer or isinstance(value, int))
    if not ok or value < minimum or (maximum is not None and value > maximum):
        kind = "an integer" if integer else "a number"
        kind_zh = "整數" if integer else "數值"
        bounds = f">= {minimum}" if maximum is None else f"between {minimum} and {maximum}"
        bounds_zh = f">= {minimum}" if maximum is None else f"介於 {minimum} 與 {maximum} 之間"
        raise ConfigError(bi(f"{key} 必須是 {bounds_zh} 的{kind_zh}，目前為 {value!r}",
                             f"{key} must be {kind} {bounds}, got {value!r}"))


def _setting_or_default(global_cfg: Mapping[str, Any], key: str, default: Any) -> Any:
    """`global.<key>`；省略或為 null 時是 `default`（與其他鍵一致，null 保留預設值）。
    `global.<key>`; `default` when it is omitted or null (like the other keys, null keeps the default)."""
    value = global_cfg.get(key)
    return default if value is None else value


def prepare_cache_dir(path: str) -> str:
    """回應快取目錄的絕對路徑（不存在時會建立）；無法建立或不可寫入時是 ConfigError。該目錄存放原始的模型回答，
    其中可能引用受稽核的程式碼：請把它當成報告一樣看待。
    The response cache directory's absolute path (created if missing); a ConfigError when it cannot be created or
    written. The directory holds raw model answers, which can quote the audited code: treat it like the reports."""
    target = os.path.abspath(path)
    try:
        os.makedirs(target, exist_ok=True)
    except OSError as e:
        raise ConfigError(bi(f"cache_dir {path!r} 無法建立：{e}", f"cache_dir {path!r} cannot be created: {e}")) from e
    if not os.access(target, os.W_OK):
        raise ConfigError(bi(f"cache_dir {path!r} 不可寫入", f"cache_dir {path!r} is not writable"))
    return target


# --- 設定 ／ Settings --------------------------------------------------------------------------------

Origin = Literal["explicit", "discovered", "bundled"]


@dataclass(frozen=True)
class Overrides:
    """CLI 旗標的值，CLI 已依自己的規則檢查過；None 表示沒有給這個旗標。
    The CLI flags' values, already checked by the CLI's own rules; None means the flag was not given."""
    execution_mode: Optional[str] = None
    max_files: Optional[int] = None
    max_model_calls: Optional[int] = None  # 0 表示不限制 ／ 0 means unlimited
    mutation_testing: Optional[bool] = None
    mutation_max_mutants: Optional[int] = None
    include: Optional[Tuple[str, ...]] = None
    exclude: Optional[Tuple[str, ...]] = None
    changed_since: Optional[str] = None
    cache_dir: Optional[str] = None
    cache_only: bool = False


@dataclass(frozen=True)
class GatewaySettings:
    execution_mode: str
    max_model_calls: Optional[int]  # None 表示不限制 ／ None means unlimited
    max_concurrent_calls: int
    retry_invalid_output: int
    timeout_seconds: float
    max_retries: int
    max_output_tokens: int
    cache_dir: Optional[str]
    cache_only: bool
    models: Mapping[str, Any]  # 唯讀，形狀與設定檔相同 ／ read-only, the same shape as the config file
    agents: Mapping[str, Any]


@dataclass(frozen=True)
class DockerSettings:
    """只在任一沙盒用 docker 時才驗證；否則是預設值 ／ Validated only when either sandbox uses docker; otherwise the defaults."""
    pids_limit: int = DEFAULT_DOCKER_PIDS_LIMIT
    network: str = "none"
    memory: str = "1g"
    cpus: str = "2"
    bin: str = "docker"
    image: str = DEFAULT_DOCKER_IMAGE


@dataclass(frozen=True)
class SandboxSettings:
    provider: str
    timeout: int
    per_test_timeout: int
    memory_mb: int  # 0 表示停用上限 ／ 0 disables the cap
    docker: DockerSettings = field(default_factory=DockerSettings)


@dataclass(frozen=True)
class NodeSettings:
    provider: str
    node_bin: str
    image: str


@dataclass(frozen=True)
class MutationSettings:
    enabled: bool
    max_mutants: int
    timeout: int
    min_score: float
    max_copy_mb: int


@dataclass(frozen=True)
class ScopeSettings:
    max_files: int
    max_file_bytes: int
    include: Tuple[str, ...] = ()
    exclude: Tuple[str, ...] = ()
    changed_since: Optional[str] = None


@dataclass(frozen=True)
class Settings:
    path: str
    origin: Origin
    gateway: GatewaySettings
    sandbox: SandboxSettings
    node: NodeSettings
    mutation: MutationSettings
    scope: ScopeSettings
    warnings: Tuple[str, ...] = ()
    # 回報用的值來源：目前只有 mutation_testing（RunMetadata.mutation_source）
    # Where a reported value came from: for now only mutation_testing (RunMetadata.mutation_source)
    sources: Mapping[str, str] = field(default_factory=dict)


def load_settings(path: str, *, origin: Origin, overrides: Optional[Overrides] = None,
                  reference_path: str = DEFAULT_CONFIG_PATH) -> Settings:
    """載入並驗證設定檔，套用 CLI 覆寫值。錯誤一律是 ConfigError（CLI 以 exit 5 結束）。各鍵依過去啟動時的順序驗證
    （閘道，然後是沙盒、Node、突變測試與檔案上限），所以同一個檔案裡有多個錯誤時，最先回報的錯誤不變。
    `discovered` 的設定檔先與 `reference_path`（內建設定檔）比較，見 discovered_config_violations。
    Loads and validates a config file and applies the CLI overrides. Every error is a ConfigError (the CLI exits 5).
    Keys are validated in the former start-up order (the gateway, then the sandbox, Node, mutation testing and the
    file limits), so the first error reported for a file with several problems is unchanged. A `discovered` config is
    first compared with `reference_path` (the bundled config), see discovered_config_violations."""
    overrides = overrides or Overrides()
    config = load_config_file(path)
    if origin == "discovered":
        _raise_discovered_violations(path, discovered_config_violations(config, load_config_file(reference_path)))
    warnings = tuple(relative_executable_warnings(config))
    # 空的 `global:` 會載入成 None：當成空對應表 ／ An empty `global:` loads as None: treat it as an empty mapping
    g: Dict[str, Any] = config.get("global") or {}
    models: Dict[str, Any] = config.get("models") or {}
    agents: Dict[str, Any] = config.get("agents") or {}

    gateway = _gateway_settings(g, models, agents, overrides)
    sandbox, node = _sandbox_settings(g)
    mutation = _mutation_settings(g, sandbox.per_test_timeout)
    scope = ScopeSettings(
        max_files=positive_int(g.get("max_files"), "max_files") or DEFAULT_MAX_FILES,
        max_file_bytes=positive_int(g.get("max_file_bytes"), "max_file_bytes") or DEFAULT_MAX_FILE_BYTES,
        include=_pattern_list(g.get("include"), "include"),
        exclude=_pattern_list(g.get("exclude"), "exclude"),
    )

    # 覆寫值在檔案的值都驗證之後才套用，順序與 CLI 過去在建構之後設定的順序相同
    # Overrides apply after every file value is validated, in the order the CLI used to set them after construction
    if overrides.max_files is not None:
        scope = replace(scope, max_files=overrides.max_files)
    if overrides.max_model_calls is not None:
        gateway = replace(gateway, max_model_calls=overrides.max_model_calls or None)
    if overrides.mutation_testing is not None:
        mutation = replace(mutation, enabled=overrides.mutation_testing)
    if overrides.mutation_max_mutants is not None:
        mutation = replace(mutation, max_mutants=overrides.mutation_max_mutants)
    if overrides.include is not None:
        scope = replace(scope, include=tuple(overrides.include))
    if overrides.exclude is not None:
        scope = replace(scope, exclude=tuple(overrides.exclude))
    if overrides.changed_since:
        scope = replace(scope, changed_since=overrides.changed_since)
    if overrides.cache_dir:
        gateway = replace(gateway, cache_dir=prepare_cache_dir(overrides.cache_dir))
    if overrides.cache_only:
        if not gateway.cache_dir:
            raise ConfigError(bi("--cache-only 需要回應快取：請指定 --cache-dir 或設定 global.cache_dir",
                                 "--cache-only needs a response cache: pass --cache-dir or set global.cache_dir"))
        gateway = replace(gateway, cache_only=True)

    if overrides.mutation_testing is not None:
        mutation_source = "cli"
    else:
        mutation_source = "config" if g.get("mutation_testing") is not None else "default"
    return Settings(path=path, origin=origin, gateway=gateway, sandbox=sandbox, node=node, mutation=mutation,
                    scope=scope, warnings=warnings, sources=FrozenDict({"mutation_testing": mutation_source}))


def _raise_discovered_violations(path: str, problems: List[str]) -> None:
    if problems:
        raise ConfigError(_discovered_config_message(path, problems))


def _gateway_settings(g: Dict[str, Any], models: Dict[str, Any], agents: Dict[str, Any],
                      overrides: Overrides) -> GatewaySettings:
    """閘道的設定，依過去 LLMGateway.__init__ 的順序驗證 ／ The gateway's settings, validated in LLMGateway.__init__'s former order."""
    execution_mode = overrides.execution_mode or g.get("execution_mode") or "hybrid"
    if execution_mode not in ("live", "hybrid", "mock"):
        raise ConfigError(bi(f"未知的 execution_mode '{execution_mode}'（應為 live、hybrid 或 mock）",
                             f"Unknown execution_mode '{execution_mode}' (expected live, hybrid or mock)"))
    # 成本防護：每次執行允許的線上模型呼叫次數（單次呼叫的 litellm 重試／fallback_model
    # 不另外計算）。None 或 0 表示不限制。
    # Cost guard: live model invocations allowed per run (litellm retries / fallback_model of one
    # invocation are not counted separately). None or 0 means unlimited.
    max_model_calls = positive_int(g.get("max_model_calls"), "max_model_calls")
    max_concurrent_calls = positive_int(
        g.get("max_concurrent_calls", DEFAULT_MAX_CONCURRENT_CALLS), "max_concurrent_calls"
    ) or DEFAULT_MAX_CONCURRENT_CALLS
    # null 與未設定相同，都用預設值（與 timeout_seconds、max_retries 一致）；只有明確的 0 才關閉
    # null means the same as unset, the default (consistent with timeout_seconds, max_retries); only an explicit 0 disables
    retries = g.get("retry_invalid_output")
    retry_invalid_output = DEFAULT_RETRY_INVALID_OUTPUT if retries is None else retries
    cache_dir = prepare_cache_dir(str(g["cache_dir"])) if g.get("cache_dir") else None
    _validate_endpoints(models)
    timeout_seconds = _setting_or_default(g, "timeout_seconds", DEFAULT_TIMEOUT_SECONDS)
    number(timeout_seconds, "global.timeout_seconds", minimum=1)
    max_retries = _setting_or_default(g, "max_retries", DEFAULT_MAX_RETRIES)
    number(max_retries, "global.max_retries", minimum=0, integer=True)
    max_output_tokens = _setting_or_default(g, "max_output_tokens", DEFAULT_MAX_OUTPUT_TOKENS)
    number(max_output_tokens, "global.max_output_tokens", minimum=1, integer=True)
    _validate_models_and_agents(models, agents, retry_invalid_output)
    return GatewaySettings(
        execution_mode=execution_mode, max_model_calls=max_model_calls, max_concurrent_calls=max_concurrent_calls,
        retry_invalid_output=retry_invalid_output, timeout_seconds=timeout_seconds, max_retries=max_retries,
        max_output_tokens=max_output_tokens, cache_dir=cache_dir, cache_only=False,
        models=freeze(models), agents=freeze(agents),
    )


def _validate_endpoints(models: Dict[str, Any]) -> None:
    """每個自訂的 api_base 都必須是 https（純 http 只允許連到 loopback）：目標原始碼與
    提示會傳送到這些端點，因此打錯字或惡意設定不得把它們以明文送到任意主機
    （OWASP LLM04:2026；允許清單內的模型端點）。
    Every custom api_base must be https (plain http only to loopback): target source code and
    prompts travel to these endpoints, so a typo or a hostile config must not send them in clear
    text to an arbitrary host (OWASP LLM04:2026; allow-listed model endpoints)."""
    for alias, info in models.items():
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


def _validate_models_and_agents(models: Dict[str, Any], agents: Dict[str, Any], retry_invalid_output: Any) -> None:
    """models 與 agents 的檢查，依過去 _validate_settings 的順序；model／fallback_model 會就地去掉前後空白。
    The models and agents checks, in _validate_settings's former order; model / fallback_model are stripped in place."""
    for alias, info in models.items():
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
            number(info["max_output_tokens"], f"models.{alias}.max_output_tokens", minimum=1, integer=True)
    for agent_id, meta in agents.items():
        # 打錯字的 model_alias 過去會悄悄解析成 unconfigured：hybrid 改用模擬，live 則在已付費的呼叫之後才中途失敗。
        # 省略或 null 仍是刻意的 unconfigured；明確寫出的別名必須存在於 models
        # A misspelled model_alias used to resolve silently to unconfigured: hybrid simulated it, live failed mid-run
        # after paid calls. Omitted or null is still a deliberate unconfigured; an alias that is written must exist in models
        model_alias = meta.get("model_alias") if isinstance(meta, dict) else None
        if model_alias is not None and model_alias != UNCONFIGURED_ALIAS and (
                not isinstance(model_alias, str) or model_alias not in models):
            known = ", ".join(sorted(str(a) for a in models)) or "-"
            raise ConfigError(bi(
                f"agents.{agent_id}.model_alias {model_alias!r} 不在 models 區段中（已定義：{known}）",
                f"agents.{agent_id}.model_alias {model_alias!r} is not defined in the models section (defined: {known})",
            ))
        if isinstance(meta, dict) and meta.get("temperature") is not None:
            number(meta["temperature"], f"agents.{agent_id}.temperature", minimum=0, maximum=2)
    number(retry_invalid_output, "global.retry_invalid_output", minimum=0, maximum=5, integer=True)
    for alias, info in models.items():
        for key in ("price_per_million_input", "price_per_million_output"):
            if isinstance(info, dict) and info.get(key) is not None:
                number(info[key], f"models.{alias}.{key}", minimum=0)
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


def _sandbox_provider(g: Mapping[str, Any]) -> str:
    """`sandbox_provider`；省略或為 null 時是 local_subprocess（與其他鍵一致，null 保留預設值）。
    `sandbox_provider`; local_subprocess when omitted or null (like the other keys, null keeps the default)."""
    value = g.get("sandbox_provider")
    return DEFAULT_SANDBOX_PROVIDER if value is None else str(value)


def _sandbox_node_provider(g: Mapping[str, Any]) -> str:
    """`sandbox_node_provider`；省略或為 null 時跟隨 sandbox_provider。
    `sandbox_node_provider`; follows sandbox_provider when omitted or null."""
    value = g.get("sandbox_node_provider")
    return _sandbox_provider(g) if value is None else str(value)


def _per_test_timeout(g: Mapping[str, Any]) -> int:
    """`per_test_timeout_seconds`，與 sandbox_timeout_seconds 同一套規則：null／0 保留預設值，負數或非整數是
    ConfigError（exit 5）。執行器與突變測試都從這裡取值，兩者不會各自解讀。
    `per_test_timeout_seconds` under the same rule as sandbox_timeout_seconds: null / 0 keep the default, a
    negative or non-integer value is a ConfigError (exit 5). The executor and mutation testing both read it from
    here, so they never interpret the value differently."""
    return positive_int(g.get("per_test_timeout_seconds"), "per_test_timeout_seconds") or DEFAULT_PER_TEST_TIMEOUT_SECONDS


def _sandbox_settings(g: Mapping[str, Any]) -> Tuple[SandboxSettings, NodeSettings]:
    """Python 與 Node 沙盒的設定，依過去 VibeHarnessCommander.__init__ 的順序驗證：共用的逾時與記憶體、docker_*（只在任一
    沙盒用 docker 時才驗證：純本機的設定檔裡殘留的 docker 鍵不會擋住啟動）、sandbox_provider 與 docker_image、
    per_test_timeout_seconds，然後是 Node 的 provider 與映像檔。
    The Python and Node sandboxes' settings, validated in VibeHarnessCommander.__init__'s former order: the shared
    timeout and memory, docker_* (validated only when either sandbox uses docker: stale docker keys in a local-only
    config never block start-up), sandbox_provider and docker_image, per_test_timeout_seconds, then the Node provider
    and image."""
    provider = _sandbox_provider(g)
    node_provider = _sandbox_node_provider(g)
    need_docker = provider == "docker" or node_provider == "docker"
    timeout = positive_int(g.get("sandbox_timeout_seconds"), "sandbox_timeout_seconds") or DEFAULT_SANDBOX_TIMEOUT_SECONDS
    raw_memory = g.get("sandbox_memory_mb")
    memory_mb = DEFAULT_SANDBOX_MEMORY_MB if raw_memory is None else (positive_int(raw_memory, "sandbox_memory_mb") or 0)
    docker = _docker_settings(g) if need_docker else DockerSettings()
    if provider not in ("local_subprocess", "docker"):
        raise ConfigError(bi(
            f"sandbox_provider '{provider}' 尚未實作；支援：'local_subprocess'、'docker'",
            f"sandbox_provider '{provider}' is not implemented; supported: 'local_subprocess', 'docker'"
        ))
    image = _setting_or_default(g, "docker_image", DEFAULT_DOCKER_IMAGE)
    if provider == "docker" and (not isinstance(image, str) or not image.strip()):
        raise ConfigError(bi("docker_image 必須是非空字串", "docker_image must be a non-empty string"))
    if isinstance(image, str) and image.strip():
        docker = replace(docker, image=image.strip())
    per_test = _per_test_timeout(g)
    if node_provider not in ("local_subprocess", "docker"):
        raise ConfigError(bi(
            f"sandbox_node_provider '{node_provider}' 尚未實作；支援：'local_subprocess'、'docker'",
            f"sandbox_node_provider '{node_provider}' is not implemented; supported: 'local_subprocess', 'docker'"
        ))
    node_image = _setting_or_default(g, "docker_node_image", DEFAULT_DOCKER_NODE_IMAGE)
    if node_provider == "docker" and (not isinstance(node_image, str) or not node_image.strip()):
        raise ConfigError(bi("docker_node_image 必須是非空字串", "docker_node_image must be a non-empty string"))
    node = NodeSettings(
        provider=node_provider, node_bin=str(g.get("node_bin") or "node"),
        image=node_image.strip() if isinstance(node_image, str) else DEFAULT_DOCKER_NODE_IMAGE,
    )
    sandbox = SandboxSettings(provider=provider, timeout=timeout, per_test_timeout=per_test, memory_mb=memory_mb, docker=docker)
    return sandbox, node


def _docker_settings(g: Mapping[str, Any]) -> DockerSettings:
    pids = g.get("docker_pids_limit")
    if isinstance(pids, bool) or not (pids is None or isinstance(pids, int)) or (pids or 0) < -1:
        raise ConfigError(bi(f"global.docker_pids_limit 必須是整數（-1 = 不限制），目前為 {pids!r}",
                             f"global.docker_pids_limit must be an integer (-1 = unlimited), got {pids!r}"))
    pids = pids or DEFAULT_DOCKER_PIDS_LIMIT
    network = _setting_or_default(g, "docker_network", "none")
    if not isinstance(network, str) or not network.strip():
        raise ConfigError(bi("global.docker_network 必須是非空字串（例如 \"none\"、\"host\"）",
                             "global.docker_network must be a non-empty string (e.g. \"none\", \"host\")"))
    memory = _setting_or_default(g, "docker_memory", "1g")
    if not isinstance(memory, str) or not re.fullmatch(r"\d+(?:\.\d+)?\s*(?:[bkmgt]|[kmgt]i?b)?", memory.strip(), re.IGNORECASE):
        raise ConfigError(bi(f"global.docker_memory 必須是 Docker 記憶體字串（例如 \"1g\"、\"512m\"），目前為 {memory!r}",
                             f"global.docker_memory must be a Docker memory string (e.g. \"1g\", \"512m\"), got {memory!r}"))
    cpus = _setting_or_default(g, "docker_cpus", "2")
    try:
        cpus_value = float(cpus) if not isinstance(cpus, bool) else float("nan")
    except (TypeError, ValueError):
        cpus_value = float("nan")
    if not math.isfinite(cpus_value) or cpus_value <= 0:
        raise ConfigError(bi(f"global.docker_cpus 必須是正數，目前為 {cpus!r}", f"global.docker_cpus must be a positive number, got {cpus!r}"))
    docker_bin = _setting_or_default(g, "docker_bin", "docker")
    if not isinstance(docker_bin, str) or not docker_bin.strip():
        raise ConfigError(bi("global.docker_bin 必須是非空字串", "global.docker_bin must be a non-empty string"))
    return DockerSettings(pids_limit=pids, network=network.strip(), memory=memory.strip(), cpus=str(cpus).strip(),
                          bin=docker_bin.strip())


def _mutation_settings(g: Mapping[str, Any], per_test: int) -> MutationSettings:
    """突變測試的設定。與其他鍵一致：null 保留預設值（max_mutants 20、min_score 70）；mutation_timeout_seconds／
    mutation_max_copy_mb 的 null 或 0 保留預設值，負數是 ConfigError。
    The mutation-testing settings. Like the other keys, null keeps the default (max_mutants 20, min_score 70); null or
    0 for mutation_timeout_seconds / mutation_max_copy_mb keeps the default, a negative value is a ConfigError."""
    enabled = g.get("mutation_testing")
    if enabled is not None and not isinstance(enabled, bool):
        raise ConfigError(bi(f"global.mutation_testing 必須是 true 或 false，目前為 {enabled!r}",
                             f"global.mutation_testing must be true or false, got {enabled!r}"))
    max_mutants = g.get("mutation_max_mutants")
    if max_mutants is None:
        max_mutants = DEFAULT_MUTATION_MAX_MUTANTS
    if isinstance(max_mutants, bool) or not isinstance(max_mutants, int) or max_mutants < 1:
        raise ConfigError(bi(f"global.mutation_max_mutants 必須是至少 1 的整數，目前為 {max_mutants!r}",
                             f"global.mutation_max_mutants must be an integer >= 1, got {max_mutants!r}"))
    timeout = positive_int(g.get("mutation_timeout_seconds"), "mutation_timeout_seconds") or per_test
    min_score = g.get("mutation_min_score")
    if min_score is None:
        min_score = DEFAULT_MUTATION_MIN_SCORE
    number(min_score, "global.mutation_min_score", 0, 100)
    max_copy_mb = positive_int(g.get("mutation_max_copy_mb"), "mutation_max_copy_mb") or DEFAULT_MAX_COPY_MB
    return MutationSettings(enabled=bool(enabled), max_mutants=max_mutants, timeout=timeout, min_score=float(min_score),
                            max_copy_mb=max_copy_mb)


def _pattern_list(value: Any, key: str) -> Tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, list) or not all(isinstance(v, str) and v.strip() for v in value):
        raise ConfigError(bi(f"global.{key} 必須是 glob 樣式的清單，實際得到 {value!r}",
                             f"global.{key} must be a list of glob patterns, got {value!r}"))
    return tuple(v.strip() for v in value)
