# 設定檔參考（agents_config.yaml）

[English](configuration.en.md) ｜ 正體中文（臺灣）

本文完整說明 `vibeharness/config/agents_config.yaml` 的每一個欄位：語義、預設值與實際生效範圍（以程式碼行為為準）。

設定檔分三大區段：**`global`**（執行與沙盒參數）、**`models`**（模型提供者定義）、**`agents`**（各 Agent 的模型路由）。找不到設定檔或 YAML 損壞會直接報錯（`ConfigError`，CLI 以 exit code 5 中止）；`--config` 指向目錄、無法讀取或二進位檔，最上層不是 mapping，`global`／`models`／`agents` 區段不是 mapping，或 `models.<alias>`／`agents.<id>` 項目不是 mapping，也一樣，不會用讀錯的設定執行。空檔案或空的 `global:` 區段代表使用預設值。

要用哪個設定檔的優先序：`--config <路徑>` ＞ 目前目錄的 `./vibeharness.yaml` ＞ `./.vibeharness.yaml` ＞ 套件內的 `vibeharness/config/agents_config.yaml`；CLI 啟動時會在 stderr 印出採用的設定檔與來源（報告的 Config 欄位也記錄路徑）。探索到的檔案與 `--config` 一樣受驗證，損壞即 exit 5。`vibeharness --init-config [PATH]` 把套件內的預設設定複製到 PATH（預設 `./vibeharness.yaml`）後以 exit 0 結束，已存在的檔案不覆寫（exit 5），除非加上 `--force`。**資安**：在不受信任的 checkout 裡執行時，該 checkout 的 `vibeharness.yaml` 會被自動載入，所以自動發現的檔案（不是以 `--config` 指定的）不得設定安全敏感的鍵；設定了就以 exit 5 拒絕，並說明信任該檔案時請以 `--config` 指定。除非與套件內建預設相同（或為 null），以下都會被拒絕：`global` 的可執行檔路徑（`docker_bin`、`node_bin` 等任何 `*_bin`）、`docker_*`、`node_*`、`sandbox_provider`／`sandbox_node_provider`（允許 `local_subprocess` 與 `docker`）與 `cache_dir`（預先放好的快取會被當成 live 回答）；每個模型的 `api_base`、`base_url`、`api_key_env`（只允許內建設定用到的金鑰變數）、`aws_*`、`extra_params`，以及任何像端點或憑證的鍵。範圍、預算與 agent 設定仍可由自動發現的檔案改變，所以不受信任的 checkout 請明確指定 `--config`。相對路徑的 `*_bin`（例如 `./node`）即使以 `--config` 指定也會印出警告：它相對於目前目錄解析，請用絕對路徑或 PATH 上的名稱。GitHub Action 一律會帶 `--config`（`extra-args` 沒指定時用套件內建的設定）。

CLI 啟動時可用 `--config <路徑>` 改用其他設定檔、`--mode` 覆蓋 `execution_mode`（優先序：CLI `--mode` ＞ `global.execution_mode` ＞ 預設 `hybrid`）；`--max-files`、`--max-model-calls` 同樣覆蓋對應的 `global` 欄位。

---

## `global` 區段

| 欄位 | 預設值 | 說明 |
| :--- | :--- | :--- |
| `execution_mode` | `"hybrid"` | `live`／`hybrid`／`mock` 三選一，行為見下方表格；其他值啟動即報錯 |
| `timeout_seconds` | `180` | 單次 LLM 請求的逾時（秒），傳給 litellm；須為 ≥ 1 的數字（啟動時驗證，否則 `ConfigError`）。`null` 等同預設 180（絕不會以不限時呼叫 litellm）；`0` 或負數是 `ConfigError` |
| `max_retries` | `2` | litellm 層級的重試次數（同一主模型重試；全部失敗後才會嘗試 `fallback_model` 一次）；須為 ≥ 0 的整數，`null` 等同預設 2 |
| `max_output_tokens` | `16384` | 單次模型回應的 token 上限；`models.<alias>.max_output_tokens` 可個別覆蓋；須為 ≥ 1 的整數，`null` 等同預設 16384 |
| `max_model_calls` | `null`（不限） | 成本護欄：每次執行最多幾次真實模型呼叫（同一次呼叫內 litellm 的重試與 `fallback_model` 不另計）。用完後 `hybrid` 改走模擬引擎、列為證據缺口（判定不會是 `READY_TO_SHIP`）；`live` 直接擲出 `LLMGatewayError`（exit 4）。須為非負整數，`0` 等同不限 |
| `max_concurrent_calls` | `6` | 每個 Agent 階段（審查、驗證、白箱測試生成、黑箱攻擊合成）同時進行的模型呼叫上限；設 `1` 即完全循序 |
| `max_file_bytes` | `1000000` | 單一原始碼檔案的大小上限（bytes），超過的檔案不分析並列入證據缺口（minified bundle、產生碼）。須為非負整數，`0`／`null` 等同預設 |
| `include` | `[]` | glob 清單，只分析相對於 `--target` 的路徑或檔名符合其一的檔案（例如 `["src/*"]`）；空清單＝全部。CLI `--include` 會整個覆蓋此清單 |
| `exclude` | `[]` | glob 清單，符合其一的檔案不分析（例如 `["tests/*", "vendor/*", "*.min.js"]`；`vendor` 也匹配整個目錄）；被排除的檔案不算證據缺口。CLI `--exclude` 會整個覆蓋 |
| `cache_dir` | `null`（關閉） | 回應快取目錄（不存在會建立）：可用的 live 回應以模型、設定（含端點：`api_base`、`aws_region_name`、`aws_profile_name`、`api_key_env`）與提示為 key 存成 JSON，之後相同的提示直接取用，不呼叫供應商、不扣 `max_model_calls`；報告「執行來源 ／ Execution Provenance」標為「真實（回應快取） ／ live (response cache)」。CLI `--cache-dir` 會覆蓋。CLI `--cache-only` 只從此快取（或 `--cache-dir`）取用、絕不呼叫供應商，也不重問；快取沒有的呼叫列為證據缺口（`hybrid` 改走模擬，`live` 以 exit 4 中止），沒有快取目錄時 `--cache-only` 是 exit 5；`mock` 模式不讀快取，`--cache-only` 沒有作用，CLI 會印出警告後照常執行。`--estimate` 搭配 `--cache-only` 時最大呼叫數不乘重問次數（不會重問）。目錄內是模型原始回應（可能引用待審程式碼），請比照報告保管 |
| `retry_invalid_output` | `1` | 模型回應無法使用（非 JSON、缺欄位、空回應）時再問幾次（提示會說明上次的問題）才記為 `invalid`；每次重問都是真實呼叫、計入 `max_model_calls`，報告「執行來源 ／ Execution Provenance」以「無法使用，已重問 ／ unusable, re-asked」列出。`null` 等同未設定（用預設值），`0` 關閉；須為 0–5 的整數 |
| `max_files` | `50` | 每次分析的原始碼檔案上限，超出的檔案列入證據缺口（判定不會是 `READY_TO_SHIP`）。須為非負整數，`0`／`null` 等同預設；負數或非整數啟動即報 `ConfigError`（exit 5） |
| `sandbox_provider` | `"local_subprocess"` | `local_subprocess`（本機子程序，**非安全邊界**）或 `docker`（一次性隔離容器）；其他值啟動即報錯 |
| `docker_image` | `"vibeharness-sandbox:latest"` | docker 沙盒映像，需預裝 `pytest`、`pytest-cov` 與目標的相依套件 |
| `docker_network` | `"none"` | 容器網路模式；`none` 全斷網。黑箱測試要打執行中的服務時需放行（例如 Linux 上的 `host`），但會降低隔離程度 |
| `docker_memory` | `"1g"` | 容器記憶體上限 |
| `docker_cpus` | `"2"` | 容器 CPU 上限 |
| `docker_pids_limit` | `256` | 容器程序數上限；≥ -1 的整數。`null` 與 `0` 都維持 256（Docker 會把 `--pids-limit 0` 當成不限制）；只有明確的 `-1` 才是不限制 |
| `sandbox_memory_mb` | `2048` | 僅 `local_subprocess`：以 `RLIMIT_AS` 限制 pytest 程序樹的位址空間（POSIX；Windows 無效），另加 CPU 時間上限（批次預算 + 10 秒）；不論此值為何，子程序寫出的單一檔案一律以 `RLIMIT_FSIZE` 限制在 64 MiB（超過的寫入得到 `OSError: [Errno 27]`，歸為無法正常執行而非缺陷）。`null` 維持 2048；只有明確的 `0` 才關閉。Node 沙盒不套 `RLIMIT_AS`（V8 啟動會失敗），改以 `--max-old-space-size=<值>` 封頂堆積、保留 CPU 上限。不是安全邊界，只是擋住失控的記憶體與 CPU 消耗；`docker` provider 改用 `docker_memory`／`docker_cpus` |
| `node_bin` | `"node"` | 執行 JS/TS 測試的 Node 可執行檔（名稱或路徑）；第一次需要時才偵測，需 ≥ 20（`.ts` 需 ≥ 22.6 的型別剝除）。找不到或版本過舊時 JS/TS 測試列為 ERROR 並寫入證據缺口，不會在啟動時失敗。白箱 JS/TS 行涵蓋率（`js_line_coverage_pct`）需 ≥ 20.11 或 ≥ 21.3（門檻是一起傳入的 `--disable-warning`；lcov 報告器本身 20.10／21.2 起就有），Node ≥ 22.5 另加 `--test-coverage-include`／`--test-coverage-exclude` 篩選，更舊時測試照跑、涵蓋率為 N/A；不需要額外設定 |
| `sandbox_node_provider` | `null` | JS/TS 測試的沙盒：`null` 跟隨 `sandbox_provider`；可單獨設 `local_subprocess`（本機 Node）或 `docker`（Node 容器，用映像檔自帶的 Node，主機不需要 node）。其他值在啟動時即報錯（exit 5） |
| `docker_node_image` | `"vibeharness-sandbox-node:latest"` | Node 容器映像（`docker/sandbox-node.Dockerfile`，node:22-slim）；容器內設 `NODE_PATH=/work/<目標>/node_modules`，只有 CommonJS 吃得到 |
| `sandbox_timeout_seconds` | `120` | 單批 pytest 的總逾時（秒），逾時會終止整個程序樹／移除容器。JS/TS 模組依序每 10 個一批，每批各有一份這個預算（每個模組在各自的 `node --test` 程序中，用這一批剩下的預算執行；Node 每個模組都要付一次啟動成本，所以預算隨模組數成長）。`null`／`0` 維持 120；負數或非整數是 `ConfigError`（exit 5） |
| `per_test_timeout_seconds` | `30` | 批次（Python 或 JS/TS）逾時後改為逐測重跑時，單一測試的逾時（秒），總時間仍受批次預算限制；也是 `mutation_timeout_seconds` 的預設值。`null`／`0` 維持 30；負數或非整數是 `ConfigError`（exit 5） |
| `mutation_testing` | `false` | 突變測試總開關（預設關閉）；CLI `--mutation`／`--no-mutation` 優先於此值。只支援 Python，完全離線、不呼叫模型 |
| `mutation_max_mutants` | `20` | 單次執行的變異體上限（≥ 1）；超過時截斷並列為證據缺口。CLI `--mutation-max-mutants` 可覆蓋 |
| `mutation_timeout_seconds` | 同 `per_test_timeout_seconds` | 每個變異體那一批沙盒的逾時（秒）；逾時視為殺死 |
| `mutation_min_score` | `70` | 分數（百分比，0–100）低於此值就列為證據缺口，不會造成 `NEEDS_FIXES` |
| `mutation_max_copy_mb` | `200` | 暫存複本的大小上限（MB，≥ 1）。複本略過與符號擷取相同的目錄（`SKIPPED_DIRS`、點開頭）、位元組碼與指向目錄的符號連結；超過上限就不執行並列為證據缺口。單一檔案目標會以所在目錄為工作目錄，特別容易碰到 |

### `execution_mode` 行為

| 值 | 行為 |
| :--- | :--- |
| `live` | 只呼叫真實模型。缺金鑰、模型定義缺 `api_key_env`、或呼叫失敗，立即擲出 `LLMGatewayError`（CLI 以 exit code 4 中止） |
| `hybrid`（預設） | 有金鑰就走真實 API；缺金鑰或呼叫失敗退回模擬引擎，並在報告的「執行來源 ／ Execution Provenance」標示 |
| `mock` | 全部使用模擬引擎（離線體驗工作流用；模擬輸出與目標程式碼無關，品質門禁不會給 `READY_TO_SHIP`） |

---

## `models` 區段

每個**鍵**是一個 `model_alias`（供 `agents` 區段的 `model_alias` 指向），每個別名可設：

| 欄位 | 必要 | 說明 |
| :--- | :--- | :--- |
| `model` | ✅ | [litellm model string](https://docs.litellm.ai/docs/providers)，例如 `"claude-sonnet-5-5"`、`"zai/glm-5.3"`、`"gemini/gemini-3.8-flash"`。建議用帶版本的 id 而非會漂移的別名（例如用 `deepseek/deepseek-v4-pro` 而非 `deepseek-chat`），供應商端換模型時才會反映在報告上 |
| `api_key_env` | live 模式必填 | 存放 API 金鑰的環境變數名稱；金鑰會明確傳給 litellm，因此即使 litellm 預設的環境變數名與 `api_key_env` 不同也能驗證。缺此欄位時 live 呼叫會擲出 `LLMGatewayError` |
| `fallback_model` | 選填 | 主模型在 `max_retries` 次重試後仍失敗時，改試這個 litellm model string **一次**；報告會記錄實際使用的模型 |
| `api_base` | 選填 | 自訂 API 端點（例如自架的 OpenAI 相容閘道 `https://llm-gateway.example.com/v1`，或本機 Ollama 的 `http://localhost:11434`）。**必須是 `https://`**；`http://` 只允許迴路位址（`localhost`／`127.0.0.1`／`::1`），其他一律在啟動時報 `ConfigError`（exit 5）。目標原始碼會送往這些端點，因此只接受明確允許的端點（OWASP LLM04:2026 供應鏈） |
| `aws_profile_name`／`aws_region_name` | 選填 | 以 AWS 憑證鏈驗證的模型（例如 `bedrock/...`）改用這兩欄取代 `api_key_env`：使用指定的 AWS profile（含 SSO）與區域；設定 profile 即視為具備 live 憑證 |
| `price_per_million_input`／`price_per_million_output` | 選填 | 每百萬 token 的價格（美元，非負數）；兩者都設定時 `--estimate` 會算出該模型的估計花費，否則只列 token 數。程式本身不會用它控管成本（請用 `max_model_calls`） |
| `extra_params` | 選填 | 原封不動傳給 litellm 的額外參數（mapping），例如 `{thinking: {type: disabled}}`、`{reasoning_effort: low}`，用來讓推理模型不要把輸出額度全花在思考；非 mapping 啟動即 `ConfigError`。保留鍵不可放進來（啟動即 `ConfigError`，exit 5）：端點與憑證 `api_base`、`base_url`、`api_key`、`api_version`、`custom_llm_provider`、`aws_*`（`aws_profile_name`、`aws_region_name`、`aws_access_key_id`、`aws_secret_access_key`、`aws_session_token`、`aws_bedrock_runtime_endpoint`、`aws_role_name`、`aws_web_identity_token`），以及 harness 自己設定的 `model`、`messages`、`timeout`、`request_timeout`、`num_retries`、`max_retries`、`fallbacks`、`stream`；否則就能繞過 `api_base` 的 https 檢查，把待審程式碼送到任意主機。輸出 token 上限 `max_tokens`、`max_completion_tokens`、`max_output_tokens` 也不行（會覆蓋 `max_output_tokens`，讓 `--estimate` 與快取 key 看錯上限）。litellm 的罐頭回應鍵 `mock_response`、`mock_tool_calls`、`mock_timeout`、`mock_delay` 也不行（完全不連網就回傳假答案，模擬的輸出會被記成 live 證據），`ssl_verify` 也不行（關掉 TLS 驗證會讓 https 檢查失去意義）。其他會改變目的地或憑證的 litellm 參數同樣保留：別名寫法（`apikey`、`token`）、路由（`model_list`、`deployment_id`、`engine`、`organization`、`use_litellm_proxy`、`custom_endpoint`、`sagemaker_base_url`、`deployment_url`）、可能覆寫 Authorization 的標頭（`extra_headers`、`headers`、`provider_specific_header`）、自備的用戶端（`client`、`shared_session`），以及雲端憑證與專案（`azure_ad_token`、`azure_ad_token_provider`、`azure_*`、`tenant_id`、`client_id`、`client_secret`、`vertex_project`、`vertex_location`、`vertex_credentials`、`vertex_ai_*`、`watsonx_*`、`project_id`、`account_id`、`oci_*`、`gigachat_*`、其餘的 `aws_*`）；任何以 `aws_`、`azure_`、`vertex_`、`oci_`、`watsonx_`、`gigachat_` 開頭，或名稱片段含 `api_key`、`token`、`secret`、`password`、`credential(s)`、`endpoint`、`url`、`base_url`、`proxy`、`header(s)` 的鍵也一律拒絕。端點請用 `api_base`，逾時與重試用 `global.timeout_seconds`／`max_retries`，輸出上限用 `max_output_tokens` |
| `max_output_tokens` | 選填 | 覆蓋 `global.max_output_tokens`（`null` 等同未設定，沿用全域值）。會思考的模型（GLM、DeepSeek、Gemini 3）的思考 token 也算在此上限內；太小時回應會是空的或被截斷，報告會標示「output truncated at the max_output_tokens limit」 |
| `provider` | 選填 | **僅供標註，程式不讀取**（實際路由完全由 litellm model string 決定） |

內建別名與預設值：

| 別名 | model | api_key_env | fallback_model |
| :--- | :--- | :--- | :--- |
| `claude` | `claude-sonnet-5-5` | `ANTHROPIC_API_KEY` | `claude-haiku-4-5-20251001` |
| `glm` | `zai/glm-5.3`（智譜 AI／Z.AI，litellm 的 `zai/` provider） | `ZAI_API_KEY` | `zai/glm-5.3-flash` |
| `deepseek` | `deepseek/deepseek-v4-pro` | `DEEPSEEK_API_KEY` | `deepseek/deepseek-v4-flash` |
| `gemini` | `gemini/gemini-3.8-flash` | `GEMINI_API_KEY` | `gemini/gemini-3.5-flash` |

> 註：`gemini-2.5-flash` 已不再供新申請的 Google API 金鑰使用，請使用 3.x 版本。
>
> 資料處理：目標原始碼會送往每個被 agent 指到的供應商（送出前已移除隱形 Unicode 字元，寫死的密鑰也已遮蔽為 `<REDACTED:kind>`），請只設定資料保留條款可接受的供應商。報告中每筆呼叫紀錄都帶有 `prompt_sha256`（system＋user 提示詞的 SHA-256），稽核時可把判定對回確切的輸入，而報告本身不必保存程式碼。

---

## `agents` 區段

每個**鍵**是一個 `agent_id`，可設：

| 欄位 | 預設值 | 說明 |
| :--- | :--- | :--- |
| `model_alias` | 無（解析為 `unconfigured`） | 指向 `models` 區段的別名；**這是實際生效的模型路由欄位**。缺少或指向不存在的別名時沒有模型也沒有金鑰：`hybrid` 以模擬引擎執行該 agent，`live` 擲出 `LLMGatewayError` |
| `temperature` | `0.2` | 取樣溫度（驗證投票類的 agent 建議 `0.0`）；須為 0–2 的數字（啟動時驗證） |
| `name` | — | `whitebox_reviewer_*`：審查者名稱，用於其提示詞與報告（「Identified by ...」）；其他 agent 僅供說明 |
| `focus` | — | `whitebox_reviewer_*`：審查焦點，**會放進該審查者的提示詞**（預設為「General correctness and security defects」） |
| `role` | — | 說明性欄位，程式不讀取 |

### 實際生效範圍（重要）

- **白箱審查者由設定檔決定**：所有以 `whitebox_reviewer_` 為前綴的條目都是審查者，各自使用自己的 `name`、`model_alias`、`temperature` 與 `focus`；**新增或刪除條目即改變審查陣容**。發現編號以模型別名前三碼為前綴（`WB-CLA-01`、`WB-DEE-01`、`WB-GLM-01`、`WB-GEM-01`）。審查者可選擇性回傳 `owasp_mapping`（例如 `LLM01:2026`、`API1:2023`），報告會標在該發現旁。若完全沒有 `whitebox_reviewer_*` 條目，白箱審查會跳過並列為證據缺口（判定不會是 `READY_TO_SHIP`）。
- **交叉驗證者是動態的**：所有以 `whitebox_verifier_` 為前綴的條目都會參與投票；**新增或刪除條目即增減該模型的票數**。每個 model alias 只投一票：路由到已經有驗證者的 alias 的第二個 verifier 條目會被略過並記警告（保留排序後的第一個 agent id）。每筆發現只由「沒有回報它」的模型投票（模型不評審自己的發現）；其他模型也回報過同一缺陷（去重合併時記錄）則算一票確認，但單靠佐證不會讓驗證「已套用」：沒有任何驗證者真正投下 confirm／reject 時，發現仍是未經驗證的假設（已確認數顯示 N/A）。
- 其餘 agent（測試生成、威脅建模、攻擊場景合成）由程式以固定 `agent_id` 呼叫，設定檔控制其模型與溫度。

### 現行 agent 一覽

| agent_id | 預設 `model_alias` | `temperature` | 職責 |
| :--- | :--- | :--- | :--- |
| `whitebox_reviewer_claude` | claude | 0.2 | 邏輯與狀態：深度邏輯邊界、未處理例外、狀態不一致、隱藏的 null／型別錯誤 |
| `whitebox_reviewer_deepseek` | deepseek | 0.1 | 安全與防禦：輸入清洗、注入（SQL／命令／路徑）、防禦性檢查、資源耗盡、不安全的並行 |
| `whitebox_reviewer_glm` | glm | 0.2 | 規格與契約：API 簽章遵守、業務規格一致性、契約違反、授權檢查（BOLA／BFLA） |
| `whitebox_reviewer_gemini` | gemini | 0.2 | AI 整合與供應鏈：呼叫模型的程式碼對照 OWASP Top 10 for LLM Applications 2026（LLM01–LLM10），以及寫死的憑證與未鎖版的相依套件 |
| `whitebox_verifier_claude`／`_deepseek`／`_glm`／`_gemini` | 各自同名模型 | 0.0 | 對非自家模型回報的發現投票：confirm／reject／unsure |
| `whitebox_test_generator` | deepseek | 0.3 | 針對確認缺陷生成可執行 pytest 測試 |
| `blackbox_threat_modeler` | claude | 0.2 | STRIDE、OWASP API 與（AI 整合型目標的）OWASP LLM 威脅建模 |
| `blackbox_test_synthesizer` | deepseek | 0.2 | 威脅場景轉黑箱攻擊腳本（BOLA、注入、限流、提示詞注入） |

---

## 常見設定範例

### 只有一組 API 金鑰（全部指向同一模型）

手上只有 Gemini 金鑰時，把 `agents` 區段中所有 `model_alias` 改成 `gemini` 即可跑 live 模式：

```yaml
agents:
  whitebox_reviewer_claude:
    model_alias: "gemini"      # 原為 claude
  whitebox_reviewer_deepseek:
    model_alias: "gemini"      # 原為 deepseek
  whitebox_reviewer_glm:
    model_alias: "gemini"      # 原為 deepseek
  whitebox_reviewer_gemini:
    model_alias: "gemini"      # 原本就是 gemini
  whitebox_verifier_claude:
    model_alias: "gemini"
  whitebox_verifier_deepseek:
    model_alias: "gemini"
  whitebox_verifier_glm:
    model_alias: "gemini"
  whitebox_verifier_gemini:
    model_alias: "gemini"
  whitebox_test_generator:
    model_alias: "gemini"      # 原為 deepseek
  blackbox_threat_modeler:
    model_alias: "gemini"      # 原為 claude
  blackbox_test_synthesizer:
    model_alias: "gemini"      # 原為 deepseek
```

> 註：只有單一模型家族時，**跨模型驗證無法執行**：所有發現都來自 `gemini`，而驗證者不評審自家模型的發現，因此沒有任何發現會得到投票（不會被過濾，共識率與已確認數都顯示 N/A；四個 verifier 條目都路由到 `gemini`，所以只保留第一個），終端機會警告「Fewer than two distinct reviewer models」，並列為證據缺口（判定不會是 `READY_TO_SHIP`）。四位審查者仍會各自依不同的 `focus` 審查，但同一顆模型的多份副本彼此同意只是一致，不是佐證（OWASP LLM07:2026）。

### 改用 Docker 沙盒

```yaml
global:
  sandbox_provider: "docker"
  docker_image: "vibeharness-sandbox:latest"   # 需先 docker build -t ... -f docker/sandbox.Dockerfile .
  docker_node_image: "vibeharness-sandbox-node:latest"   # 目標含 JS/TS 時：docker build -t ... -f docker/sandbox-node.Dockerfile .
  docker_network: "none"                        # 黑箱打執行中服務時改 "host"（Linux）
  docker_memory: "1g"
  docker_cpus: "2"
  docker_pids_limit: 256
```

### 新增自訂模型並指派給 agent

```yaml
models:
  my_model:
    model: "openai/qwen2.5-72b-instruct"   # 任何 litellm 支援的字串（此例為 OpenAI 相容端點）
    api_key_env: "MY_API_KEY"
    api_base: "https://llm-gateway.example.com/v1"   # 必須是 https（http 只限 localhost）
    fallback_model: "openai/qwen2.5-32b-instruct"   # 沿用同一組 api_key_env 與 api_base

agents:
  whitebox_reviewer_claude:
    model_alias: "my_model"
```

### 新增第五位審查者

任何新的 `whitebox_reviewer_*` 條目都會加入審查陣容，其 `focus` 直接放進它的提示詞。若希望該模型也對其他審查者的發現投票，再加一個對應的 `whitebox_verifier_*` 條目：

```yaml
agents:
  whitebox_reviewer_local:
    name: "Concurrency Reviewer (local Qwen)"
    model_alias: "my_model"
    temperature: 0.1
    focus: "Race conditions, lock ordering, async cancellation and shared mutable state"
  whitebox_verifier_local:
    model_alias: "my_model"
    temperature: 0.0
```

agent 沒有 `model_alias`，或 `model_alias` 指向 `models` 區段不存在的別名時，會解析為 `unconfigured`（沒有模型也沒有金鑰）：`hybrid` 改用模擬引擎並在報告中標示，`live` 直接擲出 `LLMGatewayError`（exit 4）。絕不會默默改走其他供應商——請確認別名拼寫一致。

---

## 相關檔案：`vibeharness/config/threat_rules.yaml`

威脅建模器會把 `vibeharness/config/threat_rules.yaml` 中的少數欄位當作提示詞指引讀取；其餘內容（`code`、`target_components`、`cwe`、`atlas_tactics` 等）僅供說明，修改不影響執行。

| 區段 | 程式讀取的欄位 | 使用時機 |
| :--- | :--- | :--- |
| `stride_categories.<key>` | `name`／`common_vibe_bugs` | 一律使用（`description` 僅供說明，不進提示詞） |
| `owasp_api_top10[*]` | `id`／`name` | 一律使用；id 供 `owasp_mapping` 引用 |
| `owasp_llm_top10_2026[*]` | `id`／`name`／`common_vibe_bugs`／`atlas_techniques` | 僅在目標匯入 AI／LLM SDK（`openai`、`anthropic`、`litellm`、`langchain`、`transformers`、`@ai-sdk/*` 等）時使用；由確定性規則偵測，並在報告中列為 `ai_components` |

`owasp_llm_top10_2026` 列出 OWASP Top 10 for LLM Applications 2026 的 LLM01:2026 至 LLM10:2026。威脅建模器會被要求以這些 id 填 `owasp_mapping`、以所列的 MITRE ATLAS 技術 id 填 `atlas_mapping`（顯示在報告的 MITRE ATLAS 欄）。`cwe` 與 `atlas_tactics` 取自 2026 文件附錄 A 的對照表（ATLAS 內容 v2026.06，戰術層級）；`atlas_techniques` 則是本工具自訂的技術層級對照，已比對 ATLAS 內容 2026.07 版。
