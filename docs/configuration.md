# 設定檔參考（agents_config.yaml）

[English](configuration.en.md) ｜ 正體中文（臺灣）

本文完整說明 `config/agents_config.yaml` 的每一個欄位：語義、預設值與實際生效範圍（以程式碼行為為準）。

設定檔分三大區段：**`global`**（執行與沙盒參數）、**`models`**（模型提供者定義）、**`agents`**（各 Agent 的模型路由）。找不到設定檔或 YAML 損壞會直接報錯（`ConfigError`，CLI 以 exit code 5 中止），不會默默用空設定執行。

CLI 啟動時可用 `--config <路徑>` 改用其他設定檔、`--mode` 覆蓋 `execution_mode`（優先序：CLI `--mode` ＞ `global.execution_mode` ＞ 預設 `hybrid`）；`--max-files`、`--max-model-calls` 同樣覆蓋對應的 `global` 欄位。

---

## `global` 區段

| 欄位 | 預設值 | 說明 |
| :--- | :--- | :--- |
| `execution_mode` | `"hybrid"` | `live`／`hybrid`／`mock` 三選一，行為見下方表格；其他值啟動即報錯 |
| `timeout_seconds` | `60` | 單次 LLM 請求的逾時（秒），傳給 litellm |
| `max_retries` | `2` | litellm 層級的重試次數（同一主模型重試；全部失敗後才會嘗試 `fallback_model` 一次） |
| `max_output_tokens` | `4096` | 單次模型回應的 token 上限 |
| `max_model_calls` | `null`（不限） | 成本護欄：每次執行最多幾次真實模型呼叫（同一次呼叫內 litellm 的重試與 `fallback_model` 不另計）。用完後 `hybrid` 改走模擬引擎、列為證據缺口（判定不會是 `READY_TO_SHIP`）；`live` 直接擲出 `LLMGatewayError`（exit 4）。須為非負整數，`0` 等同不限 |
| `max_concurrent_calls` | `6` | 每個 Agent 階段（審查、驗證、白箱測試生成、黑箱攻擊合成）同時進行的模型呼叫上限；設 `1` 即完全循序 |
| `max_files` | `50` | 每次分析的原始碼檔案上限，超出的檔案列入證據缺口（判定不會是 `READY_TO_SHIP`） |
| `sandbox_provider` | `"local_subprocess"` | `local_subprocess`（本機子程序，**非安全邊界**）或 `docker`（一次性隔離容器）；其他值啟動即報錯 |
| `docker_image` | `"vibeharness-sandbox:latest"` | docker 沙盒映像，需預裝 `pytest`、`pytest-cov` 與目標的相依套件 |
| `docker_network` | `"none"` | 容器網路模式；`none` 全斷網。黑箱測試要打執行中的服務時需放行（例如 Linux 上的 `host`），但會降低隔離程度 |
| `docker_memory` | `"1g"` | 容器記憶體上限 |
| `docker_cpus` | `"2"` | 容器 CPU 上限 |
| `docker_pids_limit` | `256` | 容器程序數上限 |
| `sandbox_timeout_seconds` | `120` | 單批 pytest 的總逾時（秒），逾時會終止整個程序樹／移除容器 |
| `per_test_timeout_seconds` | `30` | 批次逾時後改為逐測重跑時，單一測試的逾時（秒） |

### `execution_mode` 行為

| 值 | 行為 |
| :--- | :--- |
| `live` | 只呼叫真實模型。缺金鑰、模型定義缺 `api_key_env`、或呼叫失敗，立即擲出 `LLMGatewayError`（CLI 以 exit code 4 中止） |
| `hybrid`（預設） | 有金鑰就走真實 API；缺金鑰或呼叫失敗退回模擬引擎，並在報告的 Execution Provenance 標示 |
| `mock` | 全部使用模擬引擎（離線體驗工作流用；模擬輸出與目標程式碼無關，品質門禁不會給 `READY_TO_SHIP`） |

---

## `models` 區段

每個**鍵**是一個 `model_alias`（供 `agents` 區段的 `model_alias` 指向），每個別名可設：

| 欄位 | 必要 | 說明 |
| :--- | :--- | :--- |
| `model` | ✅ | [litellm model string](https://docs.litellm.ai/docs/providers)，例如 `"claude-sonnet-5"`、`"nvidia_nim/nvidia/nemotron-4-340b-instruct"`、`"gemini/gemini-3.8-flash"` |
| `api_key_env` | live 模式必填 | 存放 API 金鑰的環境變數名稱；金鑰會明確傳給 litellm，因此即使 litellm 預設的環境變數名不同（如 NVIDIA NIM）也能驗證。缺此欄位時 live 呼叫會擲出 `LLMGatewayError` |
| `fallback_model` | 選填 | 主模型在 `max_retries` 次重試後仍失敗時，改試這個 litellm model string **一次**；報告會記錄實際使用的模型 |
| `api_base` | 選填 | 自訂 API 端點（例如 NVIDIA NIM 的 `https://integrate.api.nvidia.com/v1`） |
| `provider` | 選填 | **僅供標註，程式不讀取**（實際路由完全由 litellm model string 決定） |

內建別名與預設值：

| 別名 | model | api_key_env | fallback_model |
| :--- | :--- | :--- | :--- |
| `claude` | `claude-sonnet-5` | `ANTHROPIC_API_KEY` | `claude-haiku-4-5-20251001` |
| `nemotron` | `nvidia_nim/nvidia/nemotron-4-340b-instruct` | `NVIDIA_API_KEY` | `nvidia_nim/meta/llama-3.3-70b-instruct` |
| `chatgpt` | `gpt-4o` | `OPENAI_API_KEY` | `gpt-4o-mini` |
| `gemini` | `gemini/gemini-3.8-flash` | `GEMINI_API_KEY` | `gemini/gemini-3.5-flash` |

> 註：`gemini-2.5-flash` 已不再供新申請的 Google API 金鑰使用，請使用 3.x 版本。

---

## `agents` 區段

每個**鍵**是一個 `agent_id`，可設：

| 欄位 | 預設值 | 說明 |
| :--- | :--- | :--- |
| `model_alias` | `"chatgpt"` | 指向 `models` 區段的別名；**這是實際生效的模型路由欄位** |
| `temperature` | `0.2` | 取樣溫度（驗證投票類的 agent 建議 `0.0`） |
| `name` | — | 說明性欄位，目前程式不讀取（提示詞中的 Agent 名稱寫死在程式碼） |
| `role`／`focus` | — | 說明性欄位，目前程式不讀取（reviewer 的審查焦點寫死在程式碼） |

### 實際生效範圍（重要）

- **白箱審查者名單固定三位**（`whitebox_reviewer_claude`、`whitebox_reviewer_nemotron`、`whitebox_reviewer_chatgpt`）：設定檔可改派其 `model_alias` 與 `temperature`，但無法透過設定檔新增或移除審查者。
- **交叉驗證者是動態的**：所有以 `whitebox_verifier_` 為前綴的條目都會參與投票；**新增或刪除條目即增減該模型的票數**。每筆發現只由「沒有回報它」的模型投票（模型不評審自己的發現）；其他模型也回報過同一缺陷（去重合併時記錄）則算一票確認。
- 其餘 agent（測試生成、威脅建模、攻擊場景合成）由程式以固定 `agent_id` 呼叫，設定檔控制其模型與溫度。

### 現行 agent 一覽

| agent_id | 預設 `model_alias` | `temperature` | 職責 |
| :--- | :--- | :--- | :--- |
| `whitebox_reviewer_claude` | claude | 0.2 | 深度邏輯邊界、未處理例外、狀態不一致 |
| `whitebox_reviewer_nemotron` | nemotron | 0.1 | 輸入清洗、資源上限、記憶體安全護欄 |
| `whitebox_reviewer_chatgpt` | chatgpt | 0.2 | API 契約遵守、規格一致性、測試案例合成 |
| `whitebox_verifier_claude`／`_nemotron`／`_chatgpt` | 各自同名模型 | 0.0 | 對非自家模型回報的發現投票：confirm／reject／unsure |
| `whitebox_test_generator` | chatgpt | 0.3 | 針對確認缺陷生成可執行 pytest 測試 |
| `blackbox_threat_modeler` | claude | 0.2 | STRIDE 與 OWASP 威脅建模 |
| `blackbox_test_synthesizer` | chatgpt | 0.2 | 威脅場景轉黑箱攻擊腳本（BOLA、注入、限流） |

---

## 常見設定範例

### 只有一組 API 金鑰（全部指向同一模型）

手上只有 Gemini 金鑰時，把 `agents` 區段中所有 `model_alias` 改成 `gemini` 即可跑 live 模式：

```yaml
agents:
  whitebox_reviewer_claude:
    model_alias: "gemini"      # 原為 claude
  whitebox_reviewer_nemotron:
    model_alias: "gemini"      # 原為 nemotron
  whitebox_reviewer_chatgpt:
    model_alias: "gemini"      # 原本就是 chatgpt -> 改成 gemini
  whitebox_verifier_claude:
    model_alias: "gemini"
  whitebox_verifier_nemotron:
    model_alias: "gemini"
  whitebox_verifier_chatgpt:
    model_alias: "gemini"
  whitebox_test_generator:
    model_alias: "gemini"
  blackbox_threat_modeler:
    model_alias: "gemini"
  blackbox_test_synthesizer:
    model_alias: "gemini"
```

> 註：所有 agent 指向同一顆模型時，「多模型去偏」與「跨模型驗證」的獨立性會下降（同一顆模型審查並驗證自己的發現），報告的共識率解讀時請留意。

### 改用 Docker 沙盒

```yaml
global:
  sandbox_provider: "docker"
  docker_image: "vibeharness-sandbox:latest"   # 需先 docker build -t ... -f docker/sandbox.Dockerfile .
  docker_network: "none"                        # 黑箱打執行中服務時改 "host"（Linux）
  docker_memory: "1g"
  docker_cpus: "2"
  docker_pids_limit: 256
```

### 新增自訂模型並指派給 agent

```yaml
models:
  my_model:
    model: "openai/qwen2.5-72b-instruct"   # 任何 litellm 支援的字串
    api_key_env: "MY_API_KEY"
    api_base: "https://my-endpoint.example.com/v1"
    fallback_model: "openai/gpt-4o-mini"

agents:
  whitebox_reviewer_claude:
    model_alias: "my_model"
```

找不到 `model_alias` 指向的別名時，該 agent 會退回預設模型（`gpt-4o`）與預設溫度（`0.2`），並在 live 模式因缺金鑰而報錯——請確認別名拼寫一致。
