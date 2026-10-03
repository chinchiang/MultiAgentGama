# 🛡️ VibeHarness-MAS: Multi-Agent Testing Harness for Vibe Coding

[![tests](https://github.com/chinchiang/MultiAgentGama/actions/workflows/tests.yml/badge.svg)](https://github.com/chinchiang/MultiAgentGama/actions/workflows/tests.yml)

> **先白箱（異構模型交叉評議 + 可執行測試驗證）後黑箱（STRIDE/OWASP 威脅建模驅動的攻擊測試）的 AI 軟體品質保證工具包。**

針對當前 **Vibe Coding（自然語言提示驅動編程）** 容易產生「表面看似可行（Happy Path 通過），內部缺乏防禦邊界、存在 BOLA/IDOR 與未捕獲異常」的特點設計。

---

## 🏛️ 系統架構圖 (Architecture Overview)

```
                       ┌──────────────────────────────────────────────┐
                       │      總指揮官 Harness (Commander Agent)       │
                       └──────────────────────┬───────────────────────┘
                                              │
                     ┌────────────────────────┴────────────────────────┐
                     ▼                                                 ▼
      ┌─────────────────────────────┐                   ┌─────────────────────────────┐
      │  階段一：白箱異構多模型審查  │                   │  階段二：黑箱威脅建模與穿透  │
      ├─────────────────────────────┤                   ├─────────────────────────────┤
      │ • Claude: 深度邏輯與狀態     │                   │ • 資產邊界與數據流解析     │
      │ • Nemotron: 防禦護欄與記憶體 │                   │ • STRIDE 矩陣與 OWASP Top 10│
      │ • ChatGPT: API規格與合約    │                   │ • 威脅轉化為自動化攻擊腳本  │
      │ • 交叉驗證: 非作者模型投票  │                   │ • 執行攻擊測試驗證防禦      │
      └──────────────┬──────────────┘                   └──────────────┬──────────────┘
                     │                                                 │
                     └────────────────────────┬────────────────────────┘
                                              ▼
                               ┌─────────────────────────────┐
                               │  沙盒：本機子程序 / Docker   │
                               │  (Pytest / 暫存目錄 / 逾時)  │
                               └──────────────┬──────────────┘
                                              ▼
                               ┌─────────────────────────────┐
                               │   品管門禁與最終審計報告     │
                               │  (vibe_harness_report.md)   │
                               └─────────────────────────────┘
```

---

## 🚀 核心特性

1. **AI Harness 總指揮官**：掌控全域狀態機，自動依序調度白箱與黑箱各子 Agent，並執行最後的品質閘門（Quality Gate）仲裁。
2. **多模型異構消除偏差（De-biasing）**：白箱審查階段可平行指派至不同權重體系的 LLM：
   - **Claude**：專精複雜邊界條件、非空指針假設與狀態機漏洞。
   - **NVIDIA Nemotron**：專精輸入清洗、資源消耗上限（DoS 防禦）與記憶體安全護欄。
   - **ChatGPT**：專精 API 協定契約遵守、規範一致性與通用測試案例合成。
   - **交叉驗證（Cross-Model Verification）**：不設單一仲裁模型。每筆發現由「沒有回報它」的其他模型各自獨立判定 confirm／reject／unsure，模型不會評審自己的發現；其他模型也回報了同一缺陷（去重合併時記錄）則算一票確認。確認票多於否決票即確認、否決票較多列為爭議（不生成測試）、同票則保留交給測試決定。共識率依實際票數計算。沒有任何真實有效的票時不過濾任何發現，報告標示為 N/A。
3. **黑箱強制威脅建模先行（Threat-Modeling First）**：拒絕盲目暴力測試，先依據 STRIDE（S 仿冒、T 竄改、R 否認、I 資訊洩漏、D 拒絕服務、E 越權）與 OWASP API Security Top 10 建立攻擊矩陣，再針對性生成攻擊測試。
4. **以執行結果為準的品質閘門**：模型發現與威脅僅是假設；只有實際執行的測試能讓閘門失敗或封鎖。無斷言的空測試、無效的模型輸出（非 JSON／缺欄位，記錄為 `invalid`）、未測試的威脅都列為證據缺口。
5. **兩種沙盒**：生成的測試在暫存目錄中執行，環境變數採白名單（不傳入 API 金鑰），每批與每個測試都有逾時，逾時會終止整個程序樹（Docker 則移除容器）。
   - `local_subprocess`（預設）：本機子程序。
   - `docker`：每批測試在一次性容器中執行——預設無網路、根檔案系統與目標目錄唯讀、移除所有 capabilities、禁止提權、非 root 使用者、記憶體／CPU／程序數上限。只有該次執行的暫存目錄可寫。

> ⚠️ **`local_subprocess` 不是安全邊界。** 它以你的使用者權限執行模型生成的程式碼，可讀寫檔案與存取網路。對不信任的目標或 live 模式，請使用 `sandbox_provider: docker`。

### 🧭 尚未實作（規劃中）

| 功能 | 現況 |
| :--- | :--- |
| 突變測試（Mutation Testing） | 未實作；目前以行覆蓋率（pytest-cov）衡量白箱測試 |
| 動態 DAST／Fuzzing 代理 | 未實作；黑箱測試由威脅模型逐項生成 pytest 攻擊腳本 |
| Hypothesis 性質測試 | 未內建；模型可自行生成，但需目標環境已安裝 `hypothesis` |
| `e2b` 沙盒 | 未實作；`sandbox_provider` 支援 `local_subprocess` 與 `docker`，其他值會直接報錯 |
| JS/TS 測試執行 | 僅做啟發式符號擷取供審查與威脅建模；生成與執行的測試只支援 Python |

---

## 📦 目錄結構

```text
MultiAgentGama/
├── config/
│   ├── agents_config.yaml       # 多模型路由 (Claude, Nemotron, ChatGPT)
│   └── threat_rules.yaml        # STRIDE 與 OWASP 基準規則
├── docker/
│   └── sandbox.Dockerfile       # docker 沙盒的基底映像（pytest / pytest-cov）
├── core/
│   ├── harness.py               # 指揮官狀態機 (Commander Orchestrator)
│   ├── llm_gateway.py           # 統一 LiteLLM 閘道與模擬回退引擎
│   ├── models.py                # Pydantic 數據模型
│   ├── codecheck.py             # 生成測試的靜態檢查（需有 test_ 函式與斷言）
│   ├── codecontext.py           # 提供給模型的原始碼與 import 指引
│   └── sandbox.py               # 沙盒：本機子程序（非安全邊界）與 Docker 容器
├── agents/
│   ├── whitebox/
│   │   ├── ast_extractor.py     # AST 符號解析與路由提取
│   │   ├── multi_reviewer.py    # 異構模型評議 (Ensemble)
│   │   ├── deduplicator.py      # 合併多個模型回報的同一缺陷
│   │   ├── debater.py           # 交叉驗證：由非作者模型投票判定
│   │   └── test_generator.py    # 單元/邊界測試自動生成
│   └── blackbox/
│       ├── threat_modeler.py    # STRIDE 威脅建模引擎
│       └── scenario_builder.py  # 威脅轉化可執行攻擊腳本
├── runners/
│   └── test_executor.py         # 沙盒 Pytest 執行器與 PoC 抓取
├── reports/
│   └── report_generator.py      # Markdown 審計報告生成器
├── examples/
│   └── vibe_sample_app.py       # 具代表性的 Vibe-Coding 典型缺陷範例
├── docs/
│   └── sample_report.md         # mock 模式產生的範例報告
├── tests/                       # 工具包本身之測試（離線、不需 API 金鑰）
└── main.py                      # CLI 執行入口
```

---

## 🛠️ 快速開始

### 1. 安裝依賴

```bash
pip install -r requirements.txt
```

或安裝為套件（會一併註冊 `vibeharness` 指令）：

```bash
pip install .
vibeharness --version
```

### 2. 設定 API 金鑰（可選）

工具包支援真實 API 調用與本機模擬模式（Hybrid Mode）：

```bash
# 若要使用即時模型：
export ANTHROPIC_API_KEY="sk-ant-..."
export NVIDIA_API_KEY="nvapi-..."
export OPENAI_API_KEY="sk-..."
export GEMINI_API_KEY="AIza..."
```
預設模型見 `config/agents_config.yaml`（Claude `claude-sonnet-5`、Nemotron 經 NVIDIA NIM、ChatGPT `gpt-4o`、Gemini `gemini/gemini-3.8-flash`），每個模型可設定 `fallback_model`，主模型重試失敗後會改用它，報告會記錄實際使用的模型。

任何 agent 都可透過 `model_alias` 指向任一已定義的模型。手上只有一組金鑰也能跑 live 模式——例如只有 Gemini key 時，把 `agents` 區段中所有 `model_alias` 改成 `gemini` 即可（註：`gemini-2.5-flash` 已不再供新申請的 Google API 金鑰使用，請使用 3.x 版本）。

*註：若未配置 API 金鑰，`hybrid` 模式會退回模擬引擎（Simulation Engine）以便離線體驗工作流。模擬引擎回傳的是**與目標程式碼無關的固定範本**，報告會以 `[SIMULATED]` 與「Execution Provenance」表明確標示，且品質閘門不會因此給出 `READY_TO_SHIP`。*

| `--mode` | 行為 |
| :--- | :--- |
| `live` | 只呼叫真實模型；缺金鑰或呼叫失敗即中止（exit code 4）。模型回應無法使用時記錄為 `invalid`，判定為 INCONCLUSIVE |
| `hybrid`（預設） | 能呼叫就呼叫，否則退回模擬並在報告中標示 |
| `mock` | 全部使用模擬引擎 |

模擬模式下，白箱測試改用由目標函式自動推導的 None 輸入健壯性探針（`WB-PROBE-*`）；黑箱威脅若無可執行測試，會列為「Threats Not Tested」，不會捏造測試結果。

### 3. 使用 Docker 沙盒（建議用於不信任的目標）

```bash
docker build -t vibeharness-sandbox:latest -f docker/sandbox.Dockerfile .
```

在 `config/agents_config.yaml` 設定 `sandbox_provider: "docker"`。可調整 `docker_image`、`docker_network`、`docker_memory`、`docker_cpus`、`docker_pids_limit`。

- 目標目錄以唯讀方式掛載到容器內的 `/work/<目錄名>`；生成測試中的主機絕對路徑會自動改寫為容器路徑。
- 容器預設**沒有網路**，無法在執行時安裝套件。目標的相依套件需預先裝進映像：以 `FROM vibeharness-sandbox:latest` 建立專案專用映像並 `pip install` 相依套件，再把 `docker_image` 指向它。
- 黑箱測試若要打正在執行的服務，需開放網路（例如 Linux 上 `docker_network: "host"`），這會降低隔離程度。
- 找不到 docker 指令或映像時會直接報錯並提示建置指令，不會默默退回本機子程序。

### 4. 對目標專案執行全流程檢驗

```bash
python main.py --target examples --output vibe_harness_report.md
```

`--target` 可為目錄或單一檔案。若目標服務正在 `--base-url` 上執行，黑箱測試會發送真實 HTTP 請求；否則以 in-process 方式直接 import 目標呼叫。範例輸出見 [`docs/sample_report.md`](docs/sample_report.md)。

報告格式可用 `--format md`（預設）或 `--format json`（機器可讀，含完整的 findings、威脅模型與測試結果，適合接 CI/CD）：

```bash
python main.py --target examples --output report.json --format json
```

Exit code（依序判定）：

| Code | Verdict | 條件 |
| :--- | :--- | :--- |
| `2` | BLOCKED_CRITICAL_RISK | 至少一個黑箱攻擊測試確認防禦被突破 |
| `1` | NEEDS_FIXES | 至少一個白箱測試失敗（暴露缺陷） |
| `3` | INCONCLUSIVE | 無失敗，但有證據缺口：使用模擬引擎、模型輸出無效、測試錯誤／未執行、威脅未測試、檔案解析失敗等 |
| `0` | READY_TO_SHIP | 以上皆無 |
| `4` | — | live 模式模型呼叫失敗 |

### 5. 運行工具包本身單元測試與靜態檢查

```bash
pip install -r requirements-dev.txt
python -m pytest
python -m ruff check .
```

可選：安裝 [pre-commit](https://pre-commit.com/) 讓每次 `git commit` 前自動執行 ruff 檢查：

```bash
pip install pre-commit
pre-commit install
```
