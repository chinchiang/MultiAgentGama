# 🛡️ VibeHarness-MAS: Multi-Agent Testing Harness for Vibe Coding

正體中文（臺灣）｜ [English (US)](README.en.md)

[![tests](https://github.com/chinchiang/MultiAgentGama/actions/workflows/tests.yml/badge.svg)](https://github.com/chinchiang/MultiAgentGama/actions/workflows/tests.yml)

> **先白箱（異構模型交叉評議 + 可執行測試驗證）後黑箱（STRIDE/OWASP 威脅建模驅動的攻擊測試）的 AI 軟體品質保證工具包。**

針對當前 **Vibe Coding（自然語言提示驅動編程）** 容易產生「表面看似可行（Happy Path 通過），內部缺乏防禦邊界、存在 BOLA/IDOR 與未捕獲異常」的特點設計。

---

## 🏛️ 系統架構與流程 (Architecture Overview)

`vibeharness/core/harness.py` 以六個線性階段依序調度各子 Agent（沒有狀態機的分支或回退）。所有模型呼叫都經 `vibeharness/core/llm_gateway.py`；所有讀取目標程式碼的 Agent 都先經 `vibeharness/core/sanitize.py` 的不受信任程式碼通道。

```mermaid
flowchart TD
    CLI["main.py CLI<br/>--target / --mode / --desc / --base-url<br/>--format / --sarif / --max-files / --max-model-calls"] --> CMD["🧠 總指揮官 Commander<br/>vibeharness/core/harness.py（六階段線性流程）"]
    CMD --> AST["階段 1・符號擷取<br/>ast_extractor.py（Python 用 AST；JS/TS 用 lexer）"]
    AST --> SAST["階段 1・確定性 AI 安全規則<br/>ai_static_scanner.py（VH-AI-001～009）<br/>並偵測 ai_components"]

    GW["LLM 閘道 llm_gateway.py<br/>LiteLLM 路由、fallback_model、模擬回退<br/>max_model_calls、max_concurrent_calls、call_log"]
    SAN["不受信任程式碼通道 sanitize.py<br/>去隱形字元／遮蔽密鑰／&lt;untrusted_target_code&gt;<br/>所有讀取目標程式碼的 Agent 都經過"]

    subgraph WB ["階段 2–3・白箱：多模型評議 → 交叉驗證 → 沙盒實測（模型呼叫平行）"]
        R1["邏輯與狀態審查<br/>Claude"]
        R2["防禦與資源審查<br/>DeepSeek"]
        R3["規格與合約審查<br/>GLM"]
        R4["AI 整合與供應鏈審查<br/>Gemini（OWASP LLM Top 10 2026）"]
        DEDUP["去重合併<br/>deduplicator.py"]
        DEB["交叉驗證：非作者模型投票<br/>confirm / reject / unsure"]
        GEN["白箱測試生成 test_generator.py<br/>無效測試自癒重試 2 次；<br/>無可用測試時補 WB-PROBE 探針"]
        SBX["沙盒執行（含行覆蓋率）<br/>test_executor.py → local_subprocess / docker"]
        R1 --> DEDUP
        R2 --> DEDUP
        R3 --> DEDUP
        R4 --> DEDUP
        DEDUP --> DEB
        DEB -- "確認＋同票保留" --> GEN --> SBX
    end

    AST --> SAN
    SAN --> R1
    SAN --> R2
    SAN --> R3
    SAN --> R4
    SAN --> DEB
    SAN --> GEN

    subgraph BB ["階段 4–5・黑箱：威脅建模驅動的攻擊測試（模型呼叫平行）"]
        TM["STRIDE / OWASP API／LLM 威脅建模<br/>（+ MITRE ATLAS 對應）threat_modeler.py<br/>符號分批送審、跨批次去重"]
        ATK["攻擊腳本生成<br/>scenario_builder.py"]
        BEX["黑箱測試執行<br/>test_executor.py → 同一沙盒；HTTP / in-process"]
        TM --> ATK --> BEX
    end

    AST -- "路由與符號" --> TM
    SAST -- "ai_components" --> TM
    CLI -- "--desc" --> TM
    SAN --> TM
    SAN --> ATK

    GATE["階段 6・品質門禁<br/>READY_TO_SHIP / NEEDS_FIXES /<br/>INCONCLUSIVE / BLOCKED_CRITICAL_RISK"]
    SAST --> GATE
    SBX --> GATE
    BEX --> GATE
    GW -- "call_log：模擬、invalid、預算用盡" --> GATE
    GATE --> OUT["審計報告 report_generator.py<br/>md / json / SARIF"]

    WB -. "所有模型呼叫" .-> GW
    BB -. "所有模型呼叫" .-> GW
```

### 🤖 各 Agent 分工

每個 Agent 的模型與提示詞都定義在 [`vibeharness/config/agents_config.yaml`](vibeharness/config/agents_config.yaml)，可自由改派模型；白箱審查者由設定檔中所有 `whitebox_reviewer_*` 項目組成（名稱、模型與 `focus` 都會帶入提示詞），新增或刪除項目即可調整評議陣容（欄位細節見 [docs/configuration.md](docs/configuration.md)）：

| 子 Agent（agent_id） | 預設模型 | 職責 | temperature |
| :--- | :--- | :--- | :--- |
| 邏輯與狀態審查（`whitebox_reviewer_claude`） | claude | 深度邏輯邊界、未處理例外、狀態不一致、空指標／型別缺陷 | 0.2 |
| 防禦與資源審查（`whitebox_reviewer_deepseek`） | deepseek | 輸入清洗、注入（SQL／命令／路徑）、防禦護欄、資源耗盡、並行安全 | 0.1 |
| 規格與合約審查（`whitebox_reviewer_glm`） | glm | API 簽章合規、業務規格、契約違反、授權檢查（BOLA／BFLA） | 0.2 |
| AI 整合與供應鏈審查（`whitebox_reviewer_gemini`） | gemini | 依 OWASP Top 10 for LLM Applications 2026 審查呼叫模型的程式（LLM01～LLM08、LLM10）：提示注入、提示／日誌中的密鑰、工具越權、模型與套件供應鏈、無上限消耗、未驗證的模型輸出；另查寫死的憑證與未固定版本的第三方依賴 | 0.2 |
| 交叉驗證投票（`whitebox_verifier_*` ×4） | claude／deepseek／glm／gemini | 只對「別的模型」回報的發現投票：confirm／reject／unsure；每個 model alias 只投一票（同一 alias 的第二個驗證者會被略過） | 0.0 |
| 白箱測試生成器（`whitebox_test_generator`） | deepseek | 針對確認缺陷生成可執行的 pytest 測試 | 0.3 |
| STRIDE 威脅建模師（`blackbox_threat_modeler`） | claude | 擷取信任邊界與資產、建立 STRIDE＋OWASP（API；AI 目標另加 LLM Top 10 2026）攻擊矩陣，並標註 MITRE ATLAS 技術 | 0.2 |
| 攻擊場景合成器（`blackbox_test_synthesizer`） | deepseek | 把威脅場景轉成黑箱攻擊腳本（BOLA、注入、限流、提示注入） | 0.2 |

---

## 🚀 核心特性

1. **AI Harness 總指揮官**：以六個線性階段依序調度白箱與黑箱各子 Agent，並執行最後的品質閘門（Quality Gate）仲裁。
2. **多模型異構消除偏差（De-biasing）**：白箱審查階段平行指派至四個不同模型家族的 LLM，彼此的盲點不重疊：
   - **Claude**：專精複雜邊界條件、非空指針假設與狀態機漏洞。
   - **DeepSeek**：專精輸入清洗、注入、資源消耗上限（DoS 防禦）與並行安全護欄。
   - **GLM**：專精 API 協定契約遵守、規範一致性與授權檢查（BOLA／BFLA）。
   - **Gemini**：專精 AI／LLM 整合安全——依 OWASP Top 10 for LLM Applications 2026 檢查呼叫模型的程式：不受信任輸入拼進提示詞（LLM01）、提示／日誌中的密鑰（LLM02／LLM08）、工具或 Agent 無允許清單（LLM03）、未固定或不安全載入的模型與套件（LLM04／LLM05）、無上限的 token 與花費（LLM06）、模型輸出未驗證即採信（LLM07）或流入 eval／exec／shell／SQL／HTML（LLM10）；LLM09 向量弱點未列入審查焦點。審查者可在發現上標註 `owasp_mapping`（例如 `LLM01:2026`）。
   - 審查者少於兩個模型家族時列為證據缺口（判定不會是 `READY_TO_SHIP`；同一模型的「共識」只是一致性，不是佐證；OWASP LLM07:2026）。驗證者從不評審自己模型回報的發現，所以單一模型家族時沒有任何驗證票，發現不經過濾，報告的共識率與已確認數都標示為 N/A（發現列為未經驗證的假設）。
   - **交叉驗證（Cross-Model Verification）**：不設單一仲裁模型。每筆發現由「沒有回報它」的其他模型各自獨立判定 confirm／reject／unsure；不論有幾個驗證者條目指向同一個 model alias，它都只投一票。其他模型也回報了同一缺陷（去重合併時記錄；合併採 complete-linkage，泛泛的發現無法把兩個不同缺陷串在一起）則算一票確認，但單靠佐證永遠不算驗證：驗證者沒有投下任何真正的 confirm／reject 時，發現仍是未經驗證的假設。確認票多於否決票即確認、否決票較多列為爭議（不生成測試）、同票則保留交給測試決定。共識率依實際票數計算。
3. **黑箱強制威脅建模先行（Threat-Modeling First）**：拒絕盲目暴力測試，先依據 STRIDE（S 仿冒、T 竄改、R 否認、I 資訊洩漏、D 拒絕服務、E 越權）與 OWASP API Security Top 10 建立攻擊矩陣，再針對性生成攻擊測試。威脅建模的輸入是 `--desc`（或預設描述）、階段 1 擷取的路由與符號，以及確定性規則偵測到的 `ai_components`，不依賴白箱結果。與白箱審查相同，目標符號會分批送審（以 token 預算切分），確保每個符號都進入威脅模型的視野；各批產出的威脅合併並去重編號。
4. **以執行結果為準的品質閘門**：模型發現與威脅僅是假設；只有實際執行的測試或確定性規則能讓閘門失敗或封鎖。黑箱測試只有以 `AssertionError`、裸 `assert` 或 `pytest.fail` 失敗才算確認突破。無斷言的空測試、無效的模型輸出（非 JSON／缺欄位，或審查、驗證、威脅建模的批次或攻擊合成在閘道之外崩潰，皆記錄為 `invalid`）、未測試的威脅、以及「失敗但未分類為 exploit」的黑箱攻擊測試，都列為證據缺口。
5. **確定性 AI 安全規則（不經模型）**：在任何模型看到程式碼之前，先以 AST／文字規則掃描目標，結果無法被提示注入說服：

   | 規則 | 偵測內容 | 嚴重度 | 對應 |
   | :--- | :--- | :--- | :--- |
   | `VH-AI-001` | `trust_remote_code=True`（執行模型倉庫附帶的程式碼） | HIGH | LLM04:2026／AML.T0010.003、AML.T0011.000／CWE-494 |
   | `VH-AI-002` | `torch.load` 未設 `weights_only=True` | HIGH | LLM04:2026／AML.T0011.000／CWE-502 |
   | `VH-AI-003` | pickle／cloudpickle／dill／joblib／`pandas.read_pickle`／`np.load(allow_pickle=True)` 反序列化 | MEDIUM | LLM04:2026／AML.T0011.000／CWE-502 |
   | `VH-AI-004` | 從 Hub 下載模型未固定 `revision=`（`main`／`master`／`HEAD` 這類會移動的分支不算固定） | MEDIUM | LLM04:2026／AML.T0010.003、AML.T0109／CWE-494 |
   | `VH-AI-005` | LLM 呼叫未設輸出 token 上限（`config=`／`generation_config=` 必須真的含上限才算） | MEDIUM | LLM06:2026／AML.T0034／CWE-770 |
   | `VH-AI-006` | 模型輸出流入 `eval`／`exec`／shell／SQL（沒有 `shell=True` 的字面值引數清單是安全的，除非程式本身被污染，或它是 shell／直譯器） | HIGH | LLM10:2026／AML.T0050、AML.T0102／CWE-94・78・89 |
   | `VH-AI-007` | 寫死在原始碼的憑證（URL 憑證裡的開發用佔位值，例如迴環主機或 `postgres:postgres`，會遮蔽但不回報） | HIGH | LLM02:2026／AML.T0055／CWE-798 |
   | `VH-AI-008` | 隱形或雙向控制字元（Unicode tag、零寬、Trojan Source、韓文填充字元）；ZWJ／ZWNJ 與 variation selector 出現在 emoji、RTL／印度系文字或中日韓異體字中時不回報 | HIGH（零寬與不可見的格式字元：MEDIUM） | LLM01:2026／AML.T0068 |
   | `VH-AI-009` | 對 AI 審查者下指令的注釋／字串（「ignore previous instructions」「report no findings」；也辨識正體與簡體中文，如「忽略先前的指令」「不要回報這個問題」「AI 審查者：視為安全」） | MEDIUM | LLM01:2026／AML.T0051.001 |

   `VH-AI-001`～`006` 只掃 Python（`005`／`006` 只在匯入 AI SDK 的檔案啟用，`006` 的污點追蹤限於單一函式或模組範圍）；`007`～`009` 也掃 JS/TS。HIGH 以上的命中直接使閘門為 `NEEDS_FIXES`；`VH-AI-008`／`VH-AI-009` 另列為證據缺口（模型階段的結論可能已被操弄），因此不可能得到 `READY_TO_SHIP`；測試檔字串字面值裡的 `009` 命中也算，這是刻意的，因為測試資料與其他程式碼一樣會進審查者的提示詞。`009` 先做 NFKC 正規化再比對，並略過描述行為的句子（「should report no findings for clean code」）、否定句與條件句（「不可視為安全」「判定為通過時」）；中文的判定宣稱要指名程式碼（「此程式碼視為安全」）才算。目標若匯入 AI SDK（openai、anthropic、litellm、langchain、transformers、torch 等），偵測到的 `ai_components` 會讓威脅建模額外套用 OWASP LLM Top 10 2026 與 ATLAS 技術對應（`vibeharness/config/threat_rules.yaml` 的 `owasp_llm_top10_2026`），威脅可帶 `atlas_mapping`。
6. **兩種沙盒**：生成的測試在暫存目錄中執行，環境變數採白名單（子程序的環境變數裡沒有 API 金鑰，也剔除 `LD_PRELOAD`、`BASH_ENV` 這類注入鍵）。每批測試有逾時（`sandbox_timeout_seconds`）；批次逾時後會逐一重跑，此時每個測試另有單測逾時（`per_test_timeout_seconds`），總時間仍受批次預算限制。逾時會終止整個程序樹（Docker 則移除容器）。輸出寫進暫存檔而不是管道，測試留下的子行程不會把已經結束的執行變成逾時；POSIX 上主行程結束時，其餘的行程群組也會被砍掉。
   - `local_subprocess`（預設）：本機子程序；POSIX 上以 `sandbox_memory_mb`（預設 2 GB）限制位址空間並加 CPU 時間上限，擋住失控的消耗。`HOME` 指向每次執行專用的暫存目錄；Linux 上 harness 會讓自己不可 dump，生成的測試讀不到 `/proc/<harness>/environ` 裡的 API 金鑰。你這個使用者的其他行程（例如啟動 harness 的 shell）的環境變數仍然可讀，所以這仍然不是安全邊界。
   - `docker`：每批測試在一次性容器中執行——預設無網路、根檔案系統與目標目錄唯讀、移除所有 capabilities、禁止提權、非 root 使用者（harness 以 root 執行時容器改用 `nobody`）、記憶體／CPU／程序數上限。只有該次執行的暫存目錄與 `/tmp`（noexec 的 tmpfs）可寫。
7. **JS/TS 動態測試執行**：目標檔是 `.js`／`.jsx`／`.mjs`／`.cjs`／`.ts`／`.tsx`／`.mts`／`.cts` 時，白箱測試生成與黑箱 in-process 攻擊測試改以 `node:test` + `node:assert` 的 ES module 生成（第一次需要時才偵測 `node_bin`，需 Node ≥ 20；`.ts` 需 ≥ 22.6 的型別剝除），每個測試模組各自在一個 `node --test` 程序中、以批次預算剩下的時間執行（批次逾時後，其餘模組改用 `per_test_timeout_seconds` 重跑），由 JUnit 報告判定：`AssertionError`／`ERR_ASSERTION` 失敗才算確認突破，目標內拋出的 `TypeError` 算缺陷但不算 exploit，測試自身的 `ReferenceError`／無法解析的匯入算 harness 錯誤。測試以 `file://` URL 匯入目標（提示詞會告知 ESM／CommonJS 的匯入寫法與偵測到的匯出名），裸 specifier 由目標的 `node_modules`（symlink 進執行目錄）解析；靜態閘門同樣拒絕安裝套件（`npm`／`pnpm`／`yarn`／`bun`／`npx`）。Node 沙盒不套 `RLIMIT_AS`（V8 啟動時保留大片位址空間），改以 `--max-old-space-size` 封頂堆積並保留 CPU 上限；`NODE_OPTIONS`／`NODE_PATH` 不從主機轉送。打執行中服務的黑箱 HTTP 攻擊仍一律以 Python（urllib）撰寫。沒有可用的 Node 時，JS/TS 測試列為 ERROR 並寫入證據缺口（「no usable Node runtime」），不會在啟動時失敗；mock 模式的模擬引擎不會生成 JS 測試，缺口為「no JS/TS test was generated」。Docker 下 Node 測試用另一個映像 `docker_node_image`（`docker/sandbox-node.Dockerfile`）。
8. **突變測試（選用，`--mutation`）**：覆蓋率只量到「哪些行被跑過」，量不到「測試能不能抓到行為改變」。開啟後，對通過的 Python 白箱測試所涵蓋的函式做確定性的單一 token 改動（`+`↔`-`、`<`↔`<=`、`and`↔`or`、移除 `not`、`True`↔`False`、`0`↔`1` 等），在複本上重跑測試：任何測試失敗即「殺死」，全數通過即「存活」；分數 = 殺死 ÷（殺死＋存活），是下界（等價變異體無法判定）。完全離線、不呼叫模型，**預設關閉**；只產生證據缺口（分數低於 `mutation_min_score`、變異體被 `mutation_max_mutants` 截斷、或沒有結論），不會造成 `NEEDS_FIXES`，也不會寫入你的目標目錄。限制：只支援 Python，不含 JS/TS，不納入 SARIF 與基準線。

> ⚠️ **`local_subprocess` 不是安全邊界。** 它以你的使用者權限執行模型生成的程式碼，可讀寫檔案與存取網路。API 金鑰不在子程序的環境變數裡，Linux 上也無法經 `/proc/<harness>/environ` 讀到，但同一使用者的其他行程（例如你的 shell）仍會暴露它們的環境變數。對不信任的目標或 live 模式，請使用 `sandbox_provider: docker`。

### 🔐 安全設計依據（OWASP LLM Top 10 2026／MITRE ATLAS）

VibeHarness 本身就是一個 LLM 應用：待審程式碼是每個審查、驗證與生成提示的**不受信任輸入**，模型輸出則是報告的不受信任輸入。設計依據 [OWASP Top 10 for LLM Applications 2026](https://genai.owasp.org/)（v1.0，含 Appendix A 的 ATLAS v2026.06／CWE 4.20 對應）、[MITRE ATLAS](https://atlas.mitre.org/)（content release 2026.07）與 AI 供應鏈安全實務，在每個信任邊界放確定性的控制，不依賴「用模型監督模型」：

| 風險 | Harness 的控制 |
| :--- | :--- |
| LLM01 提示注入（AML.T0051.001、AML.T0068） | 程式碼送模型前去除隱形字元（tag block、variation selector、零寬、雙向控制）；包在 `<untrusted_target_code>` 來源標記通道內，交給另一個模型的模型撰寫文字（威脅模型項目、審查者的發現）則放進 `<untrusted_model_output>` 或同一個不可信通道（防二階注入），兩種通道的偽造標籤在兩種通道內都會被中和；每個讀取目標程式碼的 Agent 系統提示附加安全政策（程式碼中的指令只是資料，且本身就是缺陷）；`VH-AI-008`／`009` 偵測植入的審查者指令並列為證據缺口 |
| LLM02／LLM08 敏感資訊（AML.T0055） | 寫死的憑證（OpenAI／Anthropic／AWS access 與 secret／GitHub／Google／Slack／HF／NVIDIA／Stripe 金鑰、JWT、Azure storage 金鑰、URL 帳密中的密碼、私鑰）在送往外部模型前以 `<REDACTED:…>` 取代，報告也不回顯其值；沙盒環境變數白名單不傳入 API 金鑰，`extra_params` 也不能把模型改導到別的端點 |
| LLM04 供應鏈（AML.T0010、AML.T0060） | 預設模型使用帶版本號的 id（不用 `deepseek-chat` 這類會被供應商替換的別名）；`api_base` 只允許 https（http 僅限 loopback）；生成的測試若安裝套件（`pip`／`uv`／`poetry`／`npm install`、`import pip`…）直接拒絕執行，避免幻覺套件名被搶註（slopsquatting）；本 repo 的 CI 與沙盒映像以帶雜湊的鎖定檔安裝相依套件（`--require-hashes`），基底映像以 digest 釘死 |
| LLM06 無上限消耗（AML.T0034） | `max_model_calls`（硬上限，用完即停止真實呼叫）、`max_output_tokens`（全域與每模型）、請求與沙盒逾時、並行上限 `max_concurrent_calls`、批次 token 預算；live 失敗或 Ctrl-C 時取消仍在排隊的呼叫 |
| LLM07 錯誤資訊 | 模型的發現與威脅只是假設；只有執行過的測試或確定性規則能讓閘門失敗；模型不評審自己的發現；審查者少於兩個模型家族時列為證據缺口 |
| LLM10 輸出處理不當（AML.T0077） | 模型文字進入 Markdown 前停用圖片與原始 HTML（防圖片 URL 外洩）、移除 ANSI／OSC 控制序列並收合換行（無法開出偽造的標題或表格）；模型選的 id 放進程式碼區段並跳脫管線符號；console 輸出跳脫 rich markup；SARIF 訊息去除控制字元 |
| 稽核可追溯 | 每次成功送出的模型呼叫記錄 `prompt_sha256`，可把判定對回實際輸入，而報告不必保存（可能敏感的）程式碼；批次（審查、驗證、威脅建模、攻擊合成）在閘道之外崩潰時經 `record_failure` 記為 `invalid`（附例外原因，無雜湊） |

### 🧭 尚未實作（規劃中）

| 功能 | 現況 |
| :--- | :--- |
| 突變測試延伸 | v1 只支援 Python（見核心特性第 8 點）；JS/TS 變異、納入基準線與 SARIF、逐運算子統計尚未實作 |
| 動態 DAST／Fuzzing 代理 | 未實作；黑箱測試由威脅模型逐項生成 pytest 攻擊腳本 |
| Hypothesis 性質測試 | 未內建；模型可自行生成，但需目標環境已安裝 `hypothesis` |
| `e2b` 沙盒 | 未實作；`sandbox_provider` 支援 `local_subprocess` 與 `docker`，其他值會直接報錯 |
| JS/TS 覆蓋率與第三方套件 | JS/TS 測試已可生成並以 Node 執行（見下方「JS/TS 動態測試執行」），但不收集 JS 覆蓋率；TypeScript 只做型別剝除（enum、namespace、參數屬性、裝飾器、tsconfig 路徑別名不支援）；Docker 沙盒內 ESM 的裸 specifier 無法解析（只有 CommonJS 吃 `NODE_PATH`） |
| 符號擷取的限制 | JS/TS lexer 不是 JSX parser：JSX 文字裡的 `/*` 或單獨一個反引號可能把檔案後半段藏起來；hapi 的陣列形式 `server.route([...])` 與 regex 路徑不會被認成 route；Python 函式裡的路由處理函式（Flask 工廠）會送審兩次：在外層函式裡一次、以自己的 route 一次 |
| 只讀快取的重跑 | CLI 沒有只讀快取的模式，`live-smoke.yml` 的 JSON 重跑可能再問一次未快取的呼叫（每次 workflow 最多 2 × `max_model_calls` 次真實呼叫） |

---

## 📦 目錄結構

```text
MultiAgentGama/
├── .github/
│   ├── CODEOWNERS               # 預設審查者
│   ├── dependabot.yml           # 每週提議 Actions、requirements*.txt／requirements.lock、沙盒基底映像與 docker/sandbox-requirements.* 的更新
│   ├── ISSUE_TEMPLATE/          # 錯誤回報／功能提議模板
│   ├── PULL_REQUEST_TEMPLATE.md
│   └── workflows/
│       ├── tests.yml            # CI：lint（ruff／mypy）、audit（pip-audit）、package（sdist＋wheel：wheel 冒煙測試、從 sdist 跑測試套件）、test（Ubuntu／Windows × Python 3.10–3.14，另加 macOS × 3.12，覆蓋率門檻 93%）
│       ├── publish.yml          # 發佈：tag 推送時先跑 tests.yml、驗證版本一致、建置 sdist／wheel、在乾淨的 venv 對 wheel 冒煙測試、上傳 GitHub Release（PyPI 需設 ENABLE_PYPI_PUBLISH）
│       └── live-smoke.yml       # 手動觸發：以 repo secrets 的真實金鑰對 examples 跑一次 live／hybrid，上傳報告
├── docker/
│   ├── sandbox.Dockerfile       # docker 沙盒的基底映像（以 digest 釘死的 python:3.12-slim，USER 65534；pytest / pytest-cov / requests）
│   ├── sandbox-node.Dockerfile  # docker Node 沙盒的基底映像（以 digest 釘死的 node:22-slim，USER 65534；執行 JS/TS 測試）
│   ├── sandbox-requirements.in  # 沙盒映像鎖定檔的直接輸入（以 requirements.lock 為約束）
│   └── sandbox-requirements.txt # 帶雜湊的沙盒相依套件鎖定檔（以 --require-hashes 安裝）
├── vibeharness/                 # 唯一的頂層套件（pip install 後 site-packages 只多這一個目錄）
│   ├── __init__.py              # 套件版本號（__version__，pyproject 的唯一來源）
│   ├── cli.py                   # CLI 進入點（vibeharness 指令）
│   ├── config/
│   │   ├── agents_config.yaml       # 全域設定（執行模式、沙盒、上限）、多模型路由 (Claude, GLM, DeepSeek, Gemini) 與各 Agent 提示詞
│   │   └── threat_rules.yaml        # STRIDE、OWASP API Top 10 與 OWASP LLM Top 10 2026（含 ATLAS／CWE 對應）
│   ├── core/
│   │   ├── __init__.py
│   │   ├── harness.py               # 指揮官：六階段線性流程與品質閘門
│   │   ├── llm_gateway.py           # 統一 LiteLLM 閘道：路由、fallback、模擬回退、呼叫預算與 call_log
│   │   ├── models.py                # Pydantic 數據模型
│   │   ├── baseline.py              # --baseline：與執行次序無關的指紋，已知問題不計入
│   │   ├── codecheck.py             # 生成測試的靜態檢查（每個 test_ 函式／方法都要有斷言；拒絕安裝套件）
│   │   ├── codecontext.py           # 提供給模型的原始碼與 import 指引（經不受信任程式碼通道）
│   │   ├── estimate.py              # --estimate：不呼叫模型即估算呼叫數、token 與花費
│   │   ├── i18n.py                  # 「中文 ／ English」雙語輸出的工具（bi／en_only）
│   │   ├── mutation.py              # 選用的突變測試（Python）
│   │   ├── sanitize.py              # 信任邊界：去隱形字元、遮蔽密鑰、不受信任程式碼／模型輸出通道、報告消毒
│   │   └── sandbox.py               # 沙盒：本機子程序（非安全邊界）與 Docker 容器；Node 版本各一（node --test）
│   ├── agents/
│   │   ├── __init__.py
│   │   ├── whitebox/
│   │   │   ├── __init__.py
│   │   │   ├── ast_extractor.py     # 符號解析與路由提取（Python 用 AST；JS/TS 用無相依 lexer）
│   │   │   ├── ai_static_scanner.py # 確定性 AI 安全規則 VH-AI-001～009（不經模型）
│   │   │   ├── common.py            # 共用工具：live 失敗或 Ctrl-C 時取消排隊中的模型呼叫
│   │   │   ├── multi_reviewer.py    # 異構模型評議 (Ensemble，由設定檔的 whitebox_reviewer_* 組成)
│   │   │   ├── deduplicator.py      # 合併多個模型回報的同一缺陷（complete-linkage）
│   │   │   ├── debater.py           # 交叉驗證：由非作者模型投票判定
│   │   │   └── test_generator.py    # 單元/邊界測試自動生成（自癒重試、WB-PROBE 探針）
│   │   └── blackbox/
│   │       ├── __init__.py
│   │       ├── threat_modeler.py    # STRIDE／OWASP API／LLM 威脅建模引擎（含 ATLAS 對應）
│   │       └── scenario_builder.py  # 威脅轉化可執行攻擊腳本
│   ├── runners/
│   │   ├── __init__.py
│   │   └── test_executor.py         # 沙盒測試執行器（pytest；JS/TS 走 node:test）與 PoC 抓取（白箱與黑箱共用）
│   ├── reports/
│   │   ├── __init__.py
│   │   └── report_generator.py      # Markdown／JSON／SARIF 審計報告生成器
├── examples/
│   └── vibe_sample_app.py       # 具代表性的 Vibe-Coding 典型缺陷範例
├── docs/
│   ├── sample_report.md         # mock 模式產生的範例報告
│   ├── configuration.md         # 設定檔欄位完整參考（正體中文）
│   ├── configuration.en.md      # Configuration reference (English)
│   ├── design.md                # 設計文件：架構、資料流、閘門判定、沙盒安全模型（正體中文）
│   └── design.en.md             # Design document (English)
├── tests/                       # 工具包本身之測試（離線、不需 API 金鑰）
│   ├── conftest.py              # 共用 fixture：以假 litellm 讓 live 路徑離線執行
│   ├── test_ai_security.py      # OWASP LLM Top 10 2026／ATLAS 控制與確定性 AI 安全規則
│   ├── test_baseline.py                # --baseline：與執行次序無關的 key、已知問題不計入、action.yml 結構
│   ├── test_cross_verification.py      # 交叉驗證：模型不評審自己的發現、依票數判定
│   ├── test_dedup_and_budget.py        # 重複發現合併與 token 預算內的提示上下文
│   ├── test_docker_sandbox.py          # Docker 沙盒：路徑映射、容器強化參數、實際執行（有 Docker 時）
│   ├── test_estimate.py                # --estimate：精確值與情境值、價格、不呼叫模型
│   ├── test_harness_components.py      # 各元件於 mock 模式下的整合測試
│   ├── test_i18n.py                    # 雙語工具、報告／console／CLI 字串、雙語的 docstring 與註解
│   ├── test_i18n_output.py             # 提示詞維持英文、雙語的規則標題、執行器原因與 PoC
│   ├── test_js_execution.py            # JS/TS 執行：程式碼閘門、ESM/CJS 偵測、Node JUnit 分類、Node 沙盒（有 node 時實跑）、端對端
│   ├── test_js_ts_extractor.py         # JS/TS 擷取器：括號配對、字面值／註解遮蔽、箭頭函式、路由
│   ├── test_mutation.py                # 突變測試：變異點與切換、決定性與上限、隔離與路徑改寫、強弱測試端對端、閘門語意、開關優先順序、CLI／Action
│   ├── test_model_output_robustness.py # 模型輸出異常時優雅降級、探針回退的揭露
│   ├── test_p0_regressions.py          # 執行器正確性、自我修復與結果來源誠實性的回歸測試
│   ├── test_parallel_and_budgets.py    # 測試生成並行、模型呼叫預算、檔案／worker 上限
│   ├── test_prompt_context.py          # live 模式：提示帶入真實程式碼與 import 路徑、閘道呼叫健壯性
│   ├── test_quality_fixes.py           # 打包、模型輸出健壯性、執行與 SARIF 修正的回歸測試
│   ├── test_review_blackbox.py         # 威脅 id、STRIDE 拼法、崩潰的黑箱批次記入 call_log
│   ├── test_review_build.py            # 釘版的 actions、workflow 輸入經 env、映像 digest、帶雜湊的鎖定檔、sdist 內容
│   ├── test_review_cli_config.py       # 崩潰的結束碼、設定驗證、重問／快取 key、未經驗證的計數
│   ├── test_review_dedup_votes.py      # complete-linkage 去重、每個驗證模型一票
│   ├── test_review_extractor_scanner.py # JSX／TS 詞法分析、路由偵測、VH-AI-004/005/006 精確度
│   ├── test_review_reports.py          # 程式碼區段、換行偽造、SARIF 路徑、威脅符號、未經驗證的假設
│   ├── test_review_sandbox_executor.py # 假家目錄、不可 dump 的 harness、殘留子行程、NameError 歸因、JS 預算
│   ├── test_review_sanitize.py         # 憑證格式、隱形字元、注入標記、通道標籤
│   ├── test_review_sanitize_blackbox_fixes.py # 佔位憑證、VH-AI-008/009 精確度、連接埠檢查、中止呼叫
│   └── test_review_whitebox_fixes.py   # 路由、Python 巢狀定義、掃描規則、嚴重度、不可信的發現文字
├── .pre-commit-config.yaml      # pre-commit：提交前執行 ruff 與 mypy
├── CHANGELOG.md                 # 變更紀錄（正體中文）；CHANGELOG.en.md 為英文版
├── CONTRIBUTING.md              # 貢獻指南：開發環境、提交前檢查、修改原則、發布步驟
├── LICENSE                      # MIT 授權
├── SECURITY.md                  # 資安政策：弱點私密通報流程
├── MANIFEST.in                  # sdist 內容：docs、config、tests、examples、main.py、action.yml、requirements 與鎖定檔、docker/、政策檔
├── action.yml                   # composite GitHub Action：目標專案一行引用即可執行稽核（uses: chinchiang/MultiAgentGama@vX.Y.Z）
├── pyproject.toml               # 套件中繼資料、vibeharness 指令進入點、pytest／ruff／mypy 設定
├── requirements.txt             # 執行期依賴
├── requirements-dev.txt         # 開發依賴（ruff、mypy、pytest-cov、build、pip-audit，版本鎖定）
├── requirements.lock            # 完整鎖定、帶雜湊的版本（CI 以 --require-hashes 安裝；pip-audit 使用）
├── README.md                    # 說明文件（正體中文）；README.en.md 為英文版
└── main.py                      # 薄殼：`python main.py …` 轉呼叫 vibeharness.cli
```

---

## 🛠️ 快速開始

### 1. 安裝依賴

```bash
pip install -r requirements.txt
```

要與 CI 測試時完全相同的相依套件（帶雜湊驗證）：`pip install --require-hashes -r requirements.lock`。

或安裝為套件（會一併註冊 `vibeharness` 指令）：

```bash
pip install .
vibeharness --version
```

### 2. 設定 API 金鑰（可選）

工具包支援真實 API 調用與本機模擬模式（Hybrid Mode）：

> 設定檔（`vibeharness/config/agents_config.yaml`）每個欄位的完整說明——含預設值、改派模型與 Docker 沙盒範例——見 **[docs/configuration.md](docs/configuration.md)**（[English](docs/configuration.en.md)）。
>
> 想了解每個元件為什麼這樣設計、資料怎麼在階段之間流動、閘門與 evidence gap 怎麼判定，見 **[docs/design.md](docs/design.md)**（設計文件，正體中文；[English](docs/design.en.md)）。

```bash
# 若要使用即時模型：
export ANTHROPIC_API_KEY="sk-ant-..."   # Claude
export ZAI_API_KEY="..."                 # GLM（智譜 Z.AI）
export DEEPSEEK_API_KEY="sk-..."         # DeepSeek
export GEMINI_API_KEY="AIza..."          # Gemini
```

預設模型見 `vibeharness/config/agents_config.yaml`（Claude `claude-sonnet-5-5`、GLM `zai/glm-5.3`、DeepSeek `deepseek/deepseek-v4-pro`、Gemini `gemini/gemini-3.8-flash`），每個模型可設定 `fallback_model`（預設分別為 `claude-haiku-4-5-20251001`、`zai/glm-5.3-flash`、`deepseek/deepseek-v4-flash`、`gemini/gemini-3.5-flash`），主模型重試 `max_retries` 次失敗後會改用它，報告會記錄實際使用的模型。每個模型的金鑰從 `api_key_env` 指定的環境變數讀取；以 AWS 憑證驗證的供應商（例如 Bedrock）可改設 `aws_profile_name`／`aws_region_name`。注意：待審程式碼會傳送給這裡列出的每一家模型供應商（已先遮蔽寫死的憑證），請只設定資料保留條款可接受的供應商。

`global` 區段的其他上限（CLI 未覆蓋時生效）：`execution_mode`（`--mode` 會覆蓋）、`timeout_seconds`（單次模型請求，預設 180 秒）、`max_retries`（2）、`max_output_tokens`（16384，思考 token 也算在內；`models.<alias>.max_output_tokens` 可逐模型覆蓋）、`max_concurrent_calls`（每個階段的並行模型呼叫數，6）、`max_model_calls`、`max_files`、`max_file_bytes`、`include`／`exclude`、`retry_invalid_output`、`sandbox_timeout_seconds`（120）與 `per_test_timeout_seconds`（30）。

任何 agent 都可透過 `model_alias` 指向任一已定義的模型；缺少 `model_alias` 的 agent 會解析為 `unconfigured`（hybrid 模式改用模擬，live 直接失敗）。手上只有一組金鑰也能跑 live 模式——例如只有 Gemini key 時，把 `agents` 區段中所有 `model_alias` 改成 `gemini` 即可（註：`gemini-2.5-flash` 已不再供新申請的 Google API 金鑰使用，請使用 3.x 版本）。但單一模型家族時驗證者不會評審自己模型的發現，沒有任何驗證票、發現不經過濾，且審查者少於兩個模型家族列為證據缺口，判定最好只到 `INCONCLUSIVE`（exit code 3），結果僅供參考。

*註：若未配置 API 金鑰，`hybrid` 模式會退回模擬引擎（Simulation Engine）以便離線體驗工作流。模擬引擎回傳的是**與目標程式碼無關的固定範本**，報告會以 `[SIMULATED]` 與「執行來源 ／ Execution Provenance」表明確標示，且品質閘門不會因此給出 `READY_TO_SHIP`。*

| `--mode` | 行為 |
| :--- | :--- |
| `live` | 只呼叫真實模型；缺金鑰或呼叫失敗即中止（exit code 4）。模型回應無法使用時記錄為 `invalid`，判定為 INCONCLUSIVE |
| `hybrid`（預設） | 能呼叫就呼叫，否則退回模擬並在報告中標示 |
| `mock` | 全部使用模擬引擎 |

模擬模式下，白箱測試改用由目標函式自動推導的 None 輸入健壯性探針（`WB-PROBE-*`）；任何模式下，確認的發現若沒有可用的模型生成測試，也會補上探針並列為證據缺口。黑箱威脅若無可執行測試，會列為「Threats Not Tested」，不會捏造測試結果。

### 3. 使用 Docker 沙盒（建議用於不信任的目標）

```bash
docker build -t vibeharness-sandbox:latest -f docker/sandbox.Dockerfile .
docker build -t vibeharness-sandbox-node:latest -f docker/sandbox-node.Dockerfile .   # 目標含 JS/TS 時
```

在 `vibeharness/config/agents_config.yaml` 設定 `sandbox_provider: "docker"`。可調整 `docker_image`、`docker_network`、`docker_memory`、`docker_cpus`、`docker_pids_limit`；JS/TS 測試的 Node 容器用 `docker_node_image`（`sandbox_node_provider` 預設跟隨 `sandbox_provider`，可單獨設為 `local_subprocess` 讓 JS 測試在本機 Node 執行）。

- 目標目錄以唯讀方式掛載到容器內的 `/work/<目錄名>`；生成測試中的主機絕對路徑會自動改寫為容器路徑。
- 容器預設**沒有網路**，無法在執行時安裝套件。目標的相依套件需預先裝進專案專用映像，再把 `docker_image` 指向它。基底映像以 `nobody`（`USER 65534`）執行，安裝時要先切成 root、裝完再切回來：

  ```dockerfile
  FROM vibeharness-sandbox:latest
  USER root
  COPY requirements.txt /tmp/requirements.txt
  RUN pip install --no-cache-dir -r /tmp/requirements.txt
  USER 65534:65534
  ```

- 兩個基底映像都以 digest 釘死，Python 映像的測試工具從帶雜湊的 `docker/sandbox-requirements.txt` 安裝。
- 黑箱測試若要打正在執行的服務，需開放網路（例如 Linux 上 `docker_network: "host"`），這會降低隔離程度。
- 找不到 docker 指令或映像時會直接報錯並提示建置指令，不會默默退回本機子程序。

### 4. 對目標專案執行全流程檢驗

```bash
python main.py --target examples --output vibe_harness_report.md
```

`--target`（`-t`，預設 `examples`）可為目錄或單一檔案；`--output`（`-o`）預設 `vibe_harness_report.md`。`--desc`（`-d`）可提供系統的高階描述供威脅建模參考；`--config`（`-c`）指定其他設定檔；`--verbose`（`-v`）開啟除錯日誌。黑箱測試預設以 in-process 方式直接 import 目標呼叫；只有明確指定 `--base-url`（`-u`，例如 `--base-url http://localhost:8000`；只接受含主機名的 `http://`／`https://`，其他 scheme 為用法錯誤）且該位址有服務回應時，才會改發真實 HTTP 請求。不會自動探測任何預設位址，以免攻擊腳本打到本機上無關的服務；live HTTP 模式下，攻擊程式碼若指向 `--base-url` 以外的主機，或同一主機的其他連接埠，會被靜態拒絕。範例輸出見 [`docs/sample_report.md`](docs/sample_report.md)。

執行前可先用 `--estimate` 看規模：它只跑第 1 階段（符號擷取與靜態規則，不呼叫模型），印出每個 agent 與每個模型的預期呼叫數（審查者與威脅建模的次數是精確值，驗證、測試生成與攻擊合成依「每批發現數」等假設列為情境值，另給含重問與自癒修復的最大值）、估計的 prompt／輸出 token，以及設定了 `price_per_million_*` 的模型的估計花費；`--format json` 時寫到 `--output`，exit code 為 0（`--changed-since` 的 ref 無法解析或 `--output` 寫不進去時為 5）。規模與成本上限可從 CLI 直接覆蓋設定檔：`--max-files`（單次分析的檔案數上限，預設 50，須 ≥ 1；其餘檔案列為 skipped 並記為證據缺口）與 `--max-model-calls`（單次執行的模型呼叫數上限，預設不限制，`0` 亦表示不限制，負數為用法錯誤；重試與 fallback 不另計次；用完時 hybrid 退回模擬並列為證據缺口、live 直接失敗）。檔案篩選：`--include GLOB`／`--exclude GLOB`（可重複，比對相對於 `--target` 的路徑或檔名，例如 `--exclude 'tests/*' --exclude '*.min.js'`；會覆蓋設定檔的 `include`／`exclude`），以及 `--changed-since <git ref>`（只分析相對該 ref 有變更的檔案，含未暫存與未追蹤，適合 PR 檢查：`--changed-since origin/main`）。超過 `max_file_bytes`（預設 1 MB）的檔案不分析並列為證據缺口。模型回應無法使用時會先重問一次（`retry_invalid_output`）再記為 `invalid`。`--output`／`--sarif` 的目錄不可寫時在任何模型呼叫前就以 exit 5 結束；執行中途崩潰或被 Ctrl-C 中斷時，已完成的階段（模型呼叫紀錄、發現、測試結果、威脅）會寫到 `<output>.partial.json`。`--cache-dir DIR` 開啟回應快取：可用的 live 回應存在 DIR，之後相同提示直接取用、不呼叫供應商也不扣預算（適合重跑或切換報告格式）。詳見 [`docs/configuration.md`](docs/configuration.md)。

報告格式可用 `--format md`（預設）或 `--format json`（機器可讀，含完整的 findings、威脅模型與測試結果，適合接 CI/CD）。兩種格式都會保存每個生成測試的程式碼：Markdown 附錄「產生的測試程式碼（稽核軌跡） ／ Generated Test Code (audit trail)」以可收合區塊列出程式碼與其執行結果（已去除控制字元）；JSON 的 `generated_tests`／`blackbox_generated_tests` 則原封不動保存，可用來稽核或重跑。模型寫的測試也只是假設——「通過」的測試可能是在斷言缺陷本身（例如 `pytest.raises(KeyError)`），請一併檢查斷言是否描述正確的行為：

```bash
python main.py --target examples --output report.json --format json
```

另可加 `--sarif <路徑>` 一併輸出 [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html) 報告：白箱確認的 findings 會帶檔案/行號位置（依 `line_number` 或符號表解析；未套用跨模型驗證時標 `properties.verified: false`，訊息以「Unverified hypothesis」開頭），黑箱確認的資安突破列為 error 級結果（攻擊向量以完整識別字或路由指名某個符號時也帶位置，最長的比對勝出）。規則 id 固定為 `vibeharness/whitebox-finding`／`vibeharness/blackbox-breach`，確定性 AI 安全規則則為 `vibeharness/VH-AI-001`～`009`（以 OWASP／ATLAS／CWE 標記 tags），本次執行的 finding／test id 放在 `properties`，因此重新編號不會讓 Code Scanning 的 alert 關掉又重開。SARIF 可上傳到 GitHub Code Scanning，讓缺陷直接顯示在 repo 的 **Security** 頁籤：

```yaml
# 目標專案的 .github/workflows/security.yml 範例：本 repo 提供 composite GitHub Action（action.yml）
- uses: chinchiang/MultiAgentGama@v0.5.1      # 從 action 本身的 checkout 安裝套件（相依套件帶雜湊驗證）並執行稽核
  with:
    target: src
    mode: hybrid
    max-model-calls: "80"
    changed-since: origin/main                 # PR 檢查：只分析有變更的檔案（可省略）
    baseline: .vibeharness/baseline.json       # 可選：只有「新出現」的問題才讓 job 失敗
    mutation: "true"                            # 可選：true／false 單次開關突變測試，留空沿用設定檔
    fail-on: needs-fixes                       # blocked | needs-fixes | inconclusive | never
  env:
    ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
    ZAI_API_KEY: ${{ secrets.ZAI_API_KEY }}
    DEEPSEEK_API_KEY: ${{ secrets.DEEPSEEK_API_KEY }}
    GEMINI_API_KEY: ${{ secrets.GEMINI_API_KEY }}
- uses: github/codeql-action/upload-sarif@9f759ee644a3e7c15c1390abf49868036c00067b # v3.38.3
  if: always()
  with:
    sarif_file: vibeharness.sarif
```

Action 的 outputs 有 `verdict`（`READY_TO_SHIP`／`NEEDS_FIXES`／`BLOCKED_CRITICAL_RISK`／`INCONCLUSIVE`，harness 本身失敗時為 `ERROR`）與 `exit-code`；報告、SARIF 與崩潰時的 `.partial.json` 會以 artifact `vibeharness-report` 上傳。不用 Action 的話，`pip install "git+https://github.com/chinchiang/MultiAgentGama@v0.5.1"` 後直接呼叫 `vibeharness` 即可。

**突變測試開關**：`--mutation` 開啟、`--no-mutation` 關閉；優先順序為 CLI 旗標 > 設定檔 `global.mutation_testing` > 預設關閉，因此設定檔開啟時可用 `--no-mutation` 單次關掉，設定檔關閉時可用 `--mutation` 單次打開。`--mutation-max-mutants N`（≥ 1）覆蓋變異體上限（預設 20）；每個變異體跑一批沙盒、不呼叫模型，`--estimate` 在開啟時會列出上限。報告的指標表有 Mutation Score 一列並列出存活的變異體；其餘鍵見 [`docs/configuration.md`](docs/configuration.md)。

**只對新問題把關（`--baseline`）**：把一次 `--format json` 的報告存起來（例如提交到 repo 的 `.vibeharness/baseline.json`），之後以 `--baseline` 指定它：報告中已經存在的白箱測試失敗（以其來源發現識別）、探針失敗、黑箱突破與 HIGH 以上的規則命中仍會列在報告的「基準中的已知問題（不計入） ／ Known from baseline (not counted)」清單與建議中，但不再計入判定與 exit code，只有新出現的問題會讓 CI 失敗。比對 key 與執行次序無關（finding 以檔案相對路徑＋符號＋標題正規化、突破以威脅的 STRIDE 分類＋標題＋攻擊向量、靜態命中以規則＋檔案＋證據但不含行號、探針以符號名），所以模型重新編號或無關的行數位移不會讓舊問題變新的。JSON 報告每個項目都帶 `fingerprint` 欄位；0.3.0 之前沒有該欄位的報告會自動重算。崩潰產生的 `.partial.json` 不能當 baseline。

> 註：SARIF 中的檔案路徑以包含 `--target` 的 git repo 根目錄為基準做相對化（找不到 repo 時才以 `--target` 目錄為基準），所以 `--target src` 也會產生 `src/app.py` 這樣與 Code Scanning 對齊的路徑。根目錄之外的檔案改用絕對 `file://` URI（不帶 `uriBaseId`），模型回報的相對路徑若會以 `..` 跳出根目錄就不給位置；絕不輸出 `..`。

Exit code（依序判定）：

| Code | 意義 | 條件 |
| :--- | :--- | :--- |
| `2` | BLOCKED_CRITICAL_RISK | 至少一個黑箱攻擊測試確認防禦被突破 |
| `1` | NEEDS_FIXES | 至少一個白箱測試失敗（暴露缺陷），或確定性 AI 安全規則有 HIGH 以上的命中；此碼專屬於此判定，harness 自身的錯誤不會使用它 |
| `3` | INCONCLUSIVE | 無失敗，但有證據缺口：使用模擬引擎、模型輸出無效或批次崩潰、`max_model_calls` 用盡、沒有審查者或審查者少於兩個模型家族、`max_files` 略過了檔案、檔案超過 `max_file_bytes`、非 Python 程式碼只做靜態審查、測試錯誤／未執行、確認的發現沒有模型生成的測試、威脅未測試、黑箱測試失敗但未分類為 exploit、檔案解析失敗、目標中植入了對 AI 審查者的指令或隱形字元（`VH-AI-008`／`009`）等；未知的判定字串也以此碼 fail closed |
| `0` | READY_TO_SHIP | 以上皆無 |
| `4` | — | live 模式模型呼叫失敗 |
| `5` | — | harness 設定或使用錯誤：`--target` 不存在、config 檔缺失、YAML 損壞、是目錄、無法讀取或是二進位檔，或最上層／區段／項目不是 mapping、`max_files`／`max_model_calls`／`max_concurrent_calls`／逾時等值不合法、`extra_params` 用了保留鍵、沙盒不可用、`--output`／`--sarif` 不可寫、`--changed-since` 的 ref 無法解析、CLI 用法錯誤，或任何未預期的內部錯誤，不論發生在啟動、`--estimate` 或執行期間（崩潰不會誤報成 verdict） |
| `130` | — | 被 Ctrl-C 中斷，未寫出完整報告（已完成的階段在 `<output>.partial.json`） |

### 5. 運行工具包本身單元測試與靜態檢查

```bash
pip install -r requirements-dev.txt
python -m pytest
python -m ruff check .
python -m mypy vibeharness/ main.py
```

另有手動觸發的 `live-smoke.yml`（Actions 頁籤 → live-smoke → Run workflow）：以 repo secrets 中的供應商金鑰對目標跑一次真實模型（可選 live／hybrid、呼叫數上限），再用回應快取重跑一次產出 JSON（快取命中不花錢；第一次沒能快取的呼叫會在同一個上限內重問，所以每次 workflow 最多 2 × 上限次真實呼叫），報告與 SARIF 以 artifact 上傳；這是唯一真正打到供應商的檢查，不在每個 PR 上跑。CI（`.github/workflows/tests.yml`）有四個 job：`lint`（ruff 與 mypy）、`audit`（pip-audit）、`package`（建置 wheel 並在檢出目錄之外以 mock 模式跑一次）與 `test`（Ubuntu／Windows × Python 3.10–3.14，另加一格 macOS × Python 3.12，以 `--require-hashes` 從 `requirements.lock` 安裝；Linux 另建 Docker 沙盒映像跑真實容器測試）。`package` 會建置 sdist 與 wheel，在檢出目錄之外以 mock 模式跑一次 wheel，並在解開的 sdist 裡跑完整測試套件；`publish.yml` 發布前會先對 tag 指向的 commit 跑這整個 workflow。`test` job 帶覆蓋率門檻，本機要跑同一條件可用：

```bash
python -m pytest --cov=vibeharness --cov-fail-under=93
```

供應鏈檢查（CI 的 `audit` job 對鎖定版本執行同一指令，含已知 CVE 的依賴會擋在合併前）：

```bash
pip install "$(grep '^pip-audit==' requirements-dev.txt)"
python -m pip_audit -r requirements.lock --disable-pip --require-hashes
```

可選：安裝 [pre-commit](https://pre-commit.com/) 讓每次 `git commit` 前自動執行 ruff 與 mypy 檢查（貢獻流程見 [CONTRIBUTING.md](CONTRIBUTING.md)，弱點通報見 [SECURITY.md](SECURITY.md)）：

```bash
pip install pre-commit
pre-commit install
```
