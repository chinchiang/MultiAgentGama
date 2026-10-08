# Changelog

正體中文（臺灣）｜ [English](CHANGELOG.en.md)

本專案所有重要變更都會記錄在本檔案。格式參考 [Keep a Changelog](https://keepachangelog.com/zh-TW/1.1.0/)，版本遵循[語意化版本](https://semver.org/lang/zh-TW/)。

## [Unreleased]

依 OWASP Top 10 for LLM Applications 2026 與 MITRE ATLAS 修正設計：白箱評議陣容改為 Claude／DeepSeek／GLM／Gemini，並加上確定性 AI 安全規則與信任邊界防護。

### 變更（依 OWASP LLM Top 10 2026／MITRE ATLAS 修正設計）
- **白箱評議陣容改為 Claude／DeepSeek／GLM／Gemini**：移除 Nemotron 與 ChatGPT（`nemotron`／`chatgpt` 模型別名、`NVIDIA_API_KEY`／`OPENAI_API_KEY` 不再使用）。DeepSeek 接手防禦與資源審查並負責白箱測試生成與黑箱攻擊合成、GLM 接手規格與合約審查（live 實測中 GLM-5.3 在 12 次攻擊合成中有 8 次把 16k 輸出額度全用於思考而回應空白，故攻擊合成改由 DeepSeek 負責）；新增 **Gemini「AI 整合與供應鏈審查」**，依 OWASP LLM01～LLM10:2026 審查呼叫模型的程式。交叉驗證者同步為四位。預設模型改用帶版本號的 id（`claude-sonnet-5-5`、`zai/glm-5.3`、`deepseek/deepseek-v4-pro`），供應商端的模型替換會在報告中可見
- **審查者改由設定檔驅動**：所有 `whitebox_reviewer_*` 項目都會被使用，名稱、模型與 `focus` 實際帶入提示詞（過去名單寫死三位，設定檔的 `focus` 不生效）；沒有任何審查者時列為證據缺口。少於兩個模型家族時提示無法交叉驗證（LLM07:2026）
- **未設定的 agent 不再默默路由到 `gpt-4o`**：改解析為 `unconfigured` 別名，hybrid 模擬、live 直接失敗
- **品質閘門**：確定性 AI 安全規則 HIGH 以上的命中會使判定為 `NEEDS_FIXES`（exit 1）

### 新增（安全設計）
- **確定性 AI 安全規則 `VH-AI-001`～`009`**（`agents/whitebox/ai_static_scanner.py`，不經模型）：`trust_remote_code=True`、`torch.load` 未設 `weights_only=True`、pickle 類反序列化、Hub 模型未固定 `revision`、LLM 呼叫無輸出上限、模型輸出流入 `eval`／`exec`／shell／SQL、寫死的憑證、隱形／雙向控制字元、對 AI 審查者下指令的注釋；每條規則標註 OWASP LLM 2026、MITRE ATLAS 技術與 CWE，並出現在 Markdown／JSON／SARIF（`vibeharness/VH-AI-00x`）
- **不受信任程式碼通道（LLM01:2026、AML.T0051.001）**：送給任何模型的程式碼先去除隱形字元與遮蔽密鑰（LLM02:2026、AML.T0055），包在 `<untrusted_target_code>` 標記內（偽造的結束標籤會被中和），所有讀程式碼的 agent 系統提示附加安全政策；偵測到植入的審查者指令或隱形字元時列為證據缺口，不可能得到 `READY_TO_SHIP`
- **OWASP LLM Top 10 2026 威脅建模**：`threat_rules.yaml` 新增 `owasp_llm_top10_2026`（ATLAS tactic／technique 與 CWE 對應）；目標匯入 AI SDK 時威脅建模自動套用，威脅新增 `atlas_mapping` 欄位，報告威脅表新增 MITRE ATLAS 欄
- **報告輸出消毒（LLM10:2026、AML.T0077）**：模型文字進入 Markdown 前停用圖片與原始 HTML、移除 ANSI／OSC 控制序列；console 跳脫 rich markup；SARIF 訊息去除控制字元
- **生成測試禁止安裝套件**（slopsquatting，LLM04:2026、AML.T0060）：`pip install`、`import pip` 等一律被靜態閘門拒絕
- **模型端點只允許 https**（http 僅限 loopback），設定錯誤在啟動時以 `ConfigError` 失敗；每次模型呼叫記錄 `prompt_sha256` 供稽核追溯
- 審查者可回報選填的 `owasp_mapping`；報告列出審查模型與偵測到的 AI 元件
- **依模型設定輸出上限**（live 實測發現）：`models.<alias>.max_output_tokens` 覆蓋全域值；全域預設由 4096 提高為 `16384`：思考 token 也算在上限內，4096 會讓 Gemini 3 的測試生成回應空白或被截斷，也會截斷 Claude 的威脅模型 JSON（上限只是封頂，成本仍由 `max_model_calls` 管控）；單次模型請求逾時 `timeout_seconds` 也由 60 秒提高為 180 秒，因為 Opus 產出長威脅模型 JSON 時超過 60 秒。被截斷的回應改記錄為「output truncated at the max_output_tokens limit」而非籠統的「not valid JSON」
- **不支援的取樣參數改為丟棄而非失敗**（live 實測發現）：Bedrock 上的 Claude Opus 5.5 只接受 `temperature=1`，過去每次呼叫都失敗並退回備援模型；改傳 `drop_params`。另外 Bedrock 等以 AWS 憑證驗證的模型可設 `aws_profile_name`／`aws_region_name` 取代 `api_key_env`；空白回應會記錄 `finish_reason`（例如安全過濾的 `content_filter`）
- **報告保存生成的測試程式碼**（稽核軌跡）：Markdown 新增附錄「Generated Test Code」，以可收合區塊列出每個白箱／黑箱測試的程式碼、來源發現／威脅與執行結果；JSON 新增 `generated_tests`／`blackbox_generated_tests`，原封不動保存程式碼。live 實測發現部分「通過」的測試其實是在斷言缺陷本身，沒有程式碼就無法稽核。程式碼區塊的 fence 會依內容中最長的反引號自動加長（原本 PoC 區塊遇到四個反引號會被跳出，一併修正）

### 修正（設計文件列出的缺口）
- **審查／驗證批次崩潰列為證據缺口**：reviewer 或 verifier 的批次在 gateway 之外拋出例外時，過去只記 log、該批當成空結果，`call_log` 沒有紀錄，閘門看不到缺席的審查；現在經 `LLMGateway.record_failure` 記成一筆 `invalid` 呼叫（原因附例外），證據缺口訊息逐一列出 agent 與原因
- **單一 reviewer 模型列為證據缺口**：所有 `whitebox_reviewer_*` 都指向同一模型時，過去只在終端機警告；現在也寫入 `inconclusive_reasons`（判定不會是 `READY_TO_SHIP`；OWASP LLM07:2026）
- **報告消毒補齊**：Markdown 的證據缺口清單與「Threats Not Tested」清單原本沒有經過 `markdown_safe`／`_code_span`，模型選定的 threat id 或失敗文字可以插入圖片、HTML 或跳出反引號
- **缺 `model_alias` 的 agent 一律顯示為 `unconfigured`**：reviewer 與 verifier 過去用 agent_id 後綴當 alias（報告顯示一個從未被呼叫的模型，debater 的「不評自家」判斷也比對錯 alias），現在與 gateway 的路由一致；finding id 為 `WB-UNC-NN`
- **設定檔 `max_files` 驗證**：負數、布林或非整數改為 `ConfigError`（exit 5），與 `max_model_calls`／`max_concurrent_calls` 相同；過去負數會被當成切片、字串會被 `int()` 默默轉換
- **以 root 執行測試套件時兩個 Docker 測試失敗**：測試現在先建立 run_dir（正式路徑一定先 `mkdtemp`），並新增以假 uid 驗證 root 分支把 run_dir 開放給 `nobody` 的測試

### 文件
- 新增設計文件 `docs/design.md`：架構與元件職責、六階段資料流、資料模型、LLM gateway 模式決策、白箱／黑箱子系統、確定性規則、沙盒安全模型、品質閘門的 15 項證據缺口與判定順序、報告格式、信任邊界、設定擴充點、並行與成本模型、測試策略、已知限制與設計決策紀錄（引用 commit `f087dfb` 的檔案行號）
- 修正文件與程式不一致：`docs/configuration.md` 的單一金鑰範例把 `blackbox_test_synthesizer` 原值寫成 `glm`（實為 `deepseek`）；`threat_rules.yaml` 檔頭與 `docs/configuration.md` 宣稱 `stride_categories.<key>.description` 會進提示詞，實際只讀 `name` 與 `common_vibe_bugs`

## [0.2.0] - 2026-10-07

深度審查後的打包、模型輸出韌性、執行正確性與 SARIF 修正，以及測試合成平行化與成本護欄；第二輪驗證補上執行歸因誠實度、閘門防誘餌與工程收斂；第三輪強化涵蓋 mypy 加嚴、CI 供應鏈防護與覆蓋率門檻上調。

### 新增
- **JS/TS 擷取器改寫**（PR #19）：改為無相依的 lexer 加真正的大括號／括號配對——先遮蔽字串、template literal（含 `${}` 巢狀）、註解與 regex literal，註解或字串內容不再造出假宣告；函式、箭頭函式與路由的行範圍正確（過去是固定 15／25 行視窗，會截斷長函式、重複相鄰符號）；支援 generator、async、多行簽名、裸參數箭頭函式與 class method（constructor／static／async，`if`／`while` 不再被誤認）；路由支援任意 receiver（app／router／server／fastify…）與字串或 template literal 路徑，Next.js App Router 以 HTTP 動詞命名的 handler 標為路由
- **白箱測試生成與黑箱攻擊合成改為平行**：與審查／驗證階段相同以 thread pool 並行呼叫模型，輸出順序（test id、報告）維持確定；單一 finding／threat 失敗不再拖垮其他項目（live 模式仍大聲失敗）
- **威脅建模多批次平行化**：`AutomatedThreatModeler` 多批次符號審計改以 thread pool 並行呼叫模型，消除大型專案 Phase 4 串行瓶頸，維持輸出確定性
- **成本護欄 `max_model_calls`**（CLI `--max-model-calls`）：限制每次執行的真實模型呼叫數，並行下計數精確；用完時 hybrid 退回模擬並列為證據缺口（不會給 `READY_TO_SHIP`）、live 直接失敗
- **可調整的上限**：`max_concurrent_calls`（並行度）與 `max_files`（CLI `--max-files`，過去寫死 50）

### 修正
- **審查、去重與黑箱合成的確定性與精度**（PR #18）：去重改為遞移的 union-find，corroborator 清單排序，同嚴重度以 finding_id 決定平手，複數詞幹化不再弄壞 `classes`／`address`；符號比對優先完全同名、再退到後綴，沒指名符號的 finding 保持未解析而不是釘到該批第一個符號；finding id 依 reviewer agent 編號並去重，兩個 agent 共用同一 model alias 也不撞號；黑箱符號相關性改用整字比對（`username` 不再拉進 `get_user`），live 模式下攻擊程式碼指向非 base URL 主機時靜態拒絕；`render_symbols` 超過預算改為截斷而非整塊省略；報告遇到無法辨識的 `overall_status` 顯示 UNKNOWN 徽章，誤傳成字串的清單欄位顯示為一項而不被逐字元拆開
- **`pytest.fail` 資安突破誤判**：執行器 `_is_assertion` 納入 `pytest.fail()` 產生的 `Failed:` 訊息，黑箱突破如實標記為 `is_security_exploit_confirmed`，不再被誤判降級為 `INCONCLUSIVE`
- **LLM JSON 解析多層容錯**：`_clean_and_parse_json` 支援自然語言前後綴包裹、非正規/未閉合 code fence 與多區塊提取，大幅降低 live 模式因模型輸出格式偏差導致的 `invalid` 錯誤
- **安裝後無法執行**：wheel 先前未包含 `config/agents_config.yaml`／`threat_rules.yaml`，`pip install` 後的 `vibeharness` 一律以「Agent config not found」失敗（exit 5）；現在隨套件安裝。threat rules 缺失或損壞時改為記警告而非靜默略過
- **模型回傳 `null` 欄位導致整個 pipeline 崩潰**：測試產生器與攻擊腳本合成器遇到 `"title": null` 等非字串欄位時會丟 `ValidationError`；現在一律退回預設值。reviewer 欄位同樣容錯，只有標題與描述皆不可用的 finding 才捨棄
- **`from __future__` 匯入的生成測試一律 ERROR**：harness 標頭改插在 docstring／`__future__` 匯入之後
- **跨批次威脅未去重**：同一威脅（STRIDE 分類＋標題＋攻擊向量，正規化後相同）只保留一筆並取最高 severity，不再每批重複合成與執行同一個攻擊
- **離線 probe 會呼叫無必填參數的函式**：`main()`、`run_server()` 這類函式不再被 probe 執行（過去會觸發真實副作用或卡到逾時）
- **黑箱測試不再自動探測 `localhost:8000`**：`--base-url` 預設改為無；只有明確指定時才進入 Live HTTP 模式，避免攻擊腳本打到本機無關服務
- **白箱誤判**：生成測試以錯誤簽名呼叫目標（`TypeError` 且發生在測試模組本身）改判為 ERROR，不再算成目標缺陷而給出 NEEDS_FIXES
- **SARIF**：不再輸出 `"locations": null`；無法歸屬的 finding（`unknown`）不再產生假 URI；URI 以 git repo 根目錄為基準；規則 id 改為固定值、指紋對大小寫與標點不敏感；黑箱突破盡量帶上被攻擊符號的位置
- **Docker 沙盒**：容器內 `timeout` 兜底改用該次執行的預算（逐一重跑時為單測預算，而非整批預算）
- **交叉驗證**：接受字串形式的 index（`"0"`），拒絕布林值（`True` 過去會被當成 1）
- **`.gitignore` 完善**：補齊 `.venv/`、`*.sarif`、`report.json` 等快取與報告檔案

### 修正（第二輪驗證）
- **執行器誠實歸因**：沙盒 junit 報告損毀／無法解析時如實回報「report could not be parsed」，不再誤報成「no tests collected」；逐一重跑時的解析失敗同樣如實標記。目標模組 import 即崩潰（語法錯誤、缺失依賴）改為歸因給目標（"Target code is broken and was never exercised by this test"，附真實例外訊息），不再讓測試背黑鍋；測試自身的 import 錯誤仍歸責測試；一般失敗訊息優先取 pytest traceback 的 `E` 行
- **父目錄同名模組遮蔽目標**：沙盒 sys.path 改為目標目錄優先，父目錄同名模組不再遮蔽被測模組
- **驗證逐批隔離**：交叉驗證單一批次拋出非閘道例外時記 log 並以「無共識」處理該批，不再中止整個仲裁；閘道錯誤在 live 模式仍大聲失敗
- **威脅規則降級**：threat_rules.yaml 的 `stride_categories`／`owasp_api_top10` 結構錯誤（null、非字串、非 dict 項目）安全降級為無指引並記警告，不再丟 `AttributeError` 崩潰
- **SARIF 家目錄防護**：家目錄本身是 git repo（dotfiles）時，`sarif_root` 不再將家目錄當作 repo 根（改以 `os.path.samefile`＋大小寫正規化比較），避免所有 finding 誤掛到 dotfiles repo
- **LLM 回應 any-of 鍵驗證**：`generate()` 新增 `required_keys_any`，測試生成器要求 `tests` 或 `code` 至少其一，廢話回應不再靜默產出零測試
- **URL 防護正確解析 IPv6 與 userinfo**：`scenario_builder` 改用 `urlsplit().hostname`（`[::1]`、帶帳密的 URL 不再遮蔽 host），解析失敗一律 fail closed
- **崩潰時印出完整 traceback**：CLI 非預期例外不再只有 `type: message` 一行
- **fallback 威脅 id 不再跳號**：模型自帶 id 時不再消耗 fallback 計數器，THREAT-XX 編號連續
- **空測試閘門防誘餌**：巢狀且從未呼叫的 helper 內之 `assert` 不再算數（僅實際被呼叫的 helper 可滿足閘門）；移除未使用的 `top_level_test_functions`
- **非 Python 目標的揭露與指引**：偵測到 JS/TS 時列為證據缺口（沙盒只執行 Python，無動態驗證）；`import_instructions` 對非 .py 檔明確告知不可 import／執行，不再給出必敗的 importlib 指引
- **雜項**：報告的偵測語言清單排序輸出（確定性）；test-generator 自癒日誌以 finding id 標識（過去的整數索引與測試無關）；乾淨目標的證據缺口訊息改寫得更明確（列出哪些邊界未被驗證）

### 工程
- CI 新增 `package` job，`publish` 的 smoke test 也改為：建置 wheel、在 checkout 之外安裝並實際以 mock 模式跑一次稽核
- `pyproject.toml` 依賴上界與 `requirements.txt` 對齊（`pydantic<3`、`litellm<2`）
- 新增 `tests/test_quality_fixes.py`（每項修正皆有 regression test，且已確認在修正前會失敗）

### 工程（第二輪驗證）
- **lint 工具釘版**：CI lint job 改從 `requirements-dev.txt` 安裝（ruff==0.16.10、mypy==2.4.0），pre-commit ruff hook 對齊升級（v0.6.9 → v0.16.9）
- **requirements-dev.txt 補齊**：加入 `build` 與 `pytest-cov`（與 CI 一致）
- **threat_rules.yaml 註解**：標明哪些欄位是功能性的（會進 prompt）、哪些僅為文件
- CI 測試 job 加 coverage 總量門檻（`--cov-fail-under`）

### 工程（第三輪強化）
- **mypy 檢查加嚴**：`check_untyped_defs = true`（未加註解的函式本體也檢查型別），`core/sandbox.py` 改以 `sys.platform` 判斷讓 mypy 完成窄化，全套 0 錯誤
- **CI Actions 以 commit SHA 釘版**：checkout／setup-python／pypa publish action 全部改釘完整 SHA（保留 tag 註解），tag 被改寫不再影響 CI
- **依賴漏洞稽核**：新增 `audit` job，以 pip-audit 掃描 `requirements.lock` 的完整解析結果（每個 PR 都執行，含已知 CVE 的依賴升級會擋在合併前）
- **選配 PyPI 發布**：publish workflow 新增 `pypi-publish` job，以 Trusted Publishing（OIDC）發布 wheel／sdist；需設定 repo variable `ENABLE_PYPI_PUBLISH=true` 才啟用，未設定時跳過
- **覆蓋率門檻上調至 93%**：補上 reviewer ensemble 容錯、threat modeler 規則降級與 coverage 表解析的 regression tests（CI 209 passed、總覆蓋率 93.48%）

## [0.1.2] - 2026-10-03

深度審查後的正確性、誠實性與工程基礎建設總整理（PR #13、#14、#15、#16）。

### 修正
- **沙盒穩定性**：逾時殺掉程序樹後以有界等待排空管道，daemonize 出新 session 的孫行程不再能讓整個 run 無限掛死；逾時哨兵碼改為 124／執行失敗 125，與 SIGHUP／SIGINT 訊號死亡脫鉤
- **Exit code 語意分離**：新增 usage code 5（`--target` 不存在、config 缺失或 YAML 損壞、沙盒不可用、CLI 誤用、未預期崩潰）；exit 1 從此專屬 NEEDS_FIXES，CI 不會把 harness 錯誤誤讀成「目標有缺陷」；未知判定字串改為 fail closed（exit 3）
- **品質閘門誠實度**：黑箱攻擊測試「失敗但未分類為 exploit」現在計入 `blackbox_tests_failed` 並列為證據缺口（過去會被静默吞掉，閘門仍可給 READY_TO_SHIP）；無斷言空測試閘門不再被 `mock.assert_called_once()` 等假斷言騙過
- **防注入**：生成測試標頭的 LLM metadata 會剝除換行，無法再繞過 `check_test_code` 靜態檢查注入程式碼；fence 剝除支援 `python3`／`Python` 等語言標籤且不再殘留進程式碼
- **威脅建模覆蓋率**：目標符號改為分批送審（與白箱審查相同的 token 預算切分），大目標不再静默漏掉多數符號；各批威脅合併並對重複 id 重新編號
- **交叉驗證計數**：Confirmed 統計扣除同票保留（undecided）的發現，與共識摘要文字一致
- **Docker 沙盒強化**：harness 以 root 執行時容器改用 `nobody`；`/tmp` tmpfs 加 `noexec,nosuid`；容器內 `timeout` 兜底（host 端 `rm -f` 失敗也不會永續執行）；`custom_env` 過濾憑證類 key 與 `BASH_ENV`/`LD_PRELOAD` 等注入向量；僅改寫目標自身路徑，sibling 路徑保留原貌以利診斷
- **執行器**：JUnit 模組 regex 支援 ≥1000 個模組；容器回傳的壞 `time` 屬性不再炸解析；單模組批次逾時如實回報；逾時重跑受批次預算上限約束；部分 skip 的模組明確標註
- **其他**：reviewer 單批失敗不再丟棄其他批結果（live 模式仍大聲失敗）；未知 severity／STRIDE 分類改為記 log；伺服器健康探測加重試；非 UTF-8 目標檔優雅降級；PoC 含三反引號時自動加寬 fence；AST 擷取納入 `*args/**kwargs` 與類別裝飾器

### 工程
- **依賴鎖定**：新增 `requirements.lock`（`uv pip compile --universal --python-version 3.10`，含版本感知 marker，覆蓋 3.10–3.13）；`litellm`／`pydantic` 加上界；CI 與沙盒映像改用與 lock 一致的固定版本
- **靜態型別檢查**：mypy 進 CI（修正全部 28 處型別問題）；`requirements-dev.txt` 加入 mypy
- **CI 衛生**：`push` 僅觸發 master（修掉 PR 分支重複跑兩次）；`permissions: contents: read`；各 job 加 `timeout-minutes`；測試矩陣補 3.11／3.12（共 2 OS × 4 版本）；pip cache 以 lock 為 key
- 測試增至 123 項（含真實 Docker 容器沙盒測試）

## [0.1.1] - 2026-10-03

### 新增
- `--sarif <路徑>`：輸出 SARIF 2.1.0 報告供 GitHub Code Scanning 使用——白箱確認 findings 帶檔案/行號位置（依 `line_number` 或符號表解析），黑箱確認的資安突破列為 error 級結果
- 文件雙語化與 README 改版：新增 Mermaid 流程架構圖、各 Agent 分工表、`docs/configuration.md` 設定檔欄位完整參考（正體中文與英文對照：README.en.md、CHANGELOG.en.md、docs/configuration.en.md）

## [0.1.0] - 2026-10-03

首次發布。

### 新增
- 雙引擎檢測流程：白箱異構多模型交叉審查（Claude / Nemotron / ChatGPT / Gemini）與辯論式交叉驗證（非作者模型投票、共識比例計算、仲裁機制）
- 黑箱檢測：STRIDE / OWASP 威脅建模驅動的動態攻擊測試（BOLA、Mass Assignment、Injection 等）
- 沙盒執行環境：本機子程序與 Docker 容器（唯讀掛載、預設無網路、環境變數密鑰隔離、批次逾時後逐測試重跑）
- 審計報告：Markdown 與 JSON（`--format md|json`），含執行溯源（Execution Provenance）、模擬結果 `[SIMULATED]` 標示、證據缺口揭露
- CLI：`--version`、`--format`、`live` / `hybrid` / `mock` 三種模式，以及品質閘門 exit code（0 / 1 / 2 / 3 / 4）
- 模型容錯：`fallback_model` 支援、模型輸出畸形時優雅降級（不捏造結果）、無模型測試的威脅列為「Threats Not Tested」
- 打包與安裝：`pip install .` 後提供 `vibeharness` 指令，版本單一來源為 `core/__init__.py`

### 工程
- 98 個單元測試（含 Docker 容器沙箱測試，於 CI Linux runner 執行）、程式覆蓋率約 93%
- ruff 靜態檢查與 pre-commit 整合
- CI 矩陣：ubuntu / windows × Python 3.10 / 3.13，含 lint 與覆蓋率報告
- MIT 授權
