# Changelog

正體中文（臺灣）｜ [English](CHANGELOG.en.md)

本專案所有重要變更都會記錄在本檔案。格式參考 [Keep a Changelog](https://keepachangelog.com/zh-TW/1.1.0/)，版本遵循[語意化版本](https://semver.org/lang/zh-TW/)。

## [Unreleased]

### 變更

- 五個代理的模型呼叫改經新的 `vibeharness/core/agent_call.py`：代理以 `AgentCall` 宣告一種呼叫（回答的 schema、items 在哪裡、把一次呼叫的 items 對應成模型的 mapper、用到的不可信通道、略過項目時的訊息與模擬輸出），`ask` 依內容種類把不可信片段包進對應的通道、依宣告插入通道的 policy、經閘道呼叫，只把可用的 items 交給 mapper，回傳 `AgentReply`（型別化的 items、來源與唯讀的頂層欄位）；測試生成的修復呼叫改走純文字的 `ask_text`。過去每個代理各自組提示、各自再檢查一次清單的型別、各自讀來源，交給 `fan_out` 的 fallback 也有五種形狀。送給模型的提示、報告、JSON、SARIF、呼叫紀錄與結束碼都不變。
- 審查者的一次呼叫已被閘道記成無效，或批次在閘道之外當掉之後，審查者不再多記一行「略過 … 無法使用的發現清單（收到 NoneType）」；威脅建模同樣不再多記「略過模型無法使用的威脅清單（收到 NoneType）」。那次失敗仍由閘道（或 `fan_out` 的錯誤 log）記錄一次。
- `LLMGateway.generate` 回答的 `ModelAnswer.data` 改為唯讀的 mapping，共用的 `NO_ANSWER` 因此不可能被改到。直接呼叫 `generate` 並修改 `data` 的程式要先複製一份（`dict(answer.data)`）。

### 測試

- 新增 `tests/test_agent_call.py`，只透過 `ask`／`ask_text` 測試代理呼叫：items 從宣告的鍵取出並交給 mapper、提示的組裝與 policy 的順序、內容種類對應的通道與偽造標籤的中和、只有可用的 items 到 mapper（含位置與兩種略過訊息）、重問後仍不合形狀時不呼叫 mapper、模擬輸出、兩種回答即 item 的來源、唯讀的頂層欄位與 `NO_REPLY`，以及純文字呼叫。
- 十七個以假的 `gateway.generate` 給回答的測試，改成真的閘道加 `scripted` transport、依請求回答；原本依並行呼叫的順序取回答的，改依提示內容取，不再有競爭條件。兩個原本鎖定閘道會拒絕之形狀的測試，改成經 transport 送出那個回答，並斷言它是一筆無效呼叫。測試在閘道之外當掉的六個測試仍在 `gateway.generate` 注入錯誤（transport 無法表達這種當機），但只讓當掉的那次呼叫拋出例外，其他呼叫照常經過閘道。`tests/model_answers.py` 不再使用，已刪除。

### 文件

- 設計文件描述 `vibeharness/core/agent_call.py`（module 表、新的第 5.8 節，以及第 5.3、5.7、6、8、12、14.1、16 章與測試章節），關鍵函式索引加上它與各代理的呼叫宣告與 mapper，行號引用改對到 commit `5aefd37`。
- `GLOSSARY.md` 加上「代理呼叫 ／ Agent call」。
- README 的專案結構列出 `core/agent_call.py` 與 `tests/test_agent_call.py`。

## [0.13.0] - 2026-10-17

架構整理輪：品質閘門、設定、模型呼叫的傳輸、並行的模型呼叫、發現的身分識別與模型回答的形狀檢查各自集中到一個模組；沙盒、檔案範圍、規則掃描與模型回答改以型別化的值回傳。鍵在、形狀卻不對的模型回答不再被讀成「零個發現」而放行；`--estimate` 不再多算驗證者的呼叫；使用 `--baseline` 時，報告的規則命中列分開新的與已知的命中；第一個威脅建模批次當掉時，報告欄位不再被清成預設值。基準線與 SARIF 的 fingerprint 完全不變。直接呼叫 `LLMGateway.generate`、`execute_pytest_files`、`execute_test_suite` 或 `select_symbols` 的函式庫程式要改讀新的回傳型別（見「變更」）。

### 新增

- JSON 報告的 `summary.new_blocking_rule_hits`：計入判定結果的 HIGH 以上確定性規則命中數（有 `--baseline` 時只算基準中沒有的）。屬於新增欄位，`schema_version` 維持 "2"。

### 變更

- 品質閘門的判定改在單一位置 `vibeharness/core/gate.py`（`evaluate(GateEvidence) -> GateResult`）決定，不再寫在 `run_full_pipeline` 裡；四種判定結果與其結束碼只在 `vibeharness/core/verdict.py` 定義一次，由 CLI 與 Action runner 共用。僅為內部變更：報告、`--summary-json`、結束碼與終端機輸出都不變。
- 設定檔改由新的 `vibeharness/core/settings.py` 裡的 `load_settings` 只載入、套用預設值並驗證一次，產生凍結的設定樹，供閘道、harness 與 `--estimate` 讀取；CLI 的旗標以覆寫值傳給它，不再於 harness 建構之後修改它。每個預設值都定義在那裡，並以舊名稱重新匯出；探索到的設定檔檢查在載入時一併執行。每個鍵都維持文件所寫的 null／0 規則、訊息與結束碼。
- 同一次執行同時有設定問題與目標或旗標問題時（例如 `--config` 的值錯誤又缺少 `--target`），現在先回報設定問題；過去要到建構 harness 時才回報，排在目標與旗標的檢查之後。兩種情況的結束碼都是 5。`--cache-dir` 現在在檢查目標與旗標之前就建立，無法使用的 Docker 沙盒則在所有設定問題之後才回報。
- 模型呼叫改經新的 `vibeharness/core/transport.py` 接縫：閘道對每次模型嘗試送出一個 `ModelRequest`（帶 `agent_id`、模型別名、候選模型字串、messages 與原樣的 litellm 參數），由 `ModelTransport` 回一個 `ModelReply`。預設的 `LiteLLMTransport` 是唯一 import litellm 的地方；`LLMGateway` 與 `VibeHarnessCommander` 接受 `transport=`。模式、預算、回應快取、fallback 順序、重問與來源紀錄都留在閘道。僅為內部變更：報告、呼叫紀錄與結束碼都不變。
- 模擬輸出改由各代理以 `generate(..., simulated=fn)` 提供（審查者、威脅建模者、驗證者、測試生成器與攻擊合成器各自的範本），閘道不再依代理名稱編造回答；代理的模型別名統一由 `GatewaySettings.alias_for` 解析。模擬的內容不變。
- 審查者、驗證者、測試生成器、威脅建模者與攻擊合成器並行的模型呼叫改由新的 `vibeharness/core/fanout.py` 執行：代理只交出呼叫清單（`Call(agent_id, label, run)`）與當掉時的 fallback，執行緒池大小、依呼叫順序收集、取消、live 失敗時的中止、錯誤 log 與 `record_failure` 都在這一個模組裡。刪除 `vibeharness/agents/whitebox/common.py`。這一步本身不改變行為；修正一節的兩個條目是隨後在同一個模組上做的修正。
- 發現、威脅與靜態命中的身分識別集中到新的 `vibeharness/core/identity.py`：模型文字的正規化（`normalize`、`key_text`）、位置規則、嚴重度順序（`severity_rank`，取代去重與威脅建模各自的一份），以及 `--baseline` 的鍵與 SARIF 的 partialFingerprints（`sarif_static_fingerprint`／`sarif_finding_fingerprint`／`sarif_breach_fingerprint`）並排定義；威脅合併改用同一個 `normalize`，不再有自己的副本。`vibeharness/core/baseline.py` 保留載入、比對與加註，並以舊名稱重新匯出這些函式。每個基準線 fingerprint 與 SARIF 指紋都逐位元組不變，既有的基準與 Code Scanning 警示照常相符；修正一節的兩個條目是隨後在這個模組上做的修正。
- 模型回答的解析與形狀檢查移到新的 `vibeharness/core/model_output.py`（`parse_json_object`、`OutputSchema`、`check_output`，皆為純函式）：每個代理宣告它期望的回答形狀，`generate(..., schema=)` 取代 `required_keys`／`required_keys_any`；閘道保留重問、回應快取、呼叫紀錄與來源標記。修正一節中形狀錯誤與 `tests` 退回 `code` 兩個條目是隨後在這個模組上做的修正。
- 執行器與沙盒改以回傳值交出結果：`execute_pytest_files` 回傳凍結的 `SandboxRun`（結束碼、stdout、stderr、執行時間、行涵蓋率與 JUnit 報告），取代六元組；執行器只依賴 `vibeharness/core/sandbox.py` 的 `Sandbox` Protocol，不再以 `getattr` 替沙盒補預設值（預設值改由 `LocalSubprocessSandbox` 提供）；`execute_test_suite` 回傳 `SuiteResult`（結果、Python 與 JS/TS 的行涵蓋率、JS/TS 涵蓋率算不出來的原因、JS 執行器的問題與 Node 執行環境），取代 `(結果, Python 涵蓋率)` 加上事後讀取的 `last_js_line_coverage_pct`、`js_coverage_unavailable_reason` 與 `js_runner_unavailable_reason`。Node 執行環境的選擇移到 `sandbox.py` 的 `build_node_sandbox`（回傳 `NodeRuntime`）；docker 映像檔內的 Node 版本由 `NodeDockerSandbox.probe_node_version` 偵測，TypeScript 旗標由沙盒自己設定（`with_probed_node`）。harness 不再呼叫沙盒的私有方法，刪除 `_build_node_sandbox`、`_docker_node_version` 與 `node_runtime`、`node_runtime_problem`、`node_typescript_problem` 屬性，改從 `SuiteResult.node_runtime` 讀取。另刪除沒有任何呼叫者的 `LocalSubprocessSandbox.execute_python_code`（改用 `execute_pytest_files({"test_exec.py": 程式碼})`）。直接呼叫這些方法的程式碼要改讀欄位；報告、`--summary-json`、判定與結束碼不變（修正一節中沒有 Node 時每個測試的原因除外）。
- `--estimate` 改為加總各代理回報的呼叫計畫，不再抄一份代理的分批與分派規則：審查者、驗證者、測試生成器、威脅建模者與攻擊合成器各有 `plan(...)`，回傳一組 `PlannedCalls`（新定義在 `vibeharness/core/fanout.py`：呼叫數、是否為 JSON 呼叫、每次呼叫的程式碼 token、是否為執行前就已知的精確值、修復這類有條件的呼叫與每次最多幾次），審查者與威脅建模和自己的執行路徑共用同一個分批 helper，驗證者、測試生成器與攻擊合成器依同樣的派工規則計數；`tests/test_call_plans.py` 釘住每個計畫等於實際發出的呼叫。測試生成器、威脅建模者與攻擊合成器公開 `AGENT_ID`（審查者與驗證者的 id 來自設定檔），測試生成器另公開 `HEAL_ATTEMPTS`（2）；`estimate.py` 刪除 `_PER_FINDING_CODE_TOKENS`、`_HEAL_ATTEMPTS_MAX` 與審查者、威脅建模批次排序的副本。這一步本身不改變行為：`--estimate` 的文字與 JSON 輸出逐位元組不變；「修正」中驗證者呼叫數的那一項是之後在驗證者計畫上做的修正。
- 呼叫計畫的種類改為 `vibeharness/core/fanout.py` 的 `CallKind` 列舉（審查者、驗證者、測試生成、修復、威脅建模、攻擊合成；值和原本的字串相同），`PlannedCalls.kind`、各代理的計畫與 `--estimate` 的提示開銷／典型輸出表都用它，不再是散落各處的字串。修復計畫自己帶被修測試的估計大小（測試生成器的 `HEAL_CODE_TOKENS`，1200），`estimate.py` 刪除 `_HEALED_CODE_TOKENS` 與對修復的特判。僅為內部變更：`--estimate` 的文字與 JSON 輸出逐位元組不變。
- 呼叫計畫的介面收斂：`WhiteboxTestGenerator.plan` 與 `ThreatScenarioBuilder.plan` 的參數改名為 `finding_count`／`threat_count`（收的是數量，不是清單）；白箱批次數改由 `HeterogeneousReviewerEnsemble.batch_count` 回答（沒有符號或沒有審查者時是 0），不再從計畫數反推；`--estimate` 的說明文字改用 `MultiModelDebater.assigned_findings`（驗證者分到幾筆發現）與 `_typical_calls`（典型呼叫數），不再自己重算一次。僅為內部變更：`--estimate` 的文字與 JSON 輸出逐位元組不變。
- 主控台串流防護集中在新的 `vibeharness/core/stdio.py`（`force_utf8_stdio`，只用標準函式庫）：CLI、Action runner 與 harness 都用它。過去 `action_runner.py` 從 CLI 匯入私有的 `_force_utf8_stdio`，harness 另有一份只處理 Windows 的同名函式，CLI 兩個都呼叫。`vibeharness.core.harness.force_utf8_stdio` 仍可匯入。CLI 與 Action 的行為不變。
- 第 1 階段的檔案範圍改為回傳值：`VibeHarnessCommander.select_symbols` 回傳 `(symbols, ScopeResult)`，`ScopeResult`（`vibeharness/agents/whitebox/ast_extractor.py`，不可變）收著這次走訪分析了哪些檔案、哪些因為什麼原因沒有分析、設定類檔案、偵測到的語言與套用的篩選描述；閘門的證據、主控台、Node 沙盒的 TypeScript 判斷與 `--estimate` 都讀它，不再讀擷取器在最後一次呼叫後留下的屬性。新增 `ASTExtractor.scan_directory`；`parse_directory` 與那些屬性保留不變。直接呼叫 `select_symbols` 的程式碼要改讀 `scope.filters`（原本的第二個回傳值）。
- 確定性規則掃描的結果也改為回傳值：`AISecurityStaticScanner.scan(source_files, config_files)` 回傳不可變的 `ScanResult`（命中、AI 元件、未完整掃描的原始碼與設定類檔案），harness 的第 1 階段與閘門讀它，不再讀掃描器在最後一次呼叫後留下的 `ai_components`／`incomplete_files`／`incomplete_config_files`。`scan_files`、`scan_config_files` 與那些屬性保留不變。
- `LLMGateway.generate` 改回傳不可變的 `ModelAnswer`（`vibeharness/core/llm_gateway.py`）：模型回答的 JSON 物件在 `data`（`json_output=False` 時原文在 `text`），來源在 `mode`、`model`、`reason`、`cached`，並有 `simulated`／`usable`；過去來源以 `_provenance` 鍵混在回答的資料裡，`json_output=False` 的原文是 `{"raw": ...}`。`PROVENANCE_KEY` 與閘道的 `is_simulated`／`is_usable` 已移除。直接呼叫 `generate` 的程式碼要改讀 `ModelAnswer` 的欄位。

### 修正

- 使用 `--baseline` 時，報告的「確定性 AI 資安規則命中」列會計入所有 HIGH 以上的命中，包括判定已忽略的已知命中，因此 `READY_TO_SHIP` 或 `INCONCLUSIVE` 的報告可能顯示「2 HIGH+」而目標是「0 HIGH+」。現在新的與已知的命中分開列出（例如「0 個新的 HIGH+，2 個基準中已知」，目標為「0 個新的 HIGH+」）。沒有 `--baseline` 時該列不變。
- 審查者、驗證者與測試生成器在 live 模式的呼叫失敗時，過去要等主執行緒依序收集到那個失敗才取消尚未開始的呼叫；主執行緒還在等前面較慢的呼叫時，佇列中的呼叫會繼續開始並付費。現在與威脅建模者、攻擊合成器相同，在失敗的那個工作執行緒裡就中止整批，佇列中的呼叫不會開始。只影響已經會以 exit 4 結束的執行。
- 測試生成在閘道之外當掉時（例如處理模型回答時拋出例外），過去只寫一行錯誤，該發現只顯示為「沒有模型產生的測試」；現在與其他代理相同，記成一筆 `whitebox_test_generator` 的無效呼叫（原因為「代理呼叫在產生輸出前就當掉 ／ agent call crashed before producing output」），報告與 JSON 的 `agent_calls` 多一筆紀錄，並列出無效模型輸出的證據缺口。判定結果不變：該發現原本就讓判定最多是 `INCONCLUSIVE`。
- 合併多個批次回報的同一威脅時，判斷方式改為與基準線的突破鍵相同（core/identity.py 的 `threat_identity`）：模擬引擎的雙語標題與攻擊向量只看英文半。過去合併看完整文字，所以（a）中文半不同、英文半相同的兩個模擬威脅不會合併，而基準線早已把它們的突破視為同一個；（b）標題字面相同的一個模擬威脅與一個真實模型的威脅會被合併，真實威脅可能被模擬範本取代。兩種情況都只會出現在同時有模擬與真實威脅、或有雙語標題的執行。
- 無法歸屬的發現位置改由單一判斷（core/identity.py 的 `is_unknown_location`）決定：None、空字串、只有空白與 `unknown` 佔位字（前後空白不計）都算未知。過去去重、測試生成、基準線鍵與 SARIF 各自判斷、條件略有不同：只有空白的路徑在基準線鍵中被當成檔名，去重會用符號而不是完全相同的標題判斷、測試生成會用空白當檔名；空字串或 ` unknown ` 在去重中也被當成已知的位置。實際上審查者只會寫出 `unknown`，所以一般執行的輸出不變。
- 鍵在、形狀卻不對的模型回答不再被當成可用的回答：過去閘道只檢查必要的鍵是否存在，審查者回答 `{"findings": 5}` 或一份沒有任何可用項目的清單（每一項都不是物件，或都沒有 title 與 description）時，這次呼叫被登記為 live、讀成「零個發現」，可能讓判定變成 `READY_TO_SHIP`（fail open）。現在每個代理宣告它期望的回答形狀（core/model_output.py 的 `OutputSchema`：欄位型別，以及清單中「可用的項目」由代理自己的判斷決定），不合時以指名欄位的原因重新詢問一次（例如 `field 'findings' must be a list of objects (got int)`），仍不合就記為 `invalid`（證據缺口）。同樣適用於驗證者（沒有任何一項裁決的 index 在範圍內、verdict 為 confirm／reject／unsure：過去只是「未經驗證」、不算證據缺口）、威脅建模（`threats` 不是物件清單）、測試生成（`tests` 沒有任何一項有 code，且沒有可用的 `code` 字串）與攻擊合成（`code` 不是字串）。空清單與只有部分項目不能用的清單照舊接受、不重問。**已知影響**：在升級前存下的回應快取若含有這類回答，`--cache-only` 重跑時那次呼叫會變成 `invalid`，原本的 `READY_TO_SHIP` 可能變成 `INCONCLUSIVE`（exit 3）；原本的判定正是建立在無法使用的輸出上。原因會標明「回應快取中的回答已不符合預期的形狀」；不帶 `--cache-only` 跑一次就會重新詢問並覆寫那些快取。`live-smoke.yml` 在同一次 workflow 中填快取再重跑，不受影響。
- 測試生成的回答同時有 `tests` 清單與單一的 `code`，但 `tests` 的每一項都沒有 code（例如 `{"tests": ["bad"], "code": "…"}`）時，現在改用那個 `code`；過去只要 `tests` 不是空清單就忽略 `code`，那個發現因此沒有模型測試、改用探針。`tests` 有任何一項可用時仍只用 `tests`。
- 沒有可用的 Node 執行環境時，每個 JS/TS 測試的原因現在寫出缺了什麼，與閘門的證據缺口相同（例如「找不到 node_bin '/usr/local/bin/node' 可用的 Node 執行環境（需要 Node >= 20.0.0）」或「Node v18.0.0 低於最低需求 20.0.0」）；過去報告與 JSON 裡每個測試只寫「找不到可用的 Node 執行環境」，詳細原因只出現在證據缺口。判定結果、證據缺口與結束碼不變；docker 映像檔不存在時的原因原本就是詳細的，也不變。
- `--estimate` 的驗證者呼叫數在某些審查者數與批次數下多算一次：發現數以「去重後的發現數 ×（1 − 自家份額）」計算，浮點誤差讓整數變成略大一點的值，無條件進位後多出一次呼叫。例如 3 個別名不同的審查者、25 個白箱批次與預設的每批 3 個發現：每位驗證者分到 120 筆發現，應為 8 次呼叫，卻估成 9 次（120.00000000000001 筆）。現在發現數改由驗證者自己的呼叫計畫依每個模型回報的數量加總，估出 8 次。只影響這類組合的驗證者呼叫數與其 token、花費與總計；預設的 4 個審查者不受影響。
- 以函式庫方式使用 harness（直接建立 `VibeHarnessCommander`）時，非 Windows 上寫不出中文的嚴格串流（例如 `PYTHONIOENCODING=ascii`、`LANG=C`）原本維持原樣，雙語輸出可能以 `UnicodeEncodeError` 當掉；現在和 CLI、Action 一樣改用 backslashreplace 輸出無法編碼的字元。
- 擷取器偵測到的語言從不重設：同一個 `ASTExtractor`（或 `VibeHarnessCommander`）用於第二個目標時，會帶著前一個目標的語言，影響顯示的技術堆疊與 JS/TS 相關的證據缺口。現在每次走訪都重新偵測。
- 威脅建模的批次在閘道之外當掉時，過去被當成可用的空回答：若第一個批次當掉，報告層級欄位（系統描述、entrypoints、信任邊界、資產）會變成預設值，後面批次真正的內容被丟掉。現在當掉的批次和無法使用的回答一樣略過，欄位取自下一個可用的批次；當掉本身仍記為一筆無效呼叫。

### 測試

- 新增 `tests/test_quality_gate.py`，只透過 `evaluate()` 測試閘門：每一級判定結果、每一種證據缺口代碼、缺口順序、基準的新／已知拆分與建議順序。
- 十二個只檢查判定或證據缺口規則的端到端 `run_full_pipeline` 測試與超大檔案測試的 pipeline 部分，改為透過 `evaluate()` 的測試，加上一個 mock pipeline 接線測試，確認擷取器、掃描器、設定的上限與審查名單的事實送進閘門。各來源仍保有自己的測試（新增一個測試鎖定哪些符號會做 None 探測）；模擬引擎、`--baseline`、沒有 Node 執行環境、未分類的黑箱失敗與突變測試中途當掉的端到端測試保留為接線測試。
- 新增 `tests/test_settings.py`，只透過 `load_settings` 測試設定：每個鍵的 null／0／負數／錯誤型別規則、驗證順序、探索到的設定檔政策、CLI 覆寫值與其來源、警告，以及唯讀的 models／agents。它取代已刪除的私有驗證函式的測試。
- `tests/conftest.py` 新增 `scripted({代理 glob: 回答})` fixture：一個依 `request.agent_id` 回答、記錄每個 `ModelRequest` 的 `ModelTransport`，腳本裡的例外在那次嘗試中拋出，就像供應商錯誤。十一個原本從提示詞文字猜測是哪個代理在呼叫的測試改用它。
- 新增 `tests/test_transport.py`：每次嘗試一個帶 `agent_id` 的請求、主要模型失敗改試 fallback、轉接器不可用時的 hybrid／live 行為、litellm 轉接器讀回覆、模擬輸出由呼叫端提供，以及 `scripted` fixture 本身。
- 新增 `tests/test_fanout.py`，只透過 `fan_out` 測試扇出：呼叫順序、當掉換成 fallback 並以代理的 logger 與 `agent_id` 記錄、live 失敗與 Ctrl-C 時佇列中的呼叫不會開始、並行數上限、空清單不開執行緒池。十個重複的測試案例改由它涵蓋；各代理只保留一個接線測試，確認當機記在自己的 `agent_id` 名下，並改經公開的 `gateway.generate` 觸發，不再替換代理的私有批次函式。覆蓋率沒有任何一行下降。
- 新增 `tests/test_identity.py`，只透過 `core/identity.py` 測試身分識別：任何文字的正規化、改寫措辭與不同文字、模擬項目的英文半、各種鍵與其 SARIF 指紋的性質、嚴重度順序與未知位置，加上一張取自 master、釘住雜湊值的 golden 表，讓之後任何會讓既有基準或 Code Scanning 警示失配的改動都會讓測試失敗。散在其他檔案、直接測試鍵函式的 11 個測試搬進來；測試鍵的使用者（基準的載入與比對、SARIF 端對端、威脅合併、去重）留在原處。覆蓋率沒有任何一行下降。
- 新增 `tests/test_model_output.py`，只透過 `core/model_output.py` 測試解析與形狀檢查：`parse_json_object` 的各種包裝與退回、`check_output` 對每種型別規格、清單規則與 `any_of` 的判斷與雙語原因、`mark_cached`，以及每個代理的模擬輸出都符合它自己的 schema（因此發現攻擊合成的模擬輸出 `{"tests": []}` 不符合它的 schema，已改為 `{"code": ""}`，行為不變）。原本直接呼叫閘道私有函式的解析與檢查測試搬進來，閘道的兩個包裝函式刪除；`core/model_output.py` 的覆蓋率 100%，沒有任何一行失去覆蓋。
- 新增 `tests/test_node_runtime.py`，測試 Node 執行環境的選擇：`build_node_sandbox` 依 provider 與版本決定 TypeScript 支援、label 與問題，docker 內的 `probe_node_version`，harness 的工廠，以及 `SuiteResult.node_runtime` 只出現在含 JS/TS 測試的 suite、只有黑箱 suite 含 JS 時 harness 也拿得到它。其中四個測試從 `tests/test_js_execution.py` 與 `tests/test_js_coverage.py` 原樣搬來（三個改名，因為舊名稱指的是已刪除的方法）。測試裡的沙盒替身改回傳 `SandboxRun`，替換 `execute_test_suite` 的假函式改回傳 `SuiteResult`。
- 新增 `tests/test_call_plans.py`：以 `scripted` fixture 實際執行每個代理，確認它的 `plan` 對同樣輸入算出的呼叫數等於實際發出的呼叫（修復以 `max_per_call` 為上限）；審查者與威脅建模的計畫每次呼叫的程式碼 token 等於實際送出的程式碼清單；驗證者的計畫在有已佐證的發現時是上限（佐證只會讓呼叫變少）。`tests/test_estimate.py` 原有的測試不變，另新增 `test_verifier_calls_have_no_float_error`，釘住「修正」中驗證者呼叫數的那一項。
- 新增 `tests/config_files.py`：`load_config()` 讀出內建設定的新副本，`write_config(tmp_path, cfg, name)` 把修改後的設定寫成暫存檔。`test_estimate.py`、`test_call_plans.py`、`test_parallel_and_budgets.py`、`test_quality_gate.py`、`test_mutation.py`、`test_js_execution.py` 與 `test_ai_security.py` 改用它，不再各自讀寫 YAML；`test_mutation.py` 與 `test_js_execution.py` 原本開檔後沒有關閉。測試數與涵蓋率不變。
- 測試不再留下沒關的檔案與 socket：讀 `action.yml`、workflow、`.pre-commit-config.yaml`、內建設定、威脅規則、原始碼與暫存目標的地方改用 `with open(...)` 或 `Path.read_text`，`test_p0_regressions.py` 的兩個本機 `HTTPServer` 在 `shutdown()` 後也呼叫 `server_close()`；以 `-W error::ResourceWarning` 跑完整套件沒有任何警告。`test_r2_extractor_scanner.py` 的時間上限在逐行追蹤器（coverage 預設的 ctrace、除錯器）之下會把量到的時間除以 3（追蹤器讓這些掃描慢約 2–5 倍），仍攔得住退回平方時間；`test_call_plans.py` 的修復測試改為直接斷言修復機會數等於產生的測試數、每個無效的測試用完所有修復次數，且總數不超過計畫的上限。

### 文件

- 設計文件的品質閘門一章說明 `evaluate(GateEvidence)` 是唯一決定判定結果的地方，證據缺口表列出每一項的 `GapCode` 與 `GateEvidence` 欄位，行號引用也更新為目前的程式碼（commit `ab5e9a8`）。
- 新增 `GLOSSARY.md`：領域用語的中英雙語詞彙表（品質閘門、判定結果、證據缺口、已執行的證據、假設、資安突破、基準、已知問題、阻擋性規則命中）。
- README 的專案結構列出 `core/gate.py`、`core/verdict.py` 與 `tests/test_quality_gate.py`。
- 設計文件改以 `load_settings` 說明設定的流程（模組表、設定的載入與驗證、探索到的設定檔檢查、CLI 覆寫值、沙盒設定），常數表指向 `vibeharness/core/settings.py`，重要函式索引新增 `settings.py` 一行，行號引用也更新為 commit `e5e95e4`。
- `GLOSSARY.md` 新增設定檔來源：內建設定檔、探索到的設定檔與指定的設定檔。
- README 的專案結構列出 `core/settings.py` 與 `tests/test_settings.py`。
- 設計文件說明模型呼叫的接縫（模組表、第 5 章的決策順序與真實呼叫細節）與由代理提供的模擬輸出（第 5.7 節），測試章節說明 `scripted` fixture，重要函式索引新增 `transport.py` 一行，行號引用也更新為 commit `c46d9b3`；回應快取一節原本誤指 `settings.py` 的四個行號引用改為指向 `llm_gateway.py`。
- `GLOSSARY.md` 新增模型回答：執行模式、真實呼叫與模擬輸出。
- README 的專案結構列出 `core/transport.py` 與 `tests/test_transport.py`。
- 設計文件說明 `vibeharness/core/fanout.py`（模組表、失敗處理的共同模式、各代理一節與並行一節），並行一節的表格改列每個代理當掉時的 fallback，重要函式索引新增 `fanout.py` 一行並移除 `common.py`，行號引用也更新為 commit `c8d1e26`。
- README 的專案結構列出 `core/fanout.py` 與 `tests/test_fanout.py`，並移除 `agents/whitebox/common.py`。
- 設計文件說明 `vibeharness/core/identity.py`（模組表、去重的位置規則與嚴重度、威脅合併、`--baseline` 一節、SARIF 的位置），重要函式索引新增 `identity.py` 一行，`baseline.py` 一行移除搬走的鍵函式，行號引用也更新為 commit `f6e741b`。
- README 的專案結構列出 `core/identity.py` 與 `tests/test_identity.py`。
- `GLOSSARY.md` 新增身分與未知位置。
- 設計文件說明 `vibeharness/core/model_output.py`（模組表、改寫的第 5.3 節「輸出驗證」、模擬輸出、各代理的回答形狀與可用項目規則），重要函式索引新增 `model_output.py` 一行與各代理的判斷式，行號引用也更新為 commit `67a8ef9`。
- README 的專案結構列出 `core/model_output.py` 與 `tests/test_model_output.py`。
- `GLOSSARY.md` 新增可用的輸出與形狀錯誤。
- 設計文件說明 `Sandbox` 接縫、`SandboxRun`、`SuiteResult` 與 `NodeRuntime`（模組表、第 3 章 Phase 3、第 9.2 至 9.5 節、擴充點與測試章節），重要函式索引新增這些名稱並移除 harness 已刪除的兩個方法；同時修正 `test_executor.py` 後段（`_run_individually`、`_aggregate`、`_result` 等）、`transport.py` 與 `GateEvidence` 組成在先前就已偏移的行號。行號改以 commit `af9af80` 為準。
- README 的專案結構列出 `tests/test_node_runtime.py`，並說明 `sandbox.py` 選擇 Node 執行環境、`test_executor.py` 回傳 `SuiteResult`。
- `GLOSSARY.md` 新增 Node 執行環境。
- 設計文件說明各代理的呼叫計畫（模組表的 `PlannedCalls` 與 `plan`、第 14.3 節 `--estimate` 改寫為加總計畫並說明 `batch_count`、`assigned_findings` 與 `_typical_calls`、第 6.6 節的 `HEAL_ATTEMPTS`、測試章節的 `test_call_plans.py`、模組表與常數表的 `CallKind` 與 `HEAL_CODE_TOKENS`、第 4 章第 1 階段與模組表的 `ScopeResult`、`ScanResult` 與第 5 章的 `ModelAnswer`），重要函式索引新增 `PlannedCalls`、`CallKind`、`_row`、`_typical_calls`、`batch_count`、`assigned_findings`、`ScopeResult`、`scan_directory`、`ScanResult`、`scan`、`ModelAnswer`、`NO_ANSWER` 與各代理的 `plan`，行號引用也更新為 commit `3d3d973`。
- README 的專案結構列出 `tests/test_call_plans.py`，並說明 `estimate.py` 加總各代理的呼叫計畫。
- 設計文件的模組表、重要函式索引與 README 目錄樹加入 `core/stdio.py`；修正過時的行號引用：第 13 章自動發現設定檔政策的常數與 `_is_sensitive_model_key`，以及索引中呼叫紀錄分類函式的位置。

## [0.12.0] - 2026-10-12

第六輪審查：中文的威脅與發現不再被誤合併；`--changed-since` 不再漏掉非 ASCII 檔名或 symlink 目標下的檔案；基準線鍵分得出不同檔案的同名函式，換機器重跑時也不會把名稱含點的目錄當成檔案；`--estimate` 與逐測重跑的錯誤原因也一併修正。

### 變更

- 確定性探測（`WB-PROBE-*`）的 `source_ref` 由函式名稱改為「相對於目標根目錄的檔案路徑 + `::` + 函式名稱」（例如 `src/a.py::process`），基準線鍵因此分得出不同檔案的同名函式。由較舊版本寫出的基準線裡、已知的探測失敗在第一次比較時會被視為新的。
- `--estimate` 的突變測試上限（`mutation_sandbox_runs_max`）改為 `mutation_max_mutants + 1`，計入先在未變異複本上確認測試通過的那一批；文字改為「最多 N 個變異體……另加未變異複本上的一批，共最多 N+1 批」。

### 資安

- `extra_params` 另外保留名稱含 `key` 片段的鍵（只指名快取項目的 `cache_key`，例如 `prompt_cache_key`，仍然允許）與 `signoz_` 前綴：litellm 1.105 新增的 `signoz_ingestion_key` 會把提示與回答轉送給 SigNoz，原本的名稱樣式攔不到。

### 修正

- 威脅建模器合併各批次重複威脅時，標題與攻擊向量改以任何文字的字母與數字正規化（與 `baseline.normalize` 相同）：原本只取 ASCII，中文標題都變成空字串，同 STRIDE 類別、同攻擊向量的不同中文威脅會被合併成一個，後面的威脅既不測試也不列為未測。
- 白箱發現去重的詞彙另外取每段中日韓文字的相鄰二字詞：原本只取 ASCII 詞，「SQL 注入於搜尋參數」與「SQL 盲注造成資料外洩」只剩 `sql` 而被合併，少了一個缺陷。
- `--changed-since` 以 `git diff -z`／`git ls-files -z` 讀取檔名：非 ASCII 檔名原本被 git 加上 C 風格引號而對不上任何檔案，悄悄排除在分析之外，也沒有列為證據缺口。
- `--changed-since` 的目標是 symlink（或位於 macOS 的 `/tmp` 這類 symlink 之下）時，git 回報的真實路徑會換回目標原本的寫法，走訪才對得上；原本一個檔案都對不上，結果是「沒有可分析的原始碼符號」的 `INCONCLUSIVE`。
- 基準線的 `target_relative` 只有在檔案不位於目標之下時，才把目標當成檔案而改用所在目錄：較舊的基準線在另一台機器上重算鍵時，名稱含點的目錄目標（`app.v2`）原本會被當成檔案，每個鍵都多了目錄前綴，已知問題全部變成新問題。存在但沒有副檔名的檔案目標也不再得到 `.` 這個鍵。
- 批次逾時後的逐測重跑沒有產生 JUnit 報告時（例如直譯器被 RLIMIT 殺掉），改回報「沙盒執行沒有產生報告」並附上該次重跑的 stderr，而不是把錯怪給產生的測試的「沒有收集到任何測試」。

### 測試

- 新增回歸測試 `tests/test_r6_review.py`。

### 文件

- 設定說明與設計文件記載 `key` 名稱片段與 `signoz_` 前綴；設計文件的突變測試估算說明計入未變異複本上的那一批，並依目前的程式碼更新引用的行號。

## [0.11.0] - 2026-10-11

第五輪審查：Action 的判定只取自這次稽核自己的摘要，`extra-args` 以 CLI 的解析器檢查；自動發現的設定檔只能調低花費；litellm 的記錄／callback 參數列為保留鍵；不支援語言的原始碼與設定檔裡的密鑰不再悄悄漏掉；沙盒的報告讀回、執行目錄權限、涵蓋率 include 與 Docker 輸出上限也一併強化。

### 新增

- 擷取器不支援的語言的原始碼檔案（`UNSUPPORTED_SOURCE_EXTENSIONS`：Go、Java、Kotlin、Rust、C／C++、C#、PHP、Ruby、Swift、Scala、Objective-C、Dart、Lua、Perl、Elixir、Erlang、Haskell、Clojure、F#、Visual Basic、Groovy、Vue、Svelte、Solidity；刻意不含 shell 腳本、SQL 與 HTML／CSS）依與原始碼相同的走訪規則（略過的目錄與隱藏目錄、`include`／`exclude`、`--changed-since`）逐語言計數，並列為證據缺口（「N 個不支援語言的原始碼檔案（go: 3, …）未納入分析」），這種目標因此不會再得到 `READY_TO_SHIP`；取代原本不可能觸發的「…只做了靜態審查」缺口。
- 設定類檔案（`.env`、`.env.*`、`*.env`、YAML、JSON、TOML、INI、CFG、`.properties`、Terraform 的 `.tf`／`.tfvars`、`Dockerfile`、`Dockerfile.*`、`*.dockerfile`、`.npmrc`、`.pypirc`、`.netrc`；略過鎖定檔）在本機以 VH-AI-007 做密鑰掃描（`AISecurityStaticScanner.scan_config_files`），絕不送給模型：每次最多 200 個（`DEFAULT_MAX_CONFIG_FILES`），各自受 `max_file_bytes` 限制，以 64 KB 為一段、在單檔 30 秒上限內掃描（私鑰區塊不會被切開）。因數量上限、`max_file_bytes` 或時間上限而沒有完整掃描的檔案是新的證據缺口。VH-AI-007 的標題改為「原始碼或設定檔中寫死的憑證 ／ Hard-coded credential in source or configuration」。
- `vibeharness.cli.parse_args_for_inspection`：沒有副作用的 CLI 參數解析器（`--help`／`--version` 不印出也不結束、只含實際給出的參數、用法錯誤拋出 `ValueError`）；Action 用它檢查 `extra-args`。
- Docker 沙盒映像附上 `hypothesis`（與其相依的 `sortedcontainers`），以雜湊鎖定在 `docker/sandbox-requirements.txt`（它們不在 `requirements.lock`），生成的性質測試因此能在容器內執行。

### 變更

- **破壞性**：Action 的判定只取自這次稽核的 `--summary-json`（`tool` 為 `vibeharness`，且 `exit_code` 與 CLI 相同）；CLI 以 0–3 結束卻沒有這份摘要時為 `ERROR`、exit 5，沒有稽核的執行不能再以 `READY_TO_SHIP` 通過。
- **破壞性**：Action 以 CLI 自己的解析器檢查 `extra-args`：不執行稽核的旗標（`--estimate`、`--help`／`-h`、`--version`、`--init-config`、`--force`、`--summary-json`）、有專屬 input 的旗標（`--output`／`-o`、`--format`／`-f`、`--sarif`）與 CLI 無法解析的參數，都在執行任何東西之前以 exit 5 結束。`--config` 不論以 CLI 接受的哪種寫法出現都認得（`--config=x`、`-c x`、`-vc x`／`-vcx` 這類合併的短旗標；與 CLI 一樣以最後一個為準）。
- **破壞性**：`extra_params` 保留 litellm 的記錄／callback 參數，它們會把完整的提示與回答（即待審程式碼）轉送給第三方觀測服務：`callbacks`、`success_callback`、`failure_callback` 與任何名稱含 `callback` 的鍵、`metadata`／`litellm_metadata`／`litellm_params`、`litellm_trusted_callback_vars`、`verbose`、`litellm_request_debug`，`langfuse_`、`langsmith_`、`gcs_`、`s3_`、`dd_`、`datadog_`、`helicone_`、`lunary_` 等整合前綴，以及名稱片段 `webhook`、`host`、`bucket`；另外是會改寫請求的 `prompt_id`／`prompt_variables`／`prompt_version`／`prompt_environment`、`litellm_system_prompt`、`model_alias_map`、`custom_prompt_dict`、`context_window_fallback_dict`、`routing_strategy`、`retry_policy`／`retry_strategy`、`force_timeout`、`client_side_timeout`、`azure` 與 `data_residency`。名稱片段含 `cost` 的成本覆寫（`input_cost_per_token`、`output_cost_per_token`、`cache_read_input_token_cost`）改為允許；其他含 `token` 片段的鍵仍然保留。
- **破壞性**：`agents.<id>.model_alias` 指向 `models` 區段沒有的別名（打錯字）時，啟動即 `ConfigError`（exit 5）；過去會悄悄解析成 `unconfigured`（hybrid 改用模擬，live 在付費呼叫之後才中途失敗）。省略、`null` 或 `unconfigured` 仍代表沒有模型。
- **破壞性**：自動發現的設定檔只能調低花費：`execution_mode` 只能是 `hybrid`（內建值）或 `mock`；`max_model_calls`、`max_concurrent_calls`、`max_output_tokens`（全域與每個模型）、`retry_invalid_output`、`max_retries`、`max_files`、`max_file_bytes` 的實際值都不能高於內建設定（自動發現的檔案整份取代內建設定，所以省略或 `null` 即 harness 預設值）；也不能新增 `whitebox_reviewer_*` agent。
- 自動發現的設定檔可以保留先前版本內建設定的同一別名模型字串（`_PREVIOUS_BUNDLED_MODELS`：`claude` 的 `claude-sonnet-5`，v0.1.0～v0.2.0 的內建值），舊版 `--init-config` 寫出的覆本因此照樣能載入；拒絕訊息也會建議以 `vibeharness --init-config <PATH> --force` 重新產生。
- 匯入 litellm 之前設定 `LITELLM_LOCAL_MODEL_COST_MAP=True`（只在環境變數尚未設定時），改用 litellm 套件內附的價格表，`mock`／`--estimate` 因此完全不連網；要讓 litellm 抓最新價格表，請設成 `False`。
- 每個 `docker_*` 鍵設為 `null` 都保留預設值；`docker_node_image` 只在 Node 沙盒用 docker 時、`docker_image` 只在 `sandbox_provider` 是 docker 時才驗證，純本機設定檔裡殘留的值不會再擋住啟動。`models.<alias>.model`／`fallback_model` 去掉前後空白後保存，前後的空白不會送進 litellm 或快取 key。
- Action：`sandbox: docker` 在設定檔覆本中也設定 `sandbox_node_provider: docker`，即使底稿把 JS／TS 測試留在本機，它們也會在容器內執行；`report`／`sarif` outputs 改由 runner 設定，只有這次稽核寫出了檔案才有值（workspace 裡舊的同名檔案不算，`ERROR` 時兩者都為空），這時 step summary 寫「沒有寫出報告 ／ No report was written」；`prep` 拒絕含換行的 `sarif` 路徑。
- Docker 沙盒：harness 以 root 執行時，執行目錄交給 `nobody`（`chown 65534:65534`、權限 0700），而不是 `chmod 0777`，主機上的其他使用者因此無法在裡面放檔案或換掉報告（CodeQL `py/overly-permissive-file`）；啟用 userns-remap 的 daemon 這時需要對沙盒停用它，或以非 root 執行 harness。
- Docker 沙盒：docker CLI 在 `RLIMIT_FSIZE` 64 MiB 下執行（忽略 SIGXFSZ），主機上的擷取暫存檔因此有上限；它的輸出達到上限時移除容器（`docker rm -f`），該批次為 `EXECUTION_FAILURE`，stderr 最後附上雙語說明（`OUTPUT_CAP_NOTE`）。容器另加 `--ulimit fsize=64 MiB` 限制可寫入的 bind，並以 `--log-driver none` 不留 daemon 端沒有上限的 json 日誌。

### 資安

- 被測程式碼可以改寫的報告（`junit.xml`、lcov 報告）改經 `jscoverage.read_untrusted_file` 讀回：POSIX 上以 `O_NOFOLLOW` 加 `O_NONBLOCK` 開啟（Windows 上以 `lstat` 檢查重新剖析點、以 `fstat` 確認是同一個檔案），只接受一般檔案、與檢查時同一個 inode、只有一個硬連結、不超過 64 MiB（`MAX_REPORT_BYTES`）；指向主機檔案的 symlink、FIFO、硬連結或過大的檔案一律算「沒有報告」，雙語原因放在 stderr 最前面（junit）或記一行 WARNING（lcov）。
- `--init-config` 即使加上 `--force` 也拒絕符號連結（不論是否懸空）與不是一般檔案的目標，並以 `O_NOFOLLOW` 加 `O_EXCL`（`--force` 時為 `O_TRUNC`）開啟，不受信任的 checkout 裡預先放好的符號連結因此無法讓它在別處建立或覆寫檔案。
- `--init-config` 建立檔案時的權限遮罩由 `0o666` 改為 `0o600`（只有擁有者可讀寫；CodeQL `py/overly-permissive-file`）。

### 修正

- POSIX 上的 JS/TS 涵蓋率：含反斜線的目標路徑再次不加 `--test-coverage-include`（0.10.1 會把 `/home/u/a\b` 改寫成指向別處的 `/home/u/a/b`）；只有在 Windows 規則下（Windows 或帶磁碟機代號）反斜線才是分隔符。目標的每種寫法（abspath 與 realpath）各給一個 include（Node 以 OR 合併）；Windows 上兩種寫法只差在磁碟機代號大小寫時才加 include（對應的網路磁碟機與 UNC、目錄名稱大小寫或 junction 不同時，退回只用排除模式與自己的 lcov 篩選）。UNC 路徑可以；`\\?\`／`\\.\` 裝置路徑、`C:foo` 與 `/` 不加 include。
- CLI：寫不出雙語文字的串流（例如 `PYTHONIOENCODING=ascii`、`LANG=C`）在每個平台上都改用 `backslashreplace` 輸出，而不是以 `UnicodeEncodeError` 當掉；參數解析、`--help`／`--version` 與 `--init-config` 也在防護內執行，意外錯誤以 5 結束（Ctrl-C 為 130），不再是 Python 預設的 1。
- Action 的 runner 在 Windows 的 cp1252 主控台印雙語 `::error::` 時不再以 `UnicodeEncodeError`（exit 1）結束：與 CLI 一樣先把 stdio 改成可寫出雙語文字。

### 測試

- 新增回歸測試 `tests/test_r5_action_cli.py`、`tests/test_r5_gateway_harness.py`（也逐一比對每個 `v*` tag 的內建設定與 `_PREVIOUS_BUNDLED_MODELS`）、`tests/test_r5_languages_secrets.py`、`tests/test_r5_sandbox_coverage.py`，以及 `tests/test_r5_coverage_gaps.py`（經由公開函式完整涵蓋 `baseline.py` 與 `sandbox.py` 穩定的輔助函式）。
- 對時間敏感的測試放寬時間上限，量測涵蓋率時再按比例放大；Stripe 格式的測試金鑰改以字串串接組成，避免 repo 被密鑰掃描標記。
- `test_large_targets_are_threat_modeled_in_batches` 的模擬回應在鎖內計數：批次並行執行時，兩個批次可能拿到同一個標題而被合併，使測試偶發失敗。

### 工程

- ruff 0.17.0（`requirements-dev.txt` 與 pre-commit hook 凍結的 SHA `44b5042…`）。

### 文件

- README、設計文件與設定說明記載以上變更；「尚未實作」表拿掉其他語言、非原始碼檔案的密鑰與 Docker 輸出沒有上限這三列，改加 userns-remap 的注意事項；架構圖畫出閘門的每一個輸入（審查者設定、沒有模型測試的發現、VH-AI-008／009 的完整性命中、測試結果、`--base-url`、不支援語言與設定檔掃描的缺口）；exit code 表列出所有 exit 5 的原因與不稽核的 exit 0；設計文件依目前的程式碼重新核對引用。

## [0.10.1] - 2026-10-11

修正版：Windows 上的 JS/TS 涵蓋率也收得到位於 `node_modules` 底下的目標，並為縮短測試 ID 的 hook 補上回歸測試。

### 修正

- JS/TS 行涵蓋率在 Windows 上同樣加上 `--test-coverage-include`：絕對路徑先改成正斜線（Node 的 win32 matcher 把 `/` 與 `\` 當成同一種分隔符），所以本身位於 `node_modules` 底下的目標在 Node ≥ 22.5 也收得到涵蓋率，與 POSIX 相同。路徑含 glob 特殊字元時仍只加排除模式。

### 測試

- `tests/test_windows_env_limit.py` 確認縮短長字串參數 ID 的 `pytest_make_parametrize_id` 持續有效（Windows 的環境變數上限是 32767 個字元，pytest 會把測試 ID 寫進 `PYTEST_CURRENT_TEST`）。

## [0.10.0] - 2026-10-11

第四輪審查：Action 不再蓋掉設定檔的成本防護、自動發現的設定檔不能再改接模型字串、別名或金鑰變數，其餘設定也改為 `null` 保留預設值。

### 變更

- **破壞性**：自動發現的 `./vibeharness.yaml`／`./.vibeharness.yaml`（沒有 `--config`）不能再改 `models.<alias>.model`／`fallback_model`、新增內建設定沒有的模型別名，或使用與內建設定同一別名不同的 `api_key_env`（過去內建設定裡任何一個金鑰變數都可以用在任何別名上，`ANTHROPIC_API_KEY` 因此可能被接到別家供應商）；這種設定檔會以 exit 5 結束並提示改用 `--config`。agent 仍可在內建的別名之間重新指派。
- **破壞性**：每個 `models.<alias>` 都要有非空的 `model` 字串，`fallback_model` 必須是非空字串或 null，`base_url`（程式不讀，端點是 `api_base`）一律拒絕；這些都在啟動時以 exit 5 結束，而不是讓 agent 悄悄改用模擬（hybrid）或在執行中途失敗（live）。
- **破壞性**：Action 的 `output` input 預設為空，依 `format` 推導（`vibeharness-report.md`，`format: json` 時為 `vibeharness-report.json`；過去不論格式都是 `vibeharness-report.md`）；`report` output 與上傳的 artifact 都用推導出的名稱。
- Action：`mode`、`max-model-calls` 與 `max-files` 預設為空，只有填了才傳給 CLI，所以 `--config` 的 `execution_mode`、`max_model_calls` 與 `max_files` 不再被悄悄蓋掉（舊的預設 `max-model-calls: "0"` 會關掉設定檔的成本防護）。
- Action：新增的第一個 `prep` step 在安裝與建置 Docker 映像之前，以純 bash 驗證 `fail-on`、`mutation`、`sandbox`、`mode`、`format` 與數值 input（`max-model-calls` 為非負整數、`max-files` ≥ 1）；`exit-code` output 的說明列出 130。
- CLI：長旗標不再接受縮寫（`allow_abbrev=False`），`--conf x` 因此繞不過 Action 對 `--config` 的偵測；縮寫是用法錯誤（exit 5）。`--output` 與 `--max-files` 的說明文字補上 JSON／估算的輸出與 ≥ 1 的規則。
- `null` 保留預設值：`agents.<id>.temperature: null` 為 0.2（`DEFAULT_TEMPERATURE`；過去 `None` 會送進 litellm 與快取 key）、`mutation_max_mutants: null`／`mutation_min_score: null` 維持 20／70（過去是 `ConfigError`）、`sandbox_provider: null` 為 `local_subprocess`（過去會被當成未知的 provider 而失敗），`sandbox_node_provider: null` 則跟隨它。內建設定檔的 `mutation_timeout_seconds` 改為 `null`（跟隨 `per_test_timeout_seconds`），分數門檻的錯誤訊息改為指名 `global.mutation_min_score`。
- 突變測試：`ELIGIBLE_TEST_TYPES` 只剩 `whitebox_unit`；原本一併列出的 `whitebox_property` 從來不會產生。

### 修正

- Action：Docker 沙盒設定檔覆本可以處理空的 `global:` 區段。

### 工程

- 新增回歸測試 `tests/test_r4_behaviour.py`；JS 涵蓋率測試與 JS 執行測試一樣遵守 `VIBEHARNESS_REQUIRE_NODE=1`（缺少 Node 時失敗而不是略過；Node 版本不支援某項功能時仍會略過）。
- 修正 `agents_config.yaml`（每個模型別名一位驗證者、批次預算、`sandbox_memory_mb: 0` 只關閉記憶體上限、JS/TS 的測試生成器寫 `node:test` 模組）與 `threat_rules.yaml`（`atlas_techniques` 是功能性欄位）的註解。

### 文件

- 架構圖補上選用的 Phase 3.5（突變測試）、基準比對、閘道的回應快取、重問與 `prompt_sha256`、兩種不受信任通道、JS/TS 涵蓋率，以及閘門每一個證據缺口的來源；「六個線性階段」改為「六個階段加上選用的 Phase 3.5」。
- README：Action 完整的 inputs 與 outputs 表、`prep` 驗證與 job 的結束語意、`--summary-json` 的欄位、exit 3 的每一種 INCONCLUSIVE 條件，以及其餘的限制（其他語言直接被忽略、非原始碼檔案不掃描密鑰、沙盒映像沒有 Hypothesis）；更正：`--estimate` 只跑符號擷取、單一審查者的檢查計算的是不同的模型別名、完全模擬的 fork PR 仍可能經 `WB-PROBE` 探針得到 `NEEDS_FIXES`。
- 設定說明：`docker_bin`、`max_concurrent_calls`、`docker_*` 鍵與 `include`／`exclude` 的驗證、`aws_region_name` 只與 `aws_profile_name` 一起生效、`sandbox_memory_mb: 0`、`temperature` 與 `drop_params`、`extra_params` 保留的內部掛鉤與名稱片段；設計文件依目前的程式碼重新核對引用並記載新的資料模型欄位，`CONTRIBUTING.md` 說明 Docker／Node 測試的開關、設定驗證的位置與 PyPI 發布的把關。

## [0.9.0] - 2026-10-11

第三輪審查：自動發現的設定檔不能再設定安全敏感的鍵、Action 以 `exec` 執行稽核而不留下持有金鑰且可讀的父行程、SARIF 不收模擬的項目、VH-AI-006 為了精確度與線性時間重寫、確定性規則會揭露未能完整掃描的檔案、補上 VH-AI-009／VH-AI-007 的缺口，並強化 repo 的 CI 與設定。

### 新增

- `--summary-json PATH`：稽核結束後寫出機器可讀的簡短摘要，與 `--format` 無關：`tool`、`version`、判定、exit code、執行模式、模型呼叫數（`total`、`live`、`simulated`、`invalid`、`cached`；同一次呼叫中 `retried` 的詢問不計入）、`all_simulated` 與證據缺口；寫入位置在任何模型呼叫前就檢查。
- `vibeharness/action_runner.py`：Action 的 audit step 以 `exec` 進入 `python -I -m vibeharness.action_runner`，它在同一個行程內執行 CLI，再寫出 `verdict`／`exit-code` outputs 與 step summary 並套用 `fail-on`；判定為 `INCONCLUSIVE` 而 `fail-on` 不會因此讓 job 失敗時，以及 hybrid／live 執行的每一次模型呼叫都是模擬的時候（例如拿不到 secrets 的 fork PR），發出 `::warning::`。
- 證據缺口「確定性 AI 安全規則未能完整掃描 N 個原始碼檔案（逾時或出錯）」：每個 Python 檔的 AST 規則有 30 秒上限（`_MAX_SCAN_SECONDS_PER_FILE`）；超過上限或意外出錯的檔案保留已找到的命中，並列入 `AISecurityStaticScanner.incomplete_files`。
- VH-AI-006 的執行點新增 `os.exec*`、`os.spawn*`、`os.posix_spawn[p]`、`pty.spawn` 與 `loop.subprocess_shell`／`loop.subprocess_exec`，也認得執行點的別名（`r = subprocess.run`、`getattr(subprocess, 'run')`、`functools.partial(subprocess.run, ...)`）。

### 變更

- **破壞性**：`extra_params` 改為保留所有會改變目的地或憑證的 litellm 參數（`extra_headers`、`headers`、`apikey`、`token`、`organization`、`model_list`、`deployment_id`、`use_litellm_proxy`、Azure／Vertex／watsonx／OCI／GigaChat 的憑證與專案、自備的 client 等），並以名稱樣式補漏（`is_reserved_extra_param`：`aws_`／`azure_`／`vertex_`／`oci_`／`watsonx_`／`gigachat_` 字首，以及名稱裡有 key、token、secret、password、credential、endpoint、url、proxy、header 等字段）；設定了這些鍵的設定檔現在會 exit 5。
- 不經 shell 的 VH-AI-006：直譯器後面接腳本路徑或 `-m 模組` 時，只有腳本或模組本身被污染才算；程式碼選項（`-c`、`-e`、`--eval`、`-ec` 這類 getopt 短選項串、`cmd /c`、`pwsh -Command`）與讀取被污染標準輸入的程式（`input=`、`Popen(...).communicate(x)`、`p.stdin.write(x)`）是 HIGH；包裝程式（`sudo`、`timeout`、`nice`、`env -S`、`xargs -I`、`flock`、`strace` 等）與執行器（`uv`／`poetry`／`pipenv`／`conda`／`pdm`／`npx`／`pnpm`／`yarn`／`npm`／`bun`、`docker`／`podman exec|run` 含 `--entrypoint`、`kubectl exec`、`find -exec`、`script -c`）依選項表跳過，`command -v` 只是查詢；`sed`／`sqlite3`／`psql`／`mysql` 的程式碼參數與 git 全域 `-c`／`--upload-pack` 的值也算；`shell=1` 與 `**{'shell': True}` 視為經過 shell。新增 MEDIUM 等級：無法確定的程式（`TOOL = os.environ.get(...)`）帶有被污染的引數，或 `shell=` 不是常數。`executable='bash'` 配上非 shell 的 argv 不再被標記。
- 沒有套用跨模型驗證時，「發現沒有模型產生的測試」這條證據缺口改稱「未經驗證」，不再說「已確認」。
- `--help`、`--version` 與 `--init-config` 在載入任何相依套件之前就解析，所以很快，在安裝不完整時也能用。
- JS/TS 涵蓋率：只排除目標根目錄以下的 `node_modules`（Node ≥ 22.5 有明確的 include，本身位於 `node_modules` 底下的目標也收得到涵蓋率）；Windows 上 lcov 的鍵經 `normcase`，同一模組的大小寫變體會合併；版本門檻的說明更正為 `--disable-warning`（20.11／21.3 起才有；lcov 報告器 20.10／21.2 就有）。

### 資安

- 自動發現的 `./vibeharness.yaml`／`./.vibeharness.yaml`（沒有 `--config`）設定了安全敏感的鍵時，以 exit 5 拒絕並提示改用 `--config`：任何 global 的 `*_bin`（啟動時就會執行：`docker_bin: ./evil.sh` 在 mock 模式也會跑）、`docker_*`／`node_*`、`local_subprocess`／`docker` 以外的 `sandbox_provider`／`sandbox_node_provider`、`cache_dir`，以及模型的 `api_base`／`base_url`／`api_key_env`（內建設定用到的金鑰變數以外）／`aws_*`／`extra_params`／任何像端點或憑證的鍵；與內建預設相同的值不算，所以 `--init-config` 的覆本照樣可用。即使以 `--config` 指定，相對路徑的 `*_bin`（例如 `./node`）也會印出警告。
- Action 不再留下持有金鑰的 bash 父行程：audit step 以 `exec` 進入稽核行程，生成的測試讀不到 `/proc/<ppid>/environ` 裡的金鑰；action 裡的每個 Python 輔助程式都以 `-I` 執行（或先把工作目錄從 `sys.path` 移除），受稽核 checkout 裡放的 `shlex.py`、`yaml.py` 或 `vibeharness/` 絕不會被匯入；`fail-on` 與 `sandbox`／`mutation` 一樣在稽核前就驗證。
- SARIF 不再收模擬引擎產生的白箱發現與衍生自模擬威脅的突破（它們在 Code Scanning 裡看起來和真的警示一樣）；run 的 properties 以 `simulated_whitebox_findings_omitted`／`simulated_breaches_omitted` 計數。
- VH-AI-009：會／已／被／曾 的描述豁免要有程式元件當主詞（主詞是 你／審查者／AI 這類讀者，或主詞省略而後面接著 請／直接／輸出／吧，都算宣稱；「此…已被視為安全」也會命中）；雙重否定（不得不、不能不）與反詰的 何不／豈能不 讓否定相消；時間／時刻 裡的「時」不是條件，「時」後面緊接祈使詞仍是命令；若干／當前 不是條件開頭，條件開頭之後出現 請／務必 就不再管轄後面的片語；同一行在描述句之前稱呼 AI／模型／審查者，或宣稱程式碼是乾淨的時，英文描述句的豁免失效。
- VH-AI-007：含 prod／primary／master／replica／rds／live／prd 字樣的單一標籤主機不再算開發用主機（`admin:admin@prod-db` 會回報）；主機為空時改看查詢字串的 `?host=`；`$VAR` 只有大寫的環境變數形狀才算範本，`{var}`／`{{var}}`／`<var>` 只有內容是佔位名稱時才算。

### 修正

- 執行器：SyntaxError 只有在最內層 frame 顯示來自匯入（import 陳述式、`__import__`／`import_module`／`reload` 呼叫，或 `<frozen importlib._bootstrap>` frame），而且指向真實的 `.py` 檔時，才算目標載入失敗；目標以 `compile()`／`ast.parse()` 解析真實檔案時的 SyntaxError 改判為缺陷（FAILED），`importlib.import_module` 匯入壞掉的模組則判為載入失敗。單檔大小上限造成的 JS EFBIG 系統錯誤（`errno: -27`、`code: 'EFBIG'`）與 Python 的 `[Errno 27]` 一樣是 harness 錯誤。
- 靜態閘門：`_asserts` 以明確的堆疊走訪輔助函式的呼叫圖，約 3000 層的輔助函式鏈不再 `RecursionError`（`check_test_code` 另有保守的保險）。
- 沙盒：本機 Python／Node 子行程的 `TMPDIR`／`TMP`／`TEMP` 指向執行目錄，Node 涵蓋率的執行也把 `NODE_V8_COVERAGE` 固定在那裡，所以逾時被砍掉的執行不會在主機的暫存目錄留下 `node-coverage-XXXX`；涵蓋率執行的 stderr 拿掉 Node 沒有警告碼的「glob is an experimental feature」警告，「沒有產生報告」之類的原因會顯示真正的錯誤。
- VH-AI-009 誤報：「不要回報」要有發現或程式碼這類對象，對象是送往前端、Sentry 或日誌時不算；檔案掃描或 KYC 應用邏輯裡對 檔案／文件 的判定，只有同一行稱呼讀者時才算；一般 AI 助理的注意事項與稱呼語，以及覆寫 system prompt（不再算成要求忽略指令），都要有跟審查相關的字眼；測試呼叫的字串與 docstring 的開頭算描述。VH-AI-007：userinfo 在第一個 `?`／`#` 就停止，除非冒號在它之前，所以查詢字串或片段裡的冒號不是憑證。
- JS/TS 擷取：泛型參數清單可以含物件型別（`function List<T extends { id: string }>`、`server.post<{...}>(...)` 路由），class 主體會跳過繼承泛型裡的 `{` 型別字面值（`extends React.Component<{ n: number }>`），`<...>` 裡的逗號不再切開參數，很長的行上的片段改以字元位置切齊，壓縮過的單行檔案不會觸發片段上限而遺失符號。
- 惡意輸入上的效能：JS/TS 詞法分析器為線性時間（正規表達式的結尾 `/` 查每行一次的表，`'/['*20000` 從 52 秒降到 0.02 秒；型別註記的往回查找有備忘，`'=>'*20000` 從 22 秒降到 0.03 秒；綁定的型別註記有長度上限，32 秒降到 0.2 秒；路由鏈以位置比對）；VH-AI-006 每個範疇的索引只建一次並快取 argv 判斷（4000 個執行點從超過 120 秒降到 0.45 秒），深層屬性鏈也不再 `RecursionError`；VH-AI-009 先以觸發詞與必要詞篩選行（1 MB 的換行從 4.9 秒降到約 0.1 秒）。

### 工程

- CodeQL：workflow 移到 `.github/workflows/codeql.yml`（workflow 與 job 名稱不變，因為它們是必要檢查），最上層 `permissions: {}`、`security-extended` 查詢、`timeout-minutes`，PR 的 concurrency 會取消進行中的舊分析。
- `publish.yml`：GitHub Release 的內文是 `CHANGELOG.en.md` 中這個版本的區段（找不到時改用自動產生的內文；Release 已存在時改寫它的內文）。
- Dependabot 也追蹤 pre-commit hook；pre-commit 的 ruff hook 釘在 v0.16.10 的 commit SHA。
- Repo 設定：`master` 要求 PR 與包含 CodeQL 在內的 16 項檢查，只接受 merge commit 合併，合併後自動刪除分支；`v*` tag 只有管理員能建立、移動或刪除；Actions 必須以完整的 commit SHA 釘版；secret scanning 與 push protection、Dependabot alerts 與 Dependabot 安全性更新都已開啟。
- Action 與 README 的範例把 `github/codeql-action/upload-sarif` 釘在 v4.38.3（與 CodeQL workflow 同一個 commit），並列出 job 需要的 `contents: read`／`security-events: write` 權限。
- 新增回歸測試 `tests/test_r3_cli_report_action.py`、`test_r3_executor_sandbox.py`、`test_r3_extractor_scanner.py`、`test_r3_repo_meta.py` 與 `test_r3_sanitize.py`；清理器的時間上限為 CI 保留餘裕。

### 文件

- `SECURITY.md` 改列 0.9.x 為支援版本並列出 repo 的資安功能；`CONTRIBUTING.md` 說明必要檢查、合併規則與擴充後的發布清單；README、設定說明與設計文件描述自動發現設定檔的防護、`exec` 啟動器、fork PR 的行為與新的限制，設計文件的引用改對應目前的程式碼。

## [0.8.0] - 2026-10-11

### 新增

- JS/TS 行涵蓋率：白箱 JS/TS 測試以 Node 內建的涵蓋率（`--experimental-test-coverage`）加上寫到執行目錄的 `lcov` 報告器收集行涵蓋率（原本的 spec／junit 報告器不變），只計入目標自己的原始檔（排除生成的 `test_vh_*` 模組、`node_modules` 與目標目錄以外的檔案；Docker 內的 `/work/<name>` 路徑對應回目標相對路徑），各模組取聯集（任一模組跑過的行就算涵蓋）。結果寫進新欄位 `summary.js_line_coverage_pct`，`line_coverage_pct` 仍只代表 Python；新增欄位，JSON `schema_version` 維持 `"2"`。Markdown 指標表在有 JS/TS 白箱測試時顯示「Python X% / JS/TS Y%」，console 另加「行涵蓋率（JS/TS） ／ Line Coverage (JS/TS)」。只計入至少被一個模組載入過的檔案（V8 不知道沒載入的檔案；與 pytest-cov 把沒匯入的 `.py` 算成 0% 不同）。需要 Node ≥ 20.11 或 ≥ 21.3（lcov 報告器），Node ≥ 22.5 另加 `--test-coverage-include`／`--test-coverage-exclude`；更舊或版本不明、全部模組逾時、報告裡沒有目標檔案時為 N/A 並記錄原因，不算證據缺口。黑箱執行與 mock 模式不收集。

## [0.7.1] - 2026-10-11

### 修正

- 執行器：剩餘逾時預算改以 `_remaining_seconds` 計算——先扣一點容差再進位，且不超過預算本身。`monotonic()` 的值很大時，`(t0 + 30.0) - t0` 的浮點誤差曾讓預算多出一秒（Windows 上出現「31 秒後逾時」）。
- `--init-config` 寫到自動尋找以外的檔名時，訊息改為提示以 `--config` 指定，不再說會自動採用。

## [0.7.0] - 2026-10-10

第二輪審查：為 pip 使用者提供誠實的計數與結束碼、執行器歸因與沙盒限制、補上 VH-AI-009／VH-AI-007 的缺口並讓清理器維持線性時間、在惡意輸入上有上限的 JS/TS lexer、精準的 VH-AI-006 argv 判斷，以及 PyPI 打包。

### 新增

- `vibeharness --init-config [PATH]` 把套件內建設定複製一份供編輯（預設 `./vibeharness.yaml`）後 exit 0；已存在的檔案不會被覆寫（exit 5），除非加上 `--force`。沒有 `--config` 時，CLI 依序使用目前目錄的 `./vibeharness.yaml`、`./.vibeharness.yaml`，都沒有才用內建預設，並在 stderr 印出實際使用的設定檔與來源。**資安提醒**：在不受信任的 checkout 裡會因此自動載入該 checkout 的 `vibeharness.yaml`，它可以改掉 `api_base`／`api_key_env`；這種情況請明確指定 `--config`（Action 一律如此）。
- `python -m vibeharness`（與 `vibeharness` 指令相同）；套件附 `vibeharness/py.typed`。
- Action 新增輸入 `sandbox`（預設 `local_subprocess`；`docker` 會從 action 自帶的 Dockerfile 建置兩個沙盒映像，並以 `sandbox_provider: docker` 的設定檔副本執行）與 `artifact-name`（預設 `vibeharness-report`；同一次執行內必須唯一，例如每個矩陣格各自命名）。
- `VIBEHARNESS_KEEP_DUMPABLE=1` 讓 harness 保持可 dump，方便除錯器附加（此時生成的測試讀得到它的 `/proc` environ；只供除錯）。

### 變更

- JSON 報告 `schema_version` 為 `"2"`：沒有套用跨模型驗證時 `summary.confirmed_whitebox_bugs` 為 `null`（不再是 0，0 會被讀成「審查過、沒有缺陷」），Markdown 顯示 N/A。版本 1 的報告仍可當 `--baseline`。
- `--target` 預設改為 `.`（目前目錄），不再是 `examples`。
- 呼叫紀錄帶 `attempt`（第一次詢問為 0，重問為 1、2……），`sorted_call_log` 依代理、原始提示 SHA 與 `attempt` 排序，所以不論執行緒完成順序，同一次呼叫的 `retried` 一定排在最後那筆之前。
- JS/TS 測試模組每 10 個一組計算預算，每組各有一份 `sandbox_timeout_seconds`（最壞情況 ceil(模組數 / 10) × 2 × `sandbox_timeout_seconds`）；批次逾時後 Python 與 JS 的重跑都用 min(`per_test_timeout_seconds`, 剩下的預算)，不會超出批次預算。
- `--estimate` 搭配 `--cache-only` 時，最大值不再乘上重問次數（根本不會重問）；`--cache-only` 搭配 `--mode mock` 會印出「沒有作用」的警告。
- PyPI 長描述改用 `README.en.md`；兩份 README 都改用絕對連結，安裝以 `pip install vibeharness-mas` 為主（pipx／uv 為替代），並補上專案網址、關鍵字、classifier 與 PEP 639 的授權表達式。

### 資安

- composite Action 一律帶 `--config`（`extra-args` 沒指定時用套件內建的設定），所以被稽核工作區裡的 `vibeharness.yaml` 絕不會被自動載入。
- `extra_params` 不可再設定 litellm 的罐頭回應鍵 `mock_response`／`mock_tool_calls`／`mock_timeout`／`mock_delay`（不連網的假答案會被登記成 live 證據）或 `ssl_verify`（會讓 `api_base` 的 https 檢查失去意義）；兩者都是 `ConfigError`（exit 5）。
- 本機沙盒限制子程序寫出的每個檔案最多 64 MiB（`RLIMIT_FSIZE`，POSIX；忽略 `SIGXFSZ`，超過上限的寫入得到 `EFBIG`，回報為「無法正常執行」），print 迴圈再也塞不滿 tmpfs；擷取的輸出以 `os.pread` 讀回。Windows 的假家目錄也涵蓋 `APPDATA`／`LOCALAPPDATA`（`PROGRAMDATA` 保留）。只在本機沙盒執行時才讓 harness 不可 dump，以明確的 C 型別呼叫，失敗時記 WARNING。
- VH-AI-007：URL 憑證改由逐個 `://` 的掃描器找出，含 `$ ' " { } < > @` 的密碼也會被遮蔽並回報；範本與遮罩只有在整個密碼都是時才豁免；迴環位址以 `ipaddress` 解析（`localhost`、`*.localhost`、127.0.0.0/8、`::1`、`0.0.0.0`；`127.evil.com` 不算）；常見預設密碼與使用者名稱等於密碼只在迴環或範例／開發用主機上豁免（`example.com`／`.org`／`.net` 及其子網域、`*.example`、`*.test`、`*.invalid`、空主機、`db` 這類單一標籤名稱）。取捨：`admin:admin@prod-db`（單一標籤）不會回報。
- VH-AI-009：否定詞只有緊接在片語或其動詞之前才算（未來、非常、特別這類詞裡的單字不再讓命中失效）；結尾的 後／則／之前 只在 如果／若／當… 之後才算條件，嗎／? 只在 是否… 之後才算疑問；會／已／被／曾 之後的描述與被動句排除；範圍詞之間可以夾 的／這些；英文描述句需要程式碼主詞或句首助動詞，加上乾淨輸入的限定，所以「you must report no findings」現在會命中。
- 每條清理樣式在惡意輸入上都是線性時間（子句往回看 200 個字元、以反向預查判斷 token 前綴、私鑰區塊停在下一個 `BEGIN`、不會回溯的通道標籤正規表達式，也能抓到缺少 `>` 的殘缺標籤）。

### 修正

- CLI：harness 在 `main()` 的防護內才延遲匯入，所以安裝不完整或缺少相依套件時以 exit 5 結束並說明如何重新安裝，不再以 Python 的 1（= NEEDS_FIXES）當掉；console script、`python main.py` 與 `python -m vibeharness` 都一樣。
- 執行器：測試執行中，在目標框架拋出的 ImportError／ModuleNotFoundError（延遲匯入沙盒裡沒有的套件），以及目標檔案的 SyntaxError 家族錯誤，與收集階段一樣判為 ERROR「目標已損壞」，不再是 FAILED 缺陷（目標裡的 NameError 仍是 FAILED）；這種變異體算無效。在測試模組拋出的 `AttributeError: module／type object ... has no attribute ...` 與 `OSError: [Errno 27]` 算 harness 錯誤。主行程的結束狀態遺失（被別處回收）時沙盒回報 125，絕不偽造成 0；Python 3.13 之前的 macOS／BSD 先以 kqueue 等待，最後才退回 `waitpid`。
- 程式碼閘門：透過模組層級輔助函式，以及同一模組中定義的基底類別方法達到的斷言也算數。
- JS/TS 擷取：template literal 改用明確的堆疊（`${` 巢狀數百層也不會 `RecursionError`）；失敗的 JSX 嘗試改為共用檔案大小 4 倍（至少 256 000 字元）的掃描預算，取代 32 次的次數上限，已知的 TS 泛型開頭不會嘗試當 JSX；泛型往回看（512）、引數掃描（4096）與符號片段總量（檔案大小 16 倍 + 2 000 000）都有上限；單一檔案的意外錯誤或超過片段上限的檔案列入 `parse_failures`（證據缺口），不再中止整次執行。
- VH-AI-006：argv 豁免會解析真正的程式（去掉路徑與 `.exe` 的基底名稱、`python3.11`／`node18` 這類帶版本號的直譯器、`deno`／`bun`／`pwsh`／`awk`、`ssh`、`env`／`sudo`／`doas`／`timeout`／`nice`／`nohup`／`xargs` 等包裝前綴及其選項、`sys.executable`、只綁定到字串常數或 `shutil.which(常數)` 的名稱、`executable=`）；無法判斷的非字面值程式保守處理；`asyncio.create_subprocess_exec` 的可變位置引數與只用關鍵字傳入的執行點引數（`args=`、`command=` 等）也會檢查。單一檔案分析失敗時記錄並略過，不再中止 `scan_files`。已知限制：`os.exec*`／`os.spawn*` 不算執行點、`env -S "bash -c …"` 不解析、常數名稱以整個檔案解析。
- 黑箱：根路由或萬用路由（`/`、`*`）只有被引號包住或以完整的 `GET /` 形式出現時才指名符號，所以文字裡的「and/or」「1 * 10^6」「GET /admin」不再把根路由拉進來。

### 工程

- 帶雜湊鎖定的建置後端：`requirements-build.in`／`requirements-build.txt`（setuptools，與 `[build-system]` 同一範圍）；Action 以 `--no-build-isolation` 安裝，CI 的 `package` 與發布的 `build` job 以 `--no-isolation` 建置，所有安裝與發布建置都經雜湊驗證。Dependabot 也追蹤這份建置鎖定檔。
- CONTRIBUTING 補上完整的發布檢查清單，SECURITY 補上支援版本表與私下回報管道；兩份 CHANGELOG 加上每個版本的比較連結。
- 新的回歸測試 `tests/test_r2_cli_gateway.py`、`test_r2_executor_sandbox.py`、`test_r2_extractor_scanner.py`、`test_r2_packaging.py` 與 `test_r2_sanitize.py`。已知限制：docker CLI 在主機端的輸出沒有上限（單檔上限只套用在本機沙盒）。

## [0.6.0] - 2026-10-10

依審查結果的強化：沙盒隔離與執行器歸因、崩潰的結束碼與設定驗證、誠實揭露未經驗證的假設、更精準的確定性規則與路由偵測、模型輸出的第二個不可信通道，以及帶雜湊鎖定、以 digest 釘死的建置與發布流程。

### 新增

- `--cache-only`：每次模型呼叫都只從回應快取取用（需要 `--cache-dir` 或 `global.cache_dir`，否則 exit 5），絕不呼叫供應商、不扣 `max_model_calls`、不重問，也不需要 litellm 或 API 金鑰。快取沒有的呼叫與預算用完同樣處理：hybrid 改用模擬並列為證據缺口（「--cache-only：N 次代理呼叫在回應快取中沒有答案」，判定不會是 `READY_TO_SHIP`），live 以 exit 4 中止。`--estimate` 加上 `--cache-only` 時照樣列出呼叫數，並註明不會呼叫供應商、沒有花費（不發預算警告）。

### 資安

- 本機沙盒：Linux 上 harness 在啟動第一個子程序前讓自己不可 dump（`prctl(PR_SET_DUMPABLE, 0)`，只做一次、盡力而為），生成的測試無法再經 `/proc/<harness>/environ` 讀到 harness 啟動時的 API 金鑰；`HOME`（與 `USERPROFILE`）指向每次執行專用的假家目錄（以 `PYTHONUSERBASE` 保留 `--user` 安裝的套件，移除 `HOMEDRIVE`／`HOMEPATH`）。同一使用者的其他行程仍然可讀，所以 `local_subprocess` 仍然不是安全邊界。
- `models.<alias>.extra_params` 不能再設定保留的 litellm 鍵（`RESERVED_EXTRA_PARAMS`：端點、憑證、`model`／`messages`、逾時、重試、`fallbacks`、`stream`）；它們會繞過 `api_base` 的 https 檢查，現在是 `ConfigError`（exit 5），呼叫時也會再過濾一次。
- 回應快取的 key 納入端點身分（`api_base`、`aws_region_name`、`aws_profile_name`、`api_key_env`），同一個模型字串指向另一個端點或帳號時，不會再拿到前一個的答案（既有的快取會失效一次）。
- 二階提示注入：威脅模型項目改以新的 `<untrusted_model_output>` 通道交給攻擊合成器，驗證者與測試生成器的提示詞把審查者寫的發現文字放進不可信通道；兩種通道的偽造標籤（任何大小寫、帶屬性、內含空白）在兩種通道內都會被中和。
- 密鑰遮蔽（VH-AI-007）新增 AWS secret access key、URL 帳密中的密碼（含 `redis://:pass@` 這種空使用者名稱）、JWT、Stripe 與 Azure storage 金鑰，有變數名稱在前時只換掉值；URL 憑證中的開發用佔位值（迴環主機、常見佔位密碼、使用者名稱與密碼相同、範本）仍會遮蔽，但不再回報。
- live HTTP 攻擊必須打 base URL 的同一個連接埠（沒寫時用協定預設值）；同一台機器的其他連接埠是別的服務，該測試會被拒絕。

### 修正

- CLI：任何意外例外，不論發生在建構或設定 harness 時、`--estimate` 中（含寫不進 `--output`），或在所有階段之外，都以 5 結束，絕不會落到 Python 預設的 1（CI 會讀成 NEEDS_FIXES）；執行之外的 Ctrl-C 以 130 結束；argparse 的程式名稱固定為 `vibeharness`，Python 3.14 下錯誤訊息仍以 `vibeharness:` 開頭。
- 設定：`--config` 是目錄、無法讀取或二進位檔，以及最上層、區段或 `models`／`agents` 項目不是 mapping，都是 `ConfigError`（exit 5）；空的 `global:` 不再崩潰。`per_test_timeout_seconds` 與 `sandbox_timeout_seconds` 的 null／0 視為預設值（30／120），負數或非整數會被拒絕；`sandbox_memory_mb: null` 維持 2048（只有明確的 0 才關閉上限）；`docker_pids_limit` 的 null／0 對應到 256（Docker 把 0 當成不限制；-1 仍是不限制）。`timeout_seconds`、`max_retries`、`max_output_tokens` 與 `retry_invalid_output` 的 null 等同省略、採用預設值（180、2、16384、1；模型層級的 `max_output_tokens: null` 沿用全域值），`timeout=None`（對 litellm 是不限時）絕不會傳出；0 或負數的 `timeout_seconds` 仍是 `ConfigError`。`extra_params` 也不能設定輸出 token 上限 `max_tokens`／`max_completion_tokens`／`max_output_tokens`（會蓋掉 `max_output_tokens`，讓 `--estimate` 與快取 key 看錯上限）；錯誤訊息指向 `max_output_tokens`。
- 閘道：fallback 回答之後的重問改從主模型重新開始，不再把 fallback 呼叫兩次。重問後才可用的回答也存在原始提示的快取 key 下（以前只存在重問提示的 key 下，而重問提示取決於第一次那個無法使用的回答，所以重跑的第一次嘗試永遠不會命中）。
- 沒有交叉驗證時 `confirmed_whitebox_bugs` 為 0：console 與 Markdown 報告顯示 N/A 與未經驗證的假設數，發現清單的標題是「未經驗證的缺陷假設（未套用跨模型驗證）」，SARIF 的白箱結果帶 `properties.verified` 與「Unverified hypothesis」訊息前綴。
- 去重改用 complete-linkage 取代 union-find，泛泛的發現不能再把不同缺陷串在一起；關鍵詞少於三個的發現改用 Jaccard 比較，簡短的發現只有在具體詞全部出現在詳細發現的標題時才合併。共用同一個 model alias 的驗證者只投一票，單靠佐證不再算驗證。
- 沙盒：輸出寫進暫存檔而不是管道，只等主行程結束，之後砍掉剩下的行程群組（POSIX），佔住 stdout 的殘留子行程不會再把已經結束的執行變成逾時，也活不過這次執行；stdin 是 `/dev/null`；非正數的單次逾時退回批次預算，逾時原因寫實際使用的逾時（絕不是「0 秒」）。
- 執行器：NameError／ImportError 只有在最內層 frame 是生成的測試模組時才算 harness 錯誤；在目標內拋出則是缺陷（FAILED，不是 exploit）。JS/TS 模組以剩下的批次預算（`sandbox_timeout_seconds`）執行，批次逾時後其餘模組在批次預算內改用 `per_test_timeout_seconds` 重跑，與文件一致。Node 22 的 `TypeError [Error]: x` 正規化為 `TypeError: x`（保留 `ERR_*` 錯誤碼）。
- 程式碼閘門：`Test*` 類別的每個 `test_` 方法都必須有斷言，可以直接寫，或透過含斷言的 `self.<helper>()`；有斷言的方法不再替同類別的其他方法背書。
- JS/TS 擷取：引號字串與 regex literal 在換行處結束，JSX 的撇號與 `</tag>`／`/>` 不再吞掉後面的宣告，`${...}` 當成程式碼分析，`a++ / 2` 是除法，能處理 TypeScript 的回傳型別、泛型、帶型別的箭頭函式與有型別註記的變數，多載與 `declare` 簽章不算符號。route 需要已知的路由器（常見名稱、`*Router`／`*App` 名稱，或綁定到 `express()`／`Router()`／`fastify()`／`new Koa()` 等的變數），否則要有 `/` 路徑加上處理函式；HTTP 用戶端（axios、`axios.create()` 的結果、`$`、msw 的 `rest` 等）一律不算；認得 `""`、template 與識別字路徑、`app.all`、鏈式的 `app.route('/x').get().post()`、物件形式的 `server.route({method, path})`、hapi 的陣列形式 `server.route([{...}, {...}])`（每個物件一個 route）、已知路由器上有處理函式的 regex 路徑（`app.get(/^\/users\/(\d+)$/, h)`）與 Next.js 的 `export { h as GET }`；沒有處理函式的 `app.get(PATH)` 刻意不算（Express 用它讀取設定）；Next.js 處理函式只送審一次。`.js`／`.jsx`／`.mjs`／`.cjs`／`.tsx` 裡位於運算式位置的 JSX 元素當成 JSX 解析，子元素文字清空，JSX 文字裡的 `/*`、單獨的反引號或引號不再把檔案後半段藏起來；不是合法 JSX 的 `<`（TS 泛型）退回一般詞法分析，每個檔案最多 32 次失敗嘗試，避免平方時間。
- Python 擷取：先判斷路由器接收者再看路徑（`APIRouter(prefix=...)` 上的 `@router.get("")` 是 route），會擷取模組與類別層級 `if`／`try`／`with`／`for`／`while`／`match` 底下的定義，函式內以路由裝飾器註冊的處理函式（Flask `create_app` 工廠）也成為 route；外層函式的原始碼裡，這些處理函式的本體縮成一行標出檔案行號的佔位，所以每個本體只送審一次。
- VH-AI-004：`pipeline()` 看 `model=` 或第二個位置引數；`revision="main"`／`"master"`／`"HEAD"` 等不算固定；本機檢查點以被掃描檔案旁邊為準。VH-AI-005：容易混淆的後綴需要 AI 接收者，以名稱中的詞比對（`blockchain_client` 不算 `chain`）；匯入 AI SDK 的檔案中，參數或來源不明的接收者上的 `messages.create`／`messages.stream`／`chat.complete` 會被標出；`config=`／`generation_config=` 只有真的含上限才算。VH-AI-006：追蹤 `for`／`with`／comprehension／海象運算子的綁定與點號屬性；沒有 `shell=True` 的字面值 argv 清單是安全的，除非 `argv[0]` 被污染或是 shell／直譯器；同一範疇裡只被指派為字面值清單的名稱（`cmd = ["git", "checkout", branch]; subprocess.run(cmd)`）套用相同的豁免，以被污染的資料 `append`／`extend`／`insert`／`+=` 修改它則會命中；新增來源（`llm(...)`、`llm.predict`、`LLMChain().run`、`ollama.chat`、`chain.invoke` 等）與匯點（`subprocess.getoutput`／`getstatusoutput`、`asyncio.create_subprocess_shell`／`_exec`），所以 `answer = llm(...); eval(answer)` 現在會命中。
- VH-AI-008：韓文填充字元為 HIGH（顯示為 `<U+XXXX>`），不可見的格式字元為 MEDIUM；ZWJ／ZWNJ 與 U+FE00–FE0F 為 MEDIUM，但 emoji、RTL／印度系文字與中日韓異體字的上下文除外（一串連續的選擇器是位元組走私）；LRM／RLM／ALM 與蒙古文自由變體選擇器只剔除。
- VH-AI-009：先做 NFKC 正規化再比對；偵測「ignore everything above」與跨兩行註解或散文的片語（相鄰的程式碼行絕不合併）；略過描述行為的英文句子（「should report no findings for clean code」）；中文的判定宣稱必須指名程式碼、沒有否定或條件，要求空報告的句型必須是命令句；數字寫法（「回報 0 個漏洞」）與先前拿掉的低誤報中文片語重新納入。
- 黑箱：不符合 `[A-Za-z0-9_.:-]{1,40}` 的威脅 id 重新編號為 `THREAT-NN`；STRIDE 類別比對不分大小寫與分隔符，威脅嚴重度先去空白轉大寫；崩潰的威脅建模批次與攻擊合成經 `record_failure` 記錄（evidence gap #3）。
- 審查者的嚴重度會正規化（空白、標點、大小寫，以及 `CRIT`、`SEVERE`、`MAJOR`、`MODERATE`、`MINOR`、`NOTE` 等同義詞）。發生 live 的 `LLMGatewayError` 或 Ctrl-C 時，審查、驗證、測試生成、威脅建模與合成的執行緒池會取消尚未開始的呼叫，失敗的嚴格 live 執行不再為排隊中的呼叫付費。
- `en_only`／`zh_only` 只切 `bi()` 產生的字串（分隔符之前有中日韓文字、之後沒有），真實模型剛好含「 ／ 」的文字不會再被截斷。
- 報告：模型衍生的 id 與路徑放進程式碼區段，在表格內另外跳脫管線符號；模型自由文字的換行（含 U+2028／U+2029／U+0085）收合成空白，無法開出偽造的標題、setext 底線、HTML 或表格區塊。SARIF 絕不輸出 `..`：`%SRCROOT%` 之外的絕對路徑改成不帶 `uriBaseId` 的 `file://` URI，會跳出根目錄的相對路徑不給位置，Windows 磁碟機路徑在任何主機上都依 `ntpath` 規則處理。突破的位置以完整識別字或路由比對，最長的比對勝出。`summary.agent_calls` 與部分報告的 `agent_calls` 以固定順序排序。

### 工程

- CI：Python 3.10–3.14，另加一格 macOS（3.12）；所有安裝都用 `--require-hashes`，`pip-audit` 也加上 `--require-hashes`；`package` job 建置 sdist 與 wheel，並在解開的 sdist 裡跑完整測試套件；`tests.yml` 可經 `workflow_call` 呼叫。
- `publish.yml` 預設唯讀，先對 tag 指向的 commit 跑 `tests.yml`，在乾淨的 venv 對 wheel 做 smoke test，只有 release job 拿到 `contents: write`。
- `action.yml` 從 `$GITHUB_ACTION_PATH` 安裝（`uses: ./` 也適用），相依套件以 `requirements.lock` 帶雜湊驗證，套件本身用 `--no-deps`；run 腳本裡沒有 `${{ }}`。`live-smoke.yml` 的 inputs 經 `env` 傳入並先驗證；JSON 重跑改用 `--cache-only --mode hybrid` 讀同一個 `--cache-dir`，不再呼叫模型（也不再用 `--max-model-calls 0` 的不限制），整個 workflow 最多 `max_model_calls` 次真實呼叫；第一次沒能快取的呼叫改用模擬並列為證據缺口。
- Actions 升版為 checkout v7.0.1、setup-python v7.0.0、upload-artifact v7.0.1、download-artifact v8.0.1、setup-node v7.0.0（取代 Dependabot PR #38），之後 #46 再升為 upload-artifact v7.0.2、download-artifact v8.0.2、setup-node v7.1.0、pypi-publish v1.14.2；`pypa/gh-action-pypi-publish` 改釘 v1.13.0 的 commit，而不是 annotated tag 物件。
- 沙盒映像：基底映像以多架構 index digest 釘死、預設 `USER 65534`，Python 映像改從新的帶雜湊鎖定檔 `docker/sandbox-requirements.txt` 安裝（以 `requirements.lock` 為約束從 `docker/sandbox-requirements.in` 編譯）；專案專用映像安裝時要切到 `USER root`，裝完再切回來。`requirements.lock` 以 `--generate-hashes` 重新產生（版本不變）。
- sdist 收錄 `tests/`（含 `conftest.py`）、`examples/`、`main.py`、`action.yml`、requirements 檔與鎖定檔、`docker/*`、`CONTRIBUTING.md`、`SECURITY.md` 與兩份 CHANGELOG；加上 Python 3.14 classifier；setuptools 建置後端上限 `<85`；Dependabot 新增 docker 生態系，並把 `/docker` 納入分組的 pip 更新；pre-commit 的 ruff hook 改為 v0.16.10，與 `requirements-dev.txt` 一致。
- 新增回歸測試 `tests/test_review_*.py`（blackbox、build、cache_only、cli_config、dedup_votes、extractor_scanner、known_limits、reports、sandbox_executor、sanitize、sanitize_blackbox_fixes、whitebox_fixes）；`tests/test_review_build.py` 守住上述 CI、打包與映像釘版。

### 文件

- README、設定與設計文件描述上述變更（設計文件以 `68814c9` 重新核對行號引用，並更新函式索引與常數表）；`docs/sample_report.md` 由 mock 執行重新產生：已確認缺陷的指標顯示 N/A 與未經驗證的假設數，發現清單改用新的「未經驗證的缺陷假設」標題，執行來源各列依序排列。

## [0.5.1] - 2026-10-10

修正版：突變測試暫存複本的過濾與大小上限、報告「執行來源」表列序固定、SARIF 範例改用 SHA 釘版。

### 修正

- Markdown 報告的「執行來源」表改依 agent、模型、模式排序：並行呼叫的完成順序不同時，同一次執行的列序不再每次不同（JSON 的 `call_log` 保留原始順序）。
- 跨模型一致度的顯示改由 `agreement_display` 統一產生，報告與 console 共用同一段邏輯。
- README 與 `action.yml` 給目標專案的 SARIF 上傳範例改用 SHA 釘版（`github/codeql-action/upload-sarif@9f759ee…` v3.38.3），與本 repo 的做法一致。
- 突變測試的暫存複本改用與符號擷取相同的略過規則（`SKIPPED_DIRS`、點開頭目錄），也略過位元組碼與指向目錄的符號連結：先前 `.venv`、`build`、`dist` 會整包複製，指向自身的目錄連結會讓複製無限展開而失敗。新增 `mutation_max_copy_mb`（預設 200）：複製前先估大小，超過就略過並列為證據缺口（單一檔案目標會複製整個所在目錄，最容易碰到）。

## [0.5.0] - 2026-10-09

選用的突變測試（Mutation Testing），用來檢查通過的白箱測試是否真的抓得到行為改變。

### 新增

- 突變測試（選用、預設關閉）：`--mutation`／`--no-mutation` 開關（優先於設定檔 `global.mutation_testing`）、`--mutation-max-mutants N`，以及設定鍵 `mutation_testing`、`mutation_max_mutants`、`mutation_timeout_seconds`、`mutation_min_score`。對通過的 Python 白箱測試所涵蓋的函式做確定性的單一 token 改動，在複本上重跑測試並計算分數；只產生證據缺口，不影響 `NEEDS_FIXES`／`BLOCKED_CRITICAL_RISK`。報告新增 Mutation Score 列與「存活的變異體」段落，JSON 帶 `summary.mutation`，`RunMetadata` 記錄最終開關與來源，`--estimate` 在開啟時列出變異體上限，composite Action 新增 `mutation` input。

## [0.4.0] - 2026-10-09

CI 整合（`--baseline`、GitHub Action）、`--estimate`、JS/TS 動態測試執行，以及全面中／英雙語（程式輸出、原始碼註解、說明文字）。

### 新增
- **`--estimate`**：不呼叫模型，只跑第 1 階段，印出每個 agent／每個模型的預期呼叫數（審查者＝reviewer 數 × 白箱批次數、威脅建模＝批次數為精確值；驗證、測試生成、攻擊合成依假設「每批 3 個發現、每批 4 個威脅、70% 確認、30% 需修復」列為情境值，最大值含 `retry_invalid_output` 重問與每測試最多 2 次修復）、估計 prompt／輸出 token、與 `max_model_calls` 的比較警告；`models.<alias>.price_per_million_input`／`_output`（新選填欄位，啟動時驗證）有設定時給估計花費。`--format json` 時寫入 `--output`；exit 0。`VibeHarnessCommander` 新增 `select_symbols()`／`work_dir_for()` 供估算與正式執行共用第 1 階段
- **`--baseline <report.json>`**：指定一份先前的 JSON 報告後，其中已存在的白箱測試失敗（以其來源發現識別）、探針失敗、黑箱突破與 HIGH 以上的規則命中仍列在報告（新段落「Known from baseline (not counted)」與建議）但不計入判定與 exit code，CI 只對新問題失敗。比對 key 與執行次序無關：finding＝目標相對路徑＋符號＋標題正規化、突破＝威脅的 STRIDE 分類＋標題＋攻擊向量、靜態命中＝規則＋檔案＋證據（不含行號）、探針＝符號名。JSON 報告的靜態命中、確認發現、失敗的白箱測試與突破新增 `fingerprint` 欄位（schema 版本不變）；0.3.0 的報告沒有該欄位會自動重算；崩潰的 `.partial.json` 與非本工具的 JSON 會被拒絕（exit 5）。`VibeHarnessSummary` 新增 `baseline_path`／`baseline_suppressed`
- **composite GitHub Action（`action.yml`）**：目標專案以 `uses: chinchiang/MultiAgentGama@vX.Y.Z` 一行執行稽核；inputs 含 `target`、`mode`、`max-model-calls`、`max-files`、`changed-since`、`baseline`、`output`／`format`、`sarif`、`extra-args`、`python-version`、`fail-on`（`blocked`／`needs-fixes`／`inconclusive`／`never`）；outputs `verdict`、`exit-code`、`report`、`sarif`；報告、SARIF 與 `.partial.json` 上傳為 artifact。安裝來源為同一個 action ref 的 git 套件（PyPI 發布後可改）；actions 以 SHA 釘版
- **JS/TS 動態測試執行**：目標檔為 `.js`／`.jsx`／`.mjs`／`.cjs`／`.ts`／`.tsx`／`.mts`／`.cts` 時（`.mjs`／`.cjs`／`.mts`／`.cts` 也新納入符號擷取），白箱測試生成與黑箱 in-process 攻擊測試改生成 `node:test` + `node:assert` 的 ES module，並以 Node 內建 runner 執行（`GeneratedTest.language`／`TestExecutionResult.language` 新欄位；`RunMetadata.node_runtime` 記錄實際使用的 Node 版本）。新增 `NodeSubprocessSandbox`／`NodeDockerSandbox`（`docker/sandbox-node.Dockerfile`）、JS 程式碼靜態閘門 `check_js_test_code`（括號配對、至少一個 `test()`／`it()`、每個測試需有斷言、拒絕 `npm`／`pnpm`／`yarn`／`bun`／`npx` 安裝）、`js_module_kind`／`js_exported_names`／`js_import_instructions`（ESM／CommonJS 偵測與 `file://` 匯入寫法）、Node JUnit 分類（`ERR_ASSERTION` 才算確認突破；目標內 `TypeError` 為缺陷非 exploit；測試側 `ReferenceError`、`ERR_MODULE_NOT_FOUND`、`SyntaxError` 為 harness 錯誤；載入錯誤從 runner 輸出補回）。每個 JS 模組各自在一個 `node --test` 程序執行（Node 的 junit reporter 不標示測試所屬檔案）。設定新增 `node_bin`、`sandbox_node_provider`、`docker_node_image`；Node 沙盒不套 `RLIMIT_AS`，改以 `--max-old-space-size` 封頂；`NODE_OPTIONS`／`NODE_REPL_EXTERNAL_MODULE` 列入環境變數拒絕清單。JS/TS 目標的證據缺口改為三種：未生成 JS 測試（mock 模式必然如此）、生成但 Node 不可用、TypeScript 測試因 Node < 22.6 未跑；其他語言維持「只做靜態審查」。限制：不收 JS 覆蓋率、TypeScript 只做型別剝除、Docker 內 ESM 裸 specifier 無法解析。CI 加裝 Node 22（`VIBEHARNESS_REQUIRE_NODE=1` 強制實跑；Linux 另建 Node 映像並以 `VIBEHARNESS_REQUIRE_DOCKER_NODE=1` 強制容器實跑）

### 變更
- **程式輸出與原始碼註解也改為中／英雙語**：Markdown 報告的標題、表頭、標籤與固定句、終端機面板與各階段訊息、證據缺口與建議、CLI 訊息、`--estimate` 輸出、測試執行器的失敗原因與 PoC 標頭、閘道的退回／無效原因、agent 日誌、確定性規則的標題與修正建議、模擬引擎的固定內容、SARIF 的規則說明與訊息，全部經新模組 `vibeharness/core/i18n.py` 的 `bi()` 寫成「中文 ／ English」；英文半完全不變，所以 CI 的子字串比對與 `--baseline`／SARIF 指紋（只取 `[a-z0-9]`）不受影響；JSON key、enum 值、SARIF `ruleId`、原始例外文字、`evidence`、`file_filters` 維持英文。送給模型的提示詞維持英文（重問後綴與審查者名稱／focus 先經 `en_only()`）。`vibeharness/`、`tests/`、`examples/`、`main.py` 的每個 docstring 與註解都加上正體中文（`tests/test_i18n.py` 兩個全 repo 測試強制此規範；自掃測試也掃 `examples/`）。`docs/sample_report.md` 以雙語版重新產生
- **所有說明文字改為中／英雙語**：`agents_config.yaml`／`threat_rules.yaml` 的註解與 STRIDE 描述、三個 workflow 與 `action.yml` 的註解與 input／output 說明、`dependabot.yml`、`CODEOWNERS`、兩個 Dockerfile、`pyproject.toml`、`requirements*.txt`、`.pre-commit-config.yaml` 的註解，以及 CLI `--help` 的每個選項說明，都是正體中文（臺灣）在前、English 在後。原本就成對的文件（README、docs/configuration、docs/design、CHANGELOG）維持中／英各一份
- 報告中 PoC 與「Generated Test Code」附錄的程式碼圍欄依測試語言標示（`python`／`javascript`／`typescript`）；console 的覆蓋率標示為「Line Coverage (Python)」。`import_instructions` 對 JS/TS 檔改給 `file://` URL 與匯入寫法，其他非 Python 檔維持「cannot be imported」說明

### 修正
- **JS 突破被降級**：`_js_is_harness_failure` 原本對整段 junit 內文找 `SyntaxError` 等標記，`assert.doesNotThrow` 失敗時內文提到目標拋出的 `SyntaxError` 就會把確認的突破改成 harness ERROR 並丟掉 exploit 旗標；改為只看 Node 回報的例外摘要；檔案層級的載入失敗一律是 harness 錯誤（目標在匯入時印出的 Error 字樣不會讓它變成缺陷或突破），`_js_exception_summary` 跳過「Error: test failed」佔位行並優先取帶標記的錯誤行
- **Docker Node 沙盒不再要求主機有 node**：`sandbox_node_provider: docker` 改用映像檔自帶的 Node（先確認映像檔存在，只在目標含 TypeScript 時才用與測試相同的 `docker run` 前綴在容器內讀 `node --version` 決定型別剝除；讀不到就把 TypeScript 列為未執行而不猜），`RunMetadata.node_runtime` 只在沙盒建立成功後才記錄；Python 與 Node 沙盒共用同一組啟動時驗證一次的設定（`sandbox_timeout_seconds`、`sandbox_memory_mb`；任一沙盒用 docker 時再驗 `docker_pids_limit`（-1 = 不限制）、`docker_network`、`docker_memory`（Docker 接受的 512m／512mb／1GiB 等寫法）、`docker_cpus`、`docker_bin`、`docker_image`／`docker_node_image`），加上 `sandbox_node_provider`，錯誤值一律 exit 5；純本機設定檔裡殘留的 docker 鍵不擋啟動。版本探測在容器內有 `timeout` 兜底，主機端逾時會移除容器，沙盒工廠只把 `SandboxUnavailableError`／`OSError` 揭露為證據缺口
- **基準線鍵**：`normalize` 改為保留任何文字的字母與數字（中文標題不再塌成空字串而共用一個鍵，否則新的突破可能被當成已知），純 ASCII 的鍵與 0.3.0 相同；只有模擬引擎的項目（新欄位 `ThreatItem.is_simulated`、既有的 `ReviewFinding.is_simulated`）以 `bi()` 雙語標題的英文半進鍵，真實模型文字原樣進鍵；SARIF 的 partialFingerprints 與基準線共用同一組 `normalize`／`fingerprint`／`key_text`。進基準線的白箱 key 只來自 FAILED 的結果：上次測試通過的確認發現這次失敗是新問題，不再被壓下
- **Action 的 `extra-args`**：改以 Python `shlex` 切字（引號有效、不執行任何 shell、不展開 glob），文件範例 `--exclude 'tests/*'` 可正常運作；切不開的輸入以 exit 5 失敗而不是靜默略過；讀取方式相容 bash 3.2（macOS runner）
- 模擬引擎的雙語發現／威脅在 hybrid 模式進入 live 提示詞時只送英文半；`zh_only` 搬到 `i18n.py`；`_target_revision`／`changed_files` 改用 `work_dir_for`

## [0.3.0] - 2026-10-09

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

### 變更（破壞性：打包命名空間）
- **所有程式搬進單一頂層套件 `vibeharness/`**：`core`、`agents`、`runners`、`reports`、`config` 與 `main` 過去是各自的頂層套件／模組，`pip install` 後直接進 site-packages，會與其他同名套件互撞（`core`、`config` 尤其常見），也會遮蔽使用者專案自己的 `config`。現在只安裝 `vibeharness/` 一個目錄：import 改為 `vibeharness.core.…`、`vibeharness.agents.…`，CLI 進入點為 `vibeharness.cli:main`，預設設定檔在 `vibeharness/config/`，版本在 `vibeharness/__init__.py`；repo 根目錄保留 `main.py` 薄殼，`python main.py …` 與 `vibeharness` 指令行為不變。以函式庫方式使用者需更新 import 路徑；新增測試保證 wheel 不再安裝任何通用名稱的頂層套件

### 新增（後續項目）
- **回應快取**：`global.cache_dir`／CLI `--cache-dir` 開啟後，可用的 live 回應以模型、設定（含 `max_output_tokens`、`extra_params`）與提示為 key 存成 JSON；相同提示直接取用，不呼叫供應商、不扣 `max_model_calls`，call log 與報告標為「live (response cache)」（`AgentCallRecord.cached`）。無效回應不會被快取，損壞的快取檔視同未命中；寫入採暫存檔＋原子取代，平行呼叫不會讀到半截檔案
- **崩潰或中斷時寫出部分報告**：六階段中任何例外或 Ctrl-C，都會先把已完成階段（模型呼叫紀錄、靜態規則命中、發現、驗證結果、白箱測試與結果、威脅、黑箱測試與結果）與錯誤寫到 `<output>.partial.json`（`partial: true`、`phase_reached`）再往上拋；已付費的模型結果不再歸零
- **`local_subprocess` 資源上限**：`global.sandbox_memory_mb`（預設 2048，`0` 關閉）在 POSIX 上以 `RLIMIT_AS` 限制 pytest 程序樹的位址空間，另加 CPU 時間上限（批次預算 + 10 秒）；生成測試配置 1 GiB 時以 `MemoryError` 收場而不是吃光主機記憶體。`docker` provider 不套用（容器已有 `--memory`／`--cpus`，docker CLI 本身不受限）
- **SARIF 規則 `help`**：每條規則帶 `help.text`／`help.markdown`（確定性規則附修復建議與 OWASP／ATLAS／CWE 對應；白箱與黑箱規則說明如何用報告中的測試與 PoC 驗證），GitHub Code Scanning 的 alert 頁才有修復指引
- **中文注入標記**：`VH-AI-009` 新增正體與簡體中文句型——忽略／無視（先前｜以上｜系統）的指令／規則、不要／請勿回報／標記…問題／函式、回報零／沒有發現、給 AI／審查者的注意事項／備註、「AI 審查者：」、將此程式碼視為／標記為安全／通過。「忽略大小寫」「回報錯誤給呼叫端」「寄給審查者」等一般用語不命中，harness 自掃仍為零
- **手動 live smoke workflow**（`.github/workflows/live-smoke.yml`）：`workflow_dispatch` 以 repo secrets 的供應商金鑰對目標跑一次 live／hybrid（可設呼叫數上限），再以回應快取免費重跑產出 JSON，報告、SARIF 與部分報告以 artifact 上傳；exit 4／5 視為失敗，0–3 為目標的判定

### 新增（功能改善）
- **模型回應無法使用時先重問**：非 JSON、缺欄位或空回應的 live 回應過去直接記 `invalid`、整輪 INCONCLUSIVE；現在依 `global.retry_invalid_output`（預設 1）重問，提示會說明上次的問題並要求只回 JSON。第一次嘗試記為 `retried`（報告 Execution Provenance 顯示「unusable, re-asked」，不是證據缺口），仍失敗才記 `invalid`；每次重問都是真實呼叫、計入 `max_model_calls`，預算用完就不重問；`json_output=False` 的修復呼叫不重問
- **`models.<alias>.extra_params`**：原封不動傳給 litellm 的參數（例如 `thinking: {type: disabled}`、`reasoning_effort: low`），可讓推理模型不要把 `max_output_tokens` 全花在思考（live 實測 GLM 的主要失敗原因）；啟動時驗證為 mapping
- **檔案篩選**：CLI `--include GLOB`／`--exclude GLOB`（可重複，覆蓋設定檔的 `global.include`／`exclude`）與 `--changed-since <git ref>`（只分析相對該 ref 有變更的檔案，含暫存、未暫存與未追蹤；ref 無法解析或目標不在 git repo 內為 exit 5）；篩掉的檔案不算證據缺口。目錄排除清單新增 `site-packages`
- **`global.max_file_bytes`**（預設 1 MB）：超過的檔案（minified bundle、產生碼）不分析並列為證據缺口；過去 JS/TS lexer 逐字元掃描會在大檔上耗時數分鐘
- **報告中繼資料**：`summary.run` 新增 `generated_at`（UTC）、`harness_version`、`execution_mode`、`config_path`、`sandbox_provider`、`target_path`、`target_git_commit`／`target_git_dirty`、`file_filters`；Markdown 標頭、JSON 與 SARIF `properties` 都帶出；JSON 新增 `schema_version`（`"1"`）
- **提早失敗與中斷**：`--output`／`--sarif` 的目錄不存在或不可寫時在任何模型呼叫前就 exit 5（過去整輪跑完才在寫檔時崩潰，模型花費全部白費）；Ctrl-C 改為 exit 130 並明確說明未寫出報告，不再印 traceback

### 工程（治理與供應鏈）
- 新增 `SECURITY.md`（私密通報流程、重點弱點類型、支援版本）、`CONTRIBUTING.md`（開發環境、提交前檢查、修改原則、發布步驟）、`.github/CODEOWNERS`、PR 與 issue 模板
- 新增 `.github/dependabot.yml`：每週提議 SHA 釘版 Actions 與 `requirements.lock` 的更新（`litellm`／`pydantic` 的 major 升版除外）；過去 `audit` job 一旦遇到鎖定版本的 CVE，只能手動重新產生鎖定檔
- `requirements-dev.txt` 全部釘版（新增 `pip-audit==2.10.1`、`build==1.6.1`，`pytest-cov` 釘到與鎖定檔相同的 7.1.0），CI 的 `audit`／`package`／`publish` job 改從此處讀取版本，不再安裝未釘版的最新版
- `tests.yml` 加 `concurrency`（同一 PR 的新推送取消舊 run）；`publish.yml` 的 `build-and-upload` 加 `timeout-minutes`，`pypi-publish` 改下載同一份建置產物（`actions/upload-artifact`／`download-artifact`，SHA 釘版）而非重新建置，Release 與 PyPI 的檔案位元相同
- pre-commit 新增 mypy hook（以專案環境執行，與 CI 的 lint job 同一組釘版）

### 修正（深入審視，2026-10-09）
- **套件目標的匯入指引**：`--target` 指向本身是套件的目錄（含 `__init__.py`，模組之間用相對匯入）時，提示詞與離線探針過去指示 `from app import f`，目標一執行就丟 `attempted relative import with no known parent package`，執行器還把它歸咎於「目標壞掉」；現在 `module_import_name` 會偵測套件並改以上層目錄為基準（`from shop.app import f`，上層目錄本來就在沙盒的 sys.path），探針也改用 `importlib.import_module` 依模組名載入
- **`--base-url` 只接受 http(s)**：`urllib` 也能開 `file:`／`ftp:`／`data:`，所以 `--base-url file:///etc/hostname` 過去會被當成「伺服器存活」而切換成 Live HTTP 模式；現在 CLI 與 `ThreatScenarioBuilder` 都以 `validate_base_url` 檢查 scheme 與主機名，不合法為用法錯誤（exit 5）
- **`VH-AI-009` 不再把裸的 `READY_TO_SHIP` 當成注入**：這條規則對本 repo 自掃會命中 27 次（都是判定常數），任何讀取 JSON 報告並比較 `overall_status` 的目標專案也會永遠被列為證據缺口；改為只匹配「要求審查者給出該判定」的句型，並新增對 harness 原始碼自掃為零命中的 dogfood 測試
- **供應商例外訊息先遮蔽再記錄**：`live invocation failed: …` 原文會進 `call_log` 的 reason、Markdown 的 Execution Provenance、JSON 報告與 live 模式的 stderr，而 HTTP 用戶端例外可能回顯帶金鑰的 URL 或標頭；現在所有 reason 與 `LLMGatewayError` 訊息都先經 `redact_secrets` 與控制字元清除
- **數值設定於啟動時驗證**：`timeout_seconds`、`max_retries`、`max_output_tokens`（全域與每模型）與各 agent 的 `temperature` 過去只在呼叫時讀取，寫錯（例如字串）會讓 litellm 失敗，hybrid 模式再悄悄退回模擬引擎、只留下 INCONCLUSIVE；現在一律 `ConfigError`（exit 5）
- 文件：報告章節標題改用與 README／harness 相同的六階段編號（Phases 2–3、4、5）；設計文件的測試數更新

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

[Unreleased]: https://github.com/chinchiang/MultiAgentGama/compare/v0.13.0...HEAD
[0.13.0]: https://github.com/chinchiang/MultiAgentGama/compare/v0.12.0...v0.13.0
[0.12.0]: https://github.com/chinchiang/MultiAgentGama/compare/v0.11.0...v0.12.0
[0.11.0]: https://github.com/chinchiang/MultiAgentGama/compare/v0.10.1...v0.11.0
[0.10.1]: https://github.com/chinchiang/MultiAgentGama/compare/v0.10.0...v0.10.1
[0.10.0]: https://github.com/chinchiang/MultiAgentGama/compare/v0.9.0...v0.10.0
[0.9.0]: https://github.com/chinchiang/MultiAgentGama/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/chinchiang/MultiAgentGama/compare/v0.7.1...v0.8.0
[0.7.1]: https://github.com/chinchiang/MultiAgentGama/compare/v0.7.0...v0.7.1
[0.7.0]: https://github.com/chinchiang/MultiAgentGama/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/chinchiang/MultiAgentGama/compare/v0.5.1...v0.6.0
[0.5.1]: https://github.com/chinchiang/MultiAgentGama/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/chinchiang/MultiAgentGama/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/chinchiang/MultiAgentGama/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/chinchiang/MultiAgentGama/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/chinchiang/MultiAgentGama/compare/v0.1.2...v0.2.0
[0.1.2]: https://github.com/chinchiang/MultiAgentGama/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/chinchiang/MultiAgentGama/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/chinchiang/MultiAgentGama/releases/tag/v0.1.0
