# Changelog

正體中文（臺灣）｜ [English](CHANGELOG.en.md)

本專案所有重要變更都會記錄在本檔案。格式參考 [Keep a Changelog](https://keepachangelog.com/zh-TW/1.1.0/)，版本遵循[語意化版本](https://semver.org/lang/zh-TW/)。

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
