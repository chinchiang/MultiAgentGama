# 程式碼規則

[English](CODING_STANDARDS.en.md) ｜ 正體中文（臺灣）

審查 diff 時逐條套用下列規則。這裡只收需要判斷的規則；機械性的規則由測試與 CI 擋下，列在最後一節，審查時不必重查。用語以 `GLOSSARY.md` 為準。

## 1. 每個修正都有一個修正前會紅的回歸測試

- 新測試要走到這次改動的分支：把修正拿掉，它就會失敗。只驗證「不會當掉」或結構存在的測試不算。
- 測試套件離線執行：mock 執行模式加上 `tests/conftest.py` 的假 litellm，不需要 API 金鑰或網路。
- 代理呼叫經 `vibeharness/core/fanout.py` 以執行緒並行，測試裡的假回應器若有共用狀態，要加鎖。
- 違規的樣子：修正沒有附測試；新測試在 `master` 上也會通過；測試需要真實模型或網路。

## 2. 判定結果只由已執行的證據決定

- 「假設」「模擬輸出」「形狀錯誤」怎麼影響判定結果，依 `GLOSSARY.md` 的定義比對。
- 任何讓判定不可信的情況都記成證據缺口（有穩定代碼），交給品質閘門，不靜默略過。
- 違規的樣子：模型的回答直接改變判定結果；`except` 吞掉錯誤後繼續，卻沒有記證據缺口；空清單被當成「沒有發現」。

## 3. 目標程式碼與模型輸出都是不可信的輸入

- 送進提示詞的不可信內容，一律以 `Untrusted(Content.X, text)` 傳給 `vibeharness/core/agent_call.py` 的 `ask`／`ask_text`，由它依種類包進標示來源的通道並附上對應的 policy。
- 模型寫的文字進報告前，要經 `markdown_safe`（`vibeharness/core/sanitize.py`）或報告產生器的 `_cell`／`_code_span`／`_cell_code`。
- 違規的樣子：用 f-string 把檔案內容或模型回答直接接進提示詞；繞過 `ask` 自己呼叫 `untrusted_block`；模型文字原樣寫進 Markdown 或 SARIF。

## 4. 設定錯誤在啟動時大聲失敗

- 新的設定鍵在 `vibeharness/core/settings.py` 的 `load_settings` 載入時驗證型別與範圍（`_validate_endpoints`、`_validate_models_and_agents`、`_sandbox_settings`、`_mutation_settings`、`_pattern_list` 等），錯誤是 `ConfigError`／`ValueError`（exit 5）。
- 使用端讀已驗證好的型別化設定值，不再自己解析原始設定。
- 違規的樣子：在使用處才用 `.get(key, default)` 讀新的鍵；型別錯誤要等到呼叫時才炸；null 被當成 0 或空字串。

## 5. 生成的測試能做的事只能收緊

- `vibeharness/core/codecheck.py` 的執行前檢查只能收緊；不安裝任何東西到使用者環境。
- 修復呼叫的界線依 `GLOSSARY.md` 的「修復呼叫」比對。
- 違規的樣子：放寬允許的 import 或系統呼叫；`pip install` 或寫入目標以外的路徑；把無效測試換成 `assert True`。

## 6. 固定輸出字串雙語，英文半不變

- 報告、終端機、日誌、失敗原因與 SARIF 文字的固定字串，一律經 `vibeharness/core/i18n.py` 的 `bi("中文", "English")`。
- 既有字串的英文半不改：CI 與指紋比對靠它。
- 送給模型的提示詞維持英文；雙語的原因進提示詞前先經 `en_only()`。
- 違規的樣子：新的固定字串只有一種語言；改了既有 `bi()` 的英文半；中文或雙語文字進了提示詞。

## 7. 文件跟著行為一起改

- 行為改了，同一個 PR 更新 `README.md`／`README.en.md`、`docs/configuration*.md`，以及兩份 CHANGELOG `[Unreleased]` 的同一個區段；設計層面的改動更新 `docs/design*.md`。
- 設定檔、workflow、`action.yml`、Dockerfile、打包檔的註解與說明文字，以及 CLI `--help`，正體中文（臺灣）在前、English 在後。
- 違規的樣子：新增設定鍵或 CLI 參數，文件沒提；只寫了一份 CHANGELOG，或兩份寫在不同區段；中英文件內容不一致。

## 由測試與 CI 檢查（審查時不必重查）

| 規則 | 由誰檢查 |
| :--- | :--- |
| `.py` 的 docstring 與註解雙語（docstring 內先中文行再英文行；獨立註解在英文上方加一行中文；行尾註解 `# 中文 ／ English`） | `tests/test_i18n.py` |
| 中文用詞通過注入自掃（避免「忽略…指令」「不要回報…」「視為…安全」這類句型） | `tests/test_ai_security.py` |
| 雜湊鎖定檔與沙盒鎖定檔一致、sdist 內容 | `tests/test_review_build.py` |
| 第三方 action 釘 commit SHA 並附版本註解 | `tests/test_review_build.py`、repo 的 Actions 設定 |
| 中英文件成對的行數相同、版本號一致 | `tests/test_r2_packaging.py` |
| 設計文件的 `path:line` 引用 | `tests/test_design_refs.py` |
| lint、型別、覆蓋率 ≥ 93% | CI 的 `ruff check .`、`mypy`、`pytest --cov-fail-under=93` |
