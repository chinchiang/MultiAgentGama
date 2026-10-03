# Changelog

本專案所有重要變更都會記錄在本檔案。格式參考 [Keep a Changelog](https://keepachangelog.com/zh-TW/1.1.0/)，版本遵循[語意化版本](https://semver.org/lang/zh-TW/)。

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
