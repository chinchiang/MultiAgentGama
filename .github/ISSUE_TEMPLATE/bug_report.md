---
name: Bug report ／ 錯誤回報
about: harness 行為錯誤、判定不誠實、報告或沙盒問題
labels: bug
---

**請勿在此回報資安弱點**，請改用 Security 頁籤的私密通報（見 `SECURITY.md`）。
**Do not report security vulnerabilities here**; use private reporting (see `SECURITY.md`).

### 版本／Version

`vibeharness --version` 的輸出，或 commit hash：

### 重現步驟／Steps to reproduce

指令（含 `--mode`、`--target` 的型態：目錄／單檔／套件）、`vibeharness/config/agents_config.yaml` 的非預設設定、沙盒 provider：

```bash
vibeharness --target ... --mode mock
```

### 預期與實際／Expected vs. actual

包含 exit code、終端機輸出與報告中相關的 Execution Provenance／evidence gap 段落（請先遮蔽金鑰與敏感程式碼）：

### 環境／Environment

OS、Python 版本、Docker 版本（若用 `docker` provider）：
