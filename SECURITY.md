# Security Policy ／ 資安政策

正體中文（臺灣）｜ [English](#english)

## 通報弱點

VibeHarness-MAS 本身是一個 LLM 應用，而且會執行模型生成的程式碼，所以我們特別重視下列幾類問題：

- 沙盒逃逸或隔離失效（`docker` provider 的容器強化參數、`local_subprocess` 的環境變數白名單）
- 待審程式碼或模型輸出對 harness 的提示注入，繞過 `vibeharness/core/sanitize.py` 的信任邊界控制
- 報告（Markdown／JSON／SARIF）中的輸出處理缺陷（可載入外部資源、跳脫程式碼區塊、ANSI／控制序列）
- 憑證外洩：API 金鑰出現在報告、日誌、沙盒環境或送往模型的提示中
- 生成測試可安裝套件或連到 `--base-url` 以外的主機
- 品質閘門可被誘導給出 `READY_TO_SHIP`（例如空測試、假斷言、未分類的失敗被吞掉）

**請不要在公開 issue 揭露弱點。** 本 repo 已公開並啟用 GitHub 的私密弱點通報：到 [repo 的 **Security** 頁籤](https://github.com/chinchiang/MultiAgentGama/security) → **Report a vulnerability**（[說明](https://docs.github.com/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)），內容只有維護者看得到。若你無法使用該功能，請開一個只寫「security contact requested」的 issue，維護者會私下聯絡你。

通報時請附上：受影響的版本或 commit、重現步驟（最好是可直接執行的目標範例與指令）、影響範圍與你認為的嚴重度。

## 處理流程

- 7 天內確認收到並初步分級。
- 確認為弱點後，修正會以 patch 版本發布到 PyPI（`pip install -U vibeharness-mas`）與 GitHub Release（見 `CHANGELOG.md`），並在 GitHub Security Advisory 公開致謝（除非你希望匿名）。PyPI 的版本不可覆寫，所以修正一律是新的版本號。
- 請給我們合理的修正時間（一般為 90 天）再公開細節。

## 支援版本

| 版本 | 支援安全修正 |
| :--- | :---: |
| 0.12.x | ✅ |
| < 0.12 | ❌ |

只有最新的 minor 版本會收到安全修正；新的 minor 版本發布後，上一個 minor 版本即停止支援。

## 使用上的安全提醒

- `sandbox_provider: local_subprocess` **不是安全邊界**：模型生成的測試以你的使用者權限執行。對不信任的目標請用 `docker`。
- 待審程式碼會送到 `vibeharness/config/agents_config.yaml` 列出的每一家模型供應商（寫死的憑證會先遮蔽）。
- 依賴的已知弱點由 CI 的 `audit` job（pip-audit）、Dependabot 警示與 Dependabot 安全性更新（自動開修正 PR）追蹤。
- 本 repo 啟用了 GitHub 的 secret scanning 與 push protection（含有憑證的推送會被擋下），以及 CodeQL 程式碼掃描（`.github/workflows/codeql.yml`，Python 與 workflow，`security-extended` 查詢；是 `master` 的必要檢查）。Actions 要求第三方 action 以完整的 commit SHA 釘版；觸發發布的 `v*` tag 只有管理員能建立、移動或刪除；`master` 只接受經過 PR 與必要檢查的合併，不能強制推送或刪除。

---

## English

### Reporting a vulnerability

VibeHarness-MAS is itself an LLM application that executes model-generated code, so we care especially about: sandbox escapes or isolation failures, prompt injection from the audited code or model output that bypasses the trust-boundary controls in `vibeharness/core/sanitize.py`, output-handling defects in the Markdown / JSON / SARIF reports, credential leakage into reports, logs, the sandbox or prompts, generated tests that install packages or reach hosts other than `--base-url`, and anything that tricks the quality gate into `READY_TO_SHIP`.

**Please do not open a public issue for a vulnerability.** The repository is public with GitHub's private vulnerability reporting enabled: go to the [repository's **Security** tab](https://github.com/chinchiang/MultiAgentGama/security) → **Report a vulnerability**; only the maintainers can see the report. If you cannot use it, open an issue saying only "security contact requested" and a maintainer will reach out privately.

Include the affected version or commit, reproduction steps (ideally a runnable target and command), impact and your severity estimate.

### Process

We acknowledge reports within 7 days, fix confirmed issues in a patch release published to PyPI (`pip install -U vibeharness-mas`) and the GitHub Release (see `CHANGELOG.md`; PyPI versions are immutable, so a fix is always a new version number), credit reporters in a GitHub Security Advisory unless they prefer otherwise, and ask for a reasonable disclosure window (normally 90 days).

### Supported versions

| Version | Supported |
| :--- | :---: |
| 0.12.x | ✅ |
| < 0.12 | ❌ |

Only the latest minor release line receives security fixes; a new minor release ends support for the previous one.

### Security notes

- `sandbox_provider: local_subprocess` is **not a security boundary**: model-generated tests run with your user's privileges. Use `docker` for untrusted targets.
- The audited code is sent to every model provider listed in `vibeharness/config/agents_config.yaml` (hard-coded credentials are masked first).
- Known vulnerabilities in dependencies are tracked by CI's `audit` job (pip-audit), Dependabot alerts and Dependabot security updates (which open fix PRs automatically).
- The repository has GitHub secret scanning and push protection enabled (pushes containing credentials are blocked), plus CodeQL code scanning (`.github/workflows/codeql.yml`, Python and the workflows, `security-extended` queries; a required check on `master`). Actions require third-party actions to be pinned to a full commit SHA; only admins can create, move or delete the `v*` tags that trigger a release; `master` only takes merges through a PR with the required checks and cannot be force-pushed or deleted.
