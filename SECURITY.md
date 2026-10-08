# Security Policy ／ 資安政策

正體中文（臺灣）｜ [English](#english)

## 通報弱點

VibeHarness-MAS 本身是一個 LLM 應用，而且會執行模型生成的程式碼，所以我們特別重視下列幾類問題：

- 沙盒逃逸或隔離失效（`docker` provider 的容器強化參數、`local_subprocess` 的環境變數白名單）
- 待審程式碼或模型輸出對 harness 的提示注入，繞過 `core/sanitize.py` 的信任邊界控制
- 報告（Markdown／JSON／SARIF）中的輸出處理缺陷（可載入外部資源、跳脫程式碼區塊、ANSI／控制序列）
- 憑證外洩：API 金鑰出現在報告、日誌、沙盒環境或送往模型的提示中
- 生成測試可安裝套件或連到 `--base-url` 以外的主機
- 品質閘門可被誘導給出 `READY_TO_SHIP`（例如空測試、假斷言、未分類的失敗被吞掉）

**請不要在公開 issue 揭露弱點。** 請改用 GitHub 的私密通報：repo 的 **Security** 頁籤 → **Report a vulnerability**（[說明](https://docs.github.com/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)）。若該功能未啟用，請開一個只寫「security contact requested」的 issue，維護者會私下聯絡你。

通報時請附上：受影響的版本或 commit、重現步驟（最好是可直接執行的目標範例與指令）、影響範圍與你認為的嚴重度。

## 處理流程

- 7 天內確認收到並初步分級。
- 確認為弱點後，修正會以 patch 版本發布（見 `CHANGELOG.md`），並在 GitHub Security Advisory 公開致謝（除非你希望匿名）。
- 請給我們合理的修正時間（一般為 90 天）再公開細節。

## 支援版本

只有最新的 minor 版本（`0.x` 中最新的 `x`）會收到安全修正。

## 使用上的安全提醒

- `sandbox_provider: local_subprocess` **不是安全邊界**：模型生成的測試以你的使用者權限執行。對不信任的目標請用 `docker`。
- 待審程式碼會送到 `config/agents_config.yaml` 列出的每一家模型供應商（寫死的憑證會先遮蔽）。
- 依賴的已知弱點由 CI 的 `audit` job（pip-audit）與 Dependabot 追蹤。

---

## English

### Reporting a vulnerability

VibeHarness-MAS is itself an LLM application that executes model-generated code, so we care especially about: sandbox escapes or isolation failures, prompt injection from the audited code or model output that bypasses the trust-boundary controls in `core/sanitize.py`, output-handling defects in the Markdown / JSON / SARIF reports, credential leakage into reports, logs, the sandbox or prompts, generated tests that install packages or reach hosts other than `--base-url`, and anything that tricks the quality gate into `READY_TO_SHIP`.

**Please do not open a public issue for a vulnerability.** Use GitHub's private reporting: the repository's **Security** tab → **Report a vulnerability**. If that is unavailable, open an issue saying only "security contact requested" and a maintainer will reach out privately.

Include the affected version or commit, reproduction steps (ideally a runnable target and command), impact and your severity estimate.

### Process

We acknowledge reports within 7 days, fix confirmed issues in a patch release (see `CHANGELOG.md`), credit reporters in a GitHub Security Advisory unless they prefer otherwise, and ask for a reasonable disclosure window (normally 90 days).

### Supported versions

Only the latest minor release line receives security fixes.
