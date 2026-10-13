# VibeHarness-MAS

稽核 AI 產生的程式碼：多個模型提出假設，只有實際執行的證據與確定性規則決定判定結果。
Audits AI-generated code: several models propose hypotheses, and only executed evidence and deterministic rules decide the verdict.

## 語言 ／ Language

### 品質閘門 ／ Quality Gate

**品質閘門 ／ Quality Gate**:
由一次執行的證據決定判定結果、證據缺口與建議的那一步。
The step that decides a run's Verdict, Evidence gaps and recommendations from that run's evidence.
_Avoid_: Commander verdict, gate synthesis, Phase 6 logic

**判定結果 ／ Verdict**:
一次執行的四種結論之一：`READY_TO_SHIP`、`NEEDS_FIXES`、`INCONCLUSIVE`、`BLOCKED_CRITICAL_RISK`，各自對應固定的結束碼（0、1、3、2）。
One of four outcomes of a run: `READY_TO_SHIP`, `NEEDS_FIXES`, `INCONCLUSIVE`, `BLOCKED_CRITICAL_RISK`, each tied to a fixed exit code (0, 1, 3, 2).
_Avoid_: overall status, result, status

**證據缺口 ／ Evidence gap**:
使 `READY_TO_SHIP` 不成立、但本身不證明有缺陷的理由；每一種都有穩定的代碼。
A reason that forbids `READY_TO_SHIP` without itself proving a defect; each kind has a stable code.
_Avoid_: inconclusive reason, warning

**已執行的證據 ／ Executed evidence**:
實際執行過的測試結果或確定性規則命中；只有它能讓判定結果成為 `NEEDS_FIXES` 或 `BLOCKED_CRITICAL_RISK`。
Results of tests that actually ran, or deterministic rule hits; only these can make the Verdict `NEEDS_FIXES` or `BLOCKED_CRITICAL_RISK`.

**假設 ／ Hypothesis**:
模型提出的發現或建模出的威脅，在測試確認之前不影響判定結果。
A model finding or modeled threat; it does not affect the Verdict until a test confirms it.
_Avoid_: confirmed finding (unless cross-model verified)

**資安突破 ／ Breach**:
被分類為已確認利用的黑箱測試失敗；任何一個新的突破都使判定結果成為 `BLOCKED_CRITICAL_RISK`。
A black-box test failure classified as a confirmed exploit; any new Breach makes the Verdict `BLOCKED_CRITICAL_RISK`.
_Avoid_: exploit, black-box failure

### 設定檔來源 ／ Config origin

**內建設定檔 ／ Bundled config**:
套件內附的預設設定檔；沒有 `--config` 也沒有探索到的設定檔時使用。
The default config file shipped inside the package; used when there is neither `--config` nor a Discovered config.
_Avoid_: default config (for the file), packaged config

**探索到的設定檔 ／ Discovered config**:
在目前目錄自動找到的 `vibeharness.yaml` 或 `.vibeharness.yaml`；它可能來自不可信的 checkout，所以只能調低花費、不得設定安全敏感的鍵。
A `vibeharness.yaml` or `.vibeharness.yaml` found automatically in the current directory; it may come from an untrusted checkout, so it may only lower spend and may set no security-sensitive key.
_Avoid_: auto-config, workspace config, local config

**指定的設定檔 ／ Explicit config**:
以 `--config` 傳入的設定檔；完全受信任，不受探索到的設定檔的限制。
A config file passed with `--config`; fully trusted, not subject to the Discovered config restrictions.
_Avoid_: custom config, user config

### 基準 ／ Baseline

**基準 ／ Baseline**:
先前一次執行的 JSON 報告，用來區分新問題與已知問題。
A previous run's JSON report, used to tell new problems from known ones.

**已知問題 ／ Known problem**:
基準中已有的問題；仍列在報告中，但不計入判定結果。
A problem already in the Baseline; it is still reported but does not count toward the Verdict.
_Avoid_: suppressed finding, ignored issue

**阻擋性規則命中 ／ Blocking rule hit**:
嚴重度 HIGH 以上的確定性規則命中；只有不屬於已知問題的才計入判定結果。
A deterministic rule hit of HIGH severity or above; only those that are not Known problems count toward the Verdict.
_Avoid_: HIGH+ hit (in prose), static blocker
