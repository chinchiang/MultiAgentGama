---
status: accepted
---

# 強化建議最多只降到 NEEDS_FIXES ／ A Hardening recommendation goes no lower than NEEDS_FIXES

黑箱測試以測試自己的斷言失敗時，原本一律算資安突破（Breach），判定成為 `BLOCKED_CRITICAL_RISK`；但攻擊合成也會寫出要求「目標沒有承諾的防禦」的測試（稽核紀錄、分頁上限、上游已負責的身分驗證），2026-11-28 對 `scratch/live/target2` 的真實模型執行裡，9 個 Breach 中有 3 個是這種。我們決定：這種失敗在跨模型確認後改記為強化建議（Hardening recommendation），不算 Breach，但判定結果仍至少是 `NEEDS_FIXES`，絕不會因此成為 `READY_TO_SHIP`。

When a black-box test failed on its own assertion it always counted as a Breach and made the Verdict `BLOCKED_CRITICAL_RISK`; but attack synthesis also writes tests that demand a defence the target never promised (an audit trail, a page-size cap, identity checks the caller is documented to do), and in the live run on `scratch/live/target2` on 2026-11-28, 3 of the 9 Breaches were of that kind. We decided that such a failure, once cross-model verification agrees, is recorded as a Hardening recommendation: not a Breach, but it still keeps the Verdict at `NEEDS_FIXES` or worse, never `READY_TO_SHIP`.

## 為什麼這樣不違反「只有已執行的證據決定判定」 ／ Why this keeps "only Executed evidence decides the Verdict"

CODING_STANDARDS 第 2 條不許模型的回答直接改變判定。這裡模型的投票只決定一個已執行、已失敗的測試落在哪一個不能放行的類別：最好的情況是 `NEEDS_FIXES`，和白箱測試 FAILED 同一級；它永遠不能讓判定變寬鬆到 `READY_TO_SHIP`。目標程式碼裡的提示注入能做到的最壞情況，是把一個真的攻擊從 `BLOCKED_CRITICAL_RISK` 降到 `NEEDS_FIXES`，執行仍然失敗、CI 仍然非 0。

CODING_STANDARDS rule 2 forbids a model answer from changing the Verdict directly. Here the models' votes only decide which non-passing category an executed, failed test falls into: at best `NEEDS_FIXES`, the level of a FAILED white-box test; they can never loosen the Verdict to `READY_TO_SHIP`. The worst a prompt injection in the target can achieve is to move a real exploit from `BLOCKED_CRITICAL_RISK` to `NEEDS_FIXES`; the run still fails and CI still exits non-zero.

## 降級的條件 ／ What a demotion takes

分類、投票與過半數規則在 #230 實作；確定性的底線在 #231 實作；其餘的 fail closed 情況（預算用盡、只剩寫測試的模型等）程式碼已經會維持資安突破，#231 補上它們的測試。 ／ Classification, the votes and the strict-majority rule are built in #230; the deterministic floor is built in #231; the remaining fail-closed cases (an exhausted budget, only the test's own model left, and so on) already keep the Breach in the code, and #231 adds their tests.

- 只在測試失敗之後分類，只看本來會算 Breach 的那些。 ／ Classification happens only after a test failed, and only for the ones that would be a Breach.
- 驗證者沿用 `whitebox_verifier_*`，排除 `blackbox_test_synthesizer` 設定的模型（寫出那些測試的模型）；被問到的驗證者過半數回答「目標沒有承諾這個防禦」才降級。平手、`unsure`、拒絕都維持 Breach。 ／ The verifiers are the `whitebox_verifier_*` agents minus the model configured for `blackbox_test_synthesizer` (the model that wrote the tests); a strict majority of those asked must answer "the target never promised this defence". A tie, `unsure` or a refusal keeps the Breach.
- 「承諾」只看目標自己的程式碼、docstring 與型別註記，不看 README 或外部文件。 ／ "Promised" is judged from the target's own code, docstrings and type hints only, not its README or outside documents.
- 確定性的底線：威脅的 STRIDE 或 OWASP 類別是注入、存取控制失效／權限提升、或敏感資料外洩時，不論投票如何都維持 Breach。 ／ A deterministic floor: a threat whose STRIDE or OWASP category is injection, broken access control / elevation of privilege, or information disclosure stays a Breach whatever the votes.
- 無法完成驗證（呼叫當掉或無效、預算用盡、mock 或模擬、沒有驗證者）就維持 Breach（fail closed）。 ／ When verification cannot complete (a crashed or invalid call, an exhausted budget, mock or simulated mode, no verifier configured) the Breach stays (fail closed).

## 考慮過的其他做法 ／ Considered options

- 維持現狀，所有失敗都算 Breach：最保守，但規格沒要求的強化項目會讓判定被誤擋成 `BLOCKED_CRITICAL_RISK`。 ／ Keep every failure a Breach: safest, but hardening the target never promised blocks the Verdict as `BLOCKED_CRITICAL_RISK`.
- 只用確定性規則分類（例如依 STRIDE 類別）：太粗，target2 的 THREAT-07 被分在 DoS，卻是未處理例外外洩的真缺陷。 ／ Classify by deterministic rules alone (by STRIDE category, say): too coarse; target2's THREAT-07 was filed under DoS yet was a real defect, an unhandled exception leaking out.
- 強化建議完全不影響判定：模型的回答會直接讓判定放行，也替提示注入開了路。 ／ Let a Hardening recommendation not affect the Verdict at all: a model answer would then pass the Verdict outright, and it opens a path for prompt injection.
