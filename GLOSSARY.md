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

### 模型回答 ／ Model answers

**執行模式 ／ Execution mode**:
整次執行何時呼叫真實模型的政策：`live`（只用真實模型，失敗即中止）、`hybrid`（能呼叫就呼叫，否則用模擬輸出）、`mock`（只用模擬輸出）。
The run-wide policy for when real models are called: `live` (real models only, a failure aborts), `hybrid` (a real model when possible, otherwise Simulated output), `mock` (Simulated output only).
_Avoid_: mock (for a test double), offline mode

**真實呼叫 ／ Live call**:
真實模型給出的回答，或由這類回答填入的回應快取取出的回答。
An answer from a real model, or from the response cache that such answers filled.
_Avoid_: real response, API call (for a cached answer)

**模擬輸出 ／ Simulated output**:
代理在不呼叫模型時給出的固定備援回答；一律在報告中揭露，絕不算已執行的證據。
An agent's fixed fallback answer, given without calling a model; it is always disclosed in the reports and never counts as Executed evidence.
_Avoid_: mock output, fake response, canned answer

**可用的輸出 ／ Usable output**:
符合代理宣告形狀的模型回答：必要欄位都在且型別正確，每份清單不為空時至少有一項代理能用的項目（例如有標題或描述的發現）。只有可用的輸出才登記為真實呼叫。
A model answer that fits the shape its agent declared: the required fields are there with the right types, and every non-empty list has at least one item the agent can use (e.g. a finding with a title or description). Only Usable output is booked as a Live call.
_Avoid_: valid JSON (for this; valid JSON can still be unusable), successful response

**形狀錯誤 ／ Shape error**:
鍵在但型別不對，或清單不為空卻沒有任何可用的項目。會以指名欄位的原因重新詢問，仍不合就記為無效呼叫，成為證據缺口，絕不讀成「什麼都沒找到」。
A key that is there with the wrong type, or a non-empty list with no usable item. It is re-asked with a reason naming the field and, if it still does not fit, booked as an invalid call and an Evidence gap, never read as "nothing found".
_Avoid_: malformed output (too vague), parse error (for this; the JSON parsed)

**代理呼叫 ／ Agent call**:
代理向模型的一次提問：它的角色、要模型讀的不可信內容（每一種都走標示來源的通道）與期望的回答形狀。結果只有三種：真實呼叫、模擬輸出，或無效呼叫（在產生回答前就當掉的呼叫也算）。
One question an agent puts to a model: its role, the untrusted content the model must read (each kind in a provenance-labeled channel) and the answer shape it expects. It ends as a Live call, Simulated output or an invalid call (a call that crashed before producing an answer counts as one too).
_Avoid_: LLM call, generate call; request (that is one attempt at one model)

**修復呼叫 ／ Heal call**:
模型寫的測試沒通過執行前的檢查（例如無法解析）時，附上檢查的錯誤、請模型修正該測試的一次代理呼叫；每個測試最多兩次，仍無效的測試原樣保留並回報為 ERROR，絕不換成會通過的空測試。它在呼叫紀錄中自成一類，不是對形狀錯誤的重新詢問。
An Agent call that asks the model to fix a test it wrote that failed the pre-run check (e.g. it does not parse), with the check's error attached; at most two per test, and a test that stays invalid is kept as is and reported as ERROR, never swapped for a no-op test that passes. It is a kind of its own in the call log, not the re-ask that follows a Shape error.
_Avoid_: retry, re-ask (for this; a re-ask answers a Shape error), self-heal loop

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

**身分 ／ Identity**:
讓同一個發現、威脅或規則命中在不同次執行之間被認出來的依據：位置、符號或規則，以及不分大小寫與標點的文字，不含逐次執行的編號。基準與 SARIF 都以它為準，所以它的雜湊一旦寫進報告就不能改變。
What lets the same finding, threat or rule hit be recognized across runs: its location, symbol or rule, and its case- and punctuation-insensitive text, never the per-run number. The Baseline and SARIF both go by it, so its hash must not change once it is in a report.
_Avoid_: fingerprint (for the concept; a fingerprint is its hash), finding id

**未知位置 ／ Unknown location**:
無法歸屬到任何檔案的發現位置（審查者寫下的 `unknown` 佔位字，或空白）。這類發現只在標題完全相同時才算同一個，其身分不含路徑。
The location of a finding that cannot be tied to any file (the reviewer's `unknown` placeholder, or a blank). Such findings are only the same when their titles are identical, and their Identity has no path.
_Avoid_: missing file, unknown file

### 測試執行 ／ Test execution

**Node 執行環境 ／ Node runtime**:
執行 JS/TS 測試用的 Node：本機的 `node_bin`，或 docker 映像檔內的 Node，連同它的版本；版本決定能不能執行 TypeScript、能不能收集 JS/TS 行涵蓋率。沒有可用的 Node 執行環境是證據缺口，不是啟動失敗，每個 JS/TS 測試的原因都說明缺了什麼；報告的 `node_runtime` 只在它真的可用時才寫。
The Node that runs the JS/TS tests: the local `node_bin`, or the Node inside the docker image, together with its version; the version decides whether TypeScript can run and whether JS/TS line coverage can be collected. No usable Node runtime is an Evidence gap, never a start-up failure, and every JS/TS test's reason says what is missing; the report's `node_runtime` is only written when one is actually usable.
_Avoid_: Node sandbox (the sandbox is where a test runs; the runtime is which Node, and which version), node version
