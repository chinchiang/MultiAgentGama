# Contributing ／ 貢獻指南

正體中文（臺灣）｜ [English](#english)

## 開發環境

```bash
pip install -r requirements-dev.txt   # 含執行期依賴、ruff、mypy、pytest-cov、build、pip-audit（版本釘死）
# 或與 CI 測試矩陣完全相同的相依套件（帶雜湊驗證）：pip install --require-hashes -r requirements.lock
pre-commit install                     # 可選：提交前自動跑 ruff 與 mypy
```

## 提交前請跑

```bash
python -m pytest --cov=vibeharness --cov-fail-under=93
python -m ruff check .
python -m mypy vibeharness/ main.py
python -m pip_audit -r requirements.lock --disable-pip --require-hashes
```

CI（`.github/workflows/tests.yml`）跑的是同一組指令，加上 Ubuntu／Windows × Python 3.10–3.14（另有一格 macOS + 3.12）的測試矩陣、Linux 上以沙盒映像實跑的容器測試、wheel 安裝冒煙測試，以及在解開的 sdist 裡重跑整個測試套件（`tests/test_review_build.py` 會比對 sdist 內容）。新增要隨 sdist 發布的檔案時，記得更新 `MANIFEST.in`。

`tests/test_js_execution.py` 與 `tests/test_js_coverage.py` 的真實 Node 測試需要本機有 Node（≥ 20；`.ts` 的型別剝除需 ≥ 22.6，JS/TS 涵蓋率需 ≥ 20.11 或 ≥ 21.3）；沒有可用的 Node 時它們會略過，設定 `VIBEHARNESS_REQUIRE_NODE=1` 則缺少 Node 改為失敗，但 Node 版本不支援某項功能時仍會略過（CI 裝 Node 22 並設定這個變數，所以本機略過的測試在 CI 仍會執行）。真實容器測試需要先建好兩個沙盒映像（`docker build -t vibeharness-sandbox:latest -f docker/sandbox.Dockerfile .` 與 `docker build -t vibeharness-sandbox-node:latest -f docker/sandbox-node.Dockerfile .`）；沒有 Docker 或映像時略過，設定 `VIBEHARNESS_REQUIRE_DOCKER=1`（Python 容器）／`VIBEHARNESS_REQUIRE_DOCKER_NODE=1`（Node 容器）則改為失敗（CI 的 Linux 測試就是如此）。

## 修改的原則

1. **每個修正附一個「修正前會失敗」的 regression test。** 先寫測試看它紅，再修。測試套件必須離線可跑（mock 模式與 `tests/conftest.py` 的假 litellm），不得需要 API 金鑰或網路。
2. **品質閘門只能因執行證據或確定性規則而失敗。** 模型的發現與威脅是假設；任何讓判定不可信的情況要記成 evidence gap（`vibeharness/core/harness.py`），不是靜默略過。
3. **目標程式碼是不受信任的輸入。** 新的 agent 若會讀目標程式碼，提示要經 `vibeharness/core/sanitize.untrusted_block` 並附 `UNTRUSTED_CODE_POLICY`；模型輸出進報告前要經 `markdown_safe`／`_cell`／`_code_span`。
4. **設定錯誤要大聲失敗。** 新增設定欄位時在啟動時驗證型別與範圍（`ConfigError`／`ValueError`，exit 5），不要等到呼叫時才炸：模型、agent 與呼叫相關的鍵在 `LLMGateway.__init__`（`_validate_endpoints`、`_validate_settings`），沙盒、突變測試與檔案選取的鍵在 `VibeHarnessCommander.__init__`（`_sandbox_settings`、`_validate_node_settings`、`_mutation_settings`、`_pattern_list` 等）。
5. **不要安裝任何東西到使用者環境**，也不要擴大生成測試能做的事（`vibeharness/core/codecheck.py` 的閘門只能收緊）。
6. **文件雙語同步。** 改了行為就同步更新 `README.md`／`README.en.md`、`docs/configuration*.md`、`CHANGELOG.md`／`CHANGELOG.en.md` 的 `[Unreleased]`；設計層面的變動更新 `docs/design*.md`。設定檔、workflow、`action.yml`、Dockerfile、打包檔的註解與說明文字，以及 CLI `--help`，一律正體中文（臺灣）在前、English 在後。程式輸出（報告、終端機、日誌、失敗原因、SARIF 文字）的固定字串一律經 `vibeharness/core/i18n.py` 的 `bi("中文", "English")`，英文半不可改（CI 與指紋比對靠它）；送給模型的提示詞維持英文，雙語原因進提示詞前先 `en_only()`。`.py` 的 docstring 與註解也要雙語（docstring 內先中文行再英文行；獨立註解在英文上方加中文行；行尾註解 `# 中文 ／ English`），`tests/test_i18n.py` 會檢查。中文用詞要通過自家的注入自掃（`tests/test_ai_security.py`），避免「忽略…指令」「不要回報…」「視為…安全」這類句型。
7. **依賴**：執行期依賴改 `requirements.txt` 與 `pyproject.toml`，然後重新產生帶雜湊的鎖定檔：`uv pip compile --universal --generate-hashes --python-version 3.10 requirements.txt -o requirements.lock`，再重新產生沙盒映像的雜湊鎖定檔：`uv pip compile --universal --generate-hashes --python-version 3.12 -c requirements.lock docker/sandbox-requirements.in -o docker/sandbox-requirements.txt`（`tests/test_review_build.py` 會檢查兩者版本一致；只在沙盒鎖定檔裡的 `hypothesis` 與其相依 `sortedcontainers` 由它自行釘版）。建置後端 setuptools 的範圍同時寫在 `pyproject.toml` 的 `[build-system]` 與 `requirements-build.in`，改了就以 `uv pip compile --universal --generate-hashes --python-version 3.10 requirements-build.in -o requirements-build.txt` 重新產生（`action.yml` 與發布建置以 `--no-build-isolation` 使用它）。CI 一律以 `--require-hashes` 安裝。沙盒 Dockerfile 的基底映像以 tag＋多架構 digest 釘死，升版時兩者一起改（Dependabot 會提議）；workflow 與 `action.yml` 的第三方 action 一律釘 commit SHA（annotated tag 要解到它指向的 commit），版本寫在行尾註解；repo 的 Actions 設定要求 SHA 釘版，沒釘的 action 會讓 workflow 直接失敗。

## Pull request

- 分支從 `master` 開；標題用 Conventional Commits 前綴（例如 `fix:`、`feat:`、`docs:`、`chore:`、`test:`、`ci:`、`build:`、`perf:`、`refactor:`）。
- PR 描述請照 `.github/PULL_REQUEST_TEMPLATE.md` 填：做了什麼、為什麼、怎麼驗證。
- CI 全綠（含覆蓋率門檻）才會審查。`master` 要求 PR 與必要檢查，其中包括 CodeQL 程式碼掃描（`.github/workflows/codeql.yml` 的 `Analyze (python)` 與 `Analyze (actions)`）；改這個 workflow 時不要改它的 workflow 名稱或 job 名稱，否則必要檢查會一直等不到結果。
- 只接受 merge commit 合併（squash 與 rebase 合併已關閉），合併後分支會自動刪除。必要檢查共 16 項：`lint`、`audit`、`package`、11 格 `test` 矩陣，以及兩個 CodeQL 分析。

## 發布

在 release 分支（例如 `release/X.Y.Z`）上：

1. 更新 `vibeharness/__init__.py` 的 `__version__`（pyproject 由此讀取）。
2. 把兩份 CHANGELOG 的 `[Unreleased]` 改成 `[X.Y.Z] - YYYY-MM-DD`，在檔尾的連結定義新增 `[X.Y.Z]: …/compare/v<上一版>...vX.Y.Z`，並把 `[Unreleased]` 改成從 `vX.Y.Z` 比較。
3. 把每一個 `@vX.Y.Z` 參照換成新版本：`action.yml` 檔頭註解、`README.md`／`README.en.md` 的 Action 範例與 `pip install vibeharness-mas==X.Y.Z` 範例（`tests/test_r2_packaging.py` 會檢查 `_VERSIONED_FILES` 列出的每個檔案——`action.yml`、兩份 README、`CONTRIBUTING.md`、`SECURITY.md`、`docs/design*.md`、`docs/configuration*.md`——裡的 `MultiAgentGama@vX.Y.Z` 與 `vibeharness-mas==X.Y.Z` 都等於 `__version__`）。
4. minor（或 major）升版時，把 `SECURITY.md` 兩個語言的「支援版本」表改成新的 `X.Y.x` ✅／`< X.Y` ❌（`tests/test_r3_repo_meta.py` 會檢查它與 `__version__` 的 major.minor 一致）。
5. 更新 `docs/design.md`／`docs/design.en.md` 第 5 行的對應版本（`__version__`、CHANGELOG 區段與日期）；程式碼有搬動時，重新核對文中的 `path:line` 引用並更新引用的 commit。
6. 開 PR、CI 全綠後合併到 `master`（merge commit；release 分支合併後會自動刪除）。CHANGELOG.en.md 中這個版本的區段就是 GitHub Release 的內文，請寫成可以直接對外的樣子。
7. 在 `master` 上的合併 commit 打 tag 並推送：`git tag vX.Y.Z <merge-sha> && git push origin vX.Y.Z`（tag ruleset 只允許管理員建立、移動或刪除 `v*` tag）。`publish.yml` 會先對 tag 指向的 commit 跑完整的 tests workflow，通過後驗證 tag 與版本一致、建置、在乾淨的 venv 冒煙測試 wheel、上傳 GitHub Release（只有 `release` job 拿到 `contents: write`；內文取自 `CHANGELOG.en.md` 的 `## [X.Y.Z]` 區段，找不到時改用自動產生的內文，Release 已存在時會改寫它的內文）；`release` 完成後，`pypi-publish` job 才在 `pypi` environment（部署政策只接受 `v*` tag）裡以 Trusted Publishing 發布到 PyPI 的 `vibeharness-mas`，它只有 `id-token: write`，而且只在 repository variable `ENABLE_PYPI_PUBLISH=true` 時執行（repo 裡不存 token）。
8. **PyPI 的版本不可覆寫。** 發錯版就修正後發新的 patch 版本（`X.Y.Z+1`），絕不刪除或重打 tag。Fork 不想發布到 PyPI 時，不要設定 repository variable `ENABLE_PYPI_PUBLISH`，`pypi-publish` job 就會被略過。

---

## English

**Setup**: `pip install -r requirements-dev.txt` (the runtime dependencies plus pinned ruff, mypy, pytest-cov, build, pip-audit) and optionally `pre-commit install`; for exactly the CI test matrix's dependencies, hash-verified: `pip install --require-hashes -r requirements.lock`.

**Before you push**, run the same checks CI runs: `python -m pytest --cov=vibeharness --cov-fail-under=93`, `python -m ruff check .`, `python -m mypy vibeharness/ main.py` and `python -m pip_audit -r requirements.lock --disable-pip --require-hashes`. CI adds a test matrix of Ubuntu / Windows x Python 3.10-3.14 (plus one macOS + 3.12 cell), the real-container tests on Linux against the sandbox images, a wheel install smoke test, and a full test run from the extracted sdist (`tests/test_review_build.py` checks the sdist contents) — update `MANIFEST.in` when adding files the sdist must ship. The real-Node tests in `tests/test_js_execution.py` and `tests/test_js_coverage.py` need a local Node (≥ 20; ≥ 22.6 for `.ts` type stripping, ≥ 20.11 or ≥ 21.3 for JS/TS coverage); without a usable Node they skip, and `VIBEHARNESS_REQUIRE_NODE=1` turns a missing Node into a failure while a Node too old for a feature still skips (CI installs Node 22 and sets it, so tests skipped locally still run in CI). The real-container tests need both sandbox images built first (`docker build -t vibeharness-sandbox:latest -f docker/sandbox.Dockerfile .` and `docker build -t vibeharness-sandbox-node:latest -f docker/sandbox-node.Dockerfile .`); without Docker or an image they skip, and `VIBEHARNESS_REQUIRE_DOCKER=1` (Python container) / `VIBEHARNESS_REQUIRE_DOCKER_NODE=1` (Node container) turn that into a failure (as on CI's Linux cells).

**Principles**: every fix ships with a regression test that fails before the fix (the suite is offline: mock mode plus the fake litellm in `tests/conftest.py`); the quality gate fails only on executed evidence or deterministic rules, everything else is an evidence gap; target code is untrusted input (wrap prompts with `untrusted_block` + `UNTRUSTED_CODE_POLICY`, sanitize model text before it reaches a report); configuration errors fail loudly at start-up (`ConfigError` / `ValueError`, exit 5): model, agent and call keys are validated in `LLMGateway.__init__` (`_validate_endpoints`, `_validate_settings`), sandbox, mutation-testing and file-selection keys in `VibeHarnessCommander.__init__` (`_sandbox_settings`, `_validate_node_settings`, `_mutation_settings`, `_pattern_list`, ...); never widen what generated tests may do; keep the zh/en docs and both CHANGELOGs in sync, and write comments / descriptions in config files, workflows, `action.yml`, Dockerfiles, packaging files and the CLI `--help` bilingually (Traditional Chinese first, English second); every fixed output string (reports, console, logs, failure reasons, SARIF text) goes through `bi("中文", "English")` from `vibeharness/core/i18n.py` with the English half unchanged (CI and fingerprints rely on it), model prompts stay English (`en_only()` before a bilingual reason enters a prompt), and `.py` docstrings / comments are bilingual too (Chinese line(s) first inside the docstring, a Chinese `#` line above each English comment, `# 中文 ／ English` for trailing comments; `tests/test_i18n.py` enforces it); Chinese wording must pass the repo's own injection self-scan; runtime dependency changes go through `requirements.txt` / `pyproject.toml`, then regenerate the hashed `requirements.lock` with `uv pip compile --universal --generate-hashes --python-version 3.10 requirements.txt -o requirements.lock` and the sandbox image's hashed lock with `uv pip compile --universal --generate-hashes --python-version 3.12 -c requirements.lock docker/sandbox-requirements.in -o docker/sandbox-requirements.txt` (`tests/test_review_build.py` checks they agree; `hypothesis` and its dependency `sortedcontainers`, which only the sandbox lock holds, are pinned by it alone; CI always installs with `--require-hashes`); the build backend range lives in both `pyproject.toml` `[build-system]` and `requirements-build.in`, so after changing it regenerate `requirements-build.txt` with `uv pip compile --universal --generate-hashes --python-version 3.10 requirements-build.in -o requirements-build.txt` (`action.yml` and the release builds use it with `--no-build-isolation`); the sandbox Dockerfiles pin their base image by tag + multi-arch digest (bump both together; Dependabot proposes it), and third-party actions in workflows and `action.yml` are pinned to commit SHAs (dereference annotated tags to their commit) with the version in a trailing comment; the repository's Actions settings require SHA pinning, so an unpinned action fails the workflow.

**Pull requests** branch from `master`, use Conventional Commit prefixes (e.g. `fix:`, `feat:`, `docs:`, `chore:`, `test:`, `ci:`, `build:`, `perf:`, `refactor:`), follow the PR template, and are reviewed once CI (including the coverage floor) is green. `master` requires a PR and the required checks, including CodeQL code scanning (`Analyze (python)` and `Analyze (actions)` from `.github/workflows/codeql.yml`); when editing that workflow keep its workflow and job names, or the required checks wait forever. Merges are merge-commit only (squash and rebase merges are off) and merged branches are deleted automatically. There are 16 required checks: `lint`, `audit`, `package`, the 11 `test` matrix cells and the two CodeQL analyses.

**Releases**, on a release branch (e.g. `release/X.Y.Z`):

1. Bump `__version__` in `vibeharness/__init__.py` (pyproject reads it from there).
2. Turn `[Unreleased]` into `[X.Y.Z] - YYYY-MM-DD` in both CHANGELOGs, add `[X.Y.Z]: …/compare/v<previous>...vX.Y.Z` to the link definitions at the bottom and make `[Unreleased]` compare from `vX.Y.Z`.
3. Bump every `@vX.Y.Z` reference: the header comment of `action.yml` and the Action and `pip install vibeharness-mas==X.Y.Z` examples in `README.md` / `README.en.md` (`tests/test_r2_packaging.py` checks that every `MultiAgentGama@vX.Y.Z` and `vibeharness-mas==X.Y.Z` in the files of its `_VERSIONED_FILES` list, i.e. `action.yml`, both READMEs, `CONTRIBUTING.md`, `SECURITY.md`, `docs/design*.md` and `docs/configuration*.md`, equals `__version__`).
4. On a minor (or major) bump, change the "Supported versions" table of `SECURITY.md` in both languages to the new `X.Y.x` ✅ / `< X.Y` ❌ (`tests/test_r3_repo_meta.py` checks it matches the major.minor of `__version__`).
5. Update the version line (line 5) of `docs/design.md` / `docs/design.en.md` (`__version__`, CHANGELOG section and date); if code moved, re-check the `path:line` references and update the cited commit.
6. Open the PR and merge it into `master` once CI is green (merge commit; the release branch is deleted automatically after the merge). This version's section of CHANGELOG.en.md becomes the GitHub Release body, so write it for a public audience.
7. Tag the merge commit on `master` and push the tag: `git tag vX.Y.Z <merge-sha> && git push origin vX.Y.Z` (a tag ruleset lets only admins create, move or delete `v*` tags). `publish.yml` first runs the full tests workflow on the tagged commit, then verifies the tag matches the version, builds, smoke-tests the wheel in a clean venv, uploads the GitHub Release (only the `release` job gets `contents: write`; the body is the `## [X.Y.Z]` section of `CHANGELOG.en.md`, falling back to generated notes when it is missing, and an existing Release has its body rewritten); after `release`, the `pypi-publish` job publishes `vibeharness-mas` to PyPI via Trusted Publishing in the `pypi` environment (whose deployment policy accepts `v*` tags only), with `id-token: write` only and only when the repository variable `ENABLE_PYPI_PUBLISH=true` is set (no token is stored in the repo).
8. **PyPI versions are immutable.** A bad release is fixed with a new patch version (`X.Y.Z+1`); never delete or re-tag. A fork that should not publish to PyPI leaves the repository variable `ENABLE_PYPI_PUBLISH` unset, which skips the `pypi-publish` job.
