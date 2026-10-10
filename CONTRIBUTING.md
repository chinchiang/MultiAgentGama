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

## 修改的原則

1. **每個修正附一個「修正前會失敗」的 regression test。** 先寫測試看它紅，再修。測試套件必須離線可跑（mock 模式與 `tests/conftest.py` 的假 litellm），不得需要 API 金鑰或網路。
2. **品質閘門只能因執行證據或確定性規則而失敗。** 模型的發現與威脅是假設；任何讓判定不可信的情況要記成 evidence gap（`vibeharness/core/harness.py`），不是靜默略過。
3. **目標程式碼是不受信任的輸入。** 新的 agent 若會讀目標程式碼，提示要經 `vibeharness/core/sanitize.untrusted_block` 並附 `UNTRUSTED_CODE_POLICY`；模型輸出進報告前要經 `markdown_safe`／`_cell`／`_code_span`。
4. **設定錯誤要大聲失敗。** 新增設定欄位時在 `LLMGateway.__init__` 驗證型別與範圍（`ConfigError`，exit 5），不要等到呼叫時才炸。
5. **不要安裝任何東西到使用者環境**，也不要擴大生成測試能做的事（`vibeharness/core/codecheck.py` 的閘門只能收緊）。
6. **文件雙語同步。** 改了行為就同步更新 `README.md`／`README.en.md`、`docs/configuration*.md`、`CHANGELOG.md`／`CHANGELOG.en.md` 的 `[Unreleased]`；設計層面的變動更新 `docs/design*.md`。設定檔、workflow、`action.yml`、Dockerfile、打包檔的註解與說明文字，以及 CLI `--help`，一律正體中文（臺灣）在前、English 在後。程式輸出（報告、終端機、日誌、失敗原因、SARIF 文字）的固定字串一律經 `vibeharness/core/i18n.py` 的 `bi("中文", "English")`，英文半不可改（CI 與指紋比對靠它）；送給模型的提示詞維持英文，雙語原因進提示詞前先 `en_only()`。`.py` 的 docstring 與註解也要雙語（docstring 內先中文行再英文行；獨立註解在英文上方加中文行；行尾註解 `# 中文 ／ English`），`tests/test_i18n.py` 會檢查。中文用詞要通過自家的注入自掃（`tests/test_ai_security.py`），避免「忽略…指令」「不要回報…」「視為…安全」這類句型。
7. **依賴**：執行期依賴改 `requirements.txt` 與 `pyproject.toml`，然後重新產生帶雜湊的鎖定檔：`uv pip compile --universal --generate-hashes --python-version 3.10 requirements.txt -o requirements.lock`，再重新產生沙盒映像的雜湊鎖定檔：`uv pip compile --universal --generate-hashes --python-version 3.12 -c requirements.lock docker/sandbox-requirements.in -o docker/sandbox-requirements.txt`（`tests/test_review_build.py` 會檢查兩者版本一致）。CI 一律以 `--require-hashes` 安裝。沙盒 Dockerfile 的基底映像以 tag＋多架構 digest 釘死，升版時兩者一起改（Dependabot 會提議）；workflow 與 `action.yml` 的第三方 action 一律釘 commit SHA（annotated tag 要解到它指向的 commit），版本寫在行尾註解。

## Pull request

- 分支從 `master` 開；標題用 Conventional Commits 前綴（`fix:`、`feat:`、`docs:`、`chore:`、`test:`）。
- PR 描述請照 `.github/PULL_REQUEST_TEMPLATE.md` 填：做了什麼、為什麼、怎麼驗證。
- CI 全綠（含覆蓋率門檻）才會審查。

## 發布

1. 更新 `vibeharness/__init__.py` 的 `__version__`（pyproject 由此讀取），把兩份 CHANGELOG 的 `[Unreleased]` 改成版本與日期。
2. 合併到 `master` 後打 tag `vX.Y.Z` 並推送；`publish.yml` 會先對 tag 指向的 commit 跑完整的 tests workflow，通過後驗證 tag 與版本一致、建置、在乾淨的 venv 冒煙測試 wheel，再上傳 GitHub Release（只有這個 job 有寫入權限；PyPI 需設 repo variable `ENABLE_PYPI_PUBLISH=true` 並完成 Trusted Publishing 設定）。

---

## English

**Setup**: `pip install -r requirements-dev.txt` (pinned ruff, mypy, pytest-cov, build, pip-audit) and optionally `pre-commit install`; for exactly the CI test matrix's dependencies, hash-verified: `pip install --require-hashes -r requirements.lock`.

**Before you push**, run the same checks CI runs: `pytest --cov=vibeharness --cov-fail-under=93`, `ruff check .`, `mypy vibeharness/ main.py` and `pip_audit -r requirements.lock --disable-pip --require-hashes`. CI adds a test matrix of Ubuntu / Windows x Python 3.10-3.14 (plus one macOS + 3.12 cell), the real-container tests on Linux against the sandbox images, a wheel install smoke test, and a full test run from the extracted sdist (`tests/test_review_build.py` checks the sdist contents) — update `MANIFEST.in` when adding files the sdist must ship.

**Principles**: every fix ships with a regression test that fails before the fix (the suite is offline: mock mode plus the fake litellm in `tests/conftest.py`); the quality gate fails only on executed evidence or deterministic rules, everything else is an evidence gap; target code is untrusted input (wrap prompts with `untrusted_block` + `UNTRUSTED_CODE_POLICY`, sanitize model text before it reaches a report); configuration errors fail loudly at start-up (`ConfigError`, exit 5); never widen what generated tests may do; keep the zh/en docs and both CHANGELOGs in sync, and write comments / descriptions in config files, workflows, `action.yml`, Dockerfiles, packaging files and the CLI `--help` bilingually (Traditional Chinese first, English second); every fixed output string (reports, console, logs, failure reasons, SARIF text) goes through `bi("中文", "English")` from `vibeharness/core/i18n.py` with the English half unchanged (CI and fingerprints rely on it), model prompts stay English (`en_only()` before a bilingual reason enters a prompt), and `.py` docstrings / comments are bilingual too (Chinese line(s) first inside the docstring, a Chinese `#` line above each English comment, `# 中文 ／ English` for trailing comments; `tests/test_i18n.py` enforces it); Chinese wording must pass the repo's own injection self-scan; runtime dependency changes go through `requirements.txt` / `pyproject.toml`, then regenerate the hashed `requirements.lock` with `uv pip compile --universal --generate-hashes --python-version 3.10 requirements.txt -o requirements.lock` and the sandbox image's hashed lock with `uv pip compile --universal --generate-hashes --python-version 3.12 -c requirements.lock docker/sandbox-requirements.in -o docker/sandbox-requirements.txt` (`tests/test_review_build.py` checks they agree; CI always installs with `--require-hashes`); the sandbox Dockerfiles pin their base image by tag + multi-arch digest (bump both together; Dependabot proposes it), and third-party actions in workflows and `action.yml` are pinned to commit SHAs (dereference annotated tags to their commit) with the version in a trailing comment.

**Pull requests** branch from `master`, use Conventional Commit prefixes, follow the PR template, and are reviewed once CI (including the coverage floor) is green.

**Releases**: bump `__version__` in `vibeharness/__init__.py`, turn `[Unreleased]` into a dated version in both CHANGELOGs, merge, then push a `vX.Y.Z` tag; `publish.yml` first runs the full tests workflow on the tagged commit, then verifies the tag, builds, smoke-tests the wheel in a clean venv and uploads the GitHub Release (only that job gets write permission; PyPI is opt-in via `ENABLE_PYPI_PUBLISH`).
