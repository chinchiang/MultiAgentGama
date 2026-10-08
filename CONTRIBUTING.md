# Contributing ／ 貢獻指南

正體中文（臺灣）｜ [English](#english)

## 開發環境

```bash
pip install -r requirements-dev.txt   # 含執行期依賴、ruff、mypy、pytest-cov、build、pip-audit（版本釘死）
pre-commit install                     # 可選：提交前自動跑 ruff 與 mypy
```

## 提交前請跑

```bash
python -m pytest --cov=vibeharness --cov-fail-under=93
python -m ruff check .
python -m mypy vibeharness/ main.py
python -m pip_audit -r requirements.lock --disable-pip --no-deps
```

CI（`.github/workflows/tests.yml`）跑的是同一組指令，加上 Ubuntu／Windows × Python 3.10–3.13 的測試矩陣與 wheel 安裝冒煙測試。

## 修改的原則

1. **每個修正附一個「修正前會失敗」的 regression test。** 先寫測試看它紅，再修。測試套件必須離線可跑（mock 模式與 `tests/conftest.py` 的假 litellm），不得需要 API 金鑰或網路。
2. **品質閘門只能因執行證據或確定性規則而失敗。** 模型的發現與威脅是假設；任何讓判定不可信的情況要記成 evidence gap（`vibeharness/core/harness.py`），不是靜默略過。
3. **目標程式碼是不受信任的輸入。** 新的 agent 若會讀目標程式碼，提示要經 `vibeharness/core/sanitize.untrusted_block` 並附 `UNTRUSTED_CODE_POLICY`；模型輸出進報告前要經 `markdown_safe`／`_cell`／`_code_span`。
4. **設定錯誤要大聲失敗。** 新增設定欄位時在 `LLMGateway.__init__` 驗證型別與範圍（`ConfigError`，exit 5），不要等到呼叫時才炸。
5. **不要安裝任何東西到使用者環境**，也不要擴大生成測試能做的事（`vibeharness/core/codecheck.py` 的閘門只能收緊）。
6. **文件雙語同步。** 改了行為就同步更新 `README.md`／`README.en.md`、`docs/configuration*.md`、`CHANGELOG.md`／`CHANGELOG.en.md` 的 `[Unreleased]`；設計層面的變動更新 `docs/design*.md`。
7. **依賴**：執行期依賴改 `requirements.txt` 與 `pyproject.toml`，然後重新產生鎖定檔：`uv pip compile --universal --python-version 3.10 requirements.txt -o requirements.lock`，並同步 `docker/sandbox.Dockerfile` 的釘版。

## Pull request

- 分支從 `master` 開；標題用 Conventional Commits 前綴（`fix:`、`feat:`、`docs:`、`chore:`、`test:`）。
- PR 描述請照 `.github/PULL_REQUEST_TEMPLATE.md` 填：做了什麼、為什麼、怎麼驗證。
- CI 全綠（含覆蓋率門檻）才會審查。

## 發布

1. 更新 `vibeharness/__init__.py` 的 `__version__`（pyproject 由此讀取），把兩份 CHANGELOG 的 `[Unreleased]` 改成版本與日期。
2. 合併到 `master` 後打 tag `vX.Y.Z` 並推送；`publish.yml` 會驗證 tag 與版本一致、建置、冒煙測試並上傳 GitHub Release（PyPI 需設 repo variable `ENABLE_PYPI_PUBLISH=true` 並完成 Trusted Publishing 設定）。

---

## English

**Setup**: `pip install -r requirements-dev.txt` (pinned ruff, mypy, pytest-cov, build, pip-audit) and optionally `pre-commit install`.

**Before you push**, run the same checks CI runs: `pytest --cov=vibeharness --cov-fail-under=93`, `ruff check .`, `mypy vibeharness/ main.py` and `pip_audit -r requirements.lock --disable-pip --no-deps`.

**Principles**: every fix ships with a regression test that fails before the fix (the suite is offline: mock mode plus the fake litellm in `tests/conftest.py`); the quality gate fails only on executed evidence or deterministic rules, everything else is an evidence gap; target code is untrusted input (wrap prompts with `untrusted_block` + `UNTRUSTED_CODE_POLICY`, sanitize model text before it reaches a report); configuration errors fail loudly at start-up (`ConfigError`, exit 5); never widen what generated tests may do; keep the zh/en docs and both CHANGELOGs in sync; runtime dependency changes go through `requirements.txt` / `pyproject.toml`, then regenerate `requirements.lock` with `uv pip compile --universal --python-version 3.10` and update `docker/sandbox.Dockerfile`.

**Pull requests** branch from `master`, use Conventional Commit prefixes, follow the PR template, and are reviewed once CI (including the coverage floor) is green.

**Releases**: bump `__version__` in `vibeharness/__init__.py`, turn `[Unreleased]` into a dated version in both CHANGELOGs, merge, then push a `vX.Y.Z` tag; `publish.yml` verifies, builds, smoke-tests and uploads the GitHub Release (PyPI is opt-in via `ENABLE_PYPI_PUBLISH`).
