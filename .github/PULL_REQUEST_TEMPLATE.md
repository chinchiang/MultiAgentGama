## 摘要／Summary

<!-- 做了什麼、為什麼。修正類請說明原本的錯誤行為與根因。 / What and why; for fixes, the old behaviour and root cause. -->

## 驗證／Verification

- [ ] `python -m pytest --cov=vibeharness --cov-fail-under=93`
- [ ] `python -m ruff check .` 與 `python -m mypy vibeharness/ main.py`
- [ ] 每個修正都有「修正前會失敗」的 regression test / every fix has a regression test that fails before it
- [ ] 行為變更已同步 `README*.md`、`docs/configuration*.md` 與兩份 `CHANGELOG` 的 `[Unreleased]` / docs and both CHANGELOGs updated

## 備註／Notes

<!-- 已知限制、後續工作、需要審查者特別看的地方。 / Known limitations, follow-ups, what reviewers should look at. -->
