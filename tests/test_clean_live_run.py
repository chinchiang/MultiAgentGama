"""`clean_live_run` 夾具本身的基準：乾淨小目標在 live 模式＋假 litellm 下是 READY_TO_SHIP，沒有任何證據缺口。
建在這個夾具上的測試（例如 #195 的 `--baseline` 測試）用它斷言判定本身；mock 模式一定有 `simulated` 缺口，做不到（#200）。
The baseline of the `clean_live_run` fixture itself: the clean small target is READY_TO_SHIP in live mode with the
fake litellm, with no evidence gap. Tests built on the fixture (such as #195's `--baseline` test) assert the Verdict
itself with it, which mock mode, always carrying the `simulated` gap, cannot (#200)."""


def test_the_clean_target_is_ready_to_ship_with_no_evidence_gap(clean_live_run):
    """乾淨目標跑完是 READY_TO_SHIP、沒有缺口、沒有阻擋的命中；之後若有新缺口在乾淨目標上成立，這裡先紅，而不是讓建在
    夾具上的測試悄悄失去意義（#200）。
    The clean target ends READY_TO_SHIP with no gap and no blocking hit; a future gap that fires on the clean target
    turns this red first, instead of quietly weakening every test built on the fixture (#200)."""
    summary = clean_live_run()
    assert summary.inconclusive_reasons == []
    assert summary.overall_status == "READY_TO_SHIP"
    assert summary.blocking_rule_hits == 0 and summary.whitebox_tests_failed == 0
    assert summary.blackbox_security_breaches == 0
