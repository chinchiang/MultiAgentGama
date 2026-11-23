"""`clean_live_run` 夾具本身的基準：乾淨小目標在 live 模式＋假 litellm 下是 READY_TO_SHIP，沒有任何證據缺口。
建在這個夾具上的測試（例如 #195 的 `--baseline` 測試）用它斷言判定本身；mock 模式一定有 `simulated` 缺口，做不到（#200）。
The baseline of the `clean_live_run` fixture itself: the clean small target is READY_TO_SHIP in live mode with the
fake litellm, with no evidence gap. Tests built on the fixture (such as #195's `--baseline` test) assert the Verdict
itself with it, which mock mode, always carrying the `simulated` gap, cannot (#200)."""
import yaml


def test_the_clean_target_is_ready_to_ship_with_no_evidence_gap(clean_live_run):
    """乾淨目標跑完是 READY_TO_SHIP、沒有缺口、沒有阻擋的命中；之後若有新缺口在乾淨目標上成立，這裡先紅，而不是讓建在
    夾具上的測試悄悄失去意義（#200）。它用的設定至少有兩個不同的審查與驗證模型、突變測試關閉，這些缺口不成立是夾具
    保證的，不是剛好。
    The clean target ends READY_TO_SHIP with no gap and no blocking hit; a future gap that fires on the clean target
    turns this red first, instead of quietly weakening every test built on the fixture (#200). The config it ran with
    has at least two distinct reviewer and verifier models and mutation testing off, so those gaps are false by the
    fixture, not by chance."""
    summary = clean_live_run()
    with open(clean_live_run.config_path, encoding="utf-8") as f:
        cfg = yaml.safe_load(f)
    aliases = {kind: {a["model_alias"] for name, a in cfg["agents"].items() if name.startswith(f"whitebox_{kind}_")}
               for kind in ("reviewer", "verifier")}
    assert len(aliases["reviewer"]) >= 2 and len(aliases["verifier"]) >= 2, aliases
    assert cfg["global"]["mutation_testing"] is False
    assert summary.inconclusive_reasons == []
    assert summary.overall_status == "READY_TO_SHIP"
    assert summary.blocking_rule_hits == 0 and summary.whitebox_tests_failed == 0
    assert summary.blackbox_security_breaches == 0


def test_a_config_edit_reaches_the_run(clean_live_run):
    """`config` 改的設定確實用在這次執行：只留一位驗證者時，交叉驗證不成立，乾淨目標變成 INCONCLUSIVE（#200）。
    A `config` edit is really used by the run: with one verifier left, cross-verification cannot happen and the clean
    target becomes INCONCLUSIVE (#200)."""
    def one_verifier(cfg):
        for name in [n for n in cfg["agents"] if n.startswith("whitebox_verifier_")][1:]:
            del cfg["agents"][name]

    summary = clean_live_run(config=one_verifier)
    assert summary.overall_status == "INCONCLUSIVE"
    assert any("verif" in reason for reason in summary.inconclusive_reasons), summary.inconclusive_reasons
