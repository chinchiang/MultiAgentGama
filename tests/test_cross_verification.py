"""跨模型驗證：沒有模型會評判自己的發現，判定結果由投票決定。
Cross-model verification: no model judges its own finding, and verdicts are decided by vote."""
import json
import os
import re

from vibeharness.core.llm_gateway import LLMGateway
from vibeharness.core.models import ReviewFinding, FindingSeverity, CodeSymbol
from vibeharness.agents.whitebox.debater import MultiModelDebater
from vibeharness.reports.report_generator import ReportGenerator

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG = os.path.join(REPO_ROOT, "vibeharness", "config", "agents_config.yaml")


def _finding(fid, model, corroborating=(), symbol="get_order"):
    return ReviewFinding(
        finding_id=fid, reviewer_name=model.title(), model_alias=model, file_path="app.py", symbol_name=symbol,
        severity=FindingSeverity.HIGH, title=f"title {fid}", description="", root_cause="",
        suspected_vibe_flaw="", suggested_test_scenario="", corroborating_models=list(corroborating),
        corroborated_by=[m.title() for m in corroborating]
    )


def _gateway(scripted, rulings):
    """rulings：{驗證者別名: {發現 id: 判定}}；回傳 live 閘道，以及每個驗證者看到了哪些發現。
    rulings: {verifier_alias: {finding_id: verdict}}; returns a live gateway and which findings each verifier was
    shown."""
    shown = {}

    def rule(request):
        alias = request.model_alias
        ids = re.findall(r"Title: title (\w+)", request.messages[1]["content"])
        shown.setdefault(alias, []).extend(ids)
        verdicts = [
            {"index": i, "verdict": rulings.get(alias, {}).get(fid, "unsure"), "reason": f"{alias} on {fid}"}
            for i, fid in enumerate(ids)
        ]
        return {"verdicts": verdicts}
    return LLMGateway(CONFIG, execution_mode="live", transport=scripted({"whitebox_verifier_*": rule})), shown


def test_no_model_verifies_its_own_or_a_corroborated_finding(scripted):
    gateway, shown = _gateway(scripted, {})
    findings = [_finding("A", "claude"), _finding("B", "deepseek", corroborating=["glm"])]
    MultiModelDebater(gateway).arbitrate(findings)
    assert sorted(shown["claude"]) == ["B"]
    assert sorted(shown["deepseek"]) == ["A"]
    assert sorted(shown["glm"]) == ["A"]  # glm 已經回報過 B，因此不會再問它 B ／ glm already reported B, so it is not asked about B
    assert sorted(shown["gemini"]) == ["A", "B"]


def test_majority_decides_and_ties_are_kept(scripted):
    gateway, _ = _gateway(scripted, {
        "deepseek": {"A": "reject", "B": "confirm", "C": "reject"},
        "glm": {"A": "reject", "B": "reject", "C": "unsure"},
        "claude": {"D": "reject"},
        "gemini": {"A": "unsure", "B": "unsure", "C": "unsure", "D": "unsure"},
    })
    findings = [
        _finding("A", "claude"),                               # 0 票確認對 2 票駁回 -> 有爭議 ／ 0 confirm vs 2 reject -> disputed
        _finding("B", "claude"),                               # 1 對 1 -> 平手，保留 ／ 1 vs 1 -> tie, kept
        # 0 對 1，但應投票的有 3 位：駁回沒有過半，保留（#183 第 6 項） ／ 0 vs 1 of 3 asked: no reject majority, kept
        # (#183 item 6)
        _finding("C", "claude"),
        _finding("D", "deepseek", corroborating=["glm"]),  # 佐證對 claude 駁回 -> 平手，保留 ／ corroborated vs claude reject -> tie, kept
    ]
    result = MultiModelDebater(gateway).arbitrate(findings)
    assert result.arbitration_applied
    assert [f.finding_id for f in result.confirmed_findings] == ["B", "C", "D"]
    assert [f.finding_id for f in result.disputed_findings] == ["A"]
    # B、C、D 未決：保留下來測試，但不算多數確認
    # B, C and D are undecided: kept for testing, but not majority-confirmed
    assert result.undecided_count == 3
    assert len(result.confirmed_findings) - result.undecided_count == 0
    # 一致的決定性票數：A 的 2 張 = 7 張決定性票中的 2 張（A 2、B 2、C 1、D 2）
    # Agreeing decisive votes: A's 2 = 2 of 7 decisive votes (A 2, B 2, C 1, D 2)
    assert abs(result.model_agreement_ratio - 2 / 7) < 1e-9
    votes_a = {v.model_alias: v.verdict for v in result.disputed_findings[0].verification_votes}
    assert votes_a == {"deepseek": "reject", "glm": "reject", "gemini": "unsure"}


def test_corroborated_finding_with_confirming_verifier_is_confirmed_unanimously(scripted):
    gateway, _ = _gateway(scripted, {"claude": {"D": "confirm"}})
    result = MultiModelDebater(gateway).arbitrate(
        [_finding("D", "deepseek", corroborating=["glm"])]
    )
    assert [f.finding_id for f in result.confirmed_findings] == ["D"]
    assert result.model_agreement_ratio == 1.0


def test_bogus_rulings_are_ignored(fake_live):
    fake_live(lambda s, u: json.dumps({"verdicts": [
        {"index": 7, "verdict": "reject"}, {"index": "0", "verdict": "reject"},
        {"index": 0, "verdict": "maybe"}, {"index": 0, "verdict": "reject"}, {"index": 0, "verdict": "confirm"},
    ]}))
    result = MultiModelDebater(LLMGateway(CONFIG, execution_mode="live")).arbitrate([_finding("A", "claude")])
    # 每個驗證者對每個發現只算第一個有效判定，三位驗證者：3 票駁回
    # Only the first valid ruling per finding from each of the three verifiers counts: 3 rejects
    assert [f.finding_id for f in result.disputed_findings] == ["A"]
    assert len(result.disputed_findings[0].verification_votes) == 3


def test_unusable_or_unsure_verifiers_leave_findings_unfiltered(scripted):
    transport = scripted({"whitebox_verifier_deepseek": "not json", "*": {"verdicts": [{"index": 0, "verdict": "unsure"}]}})
    gateway = LLMGateway(CONFIG, execution_mode="live", transport=transport)
    result = MultiModelDebater(gateway).arbitrate([_finding("A", "claude")])
    assert not result.arbitration_applied
    assert [f.finding_id for f in result.confirmed_findings] == ["A"]
    assert result.model_agreement_ratio is None
    assert gateway.invalid_calls  # 無法使用的驗證者輸出仍會揭露為證據缺口 ／ the unusable verifier output is still disclosed as an evidence gap


def test_verifiers_see_the_code_of_the_finding(fake_live, tmp_path):
    prompts = []
    fake_live(lambda s, u: prompts.append(u) or '{"verdicts": []}')
    sym = CodeSymbol(name="get_order", symbol_type="function", file_path="app.py", line_start=1, line_end=2,
                     signature="get_order(o)", source_code="def get_order(o):\n    return o['id']", parameters=["o"])
    MultiModelDebater(LLMGateway(CONFIG, execution_mode="live")).arbitrate(
        [_finding("A", "claude")], symbols=[sym], root_dir=str(tmp_path)
    )
    assert prompts and all("return o['id']" in p for p in prompts)


def test_report_shows_votes_and_agreement(scripted):
    from vibeharness.core.models import ThreatModelReport, VibeHarnessSummary
    gateway, _ = _gateway(scripted, {"deepseek": {"A": "reject"}, "glm": {"A": "reject"}})
    result = MultiModelDebater(gateway).arbitrate([_finding("A", "claude")])
    summary = VibeHarnessSummary(
        overall_status="INCONCLUSIVE", total_whitebox_findings=1, confirmed_whitebox_bugs=0,
        whitebox_tests_passed=0, whitebox_tests_failed=0, total_threats_modeled=0,
        critical_threats_count=0, blackbox_tests_passed=0, blackbox_security_breaches=0
    )
    threat_model = ThreatModelReport(system_description="", entrypoints=[], trust_boundaries=[], assets=[], threats=[])
    md = ReportGenerator().generate_markdown_report(summary, result, threat_model, [], [], "app")
    assert "Cross-Model Agreement** | `100.0%`" in md
    assert "deepseek: reject (deepseek on A)" in md


def test_one_reject_beside_unsure_or_a_failed_batch_does_not_dispute(scripted):
    """駁回必須過半數「應投票的驗證者」，不是過半數「回來的票」：只說服一個模型不夠讓缺陷不被測試（#183 第 6 項）。
    Rejects must be a majority of the verifiers asked, not of the votes that came back: convincing one model is not
    enough to keep a defect from being tested (#183 item 6)."""
    transport = scripted({
        "whitebox_verifier_deepseek": {"verdicts": [{"index": 0, "verdict": "reject", "reason": "not a defect"}]},
        "whitebox_verifier_glm": "not json",
        "*": {"verdicts": [{"index": 0, "verdict": "unsure"}]},
    })
    result = MultiModelDebater(LLMGateway(CONFIG, execution_mode="live", transport=transport)).arbitrate(
        [_finding("A", "claude")])
    assert [f.finding_id for f in result.confirmed_findings] == ["A"]
    assert result.disputed_findings == []


def test_a_reject_majority_of_the_verifiers_asked_disputes(scripted):
    gateway, _ = _gateway(scripted, {"deepseek": {"A": "reject"}, "glm": {"A": "reject"}, "gemini": {"A": "confirm"}})
    result = MultiModelDebater(gateway).arbitrate([_finding("A", "claude")])
    assert [f.finding_id for f in result.disputed_findings] == ["A"]


# --- 多樣性與「不裁決自家發現」依實際的模型，不依別名（#183 第 8 項） ------------------------------
# --- Diversity and "never rule on your own finding" go by the actual model, not the alias (#183 item 8) ---

def _one_model_config(tmp_path):
    """四個審查／驗證別名都指向同一個模型字串，別名本身維持不同。
    All four reviewer / verifier aliases point at one model string; the aliases themselves stay distinct."""
    import sys
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from config_files import load_config, write_config

    cfg = load_config()
    for alias in ("claude", "deepseek", "gemini", "glm"):
        cfg["models"][alias]["model"] = "gemini/gemini-same"
    return write_config(tmp_path, cfg, "one_model.yaml")


def test_aliases_on_one_model_are_one_reviewer_model_for_the_gate(tmp_path):
    from vibeharness.core.harness import VibeHarnessCommander

    target = tmp_path / "target"
    target.mkdir()
    (target / "app.py").write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    commander = VibeHarnessCommander(config_path=_one_model_config(tmp_path), execution_mode="mock")
    summary = commander.run_full_pipeline(str(target), output_report_path=str(tmp_path / "r.md"))
    assert any("Only one distinct reviewer model (claude/deepseek/gemini/glm)" in reason
               for reason in summary.inconclusive_reasons)


def test_a_verifier_on_the_reporters_model_does_not_rule_on_its_finding(scripted, tmp_path):
    shown = {}

    def rule(request):
        ids = re.findall(r"Title: title (\w+)", request.messages[1]["content"])
        shown.setdefault(request.model_alias, []).extend(ids)
        return {"verdicts": [{"index": i, "verdict": "reject", "reason": "x"} for i in range(len(ids))]}

    gateway = LLMGateway(_one_model_config(tmp_path), execution_mode="live",
                         transport=scripted({"whitebox_verifier_*": rule}))
    debater = MultiModelDebater(gateway)
    assert len(debater.verifiers) == 1  # 同一個模型只投一票 ／ one model votes once
    result = debater.arbitrate([_finding("A", "claude")])
    assert shown == {}
    assert not result.arbitration_applied
