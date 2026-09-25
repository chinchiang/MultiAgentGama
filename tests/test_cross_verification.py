"""Cross-model verification: no model judges its own finding, and verdicts are decided by vote."""
import json
import os
import re

from core.llm_gateway import LLMGateway
from core.models import ReviewFinding, FindingSeverity, CodeSymbol
from agents.whitebox.debater import MultiModelDebater
from reports.report_generator import ReportGenerator

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG = os.path.join(REPO_ROOT, "config", "agents_config.yaml")


def _finding(fid, model, corroborating=(), symbol="get_order"):
    return ReviewFinding(
        finding_id=fid, reviewer_name=model.title(), model_alias=model, file_path="app.py", symbol_name=symbol,
        severity=FindingSeverity.HIGH, title=f"title {fid}", description="", root_cause="",
        suspected_vibe_flaw="", suggested_test_scenario="", corroborating_models=list(corroborating),
        corroborated_by=[m.title() for m in corroborating]
    )


def _verifier(system):
    return re.search(r"\(model: (\w+)\)", system).group(1)


def _install(fake_live, rulings):
    """rulings: {verifier_alias: {finding_id: verdict}}; records which findings each verifier was shown."""
    shown = {}

    def responder(system, user):
        alias = _verifier(system)
        ids = re.findall(r"Title: title (\w+)", user)
        shown.setdefault(alias, []).extend(ids)
        verdicts = [
            {"index": i, "verdict": rulings.get(alias, {}).get(fid, "unsure"), "reason": f"{alias} on {fid}"}
            for i, fid in enumerate(ids)
        ]
        return json.dumps({"verdicts": verdicts})
    fake_live(responder)
    return shown


def test_no_model_verifies_its_own_or_a_corroborated_finding(fake_live):
    shown = _install(fake_live, {})
    findings = [_finding("A", "claude"), _finding("B", "nemotron", corroborating=["chatgpt"])]
    MultiModelDebater(LLMGateway(CONFIG, execution_mode="live")).arbitrate(findings)
    assert sorted(shown["claude"]) == ["B"]
    assert sorted(shown["nemotron"]) == ["A"]
    assert sorted(shown["chatgpt"]) == ["A"]  # chatgpt already reported B, so it is not asked about B


def test_majority_decides_and_ties_are_kept(fake_live):
    _install(fake_live, {
        "nemotron": {"A": "reject", "B": "confirm", "C": "reject"},
        "chatgpt": {"A": "reject", "B": "reject", "C": "unsure"},
        "claude": {"D": "reject"},
    })
    findings = [
        _finding("A", "claude"),                               # 0 confirm vs 2 reject -> disputed
        _finding("B", "claude"),                               # 1 vs 1 -> tie, kept
        _finding("C", "claude"),                               # 0 vs 1 -> disputed
        _finding("D", "nemotron", corroborating=["chatgpt"]),  # corroborated vs claude reject -> tie, kept
    ]
    result = MultiModelDebater(LLMGateway(CONFIG, execution_mode="live")).arbitrate(findings)
    assert result.arbitration_applied
    assert [f.finding_id for f in result.confirmed_findings] == ["B", "D"]
    assert [f.finding_id for f in result.disputed_findings] == ["A", "C"]
    # Agreeing decisive votes: A 2 + C 1 = 3 of 7 decisive votes (A 2, B 2, C 1, D 2)
    assert abs(result.model_agreement_ratio - 3 / 7) < 1e-9
    votes_a = {v.model_alias: v.verdict for v in result.disputed_findings[0].verification_votes}
    assert votes_a == {"nemotron": "reject", "chatgpt": "reject"}


def test_corroborated_finding_with_confirming_verifier_is_confirmed_unanimously(fake_live):
    _install(fake_live, {"claude": {"D": "confirm"}})
    result = MultiModelDebater(LLMGateway(CONFIG, execution_mode="live")).arbitrate(
        [_finding("D", "nemotron", corroborating=["chatgpt"])]
    )
    assert [f.finding_id for f in result.confirmed_findings] == ["D"]
    assert result.model_agreement_ratio == 1.0


def test_bogus_rulings_are_ignored(fake_live):
    fake_live(lambda s, u: json.dumps({"verdicts": [
        {"index": 7, "verdict": "reject"}, {"index": "0", "verdict": "reject"},
        {"index": 0, "verdict": "maybe"}, {"index": 0, "verdict": "reject"}, {"index": 0, "verdict": "confirm"},
    ]}))
    result = MultiModelDebater(LLMGateway(CONFIG, execution_mode="live")).arbitrate([_finding("A", "claude")])
    # Only the first valid ruling per finding from each of the two verifiers counts: 2 rejects
    assert [f.finding_id for f in result.disputed_findings] == ["A"]
    assert len(result.disputed_findings[0].verification_votes) == 2


def test_unusable_or_unsure_verifiers_leave_findings_unfiltered(fake_live):
    fake_live(lambda s, u: "not json" if "nemotron" in s else json.dumps({"verdicts": [{"index": 0, "verdict": "unsure"}]}))
    gateway = LLMGateway(CONFIG, execution_mode="live")
    result = MultiModelDebater(gateway).arbitrate([_finding("A", "claude")])
    assert not result.arbitration_applied
    assert [f.finding_id for f in result.confirmed_findings] == ["A"]
    assert result.model_agreement_ratio is None
    assert gateway.invalid_calls  # the unusable verifier output is still disclosed as an evidence gap


def test_verifiers_see_the_code_of_the_finding(fake_live, tmp_path):
    prompts = []
    fake_live(lambda s, u: prompts.append(u) or '{"verdicts": []}')
    sym = CodeSymbol(name="get_order", symbol_type="function", file_path="app.py", line_start=1, line_end=2,
                     signature="get_order(o)", source_code="def get_order(o):\n    return o['id']", parameters=["o"])
    MultiModelDebater(LLMGateway(CONFIG, execution_mode="live")).arbitrate(
        [_finding("A", "claude")], symbols=[sym], root_dir=str(tmp_path)
    )
    assert prompts and all("return o['id']" in p for p in prompts)


def test_report_shows_votes_and_agreement(fake_live):
    from core.models import ThreatModelReport, VibeHarnessSummary
    _install(fake_live, {"nemotron": {"A": "reject"}, "chatgpt": {"A": "reject"}})
    result = MultiModelDebater(LLMGateway(CONFIG, execution_mode="live")).arbitrate([_finding("A", "claude")])
    summary = VibeHarnessSummary(
        overall_status="INCONCLUSIVE", total_whitebox_findings=1, confirmed_whitebox_bugs=0,
        whitebox_tests_passed=0, whitebox_tests_failed=0, total_threats_modeled=0,
        critical_threats_count=0, blackbox_tests_passed=0, blackbox_security_breaches=0
    )
    threat_model = ThreatModelReport(system_description="", entrypoints=[], trust_boundaries=[], assets=[], threats=[])
    md = ReportGenerator().generate_markdown_report(summary, result, threat_model, [], [], "app")
    assert "Cross-Model Agreement** | `100.0%`" in md
    assert "nemotron: reject (nemotron on A)" in md
