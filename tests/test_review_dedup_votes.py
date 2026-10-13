"""回歸測試：去重不得串連不同缺陷，且票必須來自不同的裁決。
Regression tests: deduplication must not chain distinct defects, and votes must come from distinct rulings."""
import dataclasses
import os
import re

from vibeharness.core.llm_gateway import LLMGateway
from vibeharness.core.settings import Overrides, freeze, load_settings
from vibeharness.core.models import ReviewFinding, FindingSeverity
from vibeharness.agents.whitebox.debater import MultiModelDebater
from vibeharness.agents.whitebox.deduplicator import deduplicate_findings

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG = os.path.join(REPO_ROOT, "vibeharness", "config", "agents_config.yaml")


def _finding(fid, model, title, root_cause="", severity="HIGH", corroborating=()):
    return ReviewFinding(
        finding_id=fid, reviewer_name=model.title(), model_alias=model, file_path="app.py",
        symbol_name="search", severity=FindingSeverity(severity), title=title, description="",
        root_cause=root_cause, suspected_vibe_flaw="", suggested_test_scenario="",
        corroborating_models=list(corroborating), corroborated_by=[m.title() for m in corroborating],
    )


# --- 去重 ／ Deduplication ----------------------------------------------------------------

def _chain():
    return [
        _finding("1", "claude", "SQL injection via search term", "no input validation on the search term", "CRITICAL"),
        _finding("2", "gemini", "Unbounded page size", "limit input has no validation", "MEDIUM"),
        _finding("3", "glm", "Missing input validation", "", "MEDIUM"),
    ]


def test_generic_finding_does_not_chain_distinct_defects():
    merged = deduplicate_findings(_chain())
    ids = [f.finding_id for f in merged]
    # SQL 注入與分頁大小缺陷都保留下來
    # The SQL injection and the page-size defect both survive
    assert "1" in ids and "2" in ids
    sqli = next(f for f in merged if f.finding_id == "1")
    assert "gemini" not in sqli.corroborating_models
    assert "2" not in sqli.merged_finding_ids


def test_generic_two_term_finding_is_not_contained_in_a_specific_one():
    merged = deduplicate_findings(_chain()[::2])  # 只有 SQL 注入與泛用發現 ／ only the SQL injection and the generic finding
    assert [f.finding_id for f in merged] == ["1", "3"]
    assert merged[0].corroborating_models == []


def test_dedup_result_is_independent_of_input_order():
    forward = deduplicate_findings(_chain())
    backward = deduplicate_findings(_chain()[::-1])
    key = lambda fs: sorted((f.finding_id, tuple(f.merged_finding_ids)) for f in fs)  # noqa: E731
    assert key(forward) == key(backward)


def test_short_identical_findings_still_merge():
    findings = [
        _finding("A", "claude", "Missing input validation"),
        _finding("B", "glm", "missing input validation"),
    ]
    merged = deduplicate_findings(findings)
    assert len(merged) == 1 and merged[0].corroborating_models == ["glm"]


# --- 跨模型驗證 ／ Cross-model verification ------------------------------------------------------

def _gateway_with_duplicate_verifier(transport):
    settings = load_settings(CONFIG, origin="explicit", overrides=Overrides(execution_mode="live"))
    agents = {**settings.gateway.agents, "whitebox_verifier_zz_second_glm": settings.gateway.agents["whitebox_verifier_glm"]}
    return LLMGateway(settings=dataclasses.replace(settings, gateway=dataclasses.replace(settings.gateway, agents=freeze(agents))),
                      transport=transport)


def test_a_model_configured_twice_as_verifier_votes_once(scripted):
    def rule(request):
        n = len(re.findall(r"^\[\d+\]", request.messages[1]["content"], re.MULTILINE))
        return {"verdicts": [{"index": i, "verdict": "confirm" if request.model_alias == "glm" else "unsure"} for i in range(n)]}
    transport = scripted({"whitebox_verifier_*": rule})

    debater = MultiModelDebater(_gateway_with_duplicate_verifier(transport))
    assert sorted(debater.verifiers.values()) == sorted(set(debater.verifiers.values()))
    result = debater.arbitrate([_finding("A", "claude", "SQL injection via search term")])
    assert [r.model_alias for r in transport.requests].count("glm") == 1
    glm_votes = [v for v in result.confirmed_findings[0].verification_votes if v.model_alias == "glm"]
    assert len(glm_votes) == 1


def test_corroboration_alone_does_not_count_as_verification(fake_live):
    def responder(system, user):
        return "the verifiers produced no usable JSON"
    fake_live(responder)

    gw = LLMGateway(CONFIG, execution_mode="live")
    findings = [_finding("A", "claude", "SQL injection via search term", corroborating=["glm"])]
    result = MultiModelDebater(gw).arbitrate(findings)
    assert result.arbitration_applied is False
    assert result.model_agreement_ratio is None
    assert "no model ruled on its own finding" not in result.consensus_summary
    assert [f.finding_id for f in result.confirmed_findings] == ["A"]
