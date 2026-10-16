"""每個代理的呼叫計畫（`plan`，`--estimate` 加總的就是它）等於代理對同樣輸入實際發出的呼叫。
Each agent's call plan (`plan`, what `--estimate` adds up) equals the calls the agent actually makes for the same
inputs."""
import os
import re
from collections import Counter

import yaml

from vibeharness.agents.blackbox import scenario_builder, threat_modeler
from vibeharness.agents.blackbox.scenario_builder import ThreatScenarioBuilder
from vibeharness.agents.blackbox.threat_modeler import AutomatedThreatModeler
from vibeharness.agents.whitebox import test_generator
from vibeharness.agents.whitebox.ast_extractor import ASTExtractor
from vibeharness.agents.whitebox.debater import MultiModelDebater
from vibeharness.agents.whitebox.multi_reviewer import HeterogeneousReviewerEnsemble
from vibeharness.agents.whitebox.test_generator import WhiteboxTestGenerator
from vibeharness.core.codecontext import estimate_tokens
from vibeharness.core.fanout import CallKind
from vibeharness.core.llm_gateway import LLMGateway
from vibeharness.core.models import FindingSeverity, ReviewFinding, STRIDECategory, ThreatItem
from vibeharness.core.sanitize import UNTRUSTED_CODE_CLOSE, UNTRUSTED_CODE_OPEN

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG = os.path.join(REPO_ROOT, "vibeharness", "config", "agents_config.yaml")
_VALID_TEST = "def test_ok():\n    assert 1 == 1\n"
_INVALID_TEST = "def test_broken(:\n"
_LISTING_RE = re.compile(re.escape(UNTRUSTED_CODE_OPEN) + "\n(.*?)\n" + re.escape(UNTRUSTED_CODE_CLOSE), re.S)


def _symbols(tmp_path, count):
    """`count` 個函式，多到白箱與威脅建模都要分成不只一批（每批最多 15 個符號）。
    `count` functions, enough that both white-box review and threat modeling need more than one batch (at most 15
    symbols each)."""
    path = tmp_path / "svc.py"
    path.write_text("".join(f"def func_{i}(x):\n    return x + {i}\n\n" for i in range(count)), encoding="utf-8")
    return ASTExtractor().parse_file(str(path))


def _finding(i, model="claude", corroborating_models=()):
    return ReviewFinding(
        finding_id=f"F{i}", reviewer_name=model.title(), model_alias=model, file_path="unknown",
        severity=FindingSeverity.HIGH, title=f"title F{i}", description="", root_cause="",
        suspected_vibe_flaw="", suggested_test_scenario="",
        corroborated_by=[m.title() for m in corroborating_models], corroborating_models=list(corroborating_models)
    )


def _threat(i):
    return ThreatItem(
        threat_id=f"T{i}", stride_category=STRIDECategory.TAMPERING, title=f"threat {i}", description="",
        asset_at_risk="a", attack_vector="v", trust_boundary_crossed="b", severity=FindingSeverity.HIGH,
        attack_scenario="", test_verification_goal=""
    )


def _planned(plans, kind=None):
    """{(代理 id, 模型別名): 計畫的呼叫數}，可只取某一種呼叫 ／ {(agent id, model alias): planned calls}, optionally of one kind."""
    planned = Counter()
    for p in plans:
        if kind is None or p.kind == kind:
            planned[(p.agent_id, p.model_alias)] += p.calls
    return planned


def _actual(transport, system=None):
    """{(代理 id, 模型別名): 實際的呼叫數}，可只取某個系統提示詞的呼叫。
    {(agent id, model alias): actual calls}, optionally of one system prompt."""
    return Counter((r.agent_id, r.model_alias) for r in transport.requests
                   if system is None or r.messages[0]["content"] == system)


def _planned_code_tokens(plans):
    """{(代理 id, 模型別名): 每次呼叫計畫帶上的程式碼 token，排序後} ／ {(agent id, model alias): each call's planned code tokens, sorted}."""
    planned = {}
    for p in plans:
        planned.setdefault((p.agent_id, p.model_alias), []).extend([p.code_tokens] * p.calls)
    return {key: sorted(tokens) for key, tokens in planned.items()}


def _actual_code_tokens(transport):
    """{(代理 id, 模型別名): 每次呼叫實際帶上的程式碼清單的 token，排序後}；沒有程式碼區塊的呼叫算 0。
    {(agent id, model alias): the tokens of the code listing each call actually carried, sorted}; a call without a code
    block counts as 0."""
    actual = {}
    for r in transport.requests:
        listings = _LISTING_RE.findall(r.messages[1]["content"])
        assert len(listings) <= 1
        actual.setdefault((r.agent_id, r.model_alias), []).append(estimate_tokens(listings[0]) if listings else 0)
    return {key: sorted(tokens) for key, tokens in actual.items()}


def test_reviewer_plan_is_one_call_per_reviewer_and_batch(scripted, tmp_path):
    symbols = _symbols(tmp_path, 20)
    transport = scripted({"whitebox_reviewer_*": {"findings": []}})
    ensemble = HeterogeneousReviewerEnsemble(LLMGateway(CONFIG, execution_mode="live", transport=transport))
    plans = ensemble.plan(symbols, str(tmp_path))
    ensemble.review_symbols(symbols, root_dir=str(tmp_path))
    assert all(p.exact and p.kind is CallKind.REVIEWER for p in plans)
    assert set(_planned(plans).values()) == {2}  # 每個審查者兩批 ／ two batches per reviewer
    assert _planned(plans) == _actual(transport)
    assert _planned_code_tokens(plans) == _actual_code_tokens(transport)
    # 批次數等於每個審查者實際發出的呼叫數 ／ the batch count is what each reviewer actually sent
    assert set(_actual(transport).values()) == {ensemble.batch_count(symbols, str(tmp_path))} == {2}
    assert ensemble.plan([], str(tmp_path)) == []
    assert ensemble.batch_count([], str(tmp_path)) == 0


def test_reviewer_batch_count_is_zero_without_reviewers(scripted, tmp_path):
    with open(CONFIG, encoding="utf-8") as f:
        cfg = yaml.safe_load(f)
    cfg["agents"] = {k: v for k, v in cfg["agents"].items() if not k.startswith("whitebox_reviewer_")}
    config = tmp_path / "cfg.yaml"
    config.write_text(yaml.safe_dump(cfg), encoding="utf-8")
    symbols = _symbols(tmp_path, 20)
    transport = scripted({})
    ensemble = HeterogeneousReviewerEnsemble(LLMGateway(str(config), execution_mode="live", transport=transport))
    ensemble.review_symbols(symbols, root_dir=str(tmp_path))
    # 沒有審查者就不審任何一批 ／ no reviewers review no batch
    assert not transport.requests
    assert ensemble.batch_count(symbols, str(tmp_path)) == 0


_TITLE_RE = re.compile(r"Title: title (\w+)")


def _unsure_verdicts(request):
    """驗證者的回答：對請求裡的每一筆發現都裁決 unsure ／ A verifier's answer: unsure on every finding in the request."""
    titles = _TITLE_RE.findall(request.messages[1]["content"])
    return {"verdicts": [{"index": i, "verdict": "unsure", "reason": "r"} for i in range(len(titles))]}


def _ruled_on(transport):
    """{模型別名: 實際送給該驗證者裁決的發現數} ／ {model alias: findings actually sent to that verifier to rule on}."""
    ruled = Counter()
    for r in transport.requests:
        ruled[r.model_alias] += len(_TITLE_RE.findall(r.messages[1]["content"]))
    return ruled


def test_debater_plan_is_the_verifier_calls_for_the_reported_findings(scripted):
    transport = scripted({"whitebox_verifier_*": _unsure_verdicts})
    debater = MultiModelDebater(LLMGateway(CONFIG, execution_mode="live", transport=transport))
    # 跨過每次呼叫的發現上限，讓驗證者各自需要不同的呼叫數；沒有佐證（計畫看不到哪些會被佐證）
    # Crosses the findings-per-call limit so the verifiers need different numbers of calls; nothing is corroborated
    # (the plan cannot see which findings will be)
    reported = {"claude": debater.FINDINGS_PER_CALL + 5, "deepseek": 1}
    findings = [_finding(f"{alias}{i}", alias) for alias, n in reported.items() for i in range(n)]
    plans = debater.plan(reported)
    debater.arbitrate(findings)
    assert not any(p.exact for p in plans)
    assert len(set(_planned(plans).values())) > 1
    assert _planned(plans) == _actual(transport)
    # 分到的發現數等於實際送給每個驗證者的發現數（自家模型的不送） ／ the assigned findings are those actually sent
    # to each verifier (never its own model's)
    ruled = _ruled_on(transport)
    assert {p.model_alias: debater.assigned_findings(reported, p.model_alias) for p in plans} == \
        {p.model_alias: ruled[p.model_alias] for p in plans}
    assert ruled["claude"] == 1 and ruled["deepseek"] == debater.FINDINGS_PER_CALL + 5
    assert set(_planned(debater.plan({})).values()) == {0}


def test_debater_plan_is_an_upper_bound_when_findings_are_corroborated(scripted):
    transport = scripted({"whitebox_verifier_*": _unsure_verdicts})
    debater = MultiModelDebater(LLMGateway(CONFIG, execution_mode="live", transport=transport))
    # claude 回報比每次呼叫的上限多一筆，其中一筆 deepseek 也回報了：deepseek 不必再裁決它，剩 FINDINGS_PER_CALL 筆只要一次呼叫，
    # 計畫看不到佐證，算成兩次；其他驗證者不受影響
    # claude reports one finding over the per-call limit, one of which deepseek reported too: deepseek need not rule
    # on it, so its remaining FINDINGS_PER_CALL take one call, while the plan cannot see corroboration and counts two; the other
    # verifiers are unaffected
    findings = [_finding(f"claude{i}", corroborating_models=["deepseek"] if i == 0 else [])
                for i in range(debater.FINDINGS_PER_CALL + 1)]
    plans = debater.plan({"claude": len(findings)})
    debater.arbitrate(findings)
    (deepseek_id,) = [p.agent_id for p in plans if p.model_alias == "deepseek"]
    assert _planned(plans) - _actual(transport) == Counter({(deepseek_id, "deepseek"): 1})
    assert not _actual(transport) - _planned(plans)


def test_test_generator_plan_is_one_call_per_finding_and_bounds_the_heals(scripted, tmp_path):
    def answer(request):
        if request.messages[0]["content"] == "Fix Python Test Code":
            return _INVALID_TEST  # 修復一直失敗，用完所有修復次數 ／ healing keeps failing and uses every attempt
        return {"tests": [{"code": _INVALID_TEST}, {"code": _VALID_TEST}]}
    transport = scripted({test_generator.AGENT_ID: answer})
    gen = WhiteboxTestGenerator(LLMGateway(CONFIG, execution_mode="live", transport=transport))
    findings = [_finding(i) for i in range(3)]
    plans = gen.plan(len(findings), tests_per_finding=2)
    gen.generate_tests_for_findings(findings, [], root_dir=str(tmp_path))
    generation = _actual(transport) - _actual(transport, "Fix Python Test Code")
    assert _planned(plans, CallKind.TEST_GENERATOR) == generation
    (heal,) = [p for p in plans if p.kind is CallKind.HEAL]
    assert heal.conditional and not heal.json_output and heal.max_per_call == test_generator.HEAL_ATTEMPTS
    assert heal.code_tokens > 0  # 修復提示詞帶著被修的測試 ／ a repair prompt carries the test being repaired
    # 每次產生的回答有一個無效的測試：用了計畫上限的一半 ／ one invalid test per generated answer: half the plan's cap
    healed = sum(_actual(transport, "Fix Python Test Code").values())
    assert healed == len(findings) * test_generator.HEAL_ATTEMPTS == heal.calls * heal.max_per_call // 2


def test_threat_modeler_plan_is_one_call_per_batch(scripted, tmp_path):
    symbols = _symbols(tmp_path, 20)
    threat = {"threat_id": "T1", "stride_category": "Tampering", "title": "t"}
    transport = scripted({threat_modeler.AGENT_ID: {"threats": [threat], "entrypoints": []}})
    tm = AutomatedThreatModeler(LLMGateway(CONFIG, execution_mode="live", transport=transport))
    plans = tm.plan(symbols, str(tmp_path)) + tm.plan(None, str(tmp_path))
    tm.model_system("desc", ["/api"], symbols=symbols, root_dir=str(tmp_path))
    tm.model_system("desc", ["/api"], root_dir=str(tmp_path))  # 沒有符號仍有一批 ／ one batch even without symbols
    assert all(p.exact for p in plans) and [p.code_tokens > 0 for p in plans] == [True, True, False]
    assert _planned(plans) == _actual(transport) == Counter({(threat_modeler.AGENT_ID, plans[0].model_alias): 3})
    assert _planned_code_tokens(plans) == _actual_code_tokens(transport)


def test_scenario_builder_plan_is_one_call_per_threat(scripted):
    transport = scripted({scenario_builder.AGENT_ID: {"code": _VALID_TEST}})
    builder = ThreatScenarioBuilder(LLMGateway(CONFIG, execution_mode="live", transport=transport))
    threats = [_threat(i) for i in range(4)]
    plans = builder.plan(len(threats))
    builder.build_test_cases_from_threats(threats)
    assert not any(p.exact for p in plans)
    assert _planned(plans) == _actual(transport) == Counter({(scenario_builder.AGENT_ID, plans[0].model_alias): 4})
