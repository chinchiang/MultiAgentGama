import os
from core.models import STRIDECategory
from core.llm_gateway import LLMGateway
from core.sandbox import LocalSubprocessSandbox
from agents.whitebox.ast_extractor import ASTExtractor
from agents.whitebox.multi_reviewer import HeterogeneousReviewerEnsemble
from agents.whitebox.debater import MultiModelDebater
from agents.whitebox.test_generator import WhiteboxTestGenerator
from agents.blackbox.threat_modeler import AutomatedThreatModeler
from agents.blackbox.scenario_builder import ThreatScenarioBuilder

# Mock mode keeps these tests hermetic even when real API keys are set in the environment
SAMPLE_APP = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "examples", "vibe_sample_app.py")


def test_ast_extractor_on_sample_app():
    extractor = ASTExtractor()
    symbols = extractor.parse_file(SAMPLE_APP)
    assert len(symbols) >= 3
    names = [s.name for s in symbols]
    assert "get_user_profile" in names
    assert "update_user_settings" in names
    assert "process_payment_transfer" in names
    assert "Python" in extractor.detected_languages


def test_ast_extractor_js_ts_heuristic(tmp_path):
    js_file = tmp_path / "server.ts"
    js_file.write_text(
        "export async function handleLogin(req, res) { return true; }\n"
        "app.get('/api/orders', (req, res) => { return []; });\n",
        encoding="utf-8"
    )
    extractor = ASTExtractor()
    symbols = extractor.parse_file(str(js_file))
    assert len(symbols) >= 2
    names = [s.name for s in symbols]
    assert "handleLogin" in names
    assert "GET /api/orders" in names
    assert "TypeScript/JavaScript" in extractor.detected_languages


def test_llm_gateway_heterogeneous_personas():
    gateway = LLMGateway(execution_mode="mock")
    # Test Claude logic persona
    claude_resp = gateway.generate("whitebox_reviewer_claude", "sys", "prompt")
    assert "findings" in claude_resp
    assert any("Null" in f["title"] or "State" in f["title"] for f in claude_resp["findings"])

    # Test Nemotron guardrail persona
    nemotron_resp = gateway.generate("whitebox_reviewer_nemotron", "sys", "prompt")
    assert "findings" in nemotron_resp
    assert any("Sanitization" in f["title"] or "Resource" in f["title"] for f in nemotron_resp["findings"])

    # Test ChatGPT spec persona
    chatgpt_resp = gateway.generate("whitebox_reviewer_chatgpt", "sys", "prompt")
    assert "findings" in chatgpt_resp
    assert any("Contract" in f["title"] or "Specification" in f["title"] for f in chatgpt_resp["findings"])


def test_debater_consensus_resolution():
    gateway = LLMGateway(execution_mode="mock")
    extractor = ASTExtractor()
    reviewer = HeterogeneousReviewerEnsemble(gateway)
    debater = MultiModelDebater(gateway)

    symbols = extractor.parse_file(SAMPLE_APP)
    raw_findings = reviewer.review_symbols(symbols)
    assert len(raw_findings) >= 3

    debate_result = debater.arbitrate(raw_findings)
    # A simulated arbiter is a fixed template, so it must not filter real findings or invent a consensus figure
    assert debate_result.is_simulated
    assert not debate_result.arbitration_applied
    assert debate_result.model_agreement_ratio is None
    assert debate_result.confirmed_findings == raw_findings


def test_self_healing_test_generator():
    gateway = LLMGateway(execution_mode="mock")
    gen = WhiteboxTestGenerator(gateway)
    # Valid syntax
    code_valid = "def test_ok(): assert 1 == 1"
    assert gen._validate_and_heal(code_valid, 1) == code_valid

    # Unrepairable code is returned as-is (reported as ERROR later), never swapped for a passing no-op
    code_invalid = "def test_broken( invalid syntax here"
    healed = gen._validate_and_heal(code_invalid, 1)
    assert healed == code_invalid
    assert "pass" not in healed


def test_threat_modeling_stride_and_owasp():
    gateway = LLMGateway(execution_mode="mock")
    threat_modeler = AutomatedThreatModeler(gateway)
    report = threat_modeler.model_system(
        system_description="User Profile & Payment API",
        entrypoints=["/api/users", "/api/payments"]
    )
    assert len(report.threats) >= 3
    categories = [t.stride_category for t in report.threats]
    assert STRIDECategory.ELEVATION_OF_PRIVILEGE in categories
    assert STRIDECategory.TAMPERING in categories


def test_scenario_builder_server_health_check():
    gateway = LLMGateway(execution_mode="mock")
    builder = ThreatScenarioBuilder(gateway)
    # Non-existent port should return False safely without throwing an uncaught exception
    assert builder.check_server_live("http://localhost:59999", timeout_sec=0.2) is False


def test_sandbox_process_isolation_and_timeout():
    sandbox = LocalSubprocessSandbox(timeout_seconds=15)
    code_pass = "def test_ok(): assert 1 + 1 == 2"
    exit_code, stdout, stderr, dur, cov = sandbox.execute_python_code(code_pass)
    assert exit_code == 0
    assert "passed" in stdout.lower()

    # Verify timeout handling
    quick_sandbox = LocalSubprocessSandbox(timeout_seconds=1)
    code_hang = "import time\ndef test_slow(): time.sleep(3)"
    exit_code_timeout, _, err, _, _ = quick_sandbox.execute_python_code(code_hang)
    assert exit_code_timeout == -1
    assert "timed out" in err.lower()
    # The message must name the module that was attempted
    assert "test_exec.py" in err
