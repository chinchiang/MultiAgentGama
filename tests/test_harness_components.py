import os
from vibeharness.core.models import STRIDECategory
from vibeharness.core.llm_gateway import LLMGateway
from vibeharness.core.sandbox import LocalSubprocessSandbox, TIMEOUT_EXIT_CODE
from vibeharness.agents.whitebox.ast_extractor import ASTExtractor
from vibeharness.agents.whitebox.multi_reviewer import HeterogeneousReviewerEnsemble
from vibeharness.agents.whitebox.debater import MultiModelDebater
from vibeharness.agents.whitebox.test_generator import WhiteboxTestGenerator
from vibeharness.agents.blackbox.threat_modeler import AutomatedThreatModeler
from vibeharness.agents.blackbox.scenario_builder import ThreatScenarioBuilder

# 即使環境中設定了真實的 API 金鑰，mock 模式也能讓這些測試保持封閉
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
    # 測試 Claude 的邏輯人設
    # Test Claude logic persona
    claude_resp = gateway.generate("whitebox_reviewer_claude", "sys", "prompt")
    assert "findings" in claude_resp
    assert any("Null" in f["title"] or "State" in f["title"] for f in claude_resp["findings"])

    # 測試 DeepSeek 的防護人設
    # Test DeepSeek guardrail persona
    deepseek_resp = gateway.generate("whitebox_reviewer_deepseek", "sys", "prompt")
    assert "findings" in deepseek_resp
    assert any("Sanitization" in f["title"] or "Resource" in f["title"] for f in deepseek_resp["findings"])

    # 測試 GLM 的規格人設
    # Test GLM spec persona
    glm_resp = gateway.generate("whitebox_reviewer_glm", "sys", "prompt")
    assert "findings" in glm_resp
    assert any("Contract" in f["title"] or "Specification" in f["title"] for f in glm_resp["findings"])

    # 測試 Gemini 的 AI 整合人設（OWASP LLM Top 10 2026）
    # Test Gemini AI-integration persona (OWASP LLM Top 10 2026)
    gemini_resp = gateway.generate("whitebox_reviewer_gemini", "sys", "prompt")
    assert any(f.get("owasp_mapping") == "LLM01:2026" for f in gemini_resp["findings"])


def test_debater_consensus_resolution():
    gateway = LLMGateway(execution_mode="mock")
    extractor = ASTExtractor()
    reviewer = HeterogeneousReviewerEnsemble(gateway)
    debater = MultiModelDebater(gateway)

    symbols = extractor.parse_file(SAMPLE_APP)
    raw_findings = reviewer.review_symbols(symbols)
    assert len(raw_findings) >= 3

    debate_result = debater.arbitrate(raw_findings)
    # 模擬的仲裁者是固定範本，因此不得過濾真實發現，也不得捏造共識數字
    # A simulated arbiter is a fixed template, so it must not filter real findings or invent a consensus figure
    assert debate_result.is_simulated
    assert not debate_result.arbitration_applied
    assert debate_result.model_agreement_ratio is None
    assert debate_result.confirmed_findings == raw_findings


def test_self_healing_test_generator():
    gateway = LLMGateway(execution_mode="mock")
    gen = WhiteboxTestGenerator(gateway)
    # 合法語法
    # Valid syntax
    code_valid = "def test_ok(): assert 1 == 1"
    assert gen._validate_and_heal(code_valid, "finding WB-F-001") == code_valid

    # 無法修復的程式碼原樣回傳（稍後回報為 ERROR），絕不換成會通過的空操作
    # Unrepairable code is returned as-is (reported as ERROR later), never swapped for a passing no-op
    code_invalid = "def test_broken( invalid syntax here"
    healed = gen._validate_and_heal(code_invalid, "finding WB-F-001")
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
    # 不存在的連接埠應安全地回傳 False，不得拋出未捕捉的例外
    # Non-existent port should return False safely without throwing an uncaught exception
    assert builder.check_server_live("http://localhost:59999", timeout_sec=0.2) is False


def test_sandbox_process_isolation_and_timeout():
    sandbox = LocalSubprocessSandbox(timeout_seconds=15)
    code_pass = "def test_ok(): assert 1 + 1 == 2"
    exit_code, stdout, stderr, dur, cov = sandbox.execute_python_code(code_pass)
    assert exit_code == 0
    assert "passed" in stdout.lower()

    # 驗證逾時處理
    # Verify timeout handling
    quick_sandbox = LocalSubprocessSandbox(timeout_seconds=1)
    code_hang = "import time\ndef test_slow(): time.sleep(3)"
    exit_code_timeout, _, err, _, _ = quick_sandbox.execute_python_code(code_hang)
    assert exit_code_timeout == TIMEOUT_EXIT_CODE
    assert "timed out" in err.lower()
    # 訊息必須指出所嘗試的模組名稱
    # The message must name the module that was attempted
    assert "test_exec.py" in err
