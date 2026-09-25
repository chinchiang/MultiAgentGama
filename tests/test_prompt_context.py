"""Live-mode plumbing: prompts carry the target's real code and import paths, and gateway calls are robust."""
import json
import os
import re
from types import SimpleNamespace

import pytest

from core.codecontext import module_import_name, import_instructions, render_symbols
from core.llm_gateway import LLMGateway
from core.models import ReviewFinding, FindingSeverity, TestStatus
from core.sandbox import LocalSubprocessSandbox
from agents.whitebox.ast_extractor import ASTExtractor
from agents.whitebox.multi_reviewer import HeterogeneousReviewerEnsemble
from agents.whitebox.test_generator import WhiteboxTestGenerator
from agents.blackbox.threat_modeler import AutomatedThreatModeler
from runners.test_executor import TestSuiteExecutor

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG = os.path.join(REPO_ROOT, "config", "agents_config.yaml")


# --- codecontext --------------------------------------------------------------

def test_module_import_name(tmp_path):
    root = tmp_path / "proj"
    assert module_import_name(str(root / "pkg" / "orders.py"), str(root)) == "pkg.orders"
    assert module_import_name(str(root / "pkg" / "__init__.py"), str(root)) == "pkg"
    assert module_import_name(str(tmp_path / "elsewhere.py"), str(root)) is None
    assert module_import_name(str(root / "my-app.py"), str(root)) is None  # not importable by name
    assert module_import_name(str(root / "app.ts"), str(root)) is None


def test_import_instructions_name_the_module_or_fall_back_to_importlib(tmp_path):
    text = import_instructions(str(tmp_path / "svc.py"), str(tmp_path), "Cart.total")
    assert "from svc import Cart" in text
    assert "importlib" in import_instructions(str(tmp_path / "my-app.py"), str(tmp_path))


def test_render_symbols_respects_budget_and_reports_omissions(tmp_path):
    f = tmp_path / "m.py"
    f.write_text("".join(f"def f{i}(x):\n    return x + {i}\n\n" for i in range(30)), encoding="utf-8")
    symbols = ASTExtractor().parse_file(str(f))
    text = render_symbols(symbols, str(tmp_path), max_tokens=150)
    assert "def f0(x)" in text
    assert "more symbol(s) omitted" in text


# --- AST extractor ------------------------------------------------------------

def test_flask_routes_decorators_and_parse_failures_are_reported(tmp_path):
    (tmp_path / "app.py").write_text(
        "@app.route('/orders/<int:oid>')\n@login_required\ndef get_order(oid, *, verbose=False):\n    return oid\n",
        encoding="utf-8"
    )
    (tmp_path / "broken.py").write_text("def x(:\n", encoding="utf-8")
    extractor = ASTExtractor()
    symbols = extractor.parse_directory(str(tmp_path))
    route = next(s for s in symbols if s.name == "get_order")
    assert route.symbol_type == "route"
    assert "@login_required" in route.source_code  # decorators (auth guards) are visible to reviewers
    assert route.parameters == ["oid", "verbose"]
    assert extractor.parse_failures == [str(tmp_path / "broken.py")]


def test_max_files_truncation_is_recorded(tmp_path):
    for i in range(4):
        (tmp_path / f"m{i}.py").write_text(f"def f{i}():\n    return {i}\n", encoding="utf-8")
    extractor = ASTExtractor()
    symbols = extractor.parse_directory(str(tmp_path), max_files=3)
    assert len(symbols) == 3
    assert len(extractor.skipped_files) == 1


# --- Reviewer ensemble ----------------------------------------------------------

def test_reviewers_see_every_symbol_and_findings_are_attributed(fake_live, tmp_path):
    files = []
    for i in range(20):
        f = tmp_path / f"mod{i}.py"
        f.write_text(f"def handler_{i}(req):\n    return req['id']\n", encoding="utf-8")
        files.append(str(f))
    symbols = ASTExtractor().parse_directory(str(tmp_path))
    seen_by_reviewer = {}

    def responder(system, user):
        seen_by_reviewer.setdefault(system.split(",")[0], set()).update(re.findall(r"handler_\d+", user))
        if "handler_17" in user:
            return json.dumps({"findings": [{"symbol_name": "handler_17", "severity": "HIGH", "title": "KeyError"}]})
        return '{"findings": []}'
    fake_live(responder)

    findings = HeterogeneousReviewerEnsemble(LLMGateway(CONFIG, execution_mode="live")).review_symbols(
        symbols, root_dir=str(tmp_path)
    )
    assert len(seen_by_reviewer) == 3
    assert all(names == {f"handler_{i}" for i in range(20)} for names in seen_by_reviewer.values())
    assert len(findings) == 3
    assert {f.file_path for f in findings} == {files[17]}
    assert len({f.finding_id for f in findings}) == 3


# --- Test generator: the generated test must be able to import the target ----------

def test_generated_test_imports_target_as_instructed_and_runs(fake_live, tmp_path):
    target = tmp_path / "app"
    (target / "shop").mkdir(parents=True)
    (target / "shop" / "__init__.py").write_text("", encoding="utf-8")
    (target / "shop" / "cart.py").write_text(
        "def total(items):\n    return sum(i['price'] for i in items)\n", encoding="utf-8"
    )
    symbols = ASTExtractor().parse_directory(str(target))
    prompts = []

    def responder(system, user):
        prompts.append(user)
        import_line = re.search(r"import it as: `([^`]+)`", user).group(1)
        code = f"{import_line}\n\ndef test_empty_cart():\n    assert total([]) == 0\n"
        return json.dumps({"code": code, "title": "empty cart"})
    fake_live(responder)

    finding = ReviewFinding(
        finding_id="WB-CLA-01", reviewer_name="r", model_alias="claude",
        file_path=str(target / "shop" / "cart.py"), symbol_name="total", severity=FindingSeverity.HIGH,
        title="t", description="", root_cause="", suspected_vibe_flaw="", suggested_test_scenario="empty cart"
    )
    tests = WhiteboxTestGenerator(LLMGateway(CONFIG, execution_mode="live")).generate_tests_for_findings(
        [finding], symbols, root_dir=str(target)
    )
    assert "from shop.cart import total" in prompts[0]
    assert "return sum(i['price'] for i in items)" in prompts[0]
    assert [t.test_type for t in tests] == ["whitebox_unit"]  # no fallback probes needed

    results, _ = TestSuiteExecutor(LocalSubprocessSandbox(timeout_seconds=60)).execute_test_suite(
        tests, working_dir=str(target)
    )
    assert results[0].status == TestStatus.PASSED, results[0].failure_reason


def test_threat_model_prompt_contains_code_and_rules(fake_live, tmp_path):
    (tmp_path / "api.py").write_text("@app.post('/transfer')\ndef transfer(amount):\n    return amount\n", encoding="utf-8")
    symbols = ASTExtractor().parse_directory(str(tmp_path))
    prompts = []
    fake_live(lambda s, u: prompts.append(u) or '{"threats": []}')
    AutomatedThreatModeler(LLMGateway(CONFIG, execution_mode="live")).model_system(
        "bank", ["POST /transfer"], ["transfer"], symbols=symbols, root_dir=str(tmp_path)
    )
    assert "def transfer(amount)" in prompts[0]
    assert "API1:2023" in prompts[0]


# --- Gateway call options and fallback ---------------------------------------------

def test_gateway_passes_call_options_and_uses_fallback_model(fake_live, monkeypatch):
    calls = []

    def completion(**kwargs):
        calls.append(kwargs)
        if kwargs["model"] == "claude-sonnet-5":
            raise RuntimeError("overloaded")
        return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content='{"findings": []}'))])

    fake_live(lambda s, u: "")
    monkeypatch.setattr("core.llm_gateway.litellm", SimpleNamespace(completion=completion))
    gateway = LLMGateway(CONFIG, execution_mode="live")
    resp = gateway.generate("whitebox_reviewer_claude", "sys", "prompt", required_keys=["findings"])

    assert [c["model"] for c in calls] == ["claude-sonnet-5", "claude-haiku-4-5-20251001"]
    assert calls[0]["api_key"] == "test-key"
    assert calls[0]["timeout"] == 60 and calls[0]["num_retries"] == 2 and calls[0]["max_tokens"] == 4096
    assert gateway.call_log[0].mode == "live"
    assert gateway.call_log[0].model_name == "claude-haiku-4-5-20251001"
    assert resp["_provenance"]["model"] == "claude-haiku-4-5-20251001"


def test_missing_config_fails_loudly(tmp_path):
    with pytest.raises(FileNotFoundError):
        LLMGateway(str(tmp_path / "nope.yaml"))


def test_default_config_resolves_independently_of_cwd(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert "whitebox_reviewer_claude" in LLMGateway(execution_mode="mock").agents_config
