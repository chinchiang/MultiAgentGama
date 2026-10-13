"""live 模式的管線：提示詞帶有目標的真實程式碼與匯入路徑，而且閘道呼叫是穩健的。
Live-mode plumbing: prompts carry the target's real code and import paths, and gateway calls are robust."""
import json
import os
import re
from types import SimpleNamespace

import pytest

from vibeharness.core.codecontext import module_import_name, import_instructions, render_symbols
from vibeharness.core.llm_gateway import LLMGateway
from vibeharness.core.models import ReviewFinding, FindingSeverity, TestStatus
from vibeharness.core.sandbox import LocalSubprocessSandbox
from vibeharness.agents.whitebox.ast_extractor import ASTExtractor
from vibeharness.agents.whitebox.multi_reviewer import HeterogeneousReviewerEnsemble
from vibeharness.agents.whitebox.test_generator import WhiteboxTestGenerator
from vibeharness.agents.blackbox.threat_modeler import AutomatedThreatModeler
from vibeharness.runners.test_executor import TestSuiteExecutor

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG = os.path.join(REPO_ROOT, "vibeharness", "config", "agents_config.yaml")


# --- codecontext（程式碼脈絡）-------------------------------------------------
# --- codecontext --------------------------------------------------------------

def test_module_import_name(tmp_path):
    root = tmp_path / "proj"
    assert module_import_name(str(root / "pkg" / "orders.py"), str(root)) == "pkg.orders"
    assert module_import_name(str(root / "pkg" / "__init__.py"), str(root)) == "pkg"
    assert module_import_name(str(tmp_path / "elsewhere.py"), str(root)) is None
    assert module_import_name(str(root / "my-app.py"), str(root)) is None  # 無法依名稱匯入 ／ not importable by name
    assert module_import_name(str(root / "app.ts"), str(root)) is None


def test_package_target_is_imported_through_its_package(tmp_path):
    """目標目錄本身就是套件時，必須經由上層目錄匯入（沙盒也會把它放到 sys.path 上），
    否則它自己的相對匯入會壞掉，執行器就會歸咎於目標
    （「attempted relative import with no known parent package」）。
    A target directory that is itself a package must be imported via the parent directory
    (which the sandbox also puts on sys.path), or its own relative imports break and the executor
    blames the target ("attempted relative import with no known parent package")."""
    pkg = tmp_path / "src" / "shop"
    pkg.mkdir(parents=True)
    (pkg / "__init__.py").write_text("")
    (pkg / "app.py").write_text("from .models import price_of\n")
    (pkg / "models.py").write_text("def price_of(item):\n    return item['price']\n")
    assert module_import_name(str(pkg / "app.py"), str(pkg)) == "shop.app"
    assert module_import_name(str(pkg / "__init__.py"), str(pkg)) == "shop"
    text = import_instructions(str(pkg / "app.py"), str(pkg), "checkout")
    assert "from shop.app import checkout" in text and str(tmp_path / "src") in text
    # 普通目錄（沒有 __init__.py）維持直接形式
    # A plain directory (no __init__.py) keeps the direct form
    (pkg / "__init__.py").unlink()
    assert module_import_name(str(pkg / "app.py"), str(pkg)) == "app"


def test_offline_probe_imports_a_package_module_by_name(tmp_path):
    from vibeharness.agents.whitebox.ast_extractor import ASTExtractor
    from vibeharness.agents.whitebox.test_generator import WhiteboxTestGenerator
    from vibeharness.core.llm_gateway import LLMGateway
    from vibeharness.core.sandbox import LocalSubprocessSandbox
    from vibeharness.runners.test_executor import TestSuiteExecutor
    from vibeharness.core.models import TestStatus
    pkg = tmp_path / "shop"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("")
    (pkg / "models.py").write_text("def price_of(item):\n    return item['price']\n")
    (pkg / "app.py").write_text(
        "from .models import price_of\n\ndef checkout(cart):\n    return sum(price_of(i) for i in cart)\n"
    )
    symbols = [s for s in ASTExtractor().parse_directory(str(pkg)) if s.name == "checkout"]
    gen = WhiteboxTestGenerator(LLMGateway(CONFIG, execution_mode="mock"))
    probes = gen.build_offline_probes(symbols, root_dir=str(pkg))
    assert "importlib.import_module('shop.app')" in probes[0].code
    results, _ = TestSuiteExecutor(LocalSubprocessSandbox(timeout_seconds=60)).execute_test_suite(
        probes, working_dir=str(pkg)
    )
    # 探針到達了 checkout()（None 的購物車 -> TypeError）：對目標的 FAILED 判定結果，
    # 而不是歸咎於目標相對匯入的 ERROR
    # The probe reached checkout() (None cart -> TypeError): a FAILED verdict about the target,
    # not an ERROR blaming the target's relative import
    assert results[0].status == TestStatus.FAILED, results[0].failure_reason
    assert "relative import" not in (results[0].failure_reason or "")


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


# --- AST 擷取器 -----------------------------------------------------------------
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
    assert "@login_required" in route.source_code  # 裝飾器（授權防護）對審查者可見 ／ decorators (auth guards) are visible to reviewers
    assert route.parameters == ["oid", "verbose"]
    assert extractor.parse_failures == [str(tmp_path / "broken.py")]


def test_max_files_truncation_is_recorded(tmp_path):
    for i in range(4):
        (tmp_path / f"m{i}.py").write_text(f"def f{i}():\n    return {i}\n", encoding="utf-8")
    extractor = ASTExtractor()
    symbols = extractor.parse_directory(str(tmp_path), max_files=3)
    assert len(symbols) == 3
    assert len(extractor.skipped_files) == 1


# --- 審查者集成 -----------------------------------------------------------------
# --- Reviewer ensemble ----------------------------------------------------------

def test_reviewers_see_every_symbol_and_findings_are_attributed(scripted, tmp_path):
    files = []
    for i in range(20):
        f = tmp_path / f"mod{i}.py"
        f.write_text(f"def handler_{i}(req):\n    return req['id']\n", encoding="utf-8")
        files.append(str(f))
    symbols = ASTExtractor().parse_directory(str(tmp_path))
    def review(request):
        if "handler_17" in request.messages[1]["content"]:
            return {"findings": [{"symbol_name": "handler_17", "severity": "HIGH", "title": "KeyError"}]}
        return {"findings": []}
    transport = scripted({"whitebox_reviewer_*": review})

    findings = HeterogeneousReviewerEnsemble(LLMGateway(CONFIG, execution_mode="live", transport=transport)).review_symbols(
        symbols, root_dir=str(tmp_path)
    )
    seen_by_reviewer = {}
    for r in transport.requests:
        seen_by_reviewer.setdefault(r.agent_id, set()).update(re.findall(r"handler_\d+", r.messages[1]["content"]))
    assert len(seen_by_reviewer) == 4
    assert all(names == {f"handler_{i}" for i in range(20)} for names in seen_by_reviewer.values())
    assert len(findings) == 4
    assert {f.file_path for f in findings} == {files[17]}
    assert len({f.finding_id for f in findings}) == 4


# --- 測試產生器：產生的測試必須能匯入目標 ------------------------------------
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
    assert [t.test_type for t in tests] == ["whitebox_unit"]  # 不需要退回探針 ／ no fallback probes needed

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


# --- 閘道呼叫選項與退回模型 ---------------------------------------------------
# --- Gateway call options and fallback ---------------------------------------------

def test_gateway_passes_call_options_and_uses_fallback_model(fake_live, monkeypatch):
    calls = []

    def completion(**kwargs):
        calls.append(kwargs)
        if kwargs["model"] == "claude-sonnet-5-5":
            raise RuntimeError("overloaded")
        return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content='{"findings": []}'))])

    fake_live(lambda s, u: "")
    monkeypatch.setattr("vibeharness.core.transport.litellm", SimpleNamespace(completion=completion))
    gateway = LLMGateway(CONFIG, execution_mode="live")
    resp = gateway.generate("whitebox_reviewer_claude", "sys", "prompt", required_keys=["findings"])

    assert [c["model"] for c in calls] == ["claude-sonnet-5-5", "claude-haiku-4-5-20251001"]
    assert calls[0]["api_key"] == "test-key"
    assert calls[0]["timeout"] == 180 and calls[0]["num_retries"] == 2 and calls[0]["max_tokens"] == 16384
    assert gateway.call_log[0].mode == "live"
    assert gateway.call_log[0].model_name == "claude-haiku-4-5-20251001"
    assert resp["_provenance"]["model"] == "claude-haiku-4-5-20251001"


def test_missing_config_fails_loudly(tmp_path):
    from vibeharness.core.llm_gateway import ConfigError
    with pytest.raises(ConfigError):
        LLMGateway(str(tmp_path / "nope.yaml"))


def test_default_config_resolves_independently_of_cwd(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert "whitebox_reviewer_claude" in LLMGateway(execution_mode="mock").agents_config
