"""Duplicate-finding merging and token-budgeted prompt context."""
import json
import os
import re

from core.codecontext import (
    estimate_tokens, truncate_to_tokens, class_skeleton, render_symbols, batch_symbols
)
from core.llm_gateway import LLMGateway
from core.models import ReviewFinding, FindingSeverity
from agents.whitebox.ast_extractor import ASTExtractor
from agents.whitebox.deduplicator import deduplicate_findings
from agents.whitebox.multi_reviewer import HeterogeneousReviewerEnsemble

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG = os.path.join(REPO_ROOT, "config", "agents_config.yaml")


def _finding(fid, reviewer, title, root_cause="", symbol="get_order", file_path="app.py", severity="HIGH"):
    return ReviewFinding(
        finding_id=fid, reviewer_name=reviewer, model_alias=reviewer.lower(), file_path=file_path,
        symbol_name=symbol, severity=FindingSeverity(severity), title=title, description="",
        root_cause=root_cause, suspected_vibe_flaw="", suggested_test_scenario=""
    )


# --- Deduplication ----------------------------------------------------------------

def test_same_defect_from_three_models_is_merged_keeping_highest_severity():
    findings = [
        _finding("WB-CLA-01", "Claude", "Unhandled KeyError when order id is absent", "dict access order['id']", severity="MEDIUM"),
        _finding("WB-NEM-01", "Nemotron", "KeyError on absent order id", "direct order['id'] access", severity="CRITICAL"),
        _finding("WB-CHA-01", "ChatGPT", "Order id KeyError not handled", "order['id'] dict access"),
    ]
    merged = deduplicate_findings(findings)
    assert len(merged) == 1
    assert merged[0].finding_id == "WB-NEM-01"
    assert merged[0].severity == FindingSeverity.CRITICAL
    assert merged[0].corroborated_by == ["Claude", "ChatGPT"]
    assert merged[0].merged_finding_ids == ["WB-CLA-01", "WB-CHA-01"]


def test_distinct_defects_on_the_same_symbol_are_kept():
    findings = [
        _finding("A", "Claude", "Unhandled KeyError when order id is absent", "dict access order['id']"),
        _finding("B", "Nemotron", "SQL injection through unescaped search string", "f-string query building"),
    ]
    assert [f.finding_id for f in deduplicate_findings(findings)] == ["A", "B"]


def test_similar_titles_on_different_symbols_are_kept():
    findings = [
        _finding("A", "Claude", "Unhandled KeyError on absent id", symbol="get_order"),
        _finding("B", "ChatGPT", "Unhandled KeyError on absent id", symbol="get_user"),
    ]
    assert len(deduplicate_findings(findings)) == 2


def test_unattributed_findings_merge_only_on_identical_title():
    findings = [
        _finding("A", "Claude", "Race condition in cache", symbol=None, file_path="unknown"),
        _finding("B", "ChatGPT", "race condition in cache ", symbol=None, file_path="unknown"),
        _finding("C", "Nemotron", "Race condition in cache refresh", symbol=None, file_path="unknown"),
    ]
    merged = deduplicate_findings(findings)
    assert [f.finding_id for f in merged] == ["A", "C"]
    assert merged[0].corroborated_by == ["ChatGPT"]


# --- Token budget --------------------------------------------------------------------

def test_token_estimate_and_truncation():
    assert estimate_tokens("x" * 35) == 10
    assert estimate_tokens("測試") == 2
    text = "line\n" * 1000
    cut = truncate_to_tokens(text, 100)
    assert estimate_tokens(cut) <= 100
    assert cut.endswith("(truncated)")
    assert truncate_to_tokens("short", 100) == "short"


def test_class_is_rendered_as_skeleton_without_method_bodies(tmp_path):
    f = tmp_path / "svc.py"
    f.write_text(
        "class Cart:\n"
        "    TAX = 0.05\n\n"
        "    def total(self, items):\n"
        "        secret_body_marker = sum(items)\n"
        "        return secret_body_marker\n\n"
        "    def empty(self): return []\n",
        encoding="utf-8"
    )
    symbols = ASTExtractor().parse_file(str(f))
    cls = next(s for s in symbols if s.name == "Cart")
    skeleton = class_skeleton(cls.source_code)
    assert "TAX = 0.05" in skeleton
    assert "def total(self, items):" in skeleton
    assert "secret_body_marker" not in skeleton
    # The method body still appears exactly once, in the method's own block
    assert render_symbols(symbols, str(tmp_path), max_tokens=5000).count("secret_body_marker = sum") == 1


def test_batches_fit_the_budget_so_no_symbol_is_omitted(tmp_path):
    f = tmp_path / "big.py"
    f.write_text("".join(f"def f{i}(x):\n" + "    x += 1\n" * 40 + "    return x\n\n" for i in range(12)), encoding="utf-8")
    symbols = ASTExtractor().parse_file(str(f))
    batches = batch_symbols(symbols, str(tmp_path), max_tokens=400, max_symbols=15)
    assert len(batches) > 1
    assert sum(len(b) for b in batches) == len(symbols)
    for batch in batches:
        assert "omitted" not in render_symbols(batch, str(tmp_path), max_tokens=400)


def test_oversized_symbol_gets_its_own_truncated_batch(tmp_path):
    f = tmp_path / "huge.py"
    f.write_text("def small():\n    return 1\n\ndef huge():\n" + "    x = 1\n" * 2000 + "    return x\n", encoding="utf-8")
    symbols = ASTExtractor().parse_file(str(f))
    batches = batch_symbols(symbols, str(tmp_path), max_tokens=300, max_symbols=15)
    assert [[s.name for s in b] for b in batches] == [["small"], ["huge"]]
    rendered = render_symbols(batches[1], str(tmp_path), max_tokens=300)
    assert estimate_tokens(rendered) <= 300
    assert "(truncated)" in rendered


def test_reviewer_batches_by_tokens_and_reviews_every_symbol(fake_live, tmp_path, monkeypatch):
    f = tmp_path / "mod.py"
    f.write_text("".join(f"def handler_{i}(req):\n" + "    req = dict(req)\n" * 30 + "    return req\n\n" for i in range(8)), encoding="utf-8")
    symbols = ASTExtractor().parse_file(str(f))
    monkeypatch.setattr(HeterogeneousReviewerEnsemble, "BATCH_MAX_TOKENS", 500)
    seen, prompts = set(), []

    def responder(system, user):
        if "Claude Logic Reviewer" in system:
            prompts.append(user)
            seen.update(re.findall(r"Symbol: (handler_\d+)", user))
        return json.dumps({"findings": []})
    fake_live(responder)
    HeterogeneousReviewerEnsemble(LLMGateway(CONFIG, execution_mode="live")).review_symbols(symbols, root_dir=str(tmp_path))
    assert len(prompts) > 1
    assert seen == {f"handler_{i}" for i in range(8)}
    assert not any("omitted" in p for p in prompts)
    assert all(estimate_tokens(p) < 700 for p in prompts)


# --- Verifier findings listing stays within its token budget --------------------------------------

def test_debater_listing_clips_fields_and_keeps_every_index():
    from agents.whitebox.debater import MultiModelDebater

    debater = MultiModelDebater(LLMGateway(CONFIG, execution_mode="mock"))
    findings = [
        ReviewFinding(
            finding_id=f"WB-CLA-{i:02d}", reviewer_name="Claude", model_alias="claude", file_path="app.py",
            symbol_name="get_order", severity=FindingSeverity.HIGH, title="t" * 5000,
            description="d" * 5000, root_cause="c" * 5000, suspected_vibe_flaw="",
            suggested_test_scenario="s" * 5000
        )
        for i in range(MultiModelDebater.FINDINGS_PER_CALL)
    ]
    listing = debater._build_listing(findings, list(range(len(findings))))
    assert all(f"[{i}]" in listing for i in range(len(findings)))
    assert "(truncated)" in listing
    assert estimate_tokens(listing) <= MultiModelDebater.LISTING_MAX_TOKENS + 1500


def test_debater_listing_keeps_short_fields_intact():
    from agents.whitebox.debater import MultiModelDebater

    debater = MultiModelDebater(LLMGateway(CONFIG, execution_mode="mock"))
    findings = [_finding(f"WB-CLA-{i:02d}", "Claude", f"defect {i}") for i in range(3)]
    listing = debater._build_listing(findings, [0, 1, 2])
    assert "(truncated)" not in listing
    assert "defect 2" in listing
