"""身分識別模組（core/identity.py）：模型文字的正規化、位置規則、嚴重度順序，以及 `--baseline` 鍵與 SARIF 指紋。
表格驅動的性質測試，加上一張釘住雜湊值的 golden 表。
The identity module (core/identity.py): normalization of model text, the location rule, the severity order, and the
`--baseline` keys and SARIF fingerprints. Table-driven property tests, plus a golden table that pins the hashes."""
import os

import pytest

from vibeharness.core import identity
from vibeharness.core.i18n import bi
from vibeharness.core.models import (
    FindingSeverity, ReviewFinding, STRIDECategory, StaticFinding, TestExecutionResult, TestStatus, ThreatItem,
)

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXAMPLES = os.path.join(REPO_ROOT, "examples")


def _finding(fid="WB-CLA-01", title="Unchecked null in get_user", symbol="get_user_profile", path=None, simulated=False,
             line=33):
    return ReviewFinding(
        finding_id=fid, reviewer_name="Claude", model_alias="claude", file_path=path or os.path.join(EXAMPLES, "vibe_sample_app.py"),
        symbol_name=symbol, line_number=line, severity=FindingSeverity.HIGH, title=title, description="d", root_cause="r",
        suspected_vibe_flaw="v", suggested_test_scenario="s", is_simulated=simulated,
    )


def _threat(tid="THREAT-01", title="BOLA on update", vector="PUT /api/users/{id}", category=STRIDECategory.ELEVATION_OF_PRIVILEGE,
            simulated=False):
    return ThreatItem(
        threat_id=tid, stride_category=category, title=title, description="",
        asset_at_risk="a", attack_vector=vector, trust_boundary_crossed="b", severity=FindingSeverity.CRITICAL,
        attack_scenario="", test_verification_goal="", is_simulated=simulated,
    )


def _hit(path, rule="VH-AI-003", line=10, evidence="pickle.load(...)"):
    return StaticFinding(rule_id=rule, title="t", severity=FindingSeverity.MEDIUM, file_path=path, line_number=line,
                         evidence=evidence)


def _breach(tid="BB-TEST-THREAT-01", ref="THREAT-01"):
    return TestExecutionResult(test_id=tid, test_type="blackbox_security", status=TestStatus.FAILED,
                               is_security_exploit_confirmed=True, source_ref=ref)


# --- 正規化 ／ Normalization ----------------------------------------------------------------------------------

@pytest.mark.parametrize("text, normalized", [
    ("Mass_Assignment, v2!", "mass assignment v2"),
    ("  SQL   Injection!! ", "sql injection"),
    ("資金竊取：負數金額", "資金竊取 負數金額"),
    ("ユーザー認証の欠如", "ユーザー認証の欠如"),
    ("인증 누락", "인증 누락"),
    ("Ünïcödé café", "ünïcödé café"),
    ('token = "abc ／ def"', "token abc def"),
    (None, ""), ("", ""), ("___", ""),
])
def test_normalize_keeps_letters_and_digits_of_any_script_lowercased(text, normalized):
    assert identity.normalize(text) == normalized


@pytest.mark.parametrize("a, b", [
    ("Unchecked null in get_user", "unchecked NULL in get_user!"),
    ("SQL injection", "  sql   INJECTION.  "),
    ("資金竊取：負數金額", "資金竊取 負數金額！"),
])
def test_cosmetic_rewording_gives_the_same_key_text(a, b):
    assert identity.normalize(a) == identity.normalize(b)


@pytest.mark.parametrize("a, b", [
    ("大量指派管理員欄位", "跨租戶資料竄改"),
    ("ユーザー認証の欠如", "ユーザー認可の欠如"),
    ("인증 누락", "인가 누락"),
    ("SQL injection", "SQL injection 2"),
])
def test_different_text_in_any_script_gives_different_key_text(a, b):
    assert identity.normalize(a) != identity.normalize(b)


@pytest.mark.parametrize("text, simulated, expected", [
    (bi("越權", "IDOR"), True, "IDOR"),          # 模擬項目只取英文半 ／ a simulated item keeps its English half
    (bi("越權", "IDOR"), False, bi("越權", "IDOR")),  # 真實文字原樣使用 ／ real text is used as is
    ("plain ／ text", True, "plain ／ text"),      # 不是 bi() 字串：不切 ／ not a bi() string: not split
    (None, True, ""),
])
def test_key_text_takes_only_the_english_half_of_simulated_text(text, simulated, expected):
    assert identity.key_text(text, simulated) == expected


# --- 位置與嚴重度 ／ Location and severity -----------------------------------------------------------------------

_UNKNOWN_PATHS = [None, "", "   ", "unknown", " unknown "]


@pytest.mark.parametrize("path", _UNKNOWN_PATHS)
def test_every_unknown_spelling_is_an_unknown_location(path):
    from vibeharness.core.identity import is_unknown_location
    from vibeharness.reports.report_generator import ReportGenerator
    assert is_unknown_location(path)
    assert identity.target_relative(path, "/tmp/target") == ""  # 基準線鍵沒有路徑 ／ the baseline key has no path
    assert ReportGenerator._sarif_uri(path or "", "/tmp/target") is None  # SARIF 沒有位置 ／ SARIF has no location
    assert not is_unknown_location("app.py") and not is_unknown_location("unknown.py")


@pytest.mark.parametrize("path", [None, "", "unknown", "  unknown "])
def test_rel_placeholder(path):
    assert identity.target_relative(path, "/t") == ""


def test_rel_file_target(tmp_path):
    # 目標是單一檔案（即使尚不存在）時，以它所在的目錄為基準
    # A single-file target (even one that does not exist yet) is related to its directory
    target = os.path.join(str(tmp_path), "app.py")
    assert identity.target_relative(os.path.join(str(tmp_path), "pkg", "m.py"), target) == "pkg/m.py"


def test_rel_outside_and_other_drive(monkeypatch):
    assert identity.target_relative("/elsewhere/m.py", "/t") == "m.py"

    def boom(*a, **k):
        raise ValueError("path is on mount 'D:', start on mount 'C:'")
    # relpath 在不同磁碟機時拋出 ValueError：退回純檔名
    # relpath raises ValueError across drives: fall back to the bare name
    monkeypatch.setattr(identity.os.path, "relpath", boom)
    assert identity.target_relative("/t/sub/m.py", "/t") == "m.py"


def test_old_baseline_of_a_dotted_directory_from_another_machine_keys_the_same(tmp_path):
    here = tmp_path / "app.v2"
    (here / "src").mkdir(parents=True)
    other = "/nonexistent-ci/work/app.v2"
    sf = dict(rule_id="VH-AI-001", title="t", severity="HIGH", line_number=3, evidence="pickle.load(x)",
              remediation="")
    old = StaticFinding(**sf, file_path=f"{other}/src/x.py")
    now = StaticFinding(**sf, file_path=str(here / "src" / "x.py"))
    assert identity.target_relative(old.file_path, other) == "src/x.py"
    assert identity.static_key(old, other) == identity.static_key(now, str(here))
    # 檔案目標（不論是否存在）仍以檔名為鍵 ／ a file target (existing or not) still keys by its name
    assert identity.target_relative("/nonexistent-ci/work/app.py", "/nonexistent-ci/work/app.py") == "app.py"
    script = here / "run"
    script.write_text("print(1)\n", encoding="utf-8")
    assert identity.target_relative(str(script), str(script)) == "run"


def test_severity_rank_orders_by_severity_and_puts_an_unknown_one_last():
    order = [FindingSeverity.INFO, FindingSeverity.CRITICAL, FindingSeverity.LOW, FindingSeverity.HIGH, FindingSeverity.MEDIUM]
    assert sorted(order, key=identity.severity_rank) == [
        FindingSeverity.CRITICAL, FindingSeverity.HIGH, FindingSeverity.MEDIUM, FindingSeverity.LOW, FindingSeverity.INFO]
    assert identity.severity_rank("BOGUS") > identity.severity_rank(FindingSeverity.INFO)  # type: ignore[arg-type]


# --- 鍵的性質 ／ Key properties -------------------------------------------------------------------------------

def test_finding_key_ignores_run_numbering_and_cosmetic_rewording():
    a = identity.finding_key(_finding("WB-CLA-01", "Unchecked null in get_user"), EXAMPLES)
    b = identity.finding_key(_finding("WB-DEE-07", "unchecked NULL in get_user!"), EXAMPLES)
    c = identity.finding_key(_finding("WB-CLA-01", "SQL injection in get_user"), EXAMPLES)
    assert a == b != c
    # 同一個檔案透過另一個簽出路徑來看：鍵值相對於目標
    # Same file seen through another checkout path: the key is relative to the target
    d = identity.finding_key(_finding(path="/elsewhere/examples/vibe_sample_app.py"), "/elsewhere/examples")
    assert d == a


def test_static_key_ignores_line_drift_but_not_the_rule_or_evidence():
    def hit(line, rule="VH-AI-003", evidence="pickle.load(...)"):
        return StaticFinding(rule_id=rule, title="t", severity=FindingSeverity.MEDIUM,
                             file_path=os.path.join(EXAMPLES, "m.py"), line_number=line, evidence=evidence)
    assert identity.static_key(hit(10), EXAMPLES) == identity.static_key(hit(42), EXAMPLES)
    assert identity.static_key(hit(10), EXAMPLES) != identity.static_key(hit(10, rule="VH-AI-002"), EXAMPLES)
    assert identity.static_key(hit(10), EXAMPLES) != identity.static_key(hit(10, evidence="dill.load(...)"), EXAMPLES)


def test_breach_key_comes_from_the_threat_not_the_test_id():
    r1 = TestExecutionResult(test_id="BB-TEST-THREAT-01", test_type="blackbox_security", status=TestStatus.FAILED,
                             is_security_exploit_confirmed=True, source_ref="THREAT-01")
    r2 = TestExecutionResult(test_id="BB-TEST-THREAT-09", test_type="blackbox_security", status=TestStatus.FAILED,
                             is_security_exploit_confirmed=True, source_ref="THREAT-09")
    assert identity.breach_key(r1, _threat("THREAT-01")) == identity.breach_key(r2, _threat("THREAT-09", "bola ON update"))
    assert identity.breach_key(r1, _threat()) != identity.breach_key(r1, _threat(vector="DELETE /api/users/{id}"))
    assert identity.breach_key(r1, None) != identity.breach_key(r2, None)


def test_probe_failures_are_keyed_by_symbol():
    probe = TestExecutionResult(test_id="WB-PROBE-03", test_type="whitebox_probe", status=TestStatus.FAILED, source_ref="transfer")
    assert identity.whitebox_failure_key(probe, None, EXAMPLES) == identity.probe_key(probe)
    unresolved = TestExecutionResult(test_id="WB-TEST-01", test_type="whitebox_unit", status=TestStatus.FAILED, source_ref="WB-GONE-01")
    assert identity.whitebox_failure_key(unresolved, None, EXAMPLES) is None  # 無法比對：一律視為新的 ／ cannot be matched: always new


def test_keys_distinguish_cjk_titles_and_ignore_the_chinese_half_of_bilingual_text():
    """中文標題各自不同（不會塌成空字串而共用一個鍵）；`bi()` 字串只取英文半，所以 0.3.0 的鍵不變。
    CJK titles stay distinct (they no longer collapse to "" and share one key); a `bi()` string is keyed by its
    English half, so keys from 0.3.0 are unchanged."""
    from vibeharness.core.i18n import bi
    t1 = _threat().model_copy(update={"title": "大量指派管理員欄位"})
    t2 = _threat().model_copy(update={"title": "跨租戶資料竄改"})
    breach = TestExecutionResult(test_id="BB-TEST-THREAT-01", test_type="blackbox_security", status=TestStatus.FAILED,
                                 is_security_exploit_confirmed=True, source_ref="THREAT-01")
    assert identity.breach_key(breach, t1) != identity.breach_key(breach, t2)
    assert identity.normalize("大量指派管理員欄位") != "" and identity.normalize("Mass_Assignment, v2!") == "mass assignment v2"
    plain = _threat().model_copy(update={"title": "Mass assignment of admin fields"})
    simulated = _threat().model_copy(update={"title": bi("大量指派管理員欄位", "Mass assignment of admin fields"), "is_simulated": True})
    assert identity.breach_key(breach, plain) == identity.breach_key(breach, simulated)
    # 真實模型的文字原樣進鍵，即使含有全形斜線：0.3.0 的鍵不受 bi() 的分隔符影響
    # Real model text keys as is, even with a full-width slash: 0.3.0 keys are untouched by the bi() separator
    real = _threat().model_copy(update={"title": bi("大量指派管理員欄位", "Mass assignment of admin fields")})
    assert identity.breach_key(breach, real) != identity.breach_key(breach, plain)
    assert identity.normalize('token = "abc ／ def"') == "token abc def"


def test_sarif_fingerprints_use_the_same_helpers_as_the_baseline():
    """SARIF 的 partialFingerprints 與基準線鍵都定義在 core/identity.py、共用同一套 normalize／fingerprint，不會各自漂移。
    SARIF partialFingerprints and baseline keys are both defined in core/identity.py and share one normalize /
    fingerprint pair, so they cannot drift apart."""
    from vibeharness.core import baseline as bl
    from vibeharness.reports import report_generator as rg
    assert rg.sarif_finding_fingerprint is identity.sarif_finding_fingerprint
    assert rg.sarif_static_fingerprint is identity.sarif_static_fingerprint
    assert rg.sarif_breach_fingerprint is identity.sarif_breach_fingerprint
    # baseline 以舊名稱重新匯出同一批物件 ／ baseline re-exports the very same objects under the old names
    for name in ("normalize", "key_text", "fingerprint", "target_relative", "finding_key", "static_key", "probe_key",
                 "whitebox_failure_key", "breach_key"):
        assert getattr(bl, name) is getattr(identity, name), name
    assert not hasattr(rg.ReportGenerator, "_normalize") and not hasattr(rg.ReportGenerator, "_fingerprint")


def test_the_finding_key_and_its_sarif_fingerprint_change_with_the_symbol_and_location_only():
    base = _finding()
    same = _finding(fid="WB-GLM-04", title="UNCHECKED null in get_user.", line=99)
    other_symbol = _finding(symbol="transfer")
    other_file = _finding(path=os.path.join(EXAMPLES, "other.py"))
    uri = "examples/vibe_sample_app.py"
    assert identity.finding_key(base, EXAMPLES) == identity.finding_key(same, EXAMPLES)
    assert identity.sarif_finding_fingerprint(base, uri) == identity.sarif_finding_fingerprint(same, uri)
    for other in (other_symbol, other_file):
        assert identity.finding_key(other, EXAMPLES) != identity.finding_key(base, EXAMPLES)
    assert identity.sarif_finding_fingerprint(other_symbol, uri) != identity.sarif_finding_fingerprint(base, uri)
    assert identity.sarif_finding_fingerprint(base, "examples/other.py") != identity.sarif_finding_fingerprint(base, uri)
    # 模擬的雙語標題與同一英文標題的真實發現共用鍵 ／ a simulated bilingual title shares the key of the plain English one
    simulated = _finding(title=bi("未檢查的 null", "Unchecked null in get_user"), simulated=True)
    assert identity.finding_key(simulated, EXAMPLES) == identity.finding_key(base, EXAMPLES)


def test_the_static_key_ignores_the_line_but_the_sarif_fingerprint_keeps_it():
    path = os.path.join(EXAMPLES, "m.py")
    uri = "examples/m.py"
    assert identity.static_key(_hit(path, line=10), EXAMPLES) == identity.static_key(_hit(path, line=42), EXAMPLES)
    assert identity.sarif_static_fingerprint(_hit(path, line=10), uri) != identity.sarif_static_fingerprint(_hit(path, line=42), uri)
    # SARIF 指紋不含證據；基準線鍵含 ／ the SARIF fingerprint has no evidence part; the baseline key does
    assert identity.sarif_static_fingerprint(_hit(path, evidence="a"), uri) == identity.sarif_static_fingerprint(_hit(path, evidence="b"), uri)


@pytest.mark.parametrize("threat", [
    _threat(),
    _threat(title="資金竊取：負數金額", vector="process_payment_transfer", category=STRIDECategory.TAMPERING),
    _threat(title=bi("偽造權杖", "Forged session token"), vector="POST /login", category=STRIDECategory.SPOOFING, simulated=True),
])
def test_breach_key_and_the_sarif_breach_fingerprint_are_two_renderings_of_threat_identity(threat):
    breach = _breach()
    assert identity.breach_key(breach, threat) == identity.fingerprint("breach", *identity.threat_identity(threat))
    assert identity.sarif_breach_fingerprint(breach, threat) == identity.fingerprint(*identity.threat_identity(threat))
    # 沒有可解析的威脅時，兩者都只能用測試 id ／ without a resolvable threat both fall back to the test id
    assert identity.breach_key(breach, None) == identity.fingerprint("breach", breach.test_id, breach.source_ref)
    assert identity.sarif_breach_fingerprint(breach, None) == identity.fingerprint(breach.test_id, breach.source_ref)


# --- golden 表：已寫進使用者報告與 Code Scanning 的雜湊 -------------------------------------------------------
# --- Golden table: hashes already stored in users' reports and in Code Scanning ---------------------------------
# 這些值取自 master（0.12.0 之後）的實際輸出。基準線的 `fingerprint` 欄位與 SARIF 的 partialFingerprints 已存在使用者的
# 報告與 GitHub Code Scanning 的警示裡：任何一個值改變，既有基準中的已知問題就會變成「新的」，警示也會全部關閉後重開。
# 真的要改時，請刻意更新這張表並寫 CHANGELOG 條目。路徑都在 ROOT 之下（POSIX 形式），所以各作業系統算出的值相同。
# These values come from master's actual output (after 0.12.0). The baseline `fingerprint` fields and SARIF
# partialFingerprints are already stored in users' reports and GitHub Code Scanning alerts: change one value and every
# known problem in an existing baseline becomes "new" and every alert is closed and reopened. If a change is really
# intended, update this table deliberately and write a CHANGELOG entry. All paths are under ROOT (POSIX form), so every
# OS computes the same values.

ROOT = "/srv/app"

# （ROOT 下的路徑, 符號, 標題, 是否模擬, finding_key, SARIF uri, sarif_finding_fingerprint）
# (path under ROOT, symbol, title, simulated, finding_key, SARIF uri, sarif_finding_fingerprint)
FINDING_GOLDEN = [
    ('src/app.py', 'get_user', 'Unchecked null in get_user', False, 'ae624a91795a7eb588bf8478811ad51ac7ea82a8', 'app/src/app.py', '50abbefcb3f828aab8130b76f6c9125a0c8d3997'),
    ('src/app.py', 'get_user', '未檢查的 None：get_user', False, '9e09ebc8a9e5b9863d41b058844a112814c16b5c', 'app/src/app.py', '850403dd89409f2a35c2d8fd41f770edf8d28a72'),
    ('src/app.py', None, 'SQL injection via search term', False, '7375a00180d8bbec8f1517ac270aeb003deca36c', 'app/src/app.py', '06f436771fd6b46c719d81251b882007e324d80a'),
    ('lib/util.py', 'parse', '大量指派 ／ Mass assignment of admin fields', True, '892b84af268dac7ecd75c96235c0000b28ecd1fa', None, None),
    ('unknown', 'f', 'Unattributed defect', False, 'bfd547b619fddac3ab2a6fa11b336cd3fefe0d68', None, '840d54d7b5d10cead02a383a3fda5aea35f7753d'),
]
# （ROOT 下的路徑, 規則, 行號, 證據, static_key, SARIF uri, sarif_static_fingerprint）
# (path under ROOT, rule, line, evidence, static_key, SARIF uri, sarif_static_fingerprint)
STATIC_GOLDEN = [
    ('src/app.py', 'VH-AI-003', 10, 'pickle.load(...)', 'b12919e903ce4a23c610257cd1bf7890c3556dac', 'app/src/app.py', '62dd3520aec4c94a3a40cbe2dfb21b1f8cbfcdda'),
    ('src/app.py', 'VH-AI-001', 42, 'eval(answer)', '9581d37f1473fd2f065319eb4d180f1b7d35671c', 'app/src/app.py', 'ddd0ebd637507ac9484f8d63b2b62a6c21b7a963'),
    ('lib/設定.py', 'VH-AI-007', 3, 'API_KEY = "sk-…"', '01ae8846d8fe0ab0236a981572d649799767f2f1', 'app/lib/設定.py', '89c66aebbd39a3802019b438398643b98623fcc9'),
]
# （STRIDE 名稱, 標題, 攻擊向量, 是否模擬, breach_key, sarif_breach_fingerprint；模擬的威脅不進 SARIF 時為 None）
# (STRIDE name, title, vector, simulated, breach_key, sarif_breach_fingerprint; None for a simulated threat, which is not in SARIF)
THREAT_GOLDEN = [
    ('ELEVATION_OF_PRIVILEGE', 'BOLA on update', 'PUT /api/users/{id}', False, 'b845104c6bcc4b969b433d95a68bfd4e38e9ff74', 'b90786c34e8db836c35d57c33a649c7917816df4'),
    ('TAMPERING', '資金竊取：負數金額', 'process_payment_transfer', False, '61fe69d62c12412ebae36c29b8aeb36441fd6f35', 'cea470d76c87e1ae083e0f68d7fe902fdf4dc6b4'),
    ('SPOOFING', '偽造權杖 ／ Forged session token', 'POST /login', True, 'cc998fd79eb59576e11bda47629a4418742942e1', None),
]
ORPHAN_BREACH_GOLDEN = ('a8a585d2a81b6de3d972d15c056bf68e6e2072f4', 'ba500f096c18d0ce548eec8318372bc3ba20c0d5')
PROBE_GOLDEN = [
    ('src/app.py::process', '35c5bf8560ed83223558ff40eb112c2a01aac1c2'),
    ('transfer', 'a62069ecd50b1689bd642bf675ec818b23bdfd40'),
]


def _under_root(path):
    return path if path == "unknown" else f"{ROOT}/{path}"


@pytest.mark.parametrize("path, symbol, title, simulated, key, uri, sarif", FINDING_GOLDEN)
def test_finding_hashes_are_pinned(path, symbol, title, simulated, key, uri, sarif):
    f = _finding(path=_under_root(path), symbol=symbol, title=title, simulated=simulated)
    assert identity.finding_key(f, ROOT) == key
    if sarif is not None:  # 模擬的項目不進 SARIF ／ simulated items are not in SARIF
        assert identity.sarif_finding_fingerprint(f, uri) == sarif


@pytest.mark.parametrize("path, rule, line, evidence, key, uri, sarif", STATIC_GOLDEN)
def test_static_hashes_are_pinned(path, rule, line, evidence, key, uri, sarif):
    hit = _hit(_under_root(path), rule=rule, line=line, evidence=evidence)
    assert identity.static_key(hit, ROOT) == key
    assert identity.sarif_static_fingerprint(hit, uri) == sarif


@pytest.mark.parametrize("category, title, vector, simulated, key, sarif", THREAT_GOLDEN)
def test_breach_hashes_are_pinned(category, title, vector, simulated, key, sarif):
    threat = _threat(tid="T0", title=title, vector=vector, category=STRIDECategory[category], simulated=simulated)
    breach = _breach("BB-TEST-T0", "T0")
    assert identity.breach_key(breach, threat) == key
    if sarif is not None:
        assert identity.sarif_breach_fingerprint(breach, threat) == sarif


def test_breach_and_probe_hashes_without_a_threat_are_pinned():
    orphan = _breach("BB-TEST-ORPHAN", "GONE")
    assert (identity.breach_key(orphan, None), identity.sarif_breach_fingerprint(orphan, None)) == ORPHAN_BREACH_GOLDEN
    for ref, key in PROBE_GOLDEN:
        probe = TestExecutionResult(test_id="WB-PROBE-01", test_type="whitebox_probe", status=TestStatus.FAILED, source_ref=ref)
        assert identity.probe_key(probe) == key
