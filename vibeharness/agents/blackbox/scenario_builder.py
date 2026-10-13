import functools
import logging
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import List, Optional, Tuple
import os
from vibeharness.core.models import ThreatItem, GeneratedTest, CodeSymbol, text_or
from vibeharness.core.fanout import Call, fan_out
from vibeharness.core.model_output import ANY, OutputSchema
from vibeharness.core.llm_gateway import LLMGateway
from vibeharness.core.codecheck import check_test_code_for, strip_code_fences
from vibeharness.core.i18n import bi, en_only
from vibeharness.core.codecontext import render_symbols, import_instructions, language_for_file
from vibeharness.core.sanitize import (
    UNTRUSTED_CODE_POLICY, UNTRUSTED_MODEL_POLICY, untrusted_block, untrusted_model_block,
)

logger = logging.getLogger("VibeHarness.ScenarioBuilder")

# 攻擊合成回答的形狀（core/model_output.py）
# The shape of an attack-synthesis answer (core/model_output.py)
CODE_SCHEMA = OutputSchema(required={"code": ANY})

# 每個威脅所顯示目標程式碼的估計 token 預算
# Estimated-token budget for the target code shown per threat
CODE_CONTEXT_TOKENS = 4000


def validate_base_url(base_url: str) -> str:
    """即時目標的基底 URL，或是一個指出它哪裡有問題的 ValueError。

    urllib 也會開啟 ``file:``、``ftp:`` 與 ``data:`` URL，所以未經檢查的 ``--base-url
    file:///etc/hostname`` 曾經被當成即時伺服器，把每個攻擊腳本切換成 Live HTTP 模式。
    只接受具有可供攻擊瞄準之主機名稱的 http(s) URL。
    The base URL of a live target, or a ValueError naming what is wrong with it.

    urllib opens ``file:``, ``ftp:`` and ``data:`` URLs too, so an unchecked ``--base-url
    file:///etc/hostname`` once counted as a live server and switched every attack script into
    Live HTTP mode. Only http(s) URLs with a host name an attack can be aimed at are accepted.
    """
    try:
        parts = urllib.parse.urlsplit(base_url.strip())
        host = parts.hostname
    except ValueError as e:
        raise ValueError(f"base URL {base_url!r} is not a valid URL: {e}") from e
    if parts.scheme not in ("http", "https") or not host:
        raise ValueError(f"base URL {base_url!r} must be an http:// or https:// URL with a host name")
    return base_url.strip()


class ThreatScenarioBuilder:
    """
    直接從威脅建模矩陣（STRIDE 與 OWASP 的發現）合成可執行的黑箱安全測試套件。
    支援雙模式：即時伺服器 HTTP 滲透或行程內契約驗證。
    Synthesizes executable black-box security test suites directly derived from
    the Threat Modeling matrix (STRIDE & OWASP findings).
    Supports Dual-Mode: Live Server HTTP penetration or In-Process Contract verification.
    """

    def __init__(self, gateway: LLMGateway):
        self.gateway = gateway

    # 仍在啟動中的伺服器不能被誤認為已死的伺服器：先探測幾次，
    # 再退回行程內模式，因為那會改變每個測試的策略。
    # A server that is still booting must not be mistaken for a dead one: probe a few times
    # before falling back to in-process mode, which would change every test's strategy.
    PROBE_ATTEMPTS = 3
    PROBE_RETRY_DELAY_SEC = 0.5

    def check_server_live(self, base_url: str, timeout_sec: float = 1.0) -> bool:
        """探測目標 HTTP 伺服器是否可連線（對啟動緩慢的情況做短暫重試）。
        Probes whether the target HTTP server is reachable (with short retries for slow starts)."""
        for attempt in range(self.PROBE_ATTEMPTS):
            try:
                req = urllib.request.Request(base_url, headers={"User-Agent": "VibeHarness-HealthCheck"})
                with urllib.request.urlopen(req, timeout=timeout_sec):
                    return True
            except urllib.error.HTTPError:
                return True  # 任何 HTTP 狀態（'/' 的 404、500 等）都代表伺服器有回應 ／ Any HTTP status (404 on '/', 500, ...) means the server answered
            except Exception:
                if attempt < self.PROBE_ATTEMPTS - 1:
                    time.sleep(self.PROBE_RETRY_DELAY_SEC)
        return False

    @staticmethod
    def _code_context(threat: ThreatItem, symbols: Optional[List[CodeSymbol]], root_dir: Optional[str]) -> Tuple[str, str]:
        """（威脅攻擊向量所指名符號的匯入路徑與原始碼，否則為所有進入點；
        第一個相關符號所在檔案的語言：混合語言的目標以該檔案為準）。
        (import paths and source for the symbols the threat's attack vector names, else all entry points;
        the language of the first relevant symbol's file: a mixed target follows that file)."""
        if not symbols:
            return "", "python"
        root = root_dir or os.path.dirname(os.path.abspath(symbols[0].file_path))
        text = f"{threat.attack_vector} {threat.attack_scenario}"
        relevant = ThreatScenarioBuilder._named_symbols(symbols, text)
        if not relevant:
            relevant = sorted(symbols, key=lambda s: s.symbol_type != "route")
        language = language_for_file(relevant[0].file_path)
        files = sorted({s.file_path for s in relevant if language_for_file(s.file_path) == language})
        imports = "\n".join(import_instructions(f, root) for f in files)
        listing = render_symbols(relevant, root, max_tokens=CODE_CONTEXT_TOKENS)
        return f"How to import the target:\n{imports}\n\nRelevant target code:\n{untrusted_block(listing)}\n\n", language

    @staticmethod
    def _symbol_keys(sym: CodeSymbol) -> List[str]:
        """威脅文字中可以指名這個符號的寫法：完整名稱，方法再加上最後一段；
        "GET /api/x" 這種路由再加上路徑本身（路徑裡的 "." 不是方法分隔符）。
        The spellings by which threat text can name the symbol: the full name, plus the last part for a
        method; a "GET /api/x" route also by its bare path (a "." in a path is no method separator)."""
        name = sym.name.strip()
        if " " in name or name.startswith("/"):
            path = name.split(" ", 1)[-1].strip()
            return [k for k in dict.fromkeys([name, path]) if k]
        return [k for k in dict.fromkeys([name, name.split(".")[-1]]) if k]

    @staticmethod
    def _key_pattern(key: str) -> str:
        """比對一個符號鍵的正規表達式：識別字邊界把 `_` 與 JS 的 `$` 都算成識別字字元。

        只由符號組成的路由路徑（根路由 `/`、萬用路由 `*`）在一般文字中到處都是（"and/or"、"read/write"、
        "1 * 10^6"），所以單獨的路徑只在被引號或反引號包住時才算（`'/'`、`` `*` ``）；完整的 "GET /" 形式
        後面不可緊接路徑字元，因此 "GET /admin" 或 "GET /.env" 不會指名根路由。
        The regex matching one symbol key: identifier boundaries count both `_` and the JS `$` as identifier characters.

        Route paths made only of symbols (the root route `/`, the wildcard `*`) occur all over ordinary text
        ("and/or", "read/write", "1 * 10^6"), so such a bare path only counts inside quotes or backticks (`'/'`,
        `` `*` ``); the full "GET /" form must not be followed by a path character, so "GET /admin" or "GET /.env"
        does not name the root route."""
        path = key.split(" ", 1)[-1]
        symbolic = not re.search(r"[\w$]", path)
        if symbolic and " " not in key:
            return r"(?<=['\"`])" + re.escape(key) + r"(?=['\"`])"
        head = r"(?<![\w$])" if re.match(r"[\w$]", key) else ""
        if symbolic:
            tail = r"(?![\w$/*]|\.[\w$])"
        else:
            tail = r"(?![\w$])" if re.search(r"[\w$]$", key) else ""
        return head + re.escape(key) + tail

    @staticmethod
    def _named_symbols(symbols: List[CodeSymbol], text: str) -> List[CodeSymbol]:
        """威脅文字以完整識別字（或完整路由）指名的符號。

        整字比對：子字串測試會把每個提到 "user" 的威脅都綁到 get_user() 符號，把真正相關的程式碼
        藏在它後面；識別字邊界把 `_` 與 JS 的 `$` 都算成識別字字元。偏好最長的比對：只出現在另一個
        符號比對範圍內的符號會被丟掉，所以 "/api/users/:id" 不會連帶拉進 "/api/users"，
        "Service.get_user" 也不會拉進同名函式。
        Symbols the threat text names by a whole identifier (or a whole route).

        Whole-word matching: a substring test would tie every threat mentioning "user" to a get_user()
        symbol and hide the actually relevant code behind it; identifier boundaries count both `_` and the
        JS `$` as identifier characters. The longest match wins: a symbol matched only inside another
        symbol's match is dropped, so "/api/users/:id" does not drag in "/api/users" and "Service.get_user"
        does not drag in a same-named function.
        """
        spans: List[Tuple[CodeSymbol, List[Tuple[int, int]]]] = []
        for sym in symbols:
            found: List[Tuple[int, int]] = []
            for key in ThreatScenarioBuilder._symbol_keys(sym):
                found.extend(m.span() for m in re.finditer(ThreatScenarioBuilder._key_pattern(key), text))
            if found:
                spans.append((sym, found))
        all_spans = [span for _sym, found in spans for span in found]

        def inside_longer(span: Tuple[int, int]) -> bool:
            return any(o[0] <= span[0] and span[1] <= o[1] and o != span for o in all_spans)

        return [sym for sym, found in spans if not all(inside_longer(span) for span in found)]

    # 迴環名稱都是同一台機器；目標本身在本機時允許瞄準它們
    # Loopback names are the same machine; targeting them is allowed when the target itself is local
    _LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "0.0.0.0", "::1"}

    @staticmethod
    def _hosts_outside_base_url(code: str, base_url: str) -> List[str]:
        """產生的攻擊程式碼中，主機不是宣告目標的 URL 字面值。

        提示詞要求模型只攻擊基底 URL；這個靜態檢查是那條指示背後盡力而為的
        安全網（動態組出的 URL 抓不到）。主機以 urlsplit 擷取，所以 IPv6 字面值
        （'http://[::1]:8080'）會解析成 '::1'，而不是天真去括號的產物 '['；
        完全無法解析的字面值（例如被截斷的 IPv6 位址）無法被排除，所以會被
        標記 —— 安全網是失效關閉的。
        URL literals in generated attack code whose host is not the declared target.

        The prompt tells the model to attack only the base URL; this static check is the
        best-effort net behind that instruction (dynamically built URLs are not caught).
        Hosts are extracted with urlsplit so IPv6 literals ('http://[::1]:8080') resolve
        to '::1' instead of the naive bracket-stripping artifact '['; a literal that
        cannot be parsed at all (e.g. a cut-off IPv6 address) cannot be cleared, so it is
        flagged — the net fails closed.
        """
        base = urllib.parse.urlsplit(base_url)
        base_host = (base.hostname or "").lower()
        try:
            base_port: Optional[int] = ThreatScenarioBuilder._effective_port(base)
        except ValueError:
            base_port = None
        offenders: List[str] = []
        for match in re.finditer(r"https?://[^/'\"\s<>())\\]+", code, re.IGNORECASE):
            try:
                parts = urllib.parse.urlsplit(match.group(0))
                host = (parts.hostname or "").lower()
                port = ThreatScenarioBuilder._effective_port(parts) if host else None
            except ValueError:
                if match.group(0) not in offenders:
                    offenders.append(match.group(0))
                continue
            if not host:
                continue
            same_machine = host == base_host or (
                base_host in ThreatScenarioBuilder._LOOPBACK_HOSTS and host in ThreatScenarioBuilder._LOOPBACK_HOSTS)
            # 同一台機器上的其他連接埠是其他服務（redis 的 6379、ssh 的 22）：連接埠也必須相同
            # Another port on the same machine is another service (redis on 6379, ssh on 22): the port must match too
            if same_machine and port == base_port:
                continue
            if match.group(0) not in offenders:
                offenders.append(match.group(0))
        return offenders

    @staticmethod
    def _effective_port(parts: "urllib.parse.SplitResult") -> int:
        """URL 的連接埠，沒寫時用協定預設值（http 80、https 443）；無效的連接埠拋出 ValueError。
        The URL's port, or the scheme default when omitted (http 80, https 443); an invalid port raises ValueError."""
        port = parts.port
        if port is not None:
            return port
        return 443 if parts.scheme.lower() == "https" else 80

    def build_test_cases_from_threats(
        self,
        threats: List[ThreatItem],
        base_url: Optional[str] = None,
        symbols: Optional[List[CodeSymbol]] = None,
        root_dir: Optional[str] = None
    ) -> List[GeneratedTest]:
        if not threats:
            return []

        # 即時 HTTP 攻擊只對使用者明確指名的 URL 執行：探測預設值
        # （例如 localhost:8000）會把攻擊腳本瞄準那裡剛好在聽的任何不相干服務。
        # CLI 已經驗證過 URL；這個守衛讓函式庫呼叫者無法探測 file:// 等。
        # Live HTTP attacks only run against a URL the user named explicitly: probing a default
        # (e.g. localhost:8000) would aim attack scripts at whatever unrelated service listens there.
        # The CLI validates the URL already; this guard keeps library callers from probing file:// etc.
        if base_url:
            base_url = validate_base_url(base_url)
        server_is_live = self.check_server_live(base_url) if base_url else False
        mode_label = "Live HTTP" if server_is_live else "In-Process Contract"
        logger.info(bi(f"以 [{mode_label}] 模式合成威脅測試案例，目標：{base_url or '匯入的目標'}",
                       f"Synthesizing threat test cases in [{mode_label}] mode against: {base_url or 'the imported target'}"))
        if server_is_live:
            mode_rules = (
                f"Send real HTTP requests to {base_url} using only the standard library (urllib.request) "
                "or `requests`. Never target any other host.\n"
            )
        else:
            mode_rules = (
                "No server is running: import the target module in-process exactly as instructed below and call "
                "its functions/handlers directly with attacker-controlled arguments. Do not start servers or use the network.\n"
            )

        # 威脅彼此獨立：並行合成它們的攻擊測試，維持威脅順序；嚴格的 live 模式（LLMGatewayError）
        # 與 KeyboardInterrupt 會在取消尚未開始的合成之後大聲地失敗
        # Threats are independent: synthesize their attack tests concurrently, keeping threat order; strict
        # live mode (LLMGatewayError) and KeyboardInterrupt fail loudly after the syntheses not yet started are cancelled
        # 當掉的合成讓該威脅回報為未測試（fan_out 記成證據缺口），而不是中止其他的合成
        # A crashed synthesis reports that threat as untested (fan_out books it as an evidence gap) rather than
        # aborting the other syntheses
        calls: List[Call[Optional[GeneratedTest]]] = [
            Call("blackbox_test_synthesizer",
                 (f"[{threat.threat_id}] 的攻擊合成", f"Attack synthesis for [{threat.threat_id}]"),
                 functools.partial(self._test_for_threat, threat, base_url, server_is_live, mode_label, mode_rules,
                                   symbols, root_dir))
            for threat in threats
        ]
        return [test for test in fan_out(self.gateway, calls, fallback=None, logger=logger) if test is not None]

    def _test_for_threat(
        self,
        threat: ThreatItem,
        base_url: Optional[str],
        server_is_live: bool,
        mode_label: str,
        mode_rules: str,
        symbols: Optional[List[CodeSymbol]],
        root_dir: Optional[str]
    ) -> Optional[GeneratedTest]:
        """為一個威脅合成的攻擊測試，若該威脅仍未測試則為 None。
        The attack test synthesized for one threat, or None when the threat stays untested."""
        logger.info(bi(f"正在合成黑箱利用測試：[{threat.threat_id}] {threat.title}",
                       f"Synthesizing black-box exploit test for: [{threat.threat_id}] {threat.title}"))

        context, language = self._code_context(threat, symbols, root_dir)
        if server_is_live:
            language = "python"  # 不論目標語言為何，HTTP 攻擊都以 Python（urllib）撰寫 ／ HTTP attacks are written in Python (urllib) whatever the target language
        if language == "python":
            module_kind = "executable Python pytest module"
            example = ('"from module import handler\\n\\ndef test_security_case():\\n    result = handler(...)\\n'
                       '    assert result[\\"status\\"] == \\"error\\""')
            closing = "Generate the executable Python test function."
        else:
            module_kind = ("executable ES-module test file for Node's built-in `node:test` runner with `node:assert` "
                           "(no jest/mocha/vitest)")
            example = ('"import { test } from \\"node:test\\";\\nimport assert from \\"node:assert/strict\\";\\n'
                       'import { handler } from \\"file:///abs/module.js\\";\\n\\ntest(\\"rejects a foreign id\\", () => {\\n'
                       '  const result = handler({ id: 2 }, { userId: 1 });\\n  assert.equal(result.status, \\"error\\");\\n});"')
            closing = "Generate the executable node:test module."
            if not server_is_live:
                mode_rules = (
                    "No server is running: import the target module in-process through the file:// URL given below "
                    "(ESM `import`, or the default-import / createRequire form for CommonJS) and call its "
                    "functions/handlers directly with attacker-controlled arguments. Do not start servers or use the network.\n"
                )

        system_prompt = (
            "You are an Elite Offensive Security & AppSec Test Automation Engineer.\n"
            f"Execution Mode: {mode_label}.\n"
            f"{mode_rules}"
            "Your task is to translate a specific STRIDE/OWASP threat model item into a concrete, "
            f"{module_kind}.\n\n"
            "The test must assert that defensive boundaries hold (e.g. status code is 401/403/422, "
            "or sensitive fields are uncompromised), so that an assertion failure means the attack succeeded. "
            "If the attack cannot be expressed against the given code, return an empty code string instead of guessing. "
            "Never install packages or contact hosts other than the target.\n\n"
            "Output JSON:\n"
            "{\n"
            f'  "test_id": "BB-TEST-{threat.threat_id}",\n'
            '  "title": "Clear test name",\n'
            '  "rationale": "Why this test proves or disproves the threat",\n'
            '  "expected_outcome": "Defensive condition that must be met",\n'
            f'  "code": {example}\n'
            "}"
            f"{UNTRUSTED_CODE_POLICY}"
            f"{UNTRUSTED_MODEL_POLICY}"
        )

        # 威脅模型的欄位是模型寫的（可能轉述目標程式碼中的注入文字），所以放進 <untrusted_model_output> 通道；
        # 模擬引擎／預設值的雙語欄位只送英文半（提示詞維持英文）；en_only 只切 bi() 產生的字串，
        # 所以真實模型剛好含「 ／ 」的中文描述會完整保留
        # The threat-model fields are model-written (and may relay injected text from the target code), so they go
        # in the <untrusted_model_output> channel; bilingual simulated / default fields send their English half only
        # (prompts stay English), and since en_only only splits bi() output, a live model's Chinese text that
        # happens to contain " ／ " is kept whole
        def field(value: Optional[str]) -> str:
            return en_only(value or "")

        threat_text = (
            f"Title: {field(threat.title)}\n"
            f"OWASP Mapping: {field(threat.owasp_mapping)}\n"
            + (f"MITRE ATLAS Mapping: {field(threat.atlas_mapping)}\n" if threat.atlas_mapping else "")
            + f"Attack Vector: {field(threat.attack_vector)}\n"
            f"Attack Scenario: {field(threat.attack_scenario)}\n"
            f"Defense Verification Goal: {field(threat.test_verification_goal)}"
        )
        user_prompt = (
            f"Target Base URL: {base_url or 'none (in-process only)'}\n"
            f"Server Live Status: {server_is_live}\n"
            f"Threat ID: {threat.threat_id}\n"
            f"STRIDE Category: {threat.stride_category.value}\n"
            f"Threat model item:\n{untrusted_model_block(threat_text)}\n\n"
            f"{context}"
            f"{closing}"
        )

        # 模擬輸出沒有測試：模擬引擎無法撰寫針對目標的測試，這個威脅記為未測試
        # The Simulated output holds no tests: the simulation engine cannot write target-specific tests, so the threat is marked untested
        resp = self.gateway.generate(
            "blackbox_test_synthesizer", system_prompt, user_prompt, json_output=True, schema=CODE_SCHEMA,
            simulated=lambda alias: {"tests": []},
        )

        raw_code = resp.get("code")
        code_str = strip_code_fences(raw_code if isinstance(raw_code, str) else "")
        if not code_str:
            # 不捏造後備：沒有合成出測試的威脅回報為 NOT TESTED
            # No fabricated fallback: a threat without a synthesized test is reported as NOT TESTED
            logger.warning(bi(f"[{threat.threat_id}] 沒有合成出可執行的測試；此威脅仍未測試。",
                              f"No executable test synthesized for [{threat.threat_id}]; threat remains untested."))
            return None
        if server_is_live:
            offenders = self._hosts_outside_base_url(code_str, base_url or "")
            if offenders:
                logger.warning(bi(
                    f"[{threat.threat_id}] 合成的測試指向非目標主機 {', '.join(offenders)}；已拒絕，此威脅仍未測試。",
                    f"Synthesized test for [{threat.threat_id}] targets non-target host(s) "
                    f"{', '.join(offenders)}; rejected and the threat remains untested."
                ))
                return None
        is_valid, problem = check_test_code_for(code_str, language)
        if not is_valid:
            # 保留下來，讓執行器回報為 ERROR，而不是默默丟掉
            # Kept so the executor reports it as ERROR rather than silently dropping it
            logger.warning(bi(f"[{threat.threat_id}] 合成的測試無法執行：{problem}",
                              f"Synthesized test for [{threat.threat_id}] is not executable: {problem}"))

        return GeneratedTest(
            test_id=f"BB-TEST-{threat.threat_id}",
            test_type="blackbox_security",
            target_component=threat.attack_vector,
            title=text_or(resp.get("title"), bi(f"{threat.title} 的安全測試", f"Security test for {threat.title}")),
            code=code_str,
            rationale=text_or(resp.get("rationale"), threat.attack_scenario),
            expected_outcome=text_or(resp.get("expected_outcome"), threat.test_verification_goal),
            source_ref=threat.threat_id,
            language=language,
        )
