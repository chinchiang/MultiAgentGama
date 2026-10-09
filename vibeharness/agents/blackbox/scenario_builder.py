import logging
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from typing import List, Optional, Tuple
import os
from vibeharness.core.models import ThreatItem, GeneratedTest, CodeSymbol, text_or
from vibeharness.core.llm_gateway import LLMGateway, LLMGatewayError
from vibeharness.core.codecheck import check_test_code_for, strip_code_fences
from vibeharness.core.codecontext import render_symbols, import_instructions, language_for_file
from vibeharness.core.sanitize import UNTRUSTED_CODE_POLICY, untrusted_block

logger = logging.getLogger("VibeHarness.ScenarioBuilder")

# Estimated-token budget for the target code shown per threat
CODE_CONTEXT_TOKENS = 4000


def validate_base_url(base_url: str) -> str:
    """The base URL of a live target, or a ValueError naming what is wrong with it.

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
    Synthesizes executable black-box security test suites directly derived from
    the Threat Modeling matrix (STRIDE & OWASP findings).
    Supports Dual-Mode: Live Server HTTP penetration or In-Process Contract verification.
    """

    def __init__(self, gateway: LLMGateway):
        self.gateway = gateway

    # A server that is still booting must not be mistaken for a dead one: probe a few times
    # before falling back to in-process mode, which would change every test's strategy.
    PROBE_ATTEMPTS = 3
    PROBE_RETRY_DELAY_SEC = 0.5

    def check_server_live(self, base_url: str, timeout_sec: float = 1.0) -> bool:
        """Probes whether the target HTTP server is reachable (with short retries for slow starts)."""
        for attempt in range(self.PROBE_ATTEMPTS):
            try:
                req = urllib.request.Request(base_url, headers={"User-Agent": "VibeHarness-HealthCheck"})
                with urllib.request.urlopen(req, timeout=timeout_sec):
                    return True
            except urllib.error.HTTPError:
                return True  # Any HTTP status (404 on '/', 500, ...) means the server answered
            except Exception:
                if attempt < self.PROBE_ATTEMPTS - 1:
                    time.sleep(self.PROBE_RETRY_DELAY_SEC)
        return False

    @staticmethod
    def _code_context(threat: ThreatItem, symbols: Optional[List[CodeSymbol]], root_dir: Optional[str]) -> Tuple[str, str]:
        """(import paths and source for the symbols the threat's attack vector names, else all entry points;
        the language of the first relevant symbol's file: a mixed target follows that file)."""
        if not symbols:
            return "", "python"
        root = root_dir or os.path.dirname(os.path.abspath(symbols[0].file_path))
        text = f"{threat.attack_vector} {threat.attack_scenario}"
        # Whole-word matching: a substring test would tie every threat mentioning "user" to a
        # get_user() symbol and hide the actually relevant code behind it.
        relevant = [
            s for s in symbols
            if re.search(rf"\b{re.escape(s.name.split('.')[-1])}\b", text)
        ]
        if not relevant:
            relevant = sorted(symbols, key=lambda s: s.symbol_type != "route")
        language = language_for_file(relevant[0].file_path)
        files = sorted({s.file_path for s in relevant if language_for_file(s.file_path) == language})
        imports = "\n".join(import_instructions(f, root) for f in files)
        listing = render_symbols(relevant, root, max_tokens=CODE_CONTEXT_TOKENS)
        return f"How to import the target:\n{imports}\n\nRelevant target code:\n{untrusted_block(listing)}\n\n", language

    # Loopback names are the same machine; targeting them is allowed when the target itself is local
    _LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "0.0.0.0", "::1"}

    @staticmethod
    def _hosts_outside_base_url(code: str, base_url: str) -> List[str]:
        """URL literals in generated attack code whose host is not the declared target.

        The prompt tells the model to attack only the base URL; this static check is the
        best-effort net behind that instruction (dynamically built URLs are not caught).
        Hosts are extracted with urlsplit so IPv6 literals ('http://[::1]:8080') resolve
        to '::1' instead of the naive bracket-stripping artifact '['; a literal that
        cannot be parsed at all (e.g. a cut-off IPv6 address) cannot be cleared, so it is
        flagged — the net fails closed.
        """
        base_host = (urllib.parse.urlsplit(base_url).hostname or "").lower()
        offenders: List[str] = []
        for match in re.finditer(r"https?://[^/'\"\s<>())\\]+", code, re.IGNORECASE):
            try:
                host = (urllib.parse.urlsplit(match.group(0)).hostname or "").lower()
            except ValueError:
                if match.group(0) not in offenders:
                    offenders.append(match.group(0))
                continue
            if not host or host == base_host:
                continue
            if base_host in ThreatScenarioBuilder._LOOPBACK_HOSTS and host in ThreatScenarioBuilder._LOOPBACK_HOSTS:
                continue
            if match.group(0) not in offenders:
                offenders.append(match.group(0))
        return offenders

    def build_test_cases_from_threats(
        self,
        threats: List[ThreatItem],
        base_url: Optional[str] = None,
        symbols: Optional[List[CodeSymbol]] = None,
        root_dir: Optional[str] = None
    ) -> List[GeneratedTest]:
        if not threats:
            return []

        # Live HTTP attacks only run against a URL the user named explicitly: probing a default
        # (e.g. localhost:8000) would aim attack scripts at whatever unrelated service listens there.
        # The CLI validates the URL already; this guard keeps library callers from probing file:// etc.
        if base_url:
            base_url = validate_base_url(base_url)
        server_is_live = self.check_server_live(base_url) if base_url else False
        mode_label = "Live HTTP" if server_is_live else "In-Process Contract"
        logger.info(f"Synthesizing threat test cases in [{mode_label}] mode against: {base_url or 'the imported target'}")
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

        # Threats are independent: synthesize their attack tests concurrently, keeping threat order
        with ThreadPoolExecutor(max_workers=min(self.gateway.max_concurrent_calls, len(threats))) as pool:
            futures = [
                pool.submit(self._test_for_threat, threat, base_url, server_is_live, mode_label, mode_rules,
                            symbols, root_dir)
                for threat in threats
            ]
            tests: List[GeneratedTest] = []
            for threat, future in zip(threats, futures, strict=True):
                try:
                    test = future.result()
                except LLMGatewayError:
                    raise  # strict live mode fails loudly
                except Exception as e:
                    # The threat is reported as untested rather than aborting the other syntheses
                    logger.error(f"Attack synthesis for [{threat.threat_id}] failed: {type(e).__name__}: {e}")
                    continue
                if test is not None:
                    tests.append(test)
        return tests

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
        """The attack test synthesized for one threat, or None when the threat stays untested."""
        logger.info(f"Synthesizing black-box exploit test for: [{threat.threat_id}] {threat.title}")

        context, language = self._code_context(threat, symbols, root_dir)
        if server_is_live:
            language = "python"  # HTTP attacks are written in Python (urllib) whatever the target language
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
        )

        user_prompt = (
            f"Target Base URL: {base_url or 'none (in-process only)'}\n"
            f"Server Live Status: {server_is_live}\n"
            f"Threat ID: {threat.threat_id}\n"
            f"STRIDE Category: {threat.stride_category.value}\n"
            f"OWASP Mapping: {threat.owasp_mapping}\n"
            + (f"MITRE ATLAS Mapping: {threat.atlas_mapping}\n" if threat.atlas_mapping else "")
            + f"Attack Vector: {threat.attack_vector}\n"
            f"Attack Scenario: {threat.attack_scenario}\n"
            f"Defense Verification Goal: {threat.test_verification_goal}\n\n"
            f"{context}"
            f"{closing}"
        )

        resp = self.gateway.generate(
            "blackbox_test_synthesizer", system_prompt, user_prompt, json_output=True, required_keys=["code"]
        )

        raw_code = resp.get("code")
        code_str = strip_code_fences(raw_code if isinstance(raw_code, str) else "")
        if not code_str:
            # No fabricated fallback: a threat without a synthesized test is reported as NOT TESTED
            logger.warning(f"No executable test synthesized for [{threat.threat_id}]; threat remains untested.")
            return None
        if server_is_live:
            offenders = self._hosts_outside_base_url(code_str, base_url or "")
            if offenders:
                logger.warning(
                    f"Synthesized test for [{threat.threat_id}] targets non-target host(s) "
                    f"{', '.join(offenders)}; rejected and the threat remains untested."
                )
                return None
        is_valid, problem = check_test_code_for(code_str, language)
        if not is_valid:
            # Kept so the executor reports it as ERROR rather than silently dropping it
            logger.warning(f"Synthesized test for [{threat.threat_id}] is not executable: {problem}")

        return GeneratedTest(
            test_id=f"BB-TEST-{threat.threat_id}",
            test_type="blackbox_security",
            target_component=threat.attack_vector,
            title=text_or(resp.get("title"), f"Security test for {threat.title}"),
            code=code_str,
            rationale=text_or(resp.get("rationale"), threat.attack_scenario),
            expected_outcome=text_or(resp.get("expected_outcome"), threat.test_verification_goal),
            source_ref=threat.threat_id,
            language=language,
        )
