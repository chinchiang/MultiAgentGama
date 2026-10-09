"""對目標原始碼執行確定性的 AI 安全規則（不涉及任何模型）。

模型審查者產生的是假設，而被植入文字的目標可以說服它們放棄（OWASP LLM01:2026）；
這些規則則無法被說服。它們涵蓋 OWASP Top 10 for LLM Applications 2026 與 MITRE ATLAS
針對整合 AI 的應用程式特別點出的程式碼層級模式：不安全的模型成品載入與未固定版本的模型下載
（LLM04 Supply Chain / AML.T0010、AML.T0011.000）、模型輸出流入程式碼執行點
（LLM10 Improper Output Handling / AML.T0050）、沒有上限的模型呼叫
（LLM06 Unbounded Consumption / AML.T0034）、寫死的憑證（LLM02 / AML.T0055），
以及針對審查者的提示詞注入或植入程式碼中的不可見字元（LLM01 / AML.T0051.001、AML.T0068）
—— 後兩者也會破壞本框架自身由模型驅動的階段。
Deterministic AI-security rules over the target's source (no model is involved).

Model reviewers produce hypotheses that an injected target can talk them out of (OWASP LLM01:2026);
these rules cannot be argued with. They cover the code-level patterns the OWASP Top 10 for LLM
Applications 2026 and MITRE ATLAS single out for AI-integrated applications: unsafe model-artifact
loading and unpinned model downloads (LLM04 Supply Chain / AML.T0010, AML.T0011.000), model output
reaching code-execution sinks (LLM10 Improper Output Handling / AML.T0050), uncapped model calls
(LLM06 Unbounded Consumption / AML.T0034), hard-coded credentials (LLM02 / AML.T0055), and
reviewer-directed prompt injection or invisible characters planted in the code (LLM01 /
AML.T0051.001, AML.T0068) - the last two also undermine this harness's own model-driven phases.
"""
import ast
import logging
import os
import re
from typing import Dict, Iterable, List, Optional, Set

from vibeharness.core.models import FindingSeverity, StaticFinding
from vibeharness.core.i18n import bi
from vibeharness.core.sanitize import clean_model_text, find_injection_markers, find_invisible, find_secrets

logger = logging.getLogger("VibeHarness.AIStaticScanner")

# 匯入後即代表目標是整合 AI/LLM 之應用程式的 Python 模組
# Python modules whose import marks the target as an AI/LLM-integrated application
AI_PYTHON_MODULES = {
    "openai", "anthropic", "litellm", "langchain", "langchain_core", "langchain_community", "langchain_openai",
    "langchain_anthropic", "langgraph", "llama_index", "google.generativeai", "google.genai", "vertexai",
    "transformers", "torch", "tensorflow", "keras", "huggingface_hub", "sentence_transformers", "diffusers",
    "mistralai", "cohere", "ollama", "groq", "zhipuai", "zai", "dashscope", "vllm", "onnxruntime", "sklearn",
    "chromadb", "pinecone", "faiss", "qdrant_client", "weaviate", "autogen", "crewai", "semantic_kernel", "mcp",
}
_AI_JS_PACKAGE_RE = re.compile(
    r"""(?:from\s+|require\s*\(\s*|import\s*\(\s*)['"]"""
    r"""(openai|@anthropic-ai/sdk|@google/genai|@google/generative-ai|langchain|@langchain/[\w-]+|ai|@ai-sdk/[\w-]+|"""
    r"""ollama|@huggingface/[\w-]+|@mistralai/mistralai|groq-sdk|@modelcontextprotocol/sdk)['"]"""
)

# 規則目錄：id -> 該規則每次命中共用的中繼資料
# Rule catalogue: id -> metadata shared by every hit of the rule
RULES: Dict[str, Dict[str, str]] = {
    "VH-AI-001": {
        "title": bi("啟用了遠端模型程式碼執行（trust_remote_code=True）", "Remote model code execution enabled (trust_remote_code=True)"),
        "severity": "HIGH", "owasp": "LLM04:2026 Supply Chain", "atlas": "AML.T0010.003, AML.T0011.000",
        "cwe": "CWE-494",
        "remediation": bi("避免執行儲存庫提供的模型程式碼；若無法避免，請將 `revision=` 固定在經審閱的 commit 雜湊，"
                          "並在隔離的沙盒中載入（ATLAS AML.M0014 Verify AI Artifacts）。",
                          "Do not execute repository-supplied model code; if unavoidable, pin `revision=` to a reviewed "
                          "commit hash and load inside an isolated sandbox (ATLAS AML.M0014 Verify AI Artifacts)."),
    },
    "VH-AI-002": {
        "title": bi("torch.load 未加 weights_only=True（pickle 程式碼執行）", "torch.load without weights_only=True (pickle code execution)"),
        "severity": "HIGH", "owasp": "LLM04:2026 Supply Chain", "atlas": "AML.T0011.000", "cwe": "CWE-502",
        "remediation": bi("在 torch>=2.6 傳入 weights_only=True（較早版本有 CVE-2025-32434 繞過）或改用 safetensors；"
                          "載入前先驗證成品的雜湊／簽章（AML.M0014）。",
                          "Pass weights_only=True on torch>=2.6 (earlier releases had the CVE-2025-32434 bypass) or "
                          "prefer safetensors; verify artifact hashes/signatures before loading (AML.M0014)."),
    },
    "VH-AI-003": {
        "title": bi("以 pickle 反序列化資料或模型成品", "Pickle-based deserialization of a data or model artifact"),
        "severity": "MEDIUM", "owasp": "LLM04:2026 Supply Chain", "atlas": "AML.T0011.000", "cwe": "CWE-502",
        "remediation": bi("絕不反序列化不可信的 pickle 成品；改用 safetensors/JSON，或先驗證固定的雜湊或簽章。"
                          "pickle 掃描器只是縱深防禦（已有被繞過的案例）。",
                          "Never unpickle untrusted artifacts; use safetensors/JSON, or verify a pinned hash or "
                          "signature first. Pickle scanners are defense in depth only (they have been bypassed)."),
    },
    "VH-AI-004": {
        "title": bi("從模型中心下載模型時未固定修訂版本", "Model downloaded from a hub without a pinned revision"),
        "severity": "MEDIUM", "owasp": "LLM04:2026 Supply Chain", "atlas": "AML.T0010.003, AML.T0109",
        "cwe": "CWE-494",
        "remediation": bi("將 `revision=` 固定在不可變的 commit 雜湊，讓重新推送或被下架的模型無法被偷換，"
                          "並記錄在 AI-BOM 中（ATLAS AML.M0023）。",
                          "Pin `revision=` to an immutable commit hash so a re-pushed or rug-pulled model cannot be "
                          "substituted, and record it in an AI-BOM (ATLAS AML.M0023)."),
    },
    "VH-AI-005": {
        "title": bi("LLM 呼叫沒有輸出 token 上限", "LLM call without an output-token cap"),
        "severity": "MEDIUM", "owasp": "LLM06:2026 Unbounded Consumption", "atlas": "AML.T0034", "cwe": "CWE-770",
        "remediation": bi("為每次模型呼叫設定 max_tokens / max_output_tokens 與逾時，並強制執行每位使用者的速率與花費上限，"
                          "超限時中止執行而不只是告警（AML.M0036、AML.M0004）。",
                          "Set max_tokens / max_output_tokens and a timeout on every model call, and enforce per-user "
                          "rate and spend limits that stop execution rather than alert (AML.M0036, AML.M0004)."),
    },
    "VH-AI-006": {
        "title": bi("模型輸出流入程式碼、shell 或 SQL 執行點", "Model output flows into a code, shell or SQL execution sink"),
        "severity": "HIGH", "owasp": "LLM10:2026 Improper Output Handling", "atlas": "AML.T0050, AML.T0102",
        "cwe": "CWE-94",
        "remediation": bi("把模型輸出當成不可信的輸入：在應用程式碼中以嚴格的結構描述解析，使用參數化查詢與引數清單，"
                          "絕不 eval/exec 或交給 shell 執行。",
                          "Treat model output as untrusted input: parse it against a strict schema in application "
                          "code, use parameterized queries and argument lists, and never eval/exec or shell it."),
    },
    "VH-AI-007": {
        "title": bi("原始碼中寫死的憑證", "Hard-coded credential in source"),
        "severity": "HIGH", "owasp": "LLM02:2026 Sensitive Information Disclosure", "atlas": "AML.T0055",
        "cwe": "CWE-798",
        "remediation": bi("把密鑰移到密鑰管理服務或環境變數並輪替；絕不把憑證放進提示詞（LLM08:2026 Hidden Context Exposure）。",
                          "Move the secret to a secret manager or environment variable and rotate it; never place "
                          "credentials in prompts (LLM08:2026 Hidden Context Exposure)."),
    },
    "VH-AI-008": {
        "title": bi("原始碼中含有不可見或雙向控制字元", "Invisible or bidirectional-control characters in source"),
        "severity": "HIGH", "owasp": "LLM01:2026 Prompt Injection", "atlas": "AML.T0068", "cwe": "",
        "remediation": bi("移除這些字元。它們可能把隱藏內容夾帶進 AI 工具，或讓程式碼的閱讀結果與實際執行不同（Trojan Source）；"
                          "在每個資料輸入邊界都要剝除。",
                          "Remove the characters. They can smuggle hidden directives into AI tooling or make code read "
                          "differently than it executes (Trojan Source); strip them at every ingest boundary."),
    },
    "VH-AI-009": {
        "title": bi("程式碼中嵌入了針對 AI 審查工具的文字", "Instruction addressed to AI reviewers embedded in the code"),
        "severity": "MEDIUM", "owasp": "LLM01:2026 Prompt Injection", "atlas": "AML.T0051.001", "cwe": "",
        "remediation": bi("移除試圖操控 AI 工具審查結果的文字，並稽核引入它的那次變更；此目標的模型審查結果可能已遭操弄。",
                          "Remove text that tells AI tools to ignore instructions or report nothing, and review the "
                          "change that introduced it; model-based review results for this target may be manipulated."),
    },
}

# 命中後會讓本框架自身由模型驅動的判定結果存疑的規則（證據缺口）
# Rules whose hits put the harness's own model-driven verdicts in doubt (evidence gaps)
REVIEW_INTEGRITY_RULES = {"VH-AI-008", "VH-AI-009"}
_MAX_HITS_PER_RULE_PER_FILE = 20

_UNSAFE_DESERIALIZERS = {
    "pickle.load", "pickle.loads", "cPickle.load", "cPickle.loads", "_pickle.load", "_pickle.loads",
    "dill.load", "dill.loads", "cloudpickle.load", "cloudpickle.loads", "joblib.load", "pandas.read_pickle",
}
_HUB_DOWNLOADERS = {"huggingface_hub.hf_hub_download", "huggingface_hub.snapshot_download", "transformers.pipeline"}
_HUB_ID_RE = re.compile(r"^[A-Za-z0-9][\w.\-]*/[\w.\-]+$")
# LLM SDK 補全呼叫的字尾（只在匯入 AI SDK 的檔案中比對）
# Call suffixes of LLM SDK completions (only matched in files that import an AI SDK)
_LLM_CALL_SUFFIXES = (
    "chat.completions.create", "completions.create", "responses.create", "messages.create", "messages.stream",
    "litellm.completion", "litellm.acompletion", "generate_content", "chat.complete", "invoke", "ainvoke",
)
_OUTPUT_CAP_KWARGS = {"max_tokens", "max_output_tokens", "max_completion_tokens", "max_new_tokens",
                      "generation_config", "config"}
_EXEC_SINKS = {"eval": "CWE-94", "exec": "CWE-94", "compile": "CWE-94", "os.system": "CWE-78",
               "os.popen": "CWE-78", "subprocess.run": "CWE-78", "subprocess.call": "CWE-78",
               "subprocess.Popen": "CWE-78", "subprocess.check_output": "CWE-78",
               "subprocess.check_call": "CWE-78"}
_SQL_SINK_ATTRS = {"execute": "CWE-89", "executemany": "CWE-89", "executescript": "CWE-89"}


class AISecurityStaticScanner:
    """對原始碼檔案執行 VH-AI-* 規則；`ai_components` 列出目標匯入的 AI SDK。
    Runs the VH-AI-* rules over source files; `ai_components` lists the AI SDKs the target imports."""

    def __init__(self) -> None:
        self.ai_components: List[str] = []

    def scan_files(self, files: Iterable[str]) -> List[StaticFinding]:
        findings: List[StaticFinding] = []
        components: Set[str] = set()
        for path in files:
            try:
                with open(path, "r", encoding="utf-8") as f:
                    text = f.read()
            except (OSError, UnicodeDecodeError):
                continue  # 擷取器已把無法讀取的檔案回報為解析失敗 ／ the extractor already reports unreadable files as parse failures
            findings.extend(self._scan_text_rules(path, text))
            if path.endswith(".py"):
                found, file_components = self._scan_python(path, text)
                findings.extend(found)
                components |= file_components
            else:
                components |= set(_AI_JS_PACKAGE_RE.findall(text))
        self.ai_components = sorted(components)
        return self._dedupe(findings)

    @staticmethod
    def _finding(rule_id: str, path: str, line: int, evidence: str = "", severity: Optional[str] = None,
                 cwe: Optional[str] = None) -> StaticFinding:
        rule = RULES[rule_id]
        return StaticFinding(
            rule_id=rule_id,
            title=rule["title"],
            severity=FindingSeverity(severity or rule["severity"]),
            file_path=path,
            line_number=max(1, line),
            evidence=clean_model_text(evidence)[:160],
            remediation=rule["remediation"],
            owasp_mapping=rule["owasp"],
            atlas_mapping=rule["atlas"],
            cwe=(cwe if cwe is not None else rule["cwe"]) or None,
            affects_review_integrity=rule_id in REVIEW_INTEGRITY_RULES,
        )

    def _scan_text_rules(self, path: str, text: str) -> List[StaticFinding]:
        """與語言無關的規則：憑證、不可見字元、針對審查者的指示文字。
        Language-agnostic rules: credentials, invisible characters, reviewer-directed instructions."""
        out = [self._finding("VH-AI-007", path, line, f"{kind} literal (value redacted)") for line, kind in find_secrets(text)]
        out += [self._finding("VH-AI-008", path, line, desc, severity=sev) for line, sev, desc in find_invisible(text)]
        out += [self._finding("VH-AI-009", path, line, phrase) for line, phrase in find_injection_markers(text)]
        return out

    def _scan_python(self, path: str, text: str):
        try:
            tree = ast.parse(text, filename=path)
        except (SyntaxError, ValueError, RecursionError):
            return [], set()
        aliases = self._import_aliases(tree)
        components = {
            mod for mod in AI_PYTHON_MODULES
            for target in aliases.values() if target == mod or target.startswith(mod + ".")
        }
        imports_ai = bool(components)
        findings: List[StaticFinding] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                findings.extend(self._call_rules(path, node, aliases, imports_ai))
            elif imports_ai and isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Module)):
                findings.extend(self._taint_rule(path, node, aliases))
        # 頂層套件在報告中較易讀（"google.genai" 保持完整限定名稱）
        # Top-level packages read better in the report ("google.genai" stays qualified)
        return findings, {c if c.startswith("google.") else c.split(".")[0] for c in components}

    @staticmethod
    def _import_aliases(tree: ast.Module) -> Dict[str, str]:
        """本地名稱 -> 完整點號分隔的匯入目標（`import numpy as np` -> np: numpy）。
        Local name -> fully dotted import target (`import numpy as np` -> np: numpy)."""
        aliases: Dict[str, str] = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    aliases[a.asname or a.name.split(".")[0]] = a.name if a.asname else a.name.split(".")[0]
                    if not a.asname:
                        aliases[a.name] = a.name  # `import google.genai` 讓點號形式仍可解析 ／ `import google.genai` keeps the dotted form resolvable
            elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                for a in node.names:
                    aliases[a.asname or a.name] = f"{node.module}.{a.name}"
        aliases.setdefault("np", "numpy")
        aliases.setdefault("pd", "pandas")
        return aliases

    @staticmethod
    def _dotted(func: ast.AST, aliases: Dict[str, str]) -> str:
        parts: List[str] = []
        while isinstance(func, ast.Attribute):
            parts.append(func.attr)
            func = func.value
        if isinstance(func, ast.Name):
            parts.append(aliases.get(func.id, func.id))
        elif isinstance(func, ast.Call):
            parts.append("<call>")
        else:
            return ""
        return ".".join(reversed(parts))

    @staticmethod
    def _kw(node: ast.Call, name: str) -> Optional[ast.expr]:
        return next((k.value for k in node.keywords if k.arg == name), None)

    @staticmethod
    def _is_true(value: Optional[ast.expr]) -> bool:
        return isinstance(value, ast.Constant) and value.value is True

    def _is_llm_call(self, node: ast.AST, aliases: Dict[str, str]) -> bool:
        if not isinstance(node, ast.Call):
            return False
        dotted = self._dotted(node.func, aliases)
        return any(dotted == s or dotted.endswith("." + s) for s in _LLM_CALL_SUFFIXES)

    def _call_rules(self, path: str, node: ast.Call, aliases: Dict[str, str], imports_ai: bool) -> List[StaticFinding]:
        out: List[StaticFinding] = []
        dotted = self._dotted(node.func, aliases)
        line = getattr(node, "lineno", 1)
        if self._is_true(self._kw(node, "trust_remote_code")):
            out.append(self._finding("VH-AI-001", path, line, f"{dotted or 'call'}(..., trust_remote_code=True)"))
        if dotted == "torch.load" and not self._is_true(self._kw(node, "weights_only")):
            out.append(self._finding("VH-AI-002", path, line, "torch.load(...) without weights_only=True"))
        if dotted in _UNSAFE_DESERIALIZERS or (dotted == "numpy.load" and self._is_true(self._kw(node, "allow_pickle"))):
            out.append(self._finding("VH-AI-003", path, line, f"{dotted}(...)"))
        if (dotted.endswith(".from_pretrained") or dotted in _HUB_DOWNLOADERS) and self._kw(node, "revision") is None:
            model_id = self._model_id_arg(node)
            if model_id and _HUB_ID_RE.match(model_id) and not os.path.exists(model_id):
                out.append(self._finding("VH-AI-004", path, line, f"{dotted.split('.')[-1]}({model_id!r}) without revision="))
        if imports_ai and self._is_llm_call(node, aliases) and not dotted.endswith(("invoke", "ainvoke")):
            has_cap = any(k.arg in _OUTPUT_CAP_KWARGS or k.arg is None for k in node.keywords)
            if not has_cap:
                out.append(self._finding("VH-AI-005", path, line, f"{dotted}(...) has no max_tokens"))
        return out

    def _model_id_arg(self, node: ast.Call) -> Optional[str]:
        candidates = list(node.args[:1]) + [
            v for v in (self._kw(node, k) for k in ("pretrained_model_name_or_path", "repo_id", "model")) if v is not None
        ]
        for c in candidates:
            if isinstance(c, ast.Constant) and isinstance(c.value, str):
                return c.value
        return None

    def _taint_rule(self, path: str, scope: ast.AST, aliases: Dict[str, str]) -> List[StaticFinding]:
        """VH-AI-006：由 LLM 呼叫指派的名稱（以及由它們衍生的名稱）流到 exec/SQL 執行點。

        刻意只在範疇內且不考慮流程：便宜、確定，並偏向 vibe coding 會產生的
        直接 `answer = llm(...); eval(answer)` 形態。
        VH-AI-006: names assigned from an LLM call (and names derived from them) reaching an exec/SQL sink.

        Intra-scope and flow-insensitive on purpose: cheap, deterministic, and biased toward the
        direct `answer = llm(...); eval(answer)` shape vibe coding produces.
        """
        body = self._own_nodes(scope)
        tainted: Set[str] = set()
        assigns = [n for n in body if isinstance(n, (ast.Assign, ast.AnnAssign, ast.AugAssign))]
        for _ in range(4):  # 對衍生指派取定點 ／ fixpoint over derived assignments
            before = len(tainted)
            for a in assigns:
                if a.value is not None and self._expr_tainted(a.value, tainted, aliases):
                    targets = a.targets if isinstance(a, ast.Assign) else [a.target]
                    for t in targets:
                        tainted |= {n.id for n in ast.walk(t) if isinstance(n, ast.Name)}
            if len(tainted) == before:
                break
        out: List[StaticFinding] = []
        for node in body:
            if not isinstance(node, ast.Call):
                continue
            dotted = self._dotted(node.func, aliases)
            sink = dotted
            cwe = _EXEC_SINKS.get(dotted)
            if cwe is None and isinstance(node.func, ast.Attribute):
                sink = sink or node.func.attr
                cwe = _SQL_SINK_ATTRS.get(node.func.attr)
            if cwe is None:
                continue
            if node.args and self._expr_tainted(node.args[0], tainted, aliases):
                out.append(self._finding("VH-AI-006", path, node.lineno, f"model output reaches {sink}()", cwe=cwe))
        return out

    @staticmethod
    def _own_nodes(scope: ast.AST) -> List[ast.AST]:
        """此範疇的節點，不深入巢狀的函式／類別（它們會各自被掃描）。
        Nodes of this scope, not descending into nested functions/classes (they are scanned on their own)."""
        nodes: List[ast.AST] = []
        stack = list(ast.iter_child_nodes(scope))
        while stack:
            n = stack.pop()
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
                continue
            nodes.append(n)
            stack.extend(ast.iter_child_nodes(n))
        return nodes

    def _expr_tainted(self, expr: ast.AST, tainted: Set[str], aliases: Dict[str, str]) -> bool:
        return any(
            (isinstance(n, ast.Name) and n.id in tainted) or self._is_llm_call(n, aliases)
            for n in ast.walk(expr)
        )

    @staticmethod
    def _dedupe(findings: List[StaticFinding]) -> List[StaticFinding]:
        seen: Set[tuple] = set()
        per_rule_file: Dict[tuple, int] = {}
        out: List[StaticFinding] = []
        for f in sorted(findings, key=lambda f: (f.file_path, f.line_number, f.rule_id)):
            key = (f.rule_id, f.file_path, f.line_number)
            if key in seen:
                continue
            seen.add(key)
            bucket = (f.rule_id, f.file_path)
            per_rule_file[bucket] = per_rule_file.get(bucket, 0) + 1
            if per_rule_file[bucket] > _MAX_HITS_PER_RULE_PER_FILE:
                continue
            out.append(f)
        return out
