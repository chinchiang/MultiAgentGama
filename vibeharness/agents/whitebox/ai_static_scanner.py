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
# 其他函式庫也使用的後綴（Twilio `messages.create`、boto3 Lambda `invoke`）：只有當接收者解析為 AI SDK 模組或用戶端，或名稱像是 AI 物件（`llm`、`chain`…）時才算數
# Suffixes other libraries use too (Twilio `messages.create`, boto3 Lambda `invoke`): these count only
# when the receiver resolves to an AI SDK module or client, or is named like one (`llm`, `chain`, ...)
_AMBIGUOUS_LLM_SUFFIXES = ("messages.create", "messages.stream", "chat.complete", "invoke", "ainvoke")
# 在匯入 AI SDK 的檔案中，這些後綴夠有辨識度：接收者是函式參數或來源不明的名稱（`def ask(c): c.messages.create(...)`）
# 時仍算數，只有已知綁定到非 AI 物件（`tw = twilio.Client(...)`）時才不算。`invoke` 仍需要 AI 接收者。
# In a file that imports an AI SDK these suffixes are distinctive enough: they count when the receiver is a
# parameter or a name of unknown origin (`def ask(c): c.messages.create(...)`), and not only when it is known
# to be bound to a non-AI object (`tw = twilio.Client(...)`). `invoke` still needs an AI receiver.
_DISTINCTIVE_WHEN_IMPORTED = ("messages.create", "messages.stream", "chat.complete")
# 接收者名稱中代表 AI 物件的「詞」（以底線／camelCase 切分後比對，`blockchain_client` 不會因含 "chain" 而命中）
# Name *words* that mark an AI receiver (matched after splitting on underscores / camelCase, so
# `blockchain_client` does not match because it contains "chain")
_AI_RECEIVER_WORDS = {"llm", "llms", "chain", "chains", "agent", "agents", "runnable", "chatmodel", "anthropic",
                      "claude", "openai", "gpt", "gemini", "mistral", "ollama", "groq", "ai", "genai", "lm"}
_NAME_WORD_RE = re.compile(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|[0-9]+")
# 對 AI 接收者呼叫這些方法時，其回傳值是模型輸出（VH-AI-006 的污染來源：`llm.predict`、`LLMChain().run`、`ollama.chat`）
# On an AI receiver these methods return model output (VH-AI-006 taint sources: `llm.predict`, `LLMChain().run`, `ollama.chat`)
_LLM_OUTPUT_METHODS = {"run", "arun", "predict", "apredict", "invoke", "ainvoke", "generate", "agenerate", "chat",
                       "achat", "complete", "acomplete", "completion", "acompletion", "create", "stream", "batch",
                       "call", "acall", "generate_content", "send_message", "text_generation", "chat_completion",
                       "query", "aquery"}
# VH-AI-004 會往上檢查被掃描檔案的幾層父目錄，尋找同名的本機檢查點
# How many parent directories of a scanned file VH-AI-004 checks for a local checkpoint of that name
_LOCAL_MODEL_SEARCH_DEPTH = 3
# 會移動的分支名稱不算固定版本 ／ Moving branch names are not a pinned revision
_UNPINNED_REVISIONS = {"main", "master", "head", "latest", "dev", "develop"}
_OUTPUT_CAP_KWARGS = {"max_tokens", "max_output_tokens", "max_completion_tokens", "max_new_tokens"}
# 只有內含輸出上限（或不是字面值，給予善意推定）時才算上限的設定物件引數
# Config-object kwargs that count as a cap only when they contain an output cap (or are not a literal: benefit of the doubt)
_CONFIG_CAP_KWARGS = {"generation_config", "config"}
_EXEC_SINKS = {"eval": "CWE-94", "exec": "CWE-94", "compile": "CWE-94", "os.system": "CWE-78",
               "os.popen": "CWE-78", "subprocess.run": "CWE-78", "subprocess.call": "CWE-78",
               "subprocess.Popen": "CWE-78", "subprocess.check_output": "CWE-78",
               "subprocess.check_call": "CWE-78", "subprocess.getoutput": "CWE-78",
               "subprocess.getstatusoutput": "CWE-78", "asyncio.create_subprocess_shell": "CWE-78",
               "asyncio.create_subprocess_exec": "CWE-78"}
# 接受引數清單的執行點：不經 shell 的清單只有在程式本身（argv[0]）被污染、或 argv[0] 是直譯器／shell 時才危險
# Sinks that take an argument list: a list without a shell is only dangerous when the program itself (argv[0])
# is tainted, or argv[0] is an interpreter / shell
_ARGV_SINKS = {"subprocess.run", "subprocess.call", "subprocess.Popen", "subprocess.check_output", "subprocess.check_call"}
_SHELL_PROGRAMS = {"sh", "bash", "zsh", "dash", "ksh", "fish", "cmd", "cmd.exe", "powershell", "pwsh",
                   "python", "python3", "node", "perl", "ruby"}
_SQL_SINK_ATTRS = {"execute": "CWE-89", "executemany": "CWE-89", "executescript": "CWE-89"}


class AISecurityStaticScanner:
    """對原始碼檔案執行 VH-AI-* 規則；`ai_components` 列出目標匯入的 AI SDK。
    Runs the VH-AI-* rules over source files; `ai_components` lists the AI SDKs the target imports."""

    def __init__(self) -> None:
        self.ai_components: List[str] = []
        # 被掃描檔案中綁定到 AI SDK 用戶端的名稱／點號屬性（`client = OpenAI()`）
        # Names / dotted attributes bound to AI SDK clients in the file being scanned (`client = OpenAI()`)
        self._ai_clients: Set[str] = set()
        # 綁定到匯入的非 AI 建構子／工廠結果的名稱（`tw = twilio.rest.Client(...)`、`lam = boto3.client(...)`）
        # Names bound to the result of an imported non-AI constructor/factory (`tw = twilio.rest.Client(...)`, `lam = boto3.client(...)`)
        self._non_ai_bound: Set[str] = set()

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
        self._ai_clients = self._find_ai_clients(tree, aliases) if imports_ai else set()
        self._non_ai_bound = self._find_non_ai_bound(tree, aliases) if imports_ai else set()
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
    def _raw_dotted(node: ast.AST) -> str:
        """Name/Attribute 鏈未解析的點號形式（`self.client`）；其他節點回傳 ""。
        Unresolved dotted form of a Name/Attribute chain (`self.client`); "" for anything else."""
        parts: List[str] = []
        while isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
        if not isinstance(node, ast.Name):
            return ""
        parts.append(node.id)
        return ".".join(reversed(parts))

    @staticmethod
    def _is_ai_dotted(dotted: str) -> bool:
        return any(dotted == m or dotted.startswith(m + ".") for m in AI_PYTHON_MODULES)

    def _find_ai_clients(self, tree: ast.Module, aliases: Dict[str, str]) -> Set[str]:
        """由 AI SDK 建構子／工廠指派的目標，或由使用它的運算式（LCEL 管線）指派的目標。
        Targets assigned from an AI SDK constructor/factory, or from an expression using one (LCEL pipes)."""
        clients: Set[str] = set()
        # 指派、`with ... as` 與海象運算子目標；迴圈變數走訪的是結果，不是用戶端
        # Assignments, `with ... as` and walrus targets; loop variables iterate results, they are no clients
        nodes = [n for n in ast.walk(tree) if not isinstance(n, (ast.For, ast.AsyncFor, ast.comprehension))]
        bindings = [(value, target) for value, target in self._bindings(nodes) if not isinstance(target, ast.Subscript)]
        for _ in range(4):
            before = len(clients)
            for value, target in bindings:
                uses_ai = any(
                    (isinstance(n, ast.Call) and self._is_ai_dotted(self._dotted(n.func, aliases)))
                    or (isinstance(n, (ast.Name, ast.Attribute)) and self._raw_dotted(n) in clients)
                    for n in ast.walk(value)
                )
                if uses_ai:
                    clients |= self._target_keys(target)
            if len(clients) == before:
                break
        return clients

    def _find_non_ai_bound(self, tree: ast.Module, aliases: Dict[str, str]) -> Set[str]:
        """由「匯入的」非 AI 建構子／工廠呼叫指派的目標；本地輔助函式（`get_client()`）的結果來源不明，不算。
        Targets assigned from a call to an *imported* non-AI constructor/factory; the result of a local
        helper (`get_client()`) is of unknown origin and does not count."""
        bound: Set[str] = set()
        for value, target in self._bindings(list(ast.walk(tree))):
            if not isinstance(value, ast.Call) or isinstance(target, ast.Subscript):
                continue
            dotted = self._dotted(value.func, aliases)
            base = self._raw_dotted(value.func).split(".")[0]
            if dotted and base in aliases and not self._is_ai_dotted(dotted):
                bound |= self._target_keys(target)
        return bound - self._ai_clients

    @staticmethod
    def _ai_named(name: str) -> bool:
        """名稱的某個詞（或相鄰兩詞的組合，例如 open+ai、chat+model）代表 AI 物件。
        Whether a word of the name (or two adjacent words joined, e.g. open+ai, chat+model) marks an AI object."""
        words = [w.lower() for w in _NAME_WORD_RE.findall(name) if not w.isdigit()]
        joined = {a + b for a, b in zip(words, words[1:], strict=False)}
        return any(w in _AI_RECEIVER_WORDS for w in words) or bool(joined & _AI_RECEIVER_WORDS)

    def _receiver_is_ai(self, receiver: ast.AST, aliases: Dict[str, str]) -> bool:
        if isinstance(receiver, ast.Call):
            return self._is_ai_dotted(self._dotted(receiver.func, aliases)) or self._receiver_is_ai(receiver.func, aliases)
        if isinstance(receiver, (ast.Name, ast.Attribute)):
            raw = self._raw_dotted(receiver)
            if raw and (raw in self._ai_clients or self._is_ai_dotted(self._dotted(receiver, aliases))):
                return True
            last = receiver.attr if isinstance(receiver, ast.Attribute) else receiver.id
            if self._ai_named(last):
                return True
            return isinstance(receiver, ast.Attribute) and self._receiver_is_ai(receiver.value, aliases)
        if isinstance(receiver, ast.BinOp):  # LangChain LCEL 管線 ／ LangChain LCEL: (prompt | llm).invoke(...)
            return self._receiver_is_ai(receiver.left, aliases) or self._receiver_is_ai(receiver.right, aliases)
        return False

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
        suffix = next((s for s in _LLM_CALL_SUFFIXES if dotted == s or dotted.endswith("." + s)), None)
        if suffix is None:
            return False
        if suffix not in _AMBIGUOUS_LLM_SUFFIXES or self._is_ai_dotted(dotted):
            return True
        receiver: ast.AST = node.func
        for _ in suffix.split("."):
            if not isinstance(receiver, ast.Attribute):
                return False
            receiver = receiver.value
        if self._receiver_is_ai(receiver, aliases):
            return True
        return suffix in _DISTINCTIVE_WHEN_IMPORTED and self._receiver_origin_unknown(receiver, aliases)

    def _receiver_origin_unknown(self, receiver: ast.AST, aliases: Dict[str, str]) -> bool:
        """接收者是參數、未知名稱或本地輔助函式的結果，而不是已知的非 AI 物件（匯入的模組／類別或其建構結果）。
        Whether the receiver is a parameter, an unknown name or a local helper's result rather than a known
        non-AI object (an imported module / class or something constructed from one)."""
        if isinstance(receiver, ast.Call):
            base = self._raw_dotted(receiver.func).split(".")[0]
            return bool(base) and base not in aliases
        raw = self._raw_dotted(receiver)
        if not raw:
            return False
        return raw.split(".")[0] not in aliases and raw not in self._non_ai_bound

    def _is_llm_source(self, node: ast.AST, aliases: Dict[str, str]) -> bool:
        """VH-AI-006 的污染來源：LLM 補全呼叫，加上 AI 接收者上會回傳模型輸出的方法（`llm.predict`、
        `LLMChain(...).run`、`ollama.chat`、`chain.invoke`），以及直接呼叫模型／鏈物件（`llm(prompt)`）。
        VH-AI-006 taint sources: LLM completion calls, plus output-returning methods on an AI receiver
        (`llm.predict`, `LLMChain(...).run`, `ollama.chat`, `chain.invoke`), and direct calls of a model /
        chain object (`llm(prompt)`)."""
        if not isinstance(node, ast.Call):
            return False
        if self._is_llm_call(node, aliases):
            return True
        func = node.func
        if isinstance(func, ast.Attribute):
            return func.attr in _LLM_OUTPUT_METHODS and self._receiver_is_ai(func.value, aliases)
        if isinstance(func, ast.Name) and func.id not in aliases:
            # 匯入的類別（`OpenAI()`、`pipeline(...)`）是建構子，不是模型輸出
            # An imported class (`OpenAI()`, `pipeline(...)`) is a constructor, not model output
            return func.id in self._ai_clients or self._ai_named(func.id)
        return False

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
        revision = self._kw(node, "revision")
        if (dotted.endswith(".from_pretrained") or dotted in _HUB_DOWNLOADERS) and not self._pinned(revision):
            model_id = self._model_id_arg(node, dotted)
            if model_id and _HUB_ID_RE.match(model_id) and not self._local_model_dir(path, model_id):
                why = "without revision=" if revision is None else f"with unpinned revision={ast.unparse(revision)}"
                out.append(self._finding("VH-AI-004", path, line, f"{dotted.split('.')[-1]}({model_id!r}) {why}"))
        if imports_ai and self._is_llm_call(node, aliases) and not dotted.endswith(("invoke", "ainvoke")):
            if not self._has_output_cap(node):
                out.append(self._finding("VH-AI-005", path, line, f"{dotted}(...) has no max_tokens"))
        return out

    @staticmethod
    def _pinned(revision: Optional[ast.expr]) -> bool:
        """`revision=` 是否固定：缺少、None 或會移動的分支名稱（main／master／HEAD…）都不算；非字面值給予善意推定。
        Whether `revision=` pins the model: missing, None or a moving branch name (main / master / HEAD ...)
        does not; a non-literal gets the benefit of the doubt."""
        if revision is None:
            return False
        if isinstance(revision, ast.Constant):
            return isinstance(revision.value, str) and revision.value.strip().lower() not in _UNPINNED_REVISIONS \
                and bool(revision.value.strip())
        return True

    @staticmethod
    def _has_output_cap(node: ast.Call) -> bool:
        """呼叫是否帶輸出上限：直接的 max_tokens 類引數、`**kwargs`，或內含上限的 `config=`／`generation_config=`
        （dict 或呼叫字面值；非字面值的名稱給予善意推定）。
        Whether the call carries an output cap: a direct max_tokens-style kwarg, `**kwargs`, or a
        `config=` / `generation_config=` containing one (a dict or call literal; a non-literal name gets
        the benefit of the doubt)."""
        for k in node.keywords:
            if k.arg is None or k.arg in _OUTPUT_CAP_KWARGS:
                return True
            if k.arg not in _CONFIG_CAP_KWARGS:
                continue
            value = k.value
            if isinstance(value, ast.Dict):
                if any(key is None or (isinstance(key, ast.Constant) and key.value in _OUTPUT_CAP_KWARGS)
                       for key in value.keys):
                    return True
            elif isinstance(value, ast.Call):
                if any(kw.arg is None or kw.arg in _OUTPUT_CAP_KWARGS for kw in value.keywords):
                    return True
            elif not isinstance(value, ast.Constant):
                return True
        return False

    @staticmethod
    def _local_model_dir(path: str, model_id: str) -> bool:
        """`org/name` 是否為被掃描檔案旁（或往上數層）的檢查點目錄。解析基準是目標而不是框架的工作目錄，因此結果不取決於框架在哪裡執行。
        Whether `org/name` is a checkpoint directory next to the scanned file (or a few levels up).

        Resolved against the target, never the harness's working directory, so the verdict does not
        depend on where the harness happens to run."""
        directory = os.path.dirname(os.path.abspath(path))
        for _ in range(_LOCAL_MODEL_SEARCH_DEPTH + 1):
            if os.path.isdir(os.path.join(directory, model_id)):
                return True
            parent = os.path.dirname(directory)
            if parent == directory:
                break
            directory = parent
        return False

    def _model_id_arg(self, node: ast.Call, dotted: str = "") -> Optional[str]:
        """被下載的模型 id：先看關鍵字引數，再看位置引數。`pipeline(task, model)` 的第一個位置引數是任務名稱，
        所以 pipeline 改看 `model=` 或第二個位置引數。
        The model id being downloaded: keyword arguments first, then positionals. The first positional of
        `pipeline(task, model)` is the task name, so a pipeline reads `model=` or the second positional."""
        keywords = [v for v in (self._kw(node, k) for k in ("pretrained_model_name_or_path", "repo_id", "model"))
                    if v is not None]
        positional = node.args[1:2] if dotted.endswith("pipeline") else node.args[:1]
        candidates = keywords + list(positional)
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
        direct `answer = llm(...); eval(answer)` shape vibe coding produces. Bindings are assignments,
        `for` targets, `with ... as` targets, comprehension targets and walrus targets; attribute
        targets are tracked by their dotted name (`self.last`), never by their base object.
        """
        body = self._own_nodes(scope)
        tainted: Set[str] = set()
        bindings = self._bindings(body)
        for _ in range(4):  # 對衍生指派取定點 ／ fixpoint over derived assignments
            before = len(tainted)
            for value, target in bindings:
                if self._expr_tainted(value, tainted, aliases):
                    tainted |= self._target_keys(target)
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
            if cwe is None or not node.args:
                continue
            if self._sink_arg_tainted(node, dotted, tainted, aliases):
                out.append(self._finding("VH-AI-006", path, node.lineno, f"model output reaches {sink}()", cwe=cwe))
        return out

    def _sink_arg_tainted(self, node: ast.Call, dotted: str, tainted: Set[str], aliases: Dict[str, str]) -> bool:
        """執行點的第一個引數是否帶有模型輸出。不經 shell 的字面值引數清單（建議的安全形式
        `subprocess.run(["git", "checkout", "--", branch])`）只有在 argv[0] 被污染、或 argv[0] 是 shell／直譯器時才算。
        Whether the sink's first argument carries model output. A literal argument list without a shell (the
        recommended safe form `subprocess.run(["git", "checkout", "--", branch])`) only counts when argv[0] is
        tainted or argv[0] is a shell / interpreter."""
        first = node.args[0]
        if dotted in _ARGV_SINKS and isinstance(first, (ast.List, ast.Tuple)) \
                and not self._is_true(self._kw(node, "shell")):
            if not first.elts:
                return False
            program = first.elts[0]
            if self._expr_tainted(program, tainted, aliases):
                return True
            is_shell = isinstance(program, ast.Constant) and isinstance(program.value, str) \
                and os.path.basename(program.value).lower() in _SHELL_PROGRAMS
            return is_shell and any(self._expr_tainted(e, tainted, aliases) for e in first.elts[1:])
        return self._expr_tainted(first, tainted, aliases)

    @staticmethod
    def _bindings(body: List[ast.AST]) -> List[tuple]:
        """一個範疇中（值運算式, 綁定目標）的配對。
        (value expression, bound target) pairs of a scope."""
        pairs: List[tuple] = []
        for n in body:
            if isinstance(n, ast.Assign):
                pairs += [(n.value, t) for t in n.targets]
            elif isinstance(n, (ast.AnnAssign, ast.AugAssign)) and n.value is not None:
                pairs.append((n.value, n.target))
            elif isinstance(n, (ast.For, ast.AsyncFor, ast.comprehension)):
                pairs.append((n.iter, n.target))
            elif isinstance(n, (ast.With, ast.AsyncWith)):
                pairs += [(item.context_expr, item.optional_vars) for item in n.items if item.optional_vars]
            elif isinstance(n, ast.NamedExpr):
                pairs.append((n.value, n.target))
        return pairs

    def _target_keys(self, target: ast.AST) -> Set[str]:
        """指派目標綁定的污染鍵：名稱、拆包元素、點號屬性，以及下標的容器（`cache[key] = ...` 污染 `cache`，而不是 `key`）。
        Taint keys bound by an assignment target: names, unpacked elements, dotted attributes, and
        the container of a subscript (`cache[key] = ...` taints `cache`, not `key`)."""
        if isinstance(target, ast.Name):
            return {target.id}
        if isinstance(target, (ast.Tuple, ast.List)):
            return set().union(*(self._target_keys(e) for e in target.elts)) if target.elts else set()
        if isinstance(target, ast.Starred):
            return self._target_keys(target.value)
        if isinstance(target, ast.Attribute):
            raw = self._raw_dotted(target)
            return {raw} if raw else set()
        if isinstance(target, ast.Subscript):
            return self._target_keys(target.value)
        return set()

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
            (isinstance(n, ast.Name) and n.id in tainted)
            or (isinstance(n, ast.Attribute) and self._raw_dotted(n) in tainted)
            or self._is_llm_source(n, aliases)
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
