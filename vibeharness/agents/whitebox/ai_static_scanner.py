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
import functools
import logging
import os
import re
import time
from typing import Dict, Iterable, List, Optional, Set, Tuple

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
               "asyncio.create_subprocess_exec": "CWE-78", "pty.spawn": "CWE-78",
               "os.posix_spawn": "CWE-78", "os.posix_spawnp": "CWE-78"}
# os.exec*／os.spawn*：(程式引數的位置, argv 的形式)；"v" 是一個 argv 序列，"l" 是可變位置引數（argv[0] 起），
# 名稱以 e 結尾的最後一個位置引數是環境變數
# os.exec* / os.spawn*: (position of the program argument, argv form); "v" is one argv sequence, "l" is variadic
# positionals (from argv[0]); for names ending in e the last positional is the environment
_SPAWN_SINKS: Dict[str, tuple] = {}
for _suffix in ("v", "ve", "vp", "vpe", "l", "le", "lp", "lpe"):
    _SPAWN_SINKS[f"os.exec{_suffix}"] = (0, _suffix[0], _suffix.endswith("e"))
    _SPAWN_SINKS[f"os.spawn{_suffix}"] = (1, _suffix[0], _suffix.endswith("e"))
_SPAWN_SINKS["os.posix_spawn"] = _SPAWN_SINKS["os.posix_spawnp"] = (0, "v", False)
_EXEC_SINKS.update({name: "CWE-78" for name in _SPAWN_SINKS})
# 接受引數清單的執行點：不經 shell 的清單只有在程式本身（argv[0]）被污染、或 argv[0] 是直譯器／shell 時才危險
# Sinks that take an argument list: a list without a shell is only dangerous when the program itself (argv[0])
# is tainted, or argv[0] is an interpreter / shell
_ARGV_SINKS = {"subprocess.run", "subprocess.call", "subprocess.Popen", "subprocess.check_output", "subprocess.check_call",
               "pty.spawn"}
# 以可變位置引數接收 argv 的執行點（`create_subprocess_exec("bash", "-c", cmd)`）：位置引數本身就是引數清單
# Sinks that take argv as variadic positionals (`create_subprocess_exec("bash", "-c", cmd)`): the positionals are the argument list
_VARARGS_ARGV_SINKS = {"asyncio.create_subprocess_exec"}
# 標準輸入可以餵給子程序的執行點（`input=`、`.communicate(x)`、`.stdin.write(x)`）
# Sinks whose child can be fed standard input (`input=`, `.communicate(x)`, `.stdin.write(x)`)
_STDIN_SINKS = {"subprocess.run", "subprocess.Popen", "subprocess.check_output", "asyncio.create_subprocess_exec"}
# 沒有位置引數時，執行點的命令／程式碼可能以這些關鍵字傳入（`subprocess.run(args=cmd, shell=True)`、
# `create_subprocess_exec(program=x)`）
# Without positionals, a sink's command / code may come in through these keywords (`subprocess.run(args=cmd, shell=True)`,
# `create_subprocess_exec(program=x)`)
_SINK_ARG_KEYWORDS = ("args", "cmd", "command", "source", "sql", "statement", "query", "operation", "program")
_SQL_SINK_ATTRS = {"execute": "CWE-89", "executemany": "CWE-89", "executescript": "CWE-89"}
# argv 判斷的嚴重度：HIGH 是確定會被當成程式碼或命令執行；MEDIUM 是程式無法確定（非字面值、也不是只綁定到字串常數的
# 名稱，例如 `TOOL = os.environ.get(...)`）而後面的引數或標準輸入帶有模型輸出
# Severities of an argv verdict: HIGH means it is certainly run as code or a command; MEDIUM means the program cannot
# be determined (a non-literal that is no name bound only to string constants, e.g. `TOOL = os.environ.get(...)`)
# while a later argument or the standard input carries model output
_HIGH, _MEDIUM = "HIGH", "MEDIUM"
# 被污染的標準輸入（xargs 會把它附加成引數）在 argv 中的代表名稱；不是合法的識別字，不會與程式中的名稱衝突
# Stand-in name for tainted standard input in an argv (xargs appends it as arguments); not a valid identifier, so it
# cannot collide with a name in the program
_TAINT_MARK = "<model output>"
# 程式名稱無法確定時，緊接在這些選項後面的被污染元素代表它像直譯器（`[exe, "-c", answer]`）：HIGH
# With a program that cannot be determined, a tainted element right after one of these options makes it look like an
# interpreter (`[exe, "-c", answer]`): HIGH
_GENERIC_CODE_FLAGS = {"-c", "-e", "--eval", "/c", "/k", "-command", "--command", "eval"}
# 單一檔案 Python 規則分析的時間上限（秒）：縱深防禦，正常檔案遠低於此；超過時記錄警告、略過該檔案其餘的規則，
# 並列入 `incomplete_files` 讓呼叫端揭露
# The time cap (seconds) of the Python rule analysis of one file: defense in depth, normal files stay far below it;
# beyond it a warning is logged, the remaining rules of that file are skipped, and the file is listed in
# `incomplete_files` so the caller can disclose it
_MAX_SCAN_SECONDS_PER_FILE = 30.0
# 點號名稱保留的屬性層數：最後 _CHAIN_TAIL 層（後綴比對：`chat.completions.create`）與最前 _CHAIN_HEAD 層（模組字首比對）；
# 更深的鏈縮寫，所以每個節點的名稱長度有上限
# Attribute levels a dotted name keeps: the last _CHAIN_TAIL (suffix matching: `chat.completions.create`) and the first
# _CHAIN_HEAD (module prefix matching); deeper chains are abbreviated, so every node's name has a bounded length
_CHAIN_HEAD, _CHAIN_TAIL = 4, 8


class _Options:
    """一個程式（或子命令）的命令列選項規格：哪些選項帶值、哪些選項的值是程式碼／腳本／模組，以及選項之後的位置引數意義。
    The command-line option spec of a program (or subcommand): which options take a value, which options' values are
    code / a script / a module, and what the positionals after the options mean.

    - `value`：帶一個值的選項（`-u bob`、`--user=bob`、`-ubob`）／ options taking one value
    - `code`：值是要執行的程式碼或命令字串（`-c`、`--eval`）／ options whose value is code or a command string
    - `script`、`module`：值是腳本路徑／模組名稱（`-f file`、`-m pip`）／ options whose value is a script path / module
    - `stdin`：從標準輸入讀程式（`-`、`bash -s`）／ options that read the program from standard input
    - `split`：值是以空白分隔的命令（`env -S "sh -c x"`）／ options whose value is a whitespace-split command
    - `lookup`：只查詢程式而不執行（`command -v`）／ options that only look the program up instead of running it
    - `replace`：xargs 的替換字串選項（`-I {}`）／ xargs's replace-string options
    - `entrypoint`：取代映像檔程式的選項（`docker run --entrypoint`）／ options replacing the image's program
    - `positionals`：選項之後、程式之前的位置引數個數（`timeout 5 cmd`、`docker exec ctr cmd`）／ positionals between the
      options and the program
    - `positional_high`：那些位置引數被污染時是 HIGH（`docker run <image>`）而不是 MEDIUM ／ a tainted positional there is
      HIGH (`docker run <image>`) rather than MEDIUM
    - `long_values`：未列出的 `--long` 選項預設帶值（docker）／ unlisted `--long` options take a value by default (docker)
    - `flags`：`long_values` 時不帶值的長選項 ／ long options without a value when `long_values` is set
    - `assign`：略過 `VAR=value` 指派（env）／ skip `VAR=value` assignments (env)
    - `numeric`：略過 `-5` 形式的數字選項（nice）／ skip numeric options like `-5` (nice)
    - `ci`：選項大小寫不分（PowerShell、cmd）／ options are case-insensitive (PowerShell, cmd)
    - `rest_code`：程式碼選項之後所有元素都併入命令（`cmd /c`、`pwsh -Command`）／ every element after the code option
      joins the command
    - `first`：直譯器第一個位置引數的意義："script"、"code"（awk、Windows PowerShell）、"command"（`watch`，之後全部
      併入命令）、"host"（ssh，之後全部是遠端命令）、"user"（su，繼續解析選項）／ the meaning of an interpreter's first
      positional
    - `subcommands`：位置引數為子命令時的規格（`deno eval`、`bun x`）／ specs selected by a subcommand positional
    """

    def __init__(self, value=(), code=(), script=(), module=(), stdin=(), split=(), lookup=(), replace=(),
                 entrypoint=(), positionals=0, positional_high=False, long_values=False, flags=(), assign=False,
                 numeric=False, ci=False, rest_code=False, first="script", subcommands=None, runner=False):
        self.value, self.code, self.script, self.module = set(value), set(code), set(script), set(module)
        self.stdin, self.split, self.lookup, self.replace = set(stdin), set(split), set(lookup), set(replace)
        self.entrypoint, self.flags = set(entrypoint), set(flags)
        self.positionals, self.positional_high, self.long_values = positionals, positional_high, long_values
        self.assign, self.numeric, self.ci, self.rest_code, self.first = assign, numeric, ci, rest_code, first
        self.subcommands: Dict[str, "_Options"] = subcommands or {}
        self.runner = runner


# 直譯器與 shell：會把後面的引數（或標準輸入）當成程式碼或命令執行。直譯器後面接的是腳本路徑或 `-m 模組`
# （而不是 -c／-e／--eval／-）時，只有腳本或模組本身被污染才算：其後的引數只是腳本的 argv
# Interpreters and shells: they run a later argument (or standard input) as code or a command. When an interpreter is
# followed by a script path or `-m module` (rather than -c / -e / --eval / -), only a tainted script or module
# counts: the arguments after it are just the script's argv
_SH = _Options(value={"-o", "+o", "-O", "+O"}, code={"-c"}, stdin={"-s"})
_PYTHON = _Options(value={"-W", "-X", "--check-hash-based-pycs"}, code={"-c"}, module={"-m"}, stdin={"-"})
_NODE = _Options(value={"-r", "--require", "--import", "--loader", "--experimental-loader", "-C", "--conditions",
                        "--title", "--input-type"},
                 code={"-e", "--eval", "-p", "--print"}, stdin={"-"})
_INTERPRETERS = [
    (re.compile(r"(?:ba|z|da|a|k|mk|c|tc|rba|ya|lk)?sh|fish|bash[\d.]+|ksh93"), _SH),
    (re.compile(r"python[\d.]*(?:d|m|dm|u)?(?:-dbg|-debug)?w?|py|pypy[\d.]*|ipython[\d.]*"), _PYTHON),
    (re.compile(r"node(?:js)?[\d.]*|ts-node|tsx"), _NODE),
    (re.compile(r"deno"), _Options(subcommands={
        "eval": _Options(first="code"), "run": _Options(value={"--config", "-c", "--import-map"}),
        "repl": _Options(code={"--eval"})}, first="subcommand")),
    (re.compile(r"bun"), _Options(code={"-e", "--eval", "-p", "--print"}, subcommands={
        "x": _Options(runner=True), "run": _Options(), "exec": _Options(first="command")}, first="subcommand")),
    (re.compile(r"perl[\d.]*"), _Options(value={"-I", "-M", "-m", "-x"}, code={"-e", "-E"}, stdin={"-"})),
    (re.compile(r"ruby[\d.]*|jruby|irb"), _Options(value={"-I", "-r", "-C", "-E"}, code={"-e"}, stdin={"-"})),
    (re.compile(r"php[\d.]*(?:-cli|-cgi)?"), _Options(value={"-c", "-d", "-z"}, code={"-r", "-B", "-R", "-E"},
                                                       script={"-f", "-F"})),
    (re.compile(r"lua(?:jit)?[\d.]*"), _Options(value={"-l"}, code={"-e"}, stdin={"-"})),
    (re.compile(r"tclsh[\d.]*|wish[\d.]*|jshell"), _Options()),
    (re.compile(r"expect"), _Options(code={"-c"}, script={"-f"})),
    (re.compile(r"rscript|r"), _Options(code={"-e"}, value={"--default-packages"})),
    (re.compile(r"osascript"), _Options(value={"-l", "-s"}, code={"-e"}, stdin={"-"})),
    (re.compile(r"[gmn]?awk"), _Options(value={"-v", "-F"}, script={"-f", "--file"}, first="code")),
    (re.compile(r"powershell(?:_ise)?"), _Options(
        value={"-executionpolicy", "-ep", "-ex", "-workingdirectory", "-wd", "-configurationname", "-outputformat",
               "-of", "-inputformat", "-if", "-windowstyle", "-w", "-version", "-psconsolefile", "-settingsfile"},
        code={"-command", "-c", "-encodedcommand", "-ec", "-enc", "-e"}, script={"-file", "-f"}, ci=True,
        rest_code=True, first="code")),
    (re.compile(r"pwsh(?:-preview)?"), _Options(
        value={"-executionpolicy", "-ep", "-ex", "-workingdirectory", "-wd", "-configurationname", "-outputformat",
               "-of", "-inputformat", "-if", "-windowstyle", "-w", "-settingsfile", "-custompipename"},
        code={"-command", "-c", "-encodedcommand", "-ec", "-enc", "-e"}, script={"-file", "-f"}, ci=True,
        rest_code=True)),
    (re.compile(r"cmd"), _Options(code={"/c", "/k", "/r"}, ci=True, rest_code=True)),
    (re.compile(r"ssh|rsh|plink|autossh"), _Options(
        value={"-p", "-i", "-l", "-o", "-F", "-J", "-L", "-R", "-D", "-b", "-c", "-e", "-E", "-I", "-m", "-O", "-Q",
               "-S", "-W", "-w", "-B", "-P", "-pw"}, first="host")),
    (re.compile(r"su"), _Options(value={"-s", "--shell", "-g", "--group", "-G", "--supp-group", "-w"},
                                 code={"-c", "--command", "--session-command"}, first="user")),
    (re.compile(r"watch"), _Options(value={"-n", "--interval", "-d"}, first="command")),
    # 會執行 shell 跳脫（GNU sed 的 `e`、sqlite3 的 `.shell`、psql／mysql 的 `\!`）的程式碼直譯器
    # Code interpreters with shell escapes (GNU sed's `e`, sqlite3's `.shell`, psql / mysql's `\!`)
    (re.compile(r"g?sed"), _Options(value={"-l", "--line-length"}, code={"-e", "--expression"},
                                    script={"-f", "--file"}, first="code")),
    (re.compile(r"sqlite3?"), _Options(value={"-separator", "-newline", "-nullvalue", "-vfs", "-maxsize", "-mmap"},
                                       code={"-cmd"}, script={"-init"}, first="host")),
    (re.compile(r"psql"), _Options(value={"-d", "--dbname", "-h", "--host", "-p", "--port", "-U", "--username", "-v",
                                          "--set", "--variable", "-o", "--output", "-L", "--log-file", "-P", "--pset",
                                          "-F", "-R", "-T"},
                                   code={"-c", "--command"}, script={"-f", "--file"}, first="skip")),
    (re.compile(r"mysql|mariadb"), _Options(value={"-u", "--user", "-h", "--host", "-P", "--port", "-D", "--database",
                                                   "-S", "--socket", "--default-character-set"},
                                            code={"-e", "--execute"}, first="skip")),
]
# git 的全域選項（子命令之前）中帶值者；`-c` 的值能設定會執行命令的設定（`core.sshCommand`、`alias.x=!cmd`）
# git's value-taking global options (before the subcommand); a `-c` value can set command-running config
# (`core.sshCommand`, `alias.x=!cmd`)
_GIT_GLOBAL_VALUES = {"-C", "-c", "--git-dir", "--work-tree", "--namespace", "--exec-path", "--config-env",
                      "--super-prefix", "--list-cmds"}
# git 子命令中值是要執行之命令的選項 ／ git subcommand options whose value is a command to run
_GIT_COMMAND_OPTIONS = ("--upload-pack", "--receive-pack", "--exec")
# asyncio 事件迴圈的子程序方法（第一個引數是協定工廠）-> 對應的 asyncio 函式
# asyncio event-loop subprocess methods (the first argument is the protocol factory) -> the matching asyncio function
_AI_MODULE_HEADS = {m.split(".")[0] for m in AI_PYTHON_MODULES}
_LOOP_SINKS = {"subprocess_shell": "asyncio.create_subprocess_shell", "subprocess_exec": "asyncio.create_subprocess_exec"}
# 只是包住另一個程式的前綴（真正的程式在後面的元素）：`/usr/bin/env python3`、`sudo -u bob bash`、`timeout -s KILL 5 sh`
# Prefixes that only wrap another program (the real program is a later element): `/usr/bin/env python3`,
# `sudo -u bob bash`, `timeout -s KILL 5 sh`
_WRAPPERS: Dict[str, _Options] = {
    "env": _Options(value={"-u", "--unset", "-C", "--chdir"}, split={"-S", "--split-string"}, assign=True),
    "sudo": _Options(value={"-u", "--user", "-g", "--group", "-C", "--close-from", "-D", "--chdir", "-h", "--host",
                            "-p", "--prompt", "-r", "--role", "-t", "--type", "-U", "--other-user", "-T",
                            "--command-timeout", "-R", "--chroot"}),
    "doas": _Options(value={"-u", "-C"}),
    "nohup": _Options(), "setsid": _Options(), "unbuffer": _Options(), "busybox": _Options(),
    "exec": _Options(value={"-a"}),
    "time": _Options(value={"-f", "--format", "-o", "--output"}),
    "timeout": _Options(value={"-s", "--signal", "-k", "--kill-after"}, positionals=1),
    "nice": _Options(value={"-n", "--adjustment"}, numeric=True),
    "ionice": _Options(value={"-c", "--class", "-n", "--classdata", "-p", "--pid", "-P", "--pgid", "-u", "--uid"}),
    "stdbuf": _Options(value={"-i", "-o", "-e", "--input", "--output", "--error"}),
    "chrt": _Options(positionals=1),
    "taskset": _Options(positionals=1),
    "chroot": _Options(value={"--userspec", "--groups"}, positionals=1),
    "runuser": _Options(value={"-u", "--user", "-g", "--group", "-G", "--supp-group", "-s", "--shell", "-w",
                               "--whitelist-environment"}, code={"-c", "--command"}),
    "caffeinate": _Options(value={"-t", "-w"}),
    "xargs": _Options(value={"-I", "-n", "--max-args", "-P", "--max-procs", "-d", "--delimiter", "-a", "--arg-file",
                             "-E", "-s", "--max-chars", "-L", "--max-lines", "--process-slot-var", "--replace"},
                      replace={"-I", "--replace", "-i"}),
    "flock": _Options(value={"-w", "--wait", "--timeout", "-E", "--conflict-exit-code"}, code={"-c", "--command"},
                      positionals=1),
    "strace": _Options(value={"-e", "-o", "-p", "-s", "-u", "-E", "-a", "-b", "-I", "-O", "-P", "-S", "-X",
                              "--output", "--attach", "--user", "--env"}),
    "ltrace": _Options(value={"-e", "-o", "-p", "-s", "-u", "-n", "-a", "-A", "-D", "-l", "-L", "-w"}),
    "command": _Options(lookup={"-v", "-V"}),
    # `script` 只在 `-c` 時執行命令（其餘位置引數是記錄檔） ／ `script` only runs a command with `-c` (positionals are the log file)
    "script": _Options(value={"-t", "--timing", "-I", "--log-in", "-O", "--log-out", "-B", "--log-io", "-T",
                              "--log-timing", "-m", "--logging-format", "-E", "--echo"},
                       code={"-c", "--command"}, first="none"),
    "uvx": _Options(value={"--from", "--with", "--with-editable", "--with-requirements", "--python", "-p", "--index",
                           "--index-url", "--extra-index-url", "--default-index", "--find-links", "-f", "--directory",
                           "--cache-dir", "--config-file", "--color"}),
    "npx": _Options(value={"-p", "--package", "--registry", "--cache", "-w", "--workspace"},
                    code={"-c", "--call"}),
    "bunx": _Options(value={"-p", "--package"}),
}
_DOCKER_EXEC = _Options(value={"-e", "--env", "--env-file", "-u", "--user", "-w", "--workdir", "--detach-keys"},
                        positionals=1)
_DOCKER_RUN = _Options(
    value={"-a", "-c", "-e", "-h", "-l", "-m", "-p", "-u", "-v", "-w"}, entrypoint={"--entrypoint"}, long_values=True,
    flags={"--rm", "--init", "--privileged", "--read-only", "--tty", "--interactive", "--detach", "--no-healthcheck",
           "--oom-kill-disable", "--publish-all", "--sig-proxy", "--disable-content-trust", "--quiet", "--help"},
    positionals=1, positional_high=True)
_KUBECTL_EXEC = _Options(value={"-c", "--container", "-n", "--namespace", "--context", "--kubeconfig", "-f",
                                "--filename", "--pod-running-timeout", "--cluster", "--user", "-s", "--server",
                                "--token"}, positionals=1)
_CONDA_RUN = _Options(value={"-n", "--name", "-p", "--prefix", "--cwd"})
# 以子命令執行另一個程式的工具（`uv run`、`docker exec ctr`、`kubectl exec pod --`）；子命令前可以有全域選項
# Tools that run another program through a subcommand (`uv run`, `docker exec ctr`, `kubectl exec pod --`); global
# options may precede the subcommand
_RUNNERS: Dict[str, _Options] = {
    "uv": _Options(value={"--directory", "--project", "--cache-dir", "--config-file", "--color"}, subcommands={
        "run": _Options(value={"--with", "--with-editable", "--with-requirements", "--python", "-p", "--project",
                               "--directory", "--env-file", "--extra", "--group", "--only-group", "--no-group",
                               "--package", "--index", "--index-url", "--default-index", "--extra-index-url",
                               "--find-links", "-f", "--color", "--cache-dir", "--config-file",
                               "--python-preference"}),
        "tool": _Options(subcommands={"run": _WRAPPERS["uvx"]})}),
    "poetry": _Options(value={"-C", "--directory", "-P", "--project"},
                       subcommands={"run": _Options(value={"-C", "--directory", "-P", "--project"})}),
    "pipenv": _Options(subcommands={"run": _Options()}),
    "conda": _Options(subcommands={"run": _CONDA_RUN}),
    "mamba": _Options(subcommands={"run": _CONDA_RUN}),
    "micromamba": _Options(subcommands={"run": _CONDA_RUN}),
    "pdm": _Options(subcommands={"run": _Options(value={"-p", "--project"})}),
    "hatch": _Options(value={"-e", "--env"}, subcommands={"run": _Options()}),
    "pnpm": _Options(value={"-C", "--dir", "--filter", "-F"}, subcommands={
        "exec": _Options(value={"-C", "--dir", "--filter", "-F", "--workspace-concurrency"}),
        "dlx": _Options(value={"--package"})}),
    "yarn": _Options(subcommands={"exec": _Options(), "dlx": _Options(value={"-p", "--package"})}),
    "npm": _Options(subcommands={"exec": _WRAPPERS["npx"], "x": _WRAPPERS["npx"]}),
    "docker": _Options(value={"-H", "--host", "--context", "-c", "--config", "-l", "--log-level"}, subcommands={
        "exec": _DOCKER_EXEC, "run": _DOCKER_RUN, "container": _Options(subcommands={"exec": _DOCKER_EXEC,
                                                                                     "run": _DOCKER_RUN})}),
    "podman": _Options(value={"--url", "--connection", "-c"}, subcommands={
        "exec": _DOCKER_EXEC, "run": _DOCKER_RUN, "container": _Options(subcommands={"exec": _DOCKER_EXEC,
                                                                                     "run": _DOCKER_RUN})}),
    "nerdctl": _Options(value={"-n", "--namespace", "-H", "--host"}, subcommands={"exec": _DOCKER_EXEC,
                                                                                    "run": _DOCKER_RUN}),
    "kubectl": _Options(value={"-n", "--namespace", "--context", "--kubeconfig", "--cluster", "--user", "-s",
                               "--server", "--token"}, subcommands={"exec": _KUBECTL_EXEC}),
    "oc": _Options(value={"-n", "--namespace", "--context", "--kubeconfig"}, subcommands={"exec": _KUBECTL_EXEC}),
}
# `find` 的動作選項：其後到 `;`／`+` 為止是被執行的 argv ／ `find`'s action options: up to `;` / `+` is the argv run
_FIND_EXEC = {"-exec", "-execdir", "-ok", "-okdir"}
_ASSIGNMENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*=.*", re.S)
_NUMERIC_OPTION_RE = re.compile(r"-\d+")


def _max_severity(verdicts: Iterable[Optional[str]]) -> Optional[str]:
    """一組判斷中最嚴重的一個（HIGH > MEDIUM > None）／ The most severe of a set of verdicts (HIGH > MEDIUM > None)."""
    worst: Optional[str] = None
    for v in verdicts:
        if v == _HIGH:
            return _HIGH
        if v == _MEDIUM:
            worst = _MEDIUM
    return worst


class _ScanBudgetExceeded(RuntimeError):
    """單一檔案的 Python 規則分析超過時間上限 ／ The Python rule analysis of one file exceeded its time cap."""


class _ScopeIndex:
    """一個範疇的綁定／修改索引，每個範疇只走訪一次：每個名稱的字面值清單指派（或「無法確定」）、`append`／`extend`／
    `insert`／`+=` 修改、呼叫結果被綁定到的名稱，以及標準輸入被餵入模型輸出的執行點呼叫。
    The binding / mutation index of a scope, walked once per scope: each name's literal list assignments (or
    "unknowable"), its `append` / `extend` / `insert` / `+=` mutations, the names call results are bound to, and the
    sink calls whose standard input is fed model output.

    `literals(name)`：範疇中 `name` 的所有字面值清單／tuple 指派；若它也有別的綁定方式就回傳 None（保守：照一般污染判斷）。
    非字面值的重新指派、拆包、下標指派、迴圈／with／海象目標、`global`／`nonlocal`，以及任何 `insert`（可能換掉 argv[0]）
    都讓清單內容無法確定；以未污染資料 `append`／`extend`／`+=` 附加元素不改變判斷（被污染的修改由
    `mutated_with_taint` 先行標記）。
    `literals(name)`: every literal list/tuple assignment of `name` in the scope; None when it is also bound some other
    way (conservative: fall back to plain taint). A non-literal reassignment, unpacking, subscript assignment, loop /
    with / walrus target, `global` / `nonlocal`, or any `insert` (it may replace argv[0]) makes the list contents
    unknowable; appending untainted data with `append` / `extend` / `+=` does not change the verdict (a tainted
    mutation is flagged first by `mutated_with_taint`)."""

    def __init__(self, scanner: "AISecurityStaticScanner", body: List[ast.AST], tainted: Set[str],
                 aliases: Dict[str, str]) -> None:
        self._scanner, self._tainted, self._aliases = scanner, tainted, aliases
        self._literals: Dict[str, Optional[List[ast.expr]]] = {}
        self._mutations: Dict[str, List[ast.AST]] = {}
        self._mutated: Dict[str, bool] = {}
        # `_literal_argv_verdict` 的快取 ／ `_literal_argv_verdict`'s cache
        self.verdicts: Dict[tuple, Optional[str]] = {}
        # 標準輸入被餵入模型輸出的執行點呼叫（id） ／ ids of sink calls whose standard input is fed model output
        self.stdin_fed: Set[int] = set()
        bound_to: Dict[int, Set[str]] = {}
        fed_names: Set[str] = set()
        for n in body:
            scanner._tick()
            if isinstance(n, (ast.Global, ast.Nonlocal)):
                for name in n.names:
                    self._unknowable(name)
            elif isinstance(n, (ast.Assign, ast.AnnAssign)):
                targets = n.targets if isinstance(n, ast.Assign) else [n.target]
                for t in targets:
                    if isinstance(t, ast.Name):
                        if n.value is None:
                            continue  # 只有註記沒有值 ／ an annotation without a value
                        if isinstance(n.value, (ast.List, ast.Tuple)):
                            if self._literals.get(t.id, []) is not None:
                                self._literals.setdefault(t.id, []).append(n.value)  # type: ignore[union-attr]
                        else:
                            self._unknowable(t.id)
                    else:
                        for key in scanner._target_keys(t):
                            self._unknowable(key)
                    call = self._call_of(n.value)
                    if call is not None:
                        bound_to.setdefault(id(call), set()).update(scanner._target_keys(t))
            elif isinstance(n, ast.AugAssign):
                if isinstance(n.target, ast.Name):
                    self._mutations.setdefault(n.target.id, []).append(n)
                else:
                    for key in scanner._target_keys(n.target):
                        self._unknowable(key)
            elif isinstance(n, ast.Call):
                func = n.func
                if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name) \
                        and func.attr in ("append", "extend", "insert"):
                    self._mutations.setdefault(func.value.id, []).append(n)
                    if func.attr == "insert":
                        self._unknowable(func.value.id)
                fed = isinstance(func, ast.Attribute) and (
                    func.attr == "communicate"
                    or (func.attr == "write" and isinstance(func.value, ast.Attribute) and func.value.attr == "stdin"))
                if fed and any(scanner._expr_tainted(a, tainted, aliases)
                               for a in list(n.args) + [k.value for k in n.keywords]):
                    receiver = func.value.value if func.attr == "write" else func.value  # type: ignore[attr-defined]
                    receiver_call = self._call_of(receiver)
                    if receiver_call is not None:
                        self.stdin_fed.add(id(receiver_call))  # 鏈式呼叫 ／ chained: `Popen([...]).communicate(x)`
                    elif isinstance(receiver, ast.Name):
                        fed_names.add(receiver.id)
            elif isinstance(n, (ast.For, ast.AsyncFor, ast.comprehension, ast.With, ast.AsyncWith, ast.NamedExpr)):
                for value, t in scanner._bindings([n]):
                    for key in scanner._target_keys(t):
                        self._unknowable(key)
                    call = self._call_of(value)
                    if call is not None and isinstance(n, (ast.With, ast.AsyncWith)):
                        bound_to.setdefault(id(call), set()).update(scanner._target_keys(t))
        self.stdin_fed |= {cid for cid, names in bound_to.items() if names & fed_names}

    @staticmethod
    def _call_of(value: Optional[ast.AST]) -> Optional[ast.Call]:
        """`Popen(...)` 或 `await create_subprocess_exec(...)` 的呼叫節點 ／ The call node of `Popen(...)` or
        `await create_subprocess_exec(...)`."""
        if isinstance(value, ast.Await):
            value = value.value
        return value if isinstance(value, ast.Call) else None

    def _unknowable(self, name: str) -> None:
        self._literals[name] = None

    def literals(self, name: str) -> Optional[List[ast.expr]]:
        return self._literals.get(name, [])

    def mutated_with_taint(self, name: str) -> bool:
        """範疇中是否以被污染的資料 `append`／`extend`／`insert`／`+=` 修改 `name`（每個名稱只算一次）。
        Whether the scope mutates `name` with tainted data via `append` / `extend` / `insert` / `+=` (computed once
        per name)."""
        if name not in self._mutated:
            scanner, tainted, aliases = self._scanner, self._tainted, self._aliases
            result = False
            for n in self._mutations.get(name, []):
                parts = [n.value] if isinstance(n, ast.AugAssign) else \
                    list(n.args) + [k.value for k in n.keywords]  # type: ignore[attr-defined]
                if any(scanner._expr_tainted(p, tainted, aliases) for p in parts):
                    result = True
                    break
            self._mutated[name] = result
        return self._mutated[name]



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
        # 被掃描檔案中只綁定到字串常數（或 `shutil.which(常數)`）的名稱 -> 那些字串（`SHELL = "bash"`）
        # Names the scanned file only ever binds to string constants (or `shutil.which(constant)`) -> those strings (`SHELL = "bash"`)
        self._str_consts: Dict[str, Set[str]] = {}
        # 被掃描檔案中綁定到執行點的名稱 -> (執行點, partial 綁定的位置引數, partial 綁定的關鍵字)（`r = subprocess.run`）
        # Names the scanned file binds to a sink -> (sink, positionals bound by a partial, keywords bound by a partial) (`r = subprocess.run`)
        self._sink_aliases: Dict[str, tuple] = {}
        # Python 規則分析不完整的檔案（超過時間上限或發生意外錯誤）：呼叫端應揭露為證據缺口
        # Files whose Python rule analysis is incomplete (time cap exceeded or an unexpected error): the caller should
        # disclose them as evidence gaps
        self.incomplete_files: List[str] = []
        # 目前檔案的分析期限（time.monotonic()）與工作計數；`_receiver_is_ai` 的備忘表（節點 id -> 結果）
        # The current file's analysis deadline (time.monotonic()) and work counter; `_receiver_is_ai`'s memo (node id -> result)
        self._deadline: Optional[float] = None
        self._ticks = 0
        self._receiver_memo: Dict[int, bool] = {}
        # `_chain` 的備忘表（節點 id -> 鏈摘要） ／ `_chain`'s memo (node id -> chain summary)
        self._chain_memo: Dict[int, tuple] = {}
        # `_dotted`（屬性節點）與 `_is_llm_source` 的備忘表 ／ memos of `_dotted` (attribute nodes) and `_is_llm_source`
        self._dotted_memo: Dict[int, str] = {}
        self._source_memo: Dict[int, bool] = {}
        self._info_memo: Dict[int, Tuple[Set[str], List[ast.Call]]] = {}
        # 目前檔案中綁定目標的最深屬性層數（`_key_ref` 用；檔案掃描之外不限）
        # The deepest attribute level of the current file's binding targets (for `_key_ref`; unlimited outside a file scan)
        self._max_key_depth = 1 << 30
        # `_walk`／`_file_bindings` 的快取：(樹, 節點串列, 綁定配對) ／ `_walk` / `_file_bindings`'s cache: (tree, nodes, bindings)
        self._walk_cache: Tuple[Optional[ast.AST], List[ast.AST], Optional[List[tuple]]] = (None, [], None)

    def scan_files(self, files: Iterable[str]) -> List[StaticFinding]:
        findings: List[StaticFinding] = []
        components: Set[str] = set()
        self.incomplete_files = []
        for path in files:
            try:
                with open(path, "r", encoding="utf-8") as f:
                    text = f.read()
            except (OSError, UnicodeDecodeError):
                continue  # 擷取器已把無法讀取的檔案回報為解析失敗 ／ the extractor already reports unreadable files as parse failures
            findings.extend(self._scan_text_rules(path, text))
            if path.endswith(".py"):
                try:
                    found, file_components = self._scan_python(path, text)
                except Exception as e:  # noqa: BLE001
                    # 單一檔案的意外錯誤（例如病態的巢狀深度）不中止整次掃描
                    # An unexpected error in one file (e.g. pathological nesting depth) does not abort the whole scan
                    logger.warning(bi(f"AI 安全規則無法分析 {path}（{type(e).__name__}），已略過",
                                      f"The AI-security rules could not analyze {path} ({type(e).__name__}), skipped"))
                    self.incomplete_files.append(path)
                    continue
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
        self._deadline = time.monotonic() + _MAX_SCAN_SECONDS_PER_FILE
        self._receiver_memo, self._chain_memo, self._dotted_memo, self._source_memo = {}, {}, {}, {}
        self._info_memo = {}
        self._ai_clients, self._non_ai_bound, self._str_consts, self._sink_aliases = set(), set(), {}, {}
        try:
            self._max_key_depth = max([self._chain(n)[2] for _, target in self._file_bindings(tree)
                                       for n in ast.walk(target) if isinstance(n, ast.Attribute)] or [0])
            if imports_ai:
                self._ai_clients = self._find_ai_clients(tree, aliases)
                self._non_ai_bound = self._find_non_ai_bound(tree, aliases)
                self._str_consts = self._find_str_consts(tree, aliases)
                self._find_sink_aliases(tree, aliases)
            for node in self._walk(tree):
                self._tick()
                if isinstance(node, ast.Call):
                    findings.extend(self._call_rules(path, node, aliases, imports_ai))
                elif imports_ai and isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Module)):
                    findings.extend(self._taint_rule(path, node, aliases))
        except _ScanBudgetExceeded:
            # 縱深防禦：病態的檔案只略過其餘的規則，已找到的命中保留，並讓呼叫端揭露分析不完整
            # Defense in depth: a pathological file only skips its remaining rules; hits already found are kept and
            # the caller can disclose the incomplete analysis
            logger.warning(bi(f"AI 安全規則分析 {path} 超過 {_MAX_SCAN_SECONDS_PER_FILE:g} 秒的上限，該檔案其餘的規則已略過",
                              f"The AI-security rule analysis of {path} exceeded its {_MAX_SCAN_SECONDS_PER_FILE:g} s cap; "
                              "the remaining rules for that file were skipped"))
            self.incomplete_files.append(path)
        finally:
            self._deadline = None
            self._receiver_memo, self._chain_memo, self._dotted_memo, self._source_memo = {}, {}, {}, {}
            self._info_memo = {}
            self._walk_cache = (None, [], None)
            self._max_key_depth = 1 << 30
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

    def _chain(self, node: ast.AST) -> Tuple[str, str, int, Tuple[str, ...], Tuple[str, ...]]:
        """屬性鏈的摘要：(基底種類 "name"／"call"／"other", 基底名稱, 屬性層數, 最前面 _CHAIN_HEAD 個屬性, 最後面
        _CHAIN_TAIL 個屬性)。以明確的迴圈計算並依節點備忘（每個檔案共用），所以數千層的 `a.b.b.b...` 鏈不會讓鏈上
        每個節點各自重走整條鏈（平方時間）。
        A summary of an attribute chain: (base kind "name" / "call" / "other", base name, number of attributes, the
        first _CHAIN_HEAD attributes, the last _CHAIN_TAIL attributes). Computed with an explicit loop and memoized per
        node (shared by the file), so a chain `a.b.b.b...` thousands deep does not make every node on it walk the whole
        chain again (quadratic time)."""
        memo = self._chain_memo if self._deadline is not None else {}
        cached = memo.get(id(node))
        if cached is not None:
            return cached
        path: List[ast.Attribute] = []
        n = node
        while isinstance(n, ast.Attribute) and id(n) not in memo:
            path.append(n)
            n = n.value
        if isinstance(n, ast.Attribute):
            info = memo[id(n)]
        elif isinstance(n, ast.Name):
            info = ("name", n.id, 0, (), ())
        elif isinstance(n, ast.Call):
            info = ("call", "", 0, (), ())
        else:
            info = ("other", "", 0, (), ())
        for a in reversed(path):
            kind, base, depth, head, tail = info
            info = (kind, base, depth + 1, head if len(head) >= _CHAIN_HEAD else head + (a.attr,),
                    (tail + (a.attr,))[-_CHAIN_TAIL:])
            memo[id(a)] = info
        return info

    @staticmethod
    def _join_chain(base: str, depth: int, head: Tuple[str, ...], tail: Tuple[str, ...]) -> str:
        """鏈的點號形式；超過 _CHAIN_TAIL 層的鏈縮寫成 `base.前幾層.<...>.後幾層`（所有已知的名稱都很短，
        字首／字尾比對不受影響）。
        The dotted form of a chain; a chain deeper than _CHAIN_TAIL is abbreviated to `base.first.<...>.last` (every
        known name is short, so prefix / suffix matching is unaffected)."""
        if depth <= _CHAIN_TAIL:
            return ".".join((base,) + tail)
        return ".".join((base,) + head + ("<...>",) + tail)

    def _dotted(self, func: ast.AST, aliases: Dict[str, str]) -> str:
        """呼叫目標的點號形式，基底名稱經匯入別名解析（`np.load` -> `numpy.load`）；基底是呼叫時為 `<call>`，其他節點回傳 ""。
        The dotted form of a call target with the base name resolved through import aliases (`np.load` ->
        `numpy.load`); `<call>` when the base is a call, "" for anything else."""
        memo = self._dotted_memo if self._deadline is not None and isinstance(func, ast.Attribute) else None
        if memo is not None and id(func) in memo:
            return memo[id(func)]
        kind, base, depth, head, tail = self._chain(func)
        if kind == "name":
            dotted = self._join_chain(aliases.get(base, base), depth, head, tail)
        elif kind == "call":
            dotted = self._join_chain("<call>", depth, head, tail)
        else:
            dotted = ""
        if memo is not None:
            memo[id(func)] = dotted
        return dotted

    def _key_ref(self, node: ast.Attribute) -> Optional[str]:
        """屬性節點作為污染／用戶端鍵的點號名稱；比檔案中任何綁定目標都深的鏈不可能是鍵，回傳 None 而不組字串。
        The dotted name of an attribute node as a taint / client key; a chain deeper than any binding target of the
        file cannot be a key, so None is returned without building the string."""
        if self._chain(node)[2] > self._max_key_depth:
            return None
        return self._raw_dotted(node)

    def _raw_dotted(self, node: ast.AST) -> str:
        """Name/Attribute 鏈未解析的點號形式（`self.client`）；其他節點回傳 ""。
        Unresolved dotted form of a Name/Attribute chain (`self.client`); "" for anything else."""
        kind, base, depth, head, tail = self._chain(node)
        return self._join_chain(base, depth, head, tail) if kind == "name" else ""

    def _walk(self, tree: ast.AST) -> List[ast.AST]:
        """`ast.walk(tree)` 的節點串列，每個檔案只走訪一次（各個尋找器共用）。
        The node list of `ast.walk(tree)`, walked once per file (shared by the finders)."""
        if self._walk_cache[0] is not tree:
            self._walk_cache = (tree, list(ast.walk(tree)), None)
        return self._walk_cache[1]

    def _file_bindings(self, tree: ast.AST) -> List[tuple]:
        """整個檔案的（值, 目標）綁定配對，每個檔案只算一次 ／ The file's (value, target) binding pairs, computed once per file."""
        nodes = self._walk(tree)
        bindings = self._walk_cache[2]
        if bindings is None:
            bindings = self._bindings(nodes)
            self._walk_cache = (tree, nodes, bindings)
        return bindings

    @staticmethod
    @functools.lru_cache(maxsize=8192)
    def _is_ai_dotted(dotted: str) -> bool:
        if dotted.split(".", 1)[0] not in _AI_MODULE_HEADS:  # 快速排除 ／ fast rejection
            return False
        return any(dotted == m or dotted.startswith(m + ".") for m in AI_PYTHON_MODULES)

    def _find_ai_clients(self, tree: ast.Module, aliases: Dict[str, str]) -> Set[str]:
        """由 AI SDK 建構子／工廠指派的目標，或由使用它的運算式（LCEL 管線）指派的目標。
        Targets assigned from an AI SDK constructor/factory, or from an expression using one (LCEL pipes)."""
        clients: Set[str] = set()
        # 指派、`with ... as` 與海象運算子目標；迴圈變數走訪的是結果，不是用戶端
        # Assignments, `with ... as` and walrus targets; loop variables iterate results, they are no clients
        nodes = [n for n in self._walk(tree) if not isinstance(n, (ast.For, ast.AsyncFor, ast.comprehension))]
        bindings = [(value, target) for value, target in self._bindings(nodes) if not isinstance(target, ast.Subscript)]
        # 每個綁定值只走訪一次：是否含 AI SDK 呼叫，以及它引用的名稱／點號屬性；定點迭代只做集合運算
        # Each bound value is walked once: whether it holds an AI SDK call, and the names / dotted attributes it
        # references; the fixpoint iterations only do set operations
        infos = []
        for value, target in bindings:
            refs, calls = self._value_info(value)
            has_ai_call = any(self._is_ai_dotted(self._dotted(c.func, aliases)) for c in calls)
            infos.append((has_ai_call, refs, target))
        for _ in range(4):
            before = len(clients)
            for has_ai_call, refs, target in infos:
                if has_ai_call or not refs.isdisjoint(clients):
                    clients |= self._target_keys(target)
            if len(clients) == before:
                break
        return clients

    def _find_non_ai_bound(self, tree: ast.Module, aliases: Dict[str, str]) -> Set[str]:
        """由「匯入的」非 AI 建構子／工廠呼叫指派的目標；本地輔助函式（`get_client()`）的結果來源不明，不算。
        Targets assigned from a call to an *imported* non-AI constructor/factory; the result of a local
        helper (`get_client()`) is of unknown origin and does not count."""
        bound: Set[str] = set()
        for value, target in self._file_bindings(tree):
            if not isinstance(value, ast.Call) or isinstance(target, ast.Subscript):
                continue
            dotted = self._dotted(value.func, aliases)
            base = self._raw_dotted(value.func).split(".")[0]
            if dotted and base in aliases and not self._is_ai_dotted(dotted):
                bound |= self._target_keys(target)
        return bound - self._ai_clients

    def _find_str_consts(self, tree: ast.Module, aliases: Dict[str, str]) -> Dict[str, Set[str]]:
        """整個檔案中只被綁定到字串常數（或 `shutil.which(常數)`）的名稱與那些字串；任何其他綁定方式都讓名稱出局。
        Names the whole file only ever binds to string constants (or `shutil.which(constant)`), with those
        strings; any other kind of binding rules the name out."""
        consts: Dict[str, Set[str]] = {}
        other: Set[str] = set()
        for value, target in self._file_bindings(tree):
            if not isinstance(target, ast.Name):
                other |= self._target_keys(target)
                continue
            text = self._const_str(value)
            if text is None and isinstance(value, ast.Call) and self._dotted(value.func, aliases) == "shutil.which" \
                    and value.args:
                text = self._const_str(value.args[0])
            if text is None:
                other.add(target.id)
            else:
                consts.setdefault(target.id, set()).add(text)
        for n in self._walk(tree):
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
                # 參數也是綁定 ／ parameters are bindings too
                args = n.args
                other |= {a.arg for a in args.posonlyargs + args.args + args.kwonlyargs}
                other |= {a.arg for a in (args.vararg, args.kwarg) if a is not None}
        return {k: v for k, v in consts.items() if k not in other}

    @staticmethod
    def _const_str(node: Optional[ast.AST]) -> Optional[str]:
        return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None

    @staticmethod
    @functools.lru_cache(maxsize=8192)
    def _ai_named(name: str) -> bool:
        """名稱的某個詞（或相鄰兩詞的組合，例如 open+ai、chat+model）代表 AI 物件。
        Whether a word of the name (or two adjacent words joined, e.g. open+ai, chat+model) marks an AI object."""
        words = [w.lower() for w in _NAME_WORD_RE.findall(name) if not w.isdigit()]
        joined = {a + b for a, b in zip(words, words[1:], strict=False)}
        return any(w in _AI_RECEIVER_WORDS for w in words) or bool(joined & _AI_RECEIVER_WORDS)

    def _receiver_is_ai(self, receiver: ast.AST, aliases: Dict[str, str]) -> bool:
        """接收者是否為 AI 物件：AI SDK 呼叫的結果、AI 用戶端名稱、像 AI 物件的名稱，或其屬性鏈／LCEL 管線
        （`(prompt | llm).invoke`）中的任何一段。以明確的堆疊後序計算並依節點備忘（每個檔案共用），所以長的
        `x.run().run().run()...` 鏈不會遞迴過深，也不會讓每一層重算整條鏈（平方時間）。
        Whether the receiver is an AI object: the result of an AI SDK call, an AI client name, an AI-like name, or any
        link of its attribute chain / LCEL pipe (`(prompt | llm).invoke`). Computed in post-order with an explicit
        stack and memoized per node (shared by the file), so a long `x.run().run().run()...` chain neither recurses
        too deep nor makes every level recompute the whole chain (quadratic time)."""
        # 檔案掃描之外（直接呼叫時）用區域備忘表，避免節點 id 被重用 ／ outside a file scan (direct calls) a local memo is used, so reused node ids cannot leak in
        memo = self._receiver_memo if self._deadline is not None else {}
        stack: List[Tuple[ast.AST, bool]] = [(receiver, False)]
        while stack:
            node, expanded = stack.pop()
            key = id(node)
            if key in memo and not expanded:
                continue
            children: List[ast.AST] = []
            direct = False
            if isinstance(node, ast.Call):
                direct = self._is_ai_dotted(self._dotted(node.func, aliases))
                children = [node.func]
            elif isinstance(node, (ast.Name, ast.Attribute)):
                kind, _, depth, _, _ = self._chain(node)
                last = node.attr if isinstance(node, ast.Attribute) else node.id
                direct = self._ai_named(last)
                if not direct and kind == "name":
                    # 用戶端鍵不會比任何綁定目標深；模組字首只取決於最前面幾層，更深的節點與其子節點結果相同
                    # A client key is never deeper than any binding target; the module prefix depends only on the
                    # first few levels, so a deeper node gives the same result as its child
                    direct = (depth <= self._max_key_depth and self._raw_dotted(node) in self._ai_clients) \
                        or (depth <= _CHAIN_HEAD + 1 and self._is_ai_dotted(self._dotted(node, aliases)))
                children = [node.value] if isinstance(node, ast.Attribute) else []
            elif isinstance(node, ast.BinOp):  # LangChain LCEL 管線 ／ LangChain LCEL: (prompt | llm).invoke(...)
                children = [node.left, node.right]
            if direct or not children:
                memo[key] = direct
            elif expanded:
                memo[key] = any(memo.get(id(c), False) for c in children)
            else:
                stack.append((node, True))
                stack.extend((c, False) for c in children if id(c) not in memo)
        return memo.get(id(receiver), False)

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
        memo = self._source_memo if self._deadline is not None else None
        if memo is not None and id(node) in memo:
            return memo[id(node)]
        result = self._is_llm_source_uncached(node, aliases)
        if memo is not None:
            memo[id(node)] = result
        return result

    def _is_llm_source_uncached(self, node: ast.Call, aliases: Dict[str, str]) -> bool:
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
        直接 `answer = llm(...); eval(answer)` 形態。綁定包括指派、`for` 目標、`with ... as` 目標、推導式目標與海象運算子目標；
        屬性目標以點號名稱（`self.last`）追蹤，絕不追蹤其基底物件。範疇的綁定／修改索引只建一次（`_ScopeIndex`），
        所以每個執行點不必重掃整個範疇（否則同一函式裡許多執行點是平方時間）。
        VH-AI-006: names assigned from an LLM call (and names derived from them) reaching an exec/SQL sink.

        Intra-scope and flow-insensitive on purpose: cheap, deterministic, and biased toward the
        direct `answer = llm(...); eval(answer)` shape vibe coding produces. Bindings are assignments,
        `for` targets, `with ... as` targets, comprehension targets and walrus targets; attribute
        targets are tracked by their dotted name (`self.last`), never by their base object. The scope's
        binding / mutation index is built once (`_ScopeIndex`), so no sink rescans the whole scope (many sinks in
        one function would otherwise take quadratic time).
        """
        body = self._own_nodes(scope)
        tainted: Set[str] = {_TAINT_MARK}
        # 每個綁定值只走訪一次（是否含模型輸出來源、引用的名稱）；定點迭代只做集合運算
        # Each bound value is walked once (whether it holds a model-output source, the names it references); the
        # fixpoint iterations only do set operations
        infos = [(self._expr_refs(value, aliases), target) for value, target in self._bindings(body)]
        for _ in range(4):  # 對衍生指派取定點 ／ fixpoint over derived assignments
            before = len(tainted)
            for (source, refs), target in infos:
                if source or not refs.isdisjoint(tainted):
                    tainted |= self._target_keys(target)
            if len(tainted) == before:
                break
        index = _ScopeIndex(self, body, tainted, aliases)
        out: List[StaticFinding] = []
        for node in body:
            if not isinstance(node, ast.Call):
                continue
            self._tick()
            resolved = self._resolve_sink(node.func, aliases)
            call = node
            if resolved is None and isinstance(node.func, ast.Attribute) and node.func.attr in _LOOP_SINKS:
                # `loop.subprocess_shell(factory, cmd)`／`loop.subprocess_exec(factory, prog, *args)`：去掉協定工廠後
                # 與對應的 asyncio 函式相同 ／ without the protocol factory they match the corresponding asyncio function
                resolved = (_LOOP_SINKS[node.func.attr], [], [])
                call = ast.copy_location(ast.Call(func=node.func, args=list(node.args[1:]), keywords=list(node.keywords)),
                                         node)
            if resolved is not None:
                dotted, pre_args, pre_keywords = resolved
                sink, cwe = dotted, _EXEC_SINKS[dotted]
                if pre_args or pre_keywords:
                    # `functools.partial(subprocess.run, shell=True)(cmd)`：把綁定的引數併入呼叫
                    # `functools.partial(subprocess.run, shell=True)(cmd)`: merge the bound arguments into the call
                    call = ast.copy_location(ast.Call(func=node.func, args=pre_args + list(call.args),
                                                      keywords=pre_keywords + list(call.keywords)), node)
            else:
                dotted = self._dotted(node.func, aliases)
                if not isinstance(node.func, ast.Attribute) or node.func.attr not in _SQL_SINK_ATTRS:
                    continue
                sink, cwe = dotted or node.func.attr, _SQL_SINK_ATTRS[node.func.attr]
            if self._sink_first_arg(call) is None:
                continue
            verdict = self._sink_verdict(call, dotted, tainted, aliases, index, node)
            if verdict is not None:
                why = "" if verdict == _HIGH else " (the program run cannot be determined)"
                out.append(self._finding("VH-AI-006", path, node.lineno, f"model output reaches {sink}(){why}",
                                         severity=verdict, cwe=cwe))
        return out

    def _resolve_sink(self, func: ast.AST, aliases: Dict[str, str], depth: int = 0):
        """呼叫目標解析成的執行點：(點號名稱, partial 綁定的位置引數, partial 綁定的關鍵字)；不是執行點時回傳 None。
        涵蓋直接名稱、本檔案中綁定到執行點的別名（`r = subprocess.run`）、`getattr(subprocess, "run")` 與
        `functools.partial(subprocess.run, ...)`。
        The sink a call target resolves to: (dotted name, positionals bound by a partial, keywords bound by a partial);
        None when it is no sink. Covers direct names, aliases this file binds to a sink (`r = subprocess.run`),
        `getattr(subprocess, "run")` and `functools.partial(subprocess.run, ...)`."""
        if depth > 8:
            return None
        dotted = self._dotted(func, aliases)
        if dotted in _EXEC_SINKS:
            return dotted, [], []
        if isinstance(func, ast.Name) and func.id in self._sink_aliases:
            return self._sink_aliases[func.id]
        if isinstance(func, ast.Call):
            inner = self._dotted(func.func, aliases)
            if inner in ("getattr", "builtins.getattr") and len(func.args) >= 2:
                attr = self._const_str(func.args[1])
                base = self._dotted(func.args[0], aliases)
                if attr is not None and base and f"{base}.{attr}" in _EXEC_SINKS:
                    return f"{base}.{attr}", [], []
            if inner in ("functools.partial", "partial") and func.args:
                target = self._resolve_sink(func.args[0], aliases, depth + 1)
                if target is not None:
                    return target[0], target[1] + list(func.args[1:]), target[2] + list(func.keywords)
        return None

    def _find_sink_aliases(self, tree: ast.Module, aliases: Dict[str, str]) -> Dict[str, tuple]:
        """本檔案中被綁定到執行點的名稱（`r = subprocess.run`、`run_sh = functools.partial(subprocess.run, shell=True)`）。
        Names this file binds to a sink (`r = subprocess.run`, `run_sh = functools.partial(subprocess.run, shell=True)`)."""
        self._sink_aliases = {}
        bindings = [(v, t) for v, t in self._file_bindings(tree) if isinstance(t, ast.Name)]
        for _ in range(3):  # 別名的別名 ／ aliases of aliases
            before = len(self._sink_aliases)
            for value, target in bindings:
                self._tick()
                if target.id not in self._sink_aliases and isinstance(value, (ast.Name, ast.Attribute, ast.Call)):
                    resolved = self._resolve_sink(value, aliases)
                    if resolved is not None:
                        self._sink_aliases[target.id] = resolved
            if len(self._sink_aliases) == before:
                break
        return self._sink_aliases

    def _sink_verdict(self, node: ast.Call, dotted: str, tainted: Set[str], aliases: Dict[str, str],
                      index: Optional["_ScopeIndex"] = None, origin: Optional[ast.Call] = None) -> Optional[str]:
        """執行點是否帶有模型輸出，以及嚴重度（HIGH／MEDIUM；None 表示沒有）。不經 shell 的字面值引數清單（建議的安全形式
        `subprocess.run(["git", "checkout", "--", branch])`）由 `_argv_verdict` 判斷；同一範疇裡只被指派為字面值清單的名稱
        （`cmd = ["git", "checkout", branch]; subprocess.run(cmd)`）套用相同規則。`shell=` 是非常數時，清單判斷為安全
        但引數被污染者記為 MEDIUM。
        Whether the sink carries model output, and how severely (HIGH / MEDIUM; None for no). A literal argument list
        without a shell (the recommended safe form `subprocess.run(["git", "checkout", "--", branch])`) is judged by
        `_argv_verdict`; a name the same scope only ever binds to a literal list (`cmd = ["git", "checkout", branch];
        subprocess.run(cmd)`) gets the same rule. With a non-constant `shell=`, a list judged safe whose arguments are
        tainted is MEDIUM."""
        first = self._sink_first_arg(node)
        if first is None:
            return None
        stdin = self._stdin_tainted(node, dotted, tainted, aliases, index, origin or node)
        executable = self._kw(node, "executable")
        if dotted in _SPAWN_SINKS:
            return self._spawn_verdict(node, dotted, tainted, aliases, index)
        if dotted in _VARARGS_ARGV_SINKS:
            # 位置引數就是 argv；`*cmd` 展開時改看被展開的名稱（與 `subprocess.run(cmd)` 相同的規則）
            # The positionals are argv; with a `*cmd` spread the spread name is analyzed instead (the same rule as `subprocess.run(cmd)`)
            if not node.args:
                return self._argv_verdict([first], tainted, aliases, stdin)
            if not any(isinstance(a, ast.Starred) for a in node.args):
                return self._argv_verdict(self._with_executable(list(node.args), executable), tainted, aliases, stdin)
            if len(node.args) == 1:
                spread = node.args[0]
                assert isinstance(spread, ast.Starred)
                return self._argv_expr_verdict(spread.value, executable, tainted, aliases, index, stdin)
            return _HIGH if any(self._expr_tainted(a, tainted, aliases) for a in node.args) else None
        if dotted not in _ARGV_SINKS:
            return _HIGH if self._expr_tainted(first, tainted, aliases) else None
        mode = self._shell_mode(node)
        if mode == "yes":
            return _HIGH if self._expr_tainted(first, tainted, aliases) else None
        verdict = self._argv_expr_verdict(first, executable, tainted, aliases, index, stdin)
        if verdict is None and mode == "maybe" and self._expr_tainted(first, tainted, aliases):
            return _MEDIUM
        return verdict

    def _argv_expr_verdict(self, argv: ast.expr, executable: Optional[ast.expr], tainted: Set[str],
                           aliases: Dict[str, str], index: Optional["_ScopeIndex"], stdin: bool) -> Optional[str]:
        """不經 shell 的 argv 運算式：字面值清單、字串（程式名稱本身），或同一範疇只綁定到字面值清單的名稱；其他運算式照一般污染判斷。
        用被污染的資料修改清單（`cmd.append(branch)`）不是綁定，一般污染追不到：保守地標記。
        An argv expression without a shell: a literal list, a string (the program name itself), or a name the scope
        only binds to literal lists; any other expression falls back to plain taint. Mutating the list with tainted
        data (`cmd.append(branch)`) is no binding plain taint can see: it is flagged conservatively."""
        if isinstance(argv, (ast.List, ast.Tuple)):
            return self._literal_argv_verdict(argv, executable, tainted, aliases, index, stdin)
        if self._const_str(argv) is not None:
            return self._argv_verdict(self._with_executable([argv], executable), tainted, aliases, stdin)
        if isinstance(argv, ast.Name) and index is not None:
            if index.mutated_with_taint(argv.id):
                return _HIGH
            literals = index.literals(argv.id)
            if literals:
                # 依（名稱, executable, 標準輸入）快取：同一名稱被重新指派 N 次又被 N 個執行點使用時不是平方時間
                # Cached by (name, executable, stdin): a name reassigned N times and used by N sinks is not quadratic
                key = (argv.id, id(executable) if executable is not None else None, stdin)
                if key not in index.verdicts:
                    index.verdicts[key] = _max_severity(
                        self._literal_argv_verdict(lit, executable, tainted, aliases, index, stdin) for lit in literals)
                return index.verdicts[key]
        return _HIGH if self._expr_tainted(argv, tainted, aliases) else None

    def _literal_argv_verdict(self, argv, executable, tainted, aliases, index, stdin) -> Optional[str]:
        """`_argv_verdict` 對字面值清單的結果，在範疇索引中依（清單, executable, 標準輸入）快取：同一個清單被許多執行點使用時
        不重算（否則長清單乘上許多執行點是平方時間）。
        `_argv_verdict` of a literal list, cached in the scope index by (list, executable, stdin): a list used by many
        sinks is not re-evaluated (a long list times many sinks would otherwise be quadratic)."""
        key = (id(argv), id(executable) if executable is not None else None, stdin)
        cache = index.verdicts if index is not None else {}
        if key not in cache:
            cache[key] = self._argv_verdict(self._with_executable(list(argv.elts), executable), tainted, aliases, stdin)
        return cache[key]

    @staticmethod
    def _with_executable(elts: List[ast.expr], executable: Optional[ast.expr]) -> List[ast.expr]:
        """`executable=` 會取代 argv[0] 成為真正執行的程式 ／ `executable=` replaces argv[0] as the program actually run."""
        if executable is not None and not (isinstance(executable, ast.Constant) and executable.value is None):
            return [executable] + elts[1:]
        return elts

    def _shell_mode(self, node: ast.Call) -> str:
        """`shell=` 的值："yes"（真值常數，含 `shell=1` 與 `**{"shell": True}`）、"no"（缺少或假值常數）或 "maybe"（非常數）。
        非字面值的 `**kwargs` 給予善意推定（"no"）。
        The value of `shell=`: "yes" (a truthy constant, `shell=1` and `**{"shell": True}` included), "no" (missing or a
        falsy constant) or "maybe" (non-constant). A non-literal `**kwargs` gets the benefit of the doubt ("no")."""
        def truth(value: ast.expr) -> str:
            if isinstance(value, ast.Constant):
                return "yes" if value.value else "no"
            return "maybe"

        for k in node.keywords:
            if k.arg == "shell":
                return truth(k.value)
            if k.arg is None and isinstance(k.value, ast.Dict):
                for key, value in zip(k.value.keys, k.value.values, strict=False):
                    if key is not None and self._const_str(key) == "shell":
                        return truth(value)
        return "no"

    def _stdin_tainted(self, node: ast.Call, dotted: str, tainted: Set[str], aliases: Dict[str, str],
                       index: Optional["_ScopeIndex"], origin: ast.Call) -> bool:
        """子程序的標準輸入是否帶有模型輸出：`input=` 被污染，或同一範疇以被污染的資料呼叫結果的 `.communicate(x)`／`.stdin.write(x)`
        （`p = Popen(["sh"], stdin=PIPE); p.communicate(answer)`）。
        Whether the child's standard input carries model output: a tainted `input=`, or the same scope calling
        `.communicate(x)` / `.stdin.write(x)` on the result with tainted data
        (`p = Popen(["sh"], stdin=PIPE); p.communicate(answer)`)."""
        if dotted not in _STDIN_SINKS:
            return False
        fed = self._kw(node, "input")
        if fed is not None and self._expr_tainted(fed, tainted, aliases):
            return True
        return index is not None and id(origin) in index.stdin_fed

    def _spawn_verdict(self, node: ast.Call, dotted: str, tainted: Set[str], aliases: Dict[str, str],
                       index: Optional["_ScopeIndex"]) -> Optional[str]:
        """`os.exec*`、`os.spawn*`、`os.posix_spawn[p]`：程式是獨立的引數，argv[0] 只是顯示名稱。程式被污染，或程式是 shell／直譯器
        而後面的引數被污染時才算（與引數清單相同的規則）。
        `os.exec*`, `os.spawn*`, `os.posix_spawn[p]`: the program is a separate argument and argv[0] is only a display
        name. It counts when the program is tainted, or the program is a shell / interpreter with a tainted later
        argument (the same rule as an argument list)."""
        prog_pos, form, has_env = _SPAWN_SINKS[dotted]
        args = list(node.args)
        if len(args) <= prog_pos:
            return None
        program = args[prog_pos]
        if self._expr_tainted(program, tainted, aliases):
            return _HIGH
        if form == "l":
            rest = args[prog_pos + 1:len(args) - 1 if has_env else len(args)]
            if any(isinstance(a, ast.Starred) for a in rest):
                return self._opaque_args_verdict(program, rest, tainted, aliases)
            return self._argv_verdict([program] + rest[1:], tainted, aliases)
        argv = args[prog_pos + 1] if len(args) > prog_pos + 1 else None
        lists: Optional[List[ast.expr]] = None
        if argv is None:
            return self._argv_verdict([program], tainted, aliases)
        if isinstance(argv, (ast.List, ast.Tuple)):
            lists = [argv]
        elif isinstance(argv, ast.Name) and index is not None and not index.mutated_with_taint(argv.id):
            lists = index.literals(argv.id) or None
        if lists is None:
            return self._opaque_args_verdict(program, [argv], tainted, aliases)
        return _max_severity(self._argv_verdict([program] + list(lst.elts[1:]), tainted, aliases)  # type: ignore[attr-defined]
                             for lst in lists)

    def _opaque_args_verdict(self, program: ast.expr, args: List[ast.expr], tainted: Set[str],
                             aliases: Dict[str, str]) -> Optional[str]:
        """argv 內容無法確定（非字面值）但被污染：程式是 shell／直譯器／包裝程式時 HIGH，無法確定的程式 MEDIUM，其他已知程式不算。
        The argv contents cannot be determined (non-literal) but are tainted: HIGH when the program is a shell /
        interpreter / wrapper, MEDIUM for a program that cannot be determined, nothing for any other known program."""
        if not any(self._expr_tainted(a, tainted, aliases) for a in args):
            return None
        names = self._program_names(program, aliases)
        if names is None:
            return _MEDIUM
        risky = any(n in _WRAPPERS or n in _RUNNERS or n == "find" or self._interpreter_spec(n) is not None for n in names)
        return _HIGH if risky else None

    # --- VH-AI-006：argv 的程式解析 ---
    # --- VH-AI-006: resolving the argv program ---------------------------------------------------------------------

    def _argv_verdict(self, elts: List[ast.expr], tainted: Set[str], aliases: Dict[str, str], stdin: bool = False,
                      depth: int = 0) -> Optional[str]:
        """字面值引數清單（不經 shell）的判斷：程式（argv[0]）被污染是 HIGH；程式是 shell／直譯器時依其命令列語意判斷
        （`_interpreter_verdict`）；包裝前綴與執行器（`sudo -u bob --`、`timeout -s KILL 5`、`env -S`、`xargs -I{}`、
        `uv run`、`docker exec ctr`、`kubectl exec pod --`、`find -exec`）依各自的選項表跳過，改看被包住的程式；
        `command -v` 只是查詢，不是執行點；其他已知程式不算（`["git", "checkout", "--", branch]`）。
        程式的解析：基底檔名比對去掉路徑與 `.exe`；`sys.executable` 是 Python；只綁定到字串常數的名稱（`SHELL = "bash"`、
        `GIT = shutil.which("git")`）以那些字串判斷；其他非字面值的程式無法確定（`_unknown_program_verdict`）。
        The verdict on a literal argument list (no shell): a tainted program (argv[0]) is HIGH; a shell / interpreter
        is judged by its command-line semantics (`_interpreter_verdict`); wrapper prefixes and runners (`sudo -u bob --`,
        `timeout -s KILL 5`, `env -S`, `xargs -I{}`, `uv run`, `docker exec ctr`, `kubectl exec pod --`, `find -exec`)
        are skipped by their option tables in favor of the wrapped program; `command -v` only looks a program up and is
        no sink; any other known program does not count (`["git", "checkout", "--", branch]`).
        Resolving the program: basenames are matched without the path and `.exe`; `sys.executable` is Python; a name
        only ever bound to string constants (`SHELL = "bash"`, `GIT = shutil.which("git")`) is judged by those strings;
        any other non-literal program cannot be determined (`_unknown_program_verdict`)."""
        if not elts:
            return None
        if depth > 8:
            return _HIGH if stdin or any(self._expr_tainted(e, tainted, aliases) for e in elts) else None
        program = elts[0]
        if self._expr_tainted(program, tainted, aliases):
            return _HIGH
        names = self._program_names(program, aliases)
        if names is None:
            return self._unknown_program_verdict(elts[1:], tainted, aliases, stdin)
        return _max_severity(self._named_program_verdict(name, elts, tainted, aliases, stdin, depth) for name in names)

    def _named_program_verdict(self, name: str, elts: List[ast.expr], tainted: Set[str], aliases: Dict[str, str],
                               stdin: bool, depth: int) -> Optional[str]:
        if name in _WRAPPERS:
            return self._wrapper_verdict(_WRAPPERS[name], elts, 1, tainted, aliases, stdin, depth)
        if name in _RUNNERS:
            return self._runner_verdict(_RUNNERS[name], elts, 1, tainted, aliases, stdin, depth)
        if name == "find":
            return self._find_verdict(elts, tainted, aliases, depth)
        if name == "git":
            return self._git_verdict(elts, tainted, aliases)
        spec = self._interpreter_spec(name)
        if spec is not None:
            return self._interpreter_verdict(spec, elts, 1, tainted, aliases, stdin, depth)
        return None

    @staticmethod
    def _interpreter_spec(name: str) -> Optional[_Options]:
        return next((spec for pattern, spec in _INTERPRETERS if pattern.fullmatch(name)), None)

    def _program_names(self, program: ast.expr, aliases: Dict[str, str]) -> Optional[List[str]]:
        """argv 程式元素可能的基底檔名（小寫、去掉 `.exe`／`.cmd`／`.bat`）；無法確定時回傳 None。
        The possible basenames of an argv program element (lower-case, `.exe` / `.cmd` / `.bat` removed); None when it
        cannot be determined."""
        text = self._const_str(program)
        if text is not None:
            return [self._program_basename(text)]
        if isinstance(program, ast.Name) and program.id in self._str_consts:
            return sorted({self._program_basename(v) for v in self._str_consts[program.id]})
        if isinstance(program, (ast.Name, ast.Attribute)) and self._dotted(program, aliases) == "sys.executable":
            return ["python"]
        return None

    @staticmethod
    def _program_basename(text: str) -> str:
        base = re.split(r"[\\/]", text.strip())[-1].lower()
        for suffix in (".exe", ".cmd", ".bat", ".com"):
            if base.endswith(suffix):
                return base[:-len(suffix)]
        return base

    def _unknown_program_verdict(self, rest: List[ast.expr], tainted: Set[str], aliases: Dict[str, str],
                                 stdin: bool) -> Optional[str]:
        """無法確定的程式（參數、屬性、呼叫結果、`TOOL = os.environ.get(...)`）：後面的引數或標準輸入被污染時記為 MEDIUM；
        被污染的元素緊接在程式碼選項（`-c`、`-e`、`--eval`、`/c`、`-Command`）之後時看起來像直譯器，記為 HIGH。
        A program that cannot be determined (a parameter, an attribute, a call result, `TOOL = os.environ.get(...)`):
        MEDIUM when a later argument or the standard input is tainted; HIGH when a tainted element follows right after
        a code option (`-c`, `-e`, `--eval`, `/c`, `-Command`), since it then looks like an interpreter."""
        hits = [k for k, e in enumerate(rest) if self._expr_tainted(e, tainted, aliases)]
        if not hits and not stdin:
            return None
        if any(k > 0 and (self._const_str(rest[k - 1]) or "").lower() in _GENERIC_CODE_FLAGS for k in hits):
            return _HIGH
        return _MEDIUM

    @staticmethod
    def _classify_option(text: str, spec: _Options) -> Tuple[str, Optional[str]]:
        """一個選項元素的種類與附帶的值：("end", None) 是 `--`；"code"／"module"／"script"／"stdin"／"split"／"lookup"／
        "replace"／"entrypoint"／"value"／"flag"。支援 `--opt=value`、`-uvalue` 與 getopt 風格的短選項串（`-ec`、`-ne`）。
        The kind of an option element and its attached value: ("end", None) is `--`; "code" / "module" / "script" /
        "stdin" / "split" / "lookup" / "replace" / "entrypoint" / "value" / "flag". `--opt=value`, `-uvalue` and
        getopt-style short clusters (`-ec`, `-ne`) are supported."""
        key = text.lower() if spec.ci else text
        if key == "--":
            return "end", None
        kinds = (("code", spec.code), ("module", spec.module), ("script", spec.script), ("stdin", spec.stdin),
                 ("split", spec.split), ("lookup", spec.lookup), ("replace", spec.replace),
                 ("entrypoint", spec.entrypoint), ("value", spec.value))
        attached: Optional[str] = None
        if key.startswith("--") and "=" in key:
            key, attached = key.split("=", 1)
            attached = text.split("=", 1)[1]
        for kind, options in kinds:
            if key in options:
                return kind, attached
        if key.startswith("--"):
            return ("value" if spec.long_values and key not in spec.flags and attached is None else "flag"), attached
        if spec.numeric and _NUMERIC_OPTION_RE.fullmatch(key):
            return "flag", None
        if not spec.ci and key.startswith("-") and len(key) > 2:
            # getopt 短選項串：第一個帶值（或是程式碼）的字母之後的部分就是它的值 ／ a getopt short cluster: what
            # follows the first letter taking a value (or code) is that value
            for pos in range(1, min(len(key), 32)):  # 短選項串很短 ／ short clusters are short
                option = "-" + key[pos]
                rest = text[pos + 1:] or None
                for kind, options in kinds:
                    if option in options:
                        if kind == "stdin":
                            return kind, None
                        return kind, rest
        return "flag", None

    def _wrapper_verdict(self, spec: _Options, elts: List[ast.expr], j: int, tainted: Set[str],
                         aliases: Dict[str, str], stdin: bool, depth: int) -> Optional[str]:
        """包裝前綴（或執行器子命令）：依選項表跳過它的選項、選項值與固定的位置引數（`timeout` 的時限、`docker exec` 的容器），
        `--` 結束選項，然後判斷被包住的程式。被污染的選項值記為 MEDIUM；被污染的元素出現在可能是程式或選項的位置時是 HIGH。
        A wrapper prefix (or runner subcommand): its options, option values and fixed positionals (`timeout`'s
        duration, `docker exec`'s container) are skipped by the option table, `--` ends the options, and then the
        wrapped program is judged. A tainted option value is MEDIUM; a tainted element where a program or an option
        may stand is HIGH."""
        worst: Optional[str] = None
        positionals = spec.positionals
        ended = False
        replace: Optional[str] = None
        splits = 0
        entrypoint: Optional[ast.expr] = None
        elts = list(elts)
        while j < len(elts):
            e = elts[j]
            text = self._const_str(e)
            is_option = not ended and text is not None and len(text) > 1 and text.startswith("-")
            if self._expr_tainted(e, tainted, aliases):
                if positionals and not is_option:
                    worst = _max_severity([worst, _HIGH if spec.positional_high else _MEDIUM])
                    positionals -= 1
                    j += 1
                    continue
                return _HIGH  # 被污染的元素可能就是被包住的程式 ／ a tainted element may be the wrapped program itself
            if is_option:
                kind, attached = self._classify_option(text, spec)  # type: ignore[arg-type]
                value = elts[j + 1] if attached is None and j + 1 < len(elts) else None
                step = 1 if attached is not None or kind in ("flag", "end", "stdin") else 2
                if kind == "end":
                    ended = True
                elif kind == "lookup":
                    return worst  # `command -v x` 只是查詢 ／ `command -v x` only looks the program up
                elif kind == "code":
                    # 包裝程式自己以 shell 執行的命令字串（`flock -c`、`runuser -c`、`npx -c`、`script -c`）
                    # A command string the wrapper itself runs through a shell (`flock -c`, `runuser -c`, `npx -c`, `script -c`)
                    if value is not None and self._expr_tainted(value, tainted, aliases):
                        return _HIGH
                    return worst
                elif kind == "split":
                    # `env -S "bash -c ..."`：以空白切開的字串取代這個選項，再繼續解析 ／ the whitespace-split string
                    # replaces the option and parsing continues
                    words = attached if attached is not None else self._const_str(value) if value is not None else None
                    if words is None:
                        if value is not None and self._expr_tainted(value, tainted, aliases):
                            return _HIGH
                        return worst
                    splits += 1
                    if splits > 8:  # 病態的巢狀 `-S` ／ pathologically nested `-S`
                        return _HIGH if any(self._expr_tainted(x, tainted, aliases) for x in elts[j:]) else worst
                    elts[j:j + step] = [ast.Constant(value=w) for w in words.split()]
                    continue
                elif kind == "entrypoint":
                    entrypoint = ast.Constant(value=attached) if attached is not None else value
                    if entrypoint is not None and self._expr_tainted(entrypoint, tainted, aliases):
                        return _HIGH
                elif kind == "replace":
                    if attached is not None:
                        replace = attached
                    elif text == "-I":
                        replace = self._const_str(value) if value is not None else None
                    else:
                        replace, step = "{}", 1
                elif kind == "value" and value is not None and self._expr_tainted(value, tainted, aliases):
                    worst = _max_severity([worst, _MEDIUM])
                j += step
                continue
            if spec.assign and not ended and text is not None and _ASSIGNMENT_RE.fullmatch(text):
                j += 1
                continue
            if positionals:
                positionals -= 1
                j += 1
                continue
            break
        child = elts[j:]
        if entrypoint is not None:
            child = [entrypoint] + child
        if spec.first == "none" or not child:
            return worst
        child_stdin = stdin
        if spec.replace:
            # xargs：子程序的標準輸入不是我們的；被污染的輸入項目附加成引數，有 `-I` 時代入含替換字串的元素
            # xargs: the child's stdin is not ours; tainted input items are appended as arguments, or with `-I`
            # substituted into the elements containing the replace string
            child_stdin = False
            if stdin:
                mark = ast.Name(id=_TAINT_MARK, ctx=ast.Load())
                if replace:
                    child = [mark if replace in (self._const_str(c) or "") else c for c in child]
                else:
                    child = child + [mark]
        return _max_severity([worst, self._argv_verdict(child, tainted, aliases, child_stdin, depth + 1)])

    def _runner_verdict(self, spec: _Options, elts: List[ast.expr], j: int, tainted: Set[str],
                        aliases: Dict[str, str], stdin: bool, depth: int) -> Optional[str]:
        """以子命令執行另一個程式的工具（`uv run`、`docker exec`、`kubectl exec`）：跳過全域選項，比對子命令；
        其他子命令（`docker build`、`uv pip`）不執行 argv 中的程式。
        A tool that runs another program through a subcommand (`uv run`, `docker exec`, `kubectl exec`): global
        options are skipped and the subcommand matched; other subcommands (`docker build`, `uv pip`) run no program
        from the argv."""
        worst: Optional[str] = None
        while j < len(elts):
            e = elts[j]
            text = self._const_str(e)
            if self._expr_tainted(e, tainted, aliases):
                return _HIGH
            if text is None:
                return worst
            if text.startswith("-") and len(text) > 1:
                kind, attached = self._classify_option(text, spec)
                if kind == "value" and attached is None:
                    if j + 1 < len(elts) and self._expr_tainted(elts[j + 1], tainted, aliases):
                        worst = _max_severity([worst, _MEDIUM])
                    j += 2
                else:
                    j += 1
                continue
            sub = spec.subcommands.get(text)
            if sub is None:
                return worst
            if sub.subcommands:
                return _max_severity([worst, self._runner_verdict(sub, elts, j + 1, tainted, aliases, stdin, depth)])
            return _max_severity([worst, self._wrapper_verdict(sub, elts, j + 1, tainted, aliases, stdin, depth)])
        return worst

    def _git_verdict(self, elts: List[ast.expr], tainted: Set[str], aliases: Dict[str, str]) -> Optional[str]:
        """git：子命令之前被污染的全域選項值（`git -c core.sshCommand=<x> fetch`）是 HIGH，`--upload-pack`／
        `--receive-pack`／`--exec` 的值被污染也是；其他引數（分支、路徑、被污染的子命令本身）不算。
        git: a tainted global option value before the subcommand (`git -c core.sshCommand=<x> fetch`) is HIGH, and so
        is a tainted value of `--upload-pack` / `--receive-pack` / `--exec`; other arguments (branches, paths, a
        tainted subcommand itself) do not count."""
        j = 1
        while j < len(elts):  # 全域選項 ／ global options
            text = self._const_str(elts[j])
            if text is None or not text.startswith("-") or text == "--":
                break
            if text in _GIT_GLOBAL_VALUES:
                if j + 1 < len(elts) and self._expr_tainted(elts[j + 1], tainted, aliases):
                    return _HIGH
                j += 2
            else:
                j += 1
        for k in range(j + 1, len(elts)):
            e = elts[k]
            if not self._expr_tainted(e, tainted, aliases):
                continue
            before = self._const_str(elts[k - 1]) or ""
            head = e.values[0] if isinstance(e, ast.JoinedStr) and e.values else None
            prefix = self._const_str(head) or ""
            if before in _GIT_COMMAND_OPTIONS or prefix.startswith(tuple(o + "=" for o in _GIT_COMMAND_OPTIONS)):
                return _HIGH
        return None

    def _find_verdict(self, elts: List[ast.expr], tainted: Set[str], aliases: Dict[str, str],
                      depth: int) -> Optional[str]:
        """`find ... -exec prog args ;`：`-exec`／`-execdir`／`-ok`／`-okdir` 之後到 `;`／`+` 為止是被執行的 argv。
        `find ... -exec prog args ;`: after `-exec` / `-execdir` / `-ok` / `-okdir`, up to `;` / `+`, is the argv run."""
        worst: Optional[str] = None
        k = 1
        while k < len(elts):
            if self._const_str(elts[k]) in _FIND_EXEC:
                end = k + 1
                while end < len(elts) and self._const_str(elts[end]) not in (";", "+"):
                    end += 1
                worst = _max_severity([worst, self._argv_verdict(elts[k + 1:end], tainted, aliases, False, depth + 1)])
                k = end
            k += 1
        return worst

    def _interpreter_verdict(self, spec: _Options, elts: List[ast.expr], j: int, tainted: Set[str],
                             aliases: Dict[str, str], stdin: bool, depth: int) -> Optional[str]:
        """shell／直譯器後面的元素：程式碼選項（`-c`、`-e`、`--eval`、`/c`、`-Command`）的值被污染是 HIGH（`cmd /c` 與
        `pwsh -Command` 之後的所有元素都併入命令）；腳本路徑或 `-m 模組` 只有本身被污染才算，其後的引數只是腳本的 argv；
        沒有腳本也沒有程式碼時（或 `-`、`bash -s`）程式從標準輸入讀取，標準輸入被污染就是 HIGH。
        The elements after a shell / interpreter: a tainted value of a code option (`-c`, `-e`, `--eval`, `/c`,
        `-Command`) is HIGH (with `cmd /c` and `pwsh -Command` every later element joins the command); a script path or
        `-m module` counts only when it is tainted itself, the arguments after it being just the script's argv; with
        neither a script nor code (or with `-`, `bash -s`) the program is read from standard input, so tainted standard
        input is HIGH."""
        first = spec.first
        ended = False
        while j < len(elts):
            e = elts[j]
            if self._expr_tainted(e, tainted, aliases):
                return _HIGH  # 被污染的選項、腳本路徑或程式碼 ／ a tainted option, script path or code
            text = self._const_str(e)
            is_option = not ended and text is not None and len(text) > 1 \
                and (text.startswith("-") or (spec.ci and text.startswith("/")))
            if is_option:
                kind, attached = self._classify_option(text, spec)  # type: ignore[arg-type]
                value = elts[j + 1] if attached is None and j + 1 < len(elts) else None
                value_tainted = value is not None and self._expr_tainted(value, tainted, aliases)
                if kind == "end":
                    ended = True
                    j += 1
                    continue
                if kind == "code":
                    rest = elts[j + (1 if attached is not None else 2):]
                    if value_tainted or (spec.rest_code and any(self._expr_tainted(x, tainted, aliases) for x in rest)):
                        return _HIGH
                    return None
                if kind in ("module", "script"):
                    return _HIGH if value_tainted else None
                if kind == "stdin":
                    return _HIGH if stdin else None
                if kind in ("value", "split", "entrypoint", "replace", "lookup") and attached is None:
                    if value_tainted:
                        return _HIGH  # 例如 `node -r <模組>` 會載入程式碼 ／ e.g. `node -r <module>` loads code
                    j += 2
                    continue
                j += 1
                continue
            # 第一個位置引數 ／ the first positional
            if first == "subcommand":
                sub = spec.subcommands.get(text or "")
                if sub is None:
                    return None
                if sub.runner:
                    return self._wrapper_verdict(sub, elts, j + 1, tainted, aliases, stdin, depth)
                return self._interpreter_verdict(sub, elts, j + 1, tainted, aliases, stdin, depth)
            if first == "user":
                first = "script"
                j += 1
                continue
            if first == "skip":  # 資料庫名稱、使用者等位置引數 ／ positionals such as a database or user name
                j += 1
                continue
            rest = elts[j + 1:]
            if first == "command":
                return _HIGH if any(self._expr_tainted(x, tainted, aliases) for x in rest) else None
            if first == "host":
                if not rest:
                    return _HIGH if stdin else None
                return _HIGH if any(self._expr_tainted(x, tainted, aliases) for x in rest) else None
            if first == "code" and spec.rest_code:
                return _HIGH if any(self._expr_tainted(x, tainted, aliases) for x in rest) else None
            return None  # 未被污染的腳本路徑或程式碼 ／ an untainted script path or code
        # 沒有腳本也沒有程式碼：程式從標準輸入讀取 ／ neither a script nor code: the program is read from stdin
        return _HIGH if stdin else None
    @staticmethod
    def _sink_first_arg(node: ast.Call) -> Optional[ast.expr]:
        """執行點的命令／程式碼引數：第一個位置引數，沒有位置引數時是 `args=`／`command=`／`sql=` 等關鍵字。
        The sink's command / code argument: the first positional, or without positionals an `args=` /
        `command=` / `sql=`-style keyword."""
        if node.args:
            return node.args[0]
        return next((k.value for name in _SINK_ARG_KEYWORDS for k in node.keywords if k.arg == name), None)


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

    def _tick(self) -> None:
        """計一單位工作；每 1024 單位檢查一次目前檔案的分析期限，超過時拋出 `_ScanBudgetExceeded`。
        Counts one unit of work; every 1024 units the current file's analysis deadline is checked, raising
        `_ScanBudgetExceeded` once it has passed."""
        self._ticks += 1
        if not self._ticks & 1023 and self._deadline is not None and time.monotonic() > self._deadline:
            raise _ScanBudgetExceeded("analysis time cap exceeded")

    def _expr_tainted(self, expr: ast.AST, tainted: Set[str], aliases: Dict[str, str]) -> bool:
        self._tick()
        for n in ast.walk(expr):
            if isinstance(n, ast.Name):
                if n.id in tainted:
                    return True
            elif isinstance(n, ast.Attribute):
                if self._key_ref(n) in tainted:
                    return True
            elif isinstance(n, ast.Call) and self._is_llm_source(n, aliases):
                return True
        return False

    def _expr_refs(self, expr: ast.AST, aliases: Dict[str, str]) -> Tuple[bool, Set[str]]:
        """運算式是否含模型輸出來源，以及它引用的名稱／點號屬性（`_expr_tainted` 的定點用版本）。
        Whether the expression holds a model-output source, and the names / dotted attributes it references (the
        fixpoint form of `_expr_tainted`)."""
        refs, calls = self._value_info(expr)
        return any(self._is_llm_source(c, aliases) for c in calls), refs

    def _value_info(self, expr: ast.AST) -> Tuple[Set[str], List[ast.Call]]:
        """運算式引用的名稱／點號屬性與其中的呼叫節點；檔案掃描期間依節點備忘，讓用戶端尋找與污染定點共用同一次走訪。
        The names / dotted attributes an expression references and the call nodes in it; memoized per node during a
        file scan, so the client finder and the taint fixpoint share one walk."""
        memo = self._info_memo if self._deadline is not None else None
        if memo is not None and id(expr) in memo:
            return memo[id(expr)]
        self._tick()
        refs: Set[str] = set()
        calls: List[ast.Call] = []
        for n in ast.walk(expr):
            if isinstance(n, ast.Name):
                refs.add(n.id)
            elif isinstance(n, ast.Attribute):
                ref = self._key_ref(n)
                if ref:
                    refs.add(ref)
            elif isinstance(n, ast.Call):
                calls.append(n)
        if memo is not None:
            memo[id(expr)] = (refs, calls)
        return refs, calls

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
