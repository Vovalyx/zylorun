"""Log & source analyzer.

Reads pasted logs, uploaded files and unpacked ZIP archives and reports:

* real errors in logs: Python / JavaScript / Java / Go stack traces, failed
  builds and tests, process crashes and non-zero exits, resource failures
  (memory, disk, permissions, network), HTTP 5xx and rejected requests,
  attack payloads and brute-force attempts, and lines logged at
  WARNING / ERROR / CRITICAL level;
* real risks in source and config files: exposed credentials, SQL / command /
  code injection, XSS, unsafe deserialization, disabled TLS checks, weak
  hashes, debug mode and wildcard CORS.

Design rules that keep results honest:

* A word is not an error. "error", "token" or "password" appearing in a line
  is never enough on its own; each rule matches a concrete structure (a stack
  trace, a level field, a status code, a dangerous call with dynamic input).
* One finding per line: the most severe rule wins, so a line is never counted
  twice. Repeated identical log events are merged and counted.
* Secret values are masked in every result.
* Matches inside string literals, comments and test files are not treated as
  live vulnerabilities (credentials are the exception: a real key is exposed
  wherever it is written).
"""
from __future__ import annotations

import json
import math
import os
import re
from collections import OrderedDict
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import unquote_plus, urlparse

SEVERITY_RANK = {"Critical": 3, "Warning": 2, "Info": 1}
MAX_FINDINGS = 500
MAX_LINE_CHARS = 4000          # longer lines are cut before matching (minified bundles, base64 blobs)
MINIFIED_LINE_CHARS = 1500     # code lines longer than this are treated as generated / minified
DEFAULT_SOURCE = "pasted input"

FILE_HEADER = re.compile(r"^--- File: (.+?) ---\s*$")

# --------------------------------------------------------------------------- file classification

CODE_EXTENSIONS = {
    ".py": "py", ".pyw": "py",
    ".js": "js", ".jsx": "js", ".ts": "js", ".tsx": "js", ".mjs": "js", ".cjs": "js",
    ".vue": "js", ".svelte": "js", ".html": "js", ".htm": "js",
    ".java": "java", ".kt": "java", ".scala": "java",
    ".go": "go", ".rb": "other", ".php": "other", ".cs": "other", ".c": "other", ".h": "other",
    ".cpp": "other", ".hpp": "other", ".rs": "other", ".swift": "other",
    ".sh": "shell", ".bash": "shell", ".zsh": "shell", ".ps1": "shell", ".sql": "sql",
}
CONFIG_EXTENSIONS = {".json", ".yml", ".yaml", ".toml", ".ini", ".cfg", ".conf", ".properties", ".env", ".tf", ".xml"}
LOG_EXTENSIONS = {".log", ".out", ".err", ".txt", ".trace"}
DOC_EXTENSIONS = {".md", ".markdown", ".rst", ".adoc"}
SKIP_NAMES = {
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "pipfile.lock",
    "composer.lock", "cargo.lock", "go.sum", "gemfile.lock",
}
TEST_DIRS = {"tests", "test", "__tests__", "spec", "specs", "fixtures", "testdata", "__mocks__", "e2e", "cypress"}


def classify_file(name: str) -> Tuple[str, str]:
    """Returns (kind, language). kind is code | config | log | doc | skip | unknown."""
    base = name.replace("\\", "/").rstrip("/").split("/")[-1].lower()
    if base in SKIP_NAMES or base.endswith((".min.js", ".min.css", ".map")):
        return "skip", ""
    if base == ".env" or base.startswith(".env.") or base.endswith(".env"):
        return "config", "env"
    if base.startswith("dockerfile") or base in {"docker-compose.yml", "docker-compose.yaml", "procfile", "makefile"}:
        return "config", "other"
    ext = os.path.splitext(base)[1]
    if ext in CODE_EXTENSIONS:
        return "code", CODE_EXTENSIONS[ext]
    if ext in CONFIG_EXTENSIONS:
        return "config", "env" if ext in {".properties", ".ini", ".cfg", ".conf"} else "other"
    if ext in LOG_EXTENSIONS:
        return "log", ""
    if ext in DOC_EXTENSIONS:
        return "doc", ""
    if ext in {".css", ".scss", ".less", ".svg", ".csv", ".lock"}:
        return "skip", ""
    return "unknown", ""


def is_test_path(name: str) -> bool:
    """Test code, fixtures, and example/template config files (.env.example, settings.sample.py)."""
    norm = name.replace("\\", "/").lower()
    parts = [p for p in norm.split("/") if p]
    base = parts[-1] if parts else ""
    if any(p in TEST_DIRS for p in parts[:-1]):
        return True
    stem = os.path.splitext(base)[0]
    return (
        bool(re.search(r"(?:^|[_.-])(?:e2e|tests?|spec|fixtures?|example|sample|template|dist)(?:[_.-]|$)", base))
        or base.startswith("test_") or base == "conftest.py"
        or bool(re.search(r"[._-](test|spec)\.[a-z0-9]+$", base))
        or base.endswith(("_test.py", "_test.go", "tests.py"))
    )


_CODE_LINE = re.compile(
    r"^\s*(?:import\s|from\s+\S+\s+import\s|def\s|class\s|function\s|const\s|let\s|var\s|export\s|return\b|"
    r"if\s*\(|for\s*\(|while\s*\(|#include|package\s|public\s|private\s|async\s|await\s|@\w+|\}|\{$)"
    r"|[;{]\s*$|\)\s*:\s*$"
)
_LOG_LINE = re.compile(
    r"^\s*(?:\d{4}[-/]\d{2}[-/]\d{2}|\[\w+\]|\w{3}\s+\d{1,2}\s+\d{2}:\d{2}|\d{1,3}(?:\.\d{1,3}){3}\s|"
    r"(?:INFO|WARN|WARNING|ERROR|DEBUG|FATAL|CRITICAL|TRACE)\b|Traceback|npm (?:ERR|WARN)|\s+at\s|==>)"
)


def looks_like_log(lines: List[str]) -> bool:
    """Strong log signals and little code: a stack trace, or most lines timestamped / levelled."""
    sample = [l for l in lines[:400] if l.strip()]
    if not sample or looks_like_code(lines):
        return False
    if any(PY_TRACEBACK_START.match(l) or GO_PANIC.match(l.strip()) for l in sample):
        return True
    log = sum(1 for l in sample if _LOG_LINE.search(l) or _TIMESTAMP_PREFIX.match(l))
    return log >= max(3, 0.6 * len(sample))


def looks_like_code(lines: List[str]) -> bool:
    sample = [l for l in lines[:400] if l.strip()]
    if not sample:
        return False
    code = sum(1 for l in sample if _CODE_LINE.search(l))
    log = sum(1 for l in sample if _LOG_LINE.search(l))
    return code >= max(2, 0.3 * len(sample)) and code > log


_GIT_COMMIT = re.compile(r"^commit [0-9a-f]{7,40}\b")
_GIT_ONELINE = re.compile(r"^[0-9a-f]{7,12} \S")


def looks_like_git_history(lines: List[str]) -> bool:
    """`git log` output is a history of commit messages (prose), not a running system's log."""
    sample = [l for l in lines[:400] if l.strip()]
    if not sample:
        return False
    commits = sum(1 for l in sample if _GIT_COMMIT.match(l))
    authors = sum(1 for l in sample if l.startswith("Author: "))
    oneline = sum(1 for l in sample if _GIT_ONELINE.match(l))
    return (commits >= 1 and authors >= 1) or oneline >= max(3, 0.8 * len(sample))


# --------------------------------------------------------------------------- helpers

_TIMESTAMP_PREFIX = re.compile(
    r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?[ \t]?"
)


def strip_timestamp(line: str) -> str:
    """Removes a leading ISO timestamp (Render, Docker, Kubernetes) but keeps indentation after it."""
    return _TIMESTAMP_PREFIX.sub("", line, count=1)


def in_string_literal(line: str, pos: int) -> bool:
    """True when position `pos` lies inside a single-line ' " or ` string literal."""
    quote = None
    i = 0
    while i < pos and i < len(line):
        ch = line[i]
        if quote:
            if ch == "\\":
                i += 2
                continue
            if ch == quote:
                quote = None
        elif ch in ("'", '"', "`"):
            quote = ch
        elif ch == "#" and not quote:
            # Python / shell comment start: everything after is not code
            return True
        i += 1
    return quote is not None


def is_comment_line(stripped: str, lang: str) -> bool:
    if stripped.startswith(("//", "/*", "*", "<!--", "-->")):
        return True
    if stripped.startswith("#") and lang in ("py", "shell", "env", "other", "unknown", ""):
        return not stripped.startswith(("#include", "#!"))
    if stripped.startswith("--") and lang == "sql":
        return True
    return False


def mask(value: str) -> str:
    if len(value) <= 8:
        return "*" * len(value)
    keep = 4 if len(value) >= 16 else 2
    return value[:keep] + "*" * (len(value) - 2 * keep) + value[-keep:]


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts: Dict[str, int] = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    return -sum(c / len(value) * math.log2(c / len(value)) for c in counts.values())


def char_classes(value: str) -> int:
    return sum(bool(re.search(p, value)) for p in (r"[a-z]", r"[A-Z]", r"\d", r"[^A-Za-z0-9]"))


def normalise_for_grouping(text: str) -> str:
    text = re.sub(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", "<id>", text, flags=re.I)
    text = re.sub(r"0x[0-9a-f]+", "<hex>", text, flags=re.I)
    return re.sub(r"\d+", "#", text).strip()[:200]


USER_INPUT = re.compile(
    r"\b(?:req|request)\.(?:body|query|params|args|form|values|json|data|files|cookies|headers|GET|POST|"
    r"get_json|path_params|query_params)\b"
    r"|(?<![\w.])input\s*\("
    r"|\b(?:sys|process)\.argv\b"
    r"|\blocation\.(?:search|hash|href|pathname)\b"
    r"|\bdocument\.(?:cookie|URL|referrer|location)\b"
    r"|\bwindow\.name\b|\bevent\.data\b"
    r"|\$_(?:GET|POST|REQUEST|COOKIE)\b"
    r"|\bctx\.(?:query|params|request\.body)\b"
)

SANITIZED = re.compile(r"DOMPurify|sanitiz|escape\(|escapeHtml|encodeURIComponent|bleach\.clean|markupsafe\.escape", re.I)

PLACEHOLDER_VALUE = re.compile(
    r"^(?:x+|\*+|\.+|-+|_+|0+)$|your|example|changeme|change[_-]?me|placeholder|dummy|sample|fake|"
    r"redacted|replace|insert|todo|<[^>]*>|\$\{[^}]*\}|\{\{[^}]*\}\}|%\([^)]*\)s|^\$[A-Z_]+$"
    r"|^(?:none|null|nil|true|false|undefined|password|passwd|pass|pw|pwd|secret|token|admin|string|value|user|username|dbname)$",
    re.I,
)
DOC_EXAMPLE_VALUE = re.compile(r"example|dummy|sample|fake|xxxx|placeholder|test", re.I)
HEADER_NAME_VALUE = re.compile(r"^(?:X-)?[A-Z][A-Za-z]*(?:-[A-Z][A-Za-z]*)+$")


def is_placeholder(value: str) -> bool:
    return bool(PLACEHOLDER_VALUE.search(value)) or bool(HEADER_NAME_VALUE.match(value))


# --------------------------------------------------------------------------- finding collection

class Collector:
    """Holds findings, enforces one finding per line, merges repeated log events."""

    def __init__(self) -> None:
        self.by_line: Dict[Tuple[str, int], Dict[str, Any]] = {}
        self.groups: "OrderedDict[Tuple[str, str, str], Dict[str, Any]]" = OrderedDict()
        self.aggregates: List[Dict[str, Any]] = []

    def add(self, *, file: str, line: int, severity: str, rule_id: str, category: str, title: str,
            detail: str = "", recommendation: str = "", matched_line: str = "", group: Optional[str] = None,
            context: Optional[List[str]] = None, priority: int = 0) -> None:
        finding = {
            "severity": severity, "rule_id": rule_id, "category": category, "title": title,
            "detail": detail, "recommendation": recommendation, "file": file, "line": line,
            "matched_line": matched_line.strip()[:300], "count": 1, "context": context or [],
            "_group": group, "_priority": priority,
        }
        key = (file, line)
        current = self.by_line.get(key)
        if current is not None:
            better = (SEVERITY_RANK[severity], priority) > (SEVERITY_RANK[current["severity"]], current["_priority"])
            if not better:
                return
        self.by_line[key] = finding

    def add_aggregate(self, **kwargs: Any) -> None:
        self.aggregates.append(kwargs)

    def results(self) -> List[Dict[str, Any]]:
        merged: "OrderedDict[Tuple[str, str, str], Dict[str, Any]]" = OrderedDict()
        for (file, line), f in sorted(self.by_line.items(), key=lambda kv: (kv[0][0], kv[0][1])):
            if f["_group"] is None:
                merged[(file, f["rule_id"], f"line:{line}")] = f
                continue
            gkey = (file, f["rule_id"], f["_group"])
            if gkey in merged:
                merged[gkey]["count"] += 1
            else:
                merged[gkey] = f
        out = list(merged.values())
        for agg in self.aggregates:
            out.append({
                "severity": agg["severity"], "rule_id": agg["rule_id"], "category": agg["category"],
                "title": agg["title"], "detail": agg.get("detail", ""), "recommendation": agg.get("recommendation", ""),
                "file": agg["file"], "line": agg["line"], "matched_line": agg.get("matched_line", "")[:300],
                "count": agg.get("count", 1), "context": agg.get("context", []), "_group": None, "_priority": 0,
            })
        # Most severe first; within a severity, root causes (stack traces, priority 5) come
        # before their after-effects such as "process exited with code 1"; then by position.
        out.sort(key=lambda f: (-SEVERITY_RANK[f["severity"]], f["file"], -f["_priority"], f["line"]))
        for f in out:
            f.pop("_group", None)
            f.pop("_priority", None)
            where = f"{f['file']}:{f['line']}"
            detail = f" — {f['detail']}" if f["detail"] else ""
            repeat = f" (seen {f['count']} times)" if f["count"] > 1 else ""
            f["message"] = f"{where} — {f['title']}{detail}{repeat}"
        return out


# --------------------------------------------------------------------------- log rules

PY_TRACEBACK_START = re.compile(r"^\s*Traceback \(most recent call last\):\s*$")
PY_FRAME = re.compile(r'^\s*File "([^"]+)", line (\d+)(?:, in (.+))?\s*$')
PY_EXCEPTION = re.compile(
    r"^((?:[A-Za-z_]\w*\.)*[A-Za-z_]\w*(?:Error|Exception|Exit|Interrupt|Warning|Failure|Fault))(?::\s?(.*))?$"
)
PY_CHAIN = re.compile(r"^\s*(?:During handling of the above exception|The above exception was the direct cause)")
LIB_PATH = re.compile(r"site-packages|dist-packages|/lib/python\d|<frozen|/usr/local/bin/|\\lib\\", re.I)

EXC_HEADER = re.compile(
    r"^(?:Uncaught\s+(?:\(in promise\)\s+)?)?(?:Exception in thread \"[^\"]*\"\s+|Caused by:\s+)?"
    r"((?:[A-Za-z_$][\w$]*\.)*(?:[A-Z][\w$]*)?(?:Error|Exception))(?:\s*\[[\w-]+\])?(?::\s?(.*))?$"
)
JS_FRAME = re.compile(r"^\s+at\s+(?:(.+?)\s+\()?((?:[A-Za-z]:)?[^\s()]+?):(\d+):(\d+)\)?\s*$")
JAVA_FRAME = re.compile(r"^\s*at\s+([\w$.<>]+)\(([^)]*)\)\s*$")
JAVA_CAUSE = re.compile(r"^\s*Caused by:\s+(.+)$")
JAVA_MORE = re.compile(r"^\s*\.\.\. \d+ more\s*$")
GO_PANIC = re.compile(r"^panic: (.+)$")
GO_FRAME_FILE = re.compile(r"^\s+(\S+\.go):(\d+)")

NPM_ERR = re.compile(r"^npm (?:ERR!|error)\s?(.*)$")

OOM = re.compile(
    r"out of memory|OOMKilled|Killed process \d+|heap out of memory|\bMemoryError\b|Cannot allocate memory"
    r"|^Killed$|exit code 137|std::bad_alloc", re.I)
DISK = re.compile(r"\bENOSPC\b|No space left on device|Disk quota exceeded", re.I)
PERMISSION = re.compile(r"\bEACCES\b|\bEPERM\b|Permission denied|PermissionError|Access is denied", re.I)
NETWORK = re.compile(
    r"net::(ERR_[A-Z_]+)|\b(E(?:CONNREFUSED|CONNRESET|TIMEDOUT|NOTFOUND|AI_AGAIN|HOSTUNREACH|NETUNREACH|PIPE))\b"
    r"|(Connection refused|Connection reset by peer|Connection timed out|could not connect to (?:server|database|host)"
    r"|Name or service not known|Temporary failure in name resolution|Network is unreachable|No route to host"
    r"|getaddrinfo \w+|Failed to fetch|CERTIFICATE_VERIFY_FAILED|TLS handshake timeout|Read timed out"
    r"|ConnectTimeout|ReadTimeout|socket hang up)", re.I)
PROCESS_EXIT = re.compile(
    r"(?:exited with (?:status|code|exit code)|exit (?:status|code)|process completed with exit code"
    r"|command failed with exit code|returned non-zero exit status|terminated with exit code)\s*:?\s*(-?\d+)", re.I)
TS_ERROR = re.compile(r"^(.+?)(?:\((\d+),(\d+)\):| ?:(\d+):(\d+) -) error (TS\d+): (.+)$")
COMPILER_ERROR = re.compile(r"^(\S+?):(\d+)(?::(\d+))?: (?:fatal )?error(?:\[\w+\])?: (.+)$")
RUST_ERROR = re.compile(r"^error(?:\[E\d+\])?: (.+)$")
BUILD_FAILED = re.compile(
    r"\bBUILD (?:FAILED|FAILURE)\b|FAILURE: Build failed|Build failed with \d+ errors?|Compilation failed"
    r"|Failed to compile|^ERROR in |make(?:\[\d+\])?: \*\*\* .*Error \d+")
TEST_FAILED = re.compile(r"^FAILED\s+(\S+?)(?:\s+-\s+(.+))?$|^--- FAIL: (\S+)|^\s*FAIL\s+(\S+)|^\s*●\s+(.+\s›\s.+)$")
ESLINT = re.compile(r"^\s*(\d+):(\d+)\s+(error|warning)\s+(.+?)(?:\s{2,}([\w@/-]+))?\s*$")
SYNTAX = re.compile(
    r"\b(SyntaxError|IndentationError|TabError|Parsing error|Unexpected token|Unexpected end of (?:input|file|JSON input)"
    r"|Unterminated (?:string|template|regular expression)|Identifier directly after number|invalid syntax)\b")
CRASH = re.compile(r"Segmentation fault|core dumped|\bSIGSEGV\b|\bSIGABRT\b|Bus error|Illegal instruction|thread '[^']*' panicked at", re.I)
FAILURE_MESSAGE = re.compile(
    r"(?<![\w-])(?:failed|failure|cannot|can't|could not|couldn't|unable to|aborted|aborting|timed out|refused|rejected|denied)(?![\w-])", re.I)
NO_FAILURE = re.compile(r"\b(?:0|no|zero|without)\s+(?:\w+\s+)?(?:errors?|failures?|failed)\b|\bfailed=0\b|\bfailures?:\s*0\b", re.I)
EXPLICIT_WARNING = re.compile(r"^(?:\[?(?:warning|warn)\]?[:\s]|npm WARN\s)", re.I)
DEPRECATION = re.compile(r"\b(?:DeprecationWarning|PendingDeprecationWarning|FutureWarning)\b|^npm WARN deprecated|\bDEPRECATION:")

LEVEL_BRACKET = re.compile(
    r"\[((?i:fatal|critical|crit|emerg|emergency|alert|panic|severe|error|err|warning|warn))\]")
LEVEL_PLAIN = re.compile(r"(?:^|[\s|])(FATAL|CRITICAL|SEVERE|PANIC|ERROR|WARNING|WARN)(?=[\s:|\]]|$)")
LEVEL_JSON = re.compile(
    r'"(?:level|severity|lvl|log\.level)"\s*:\s*"((?i:fatal|critical|crit|panic|emerg|alert|error|err|warning|warn))"')
LEVEL_KV = re.compile(r"\b(?:level|lvl|severity)=((?i:fatal|critical|crit|panic|error|err|warning|warn))\b")
FATAL_LEVELS = {"fatal", "critical", "crit", "emerg", "emergency", "alert", "panic", "severe"}
ERROR_LEVELS = {"error", "err"}

HTTP_ACCESS = re.compile(r'"(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|CONNECT|TRACE) (\S+) HTTP/[\d.]+" (\d{3})\b')
HTTP_CONSOLE = re.compile(r"\b(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(https?://\S+)\s+(\d{3})\b(?:\s*\(([^)]*)\))?")
ATTACK_PATTERNS = [
    ("SQL injection", re.compile(
        r"'\s*(?:or|and)\s*'?[\w]*'?\s*=\s*'?[\w]*|\bunion(?:\s+all)?\s+select\b|\bor\s+1\s*=\s*1\b|'\s*--|;\s*drop\s+table"
        r"|\bsleep\s*\(\s*\d+\s*\)|\bbenchmark\s*\(|information_schema", re.I)),
    ("Cross-site scripting", re.compile(r"<\s*script|javascript:|\bon(?:error|load|mouseover)\s*=|<\s*img[^>]+src|alert\s*\(", re.I)),
    ("Path traversal", re.compile(r"\.\./|\.\.\\|/etc/passwd|/etc/shadow|win\.ini|boot\.ini", re.I)),
    ("Log4Shell (JNDI injection)", re.compile(r"\$\{\s*jndi\s*:", re.I)),
    ("Command injection", re.compile(r";\s*(?:cat|wget|curl|bash|sh|nc|id|whoami)\b|\|\s*(?:nc|bash|sh)\b|`(?:id|whoami)`|\$\((?:id|whoami)\)", re.I)),
]
FAILED_AUTH = re.compile(
    r"failed password|authentication failure|invalid user|failed login|login failed|failed sign-?in|invalid credentials", re.I)
IPV4 = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])")
ERROR_COUNT = re.compile(r"\b([1-9]\d*)\s+(errors?|failed|failures?)\b", re.I)
BRUTE_FORCE_THRESHOLD = 5

PY_HINTS = {
    "NameError": "A name is used before it is defined or imported. Add the missing import or definition at the location shown.",
    "ModuleNotFoundError": "A package is not installed or the import path is wrong. Add it to requirements.txt or fix the import.",
    "ImportError": "An import failed. Check the package is installed and the imported name exists in that version.",
    "KeyError": "A dictionary key or environment variable is missing. Check the key exists or use .get() with a default.",
    "AttributeError": "An object does not have the attribute being used, often because a value is None. Check the object at the location shown.",
    "TypeError": "A value of the wrong type was passed. Check the arguments at the location shown.",
    "OperationalError": "The database could not be reached or rejected the query. Check DATABASE_URL, credentials and that the database is running.",
    "IntegrityError": "A database constraint was violated (duplicate or missing related row).",
    "RuntimeError": "The program stopped deliberately; the message explains why.",
}
NETWORK_HINTS = {
    "ERR_NETWORK_CHANGED": "The browser's network changed while the request was in flight (Wi-Fi, VPN or hotspot switch). Retry; this is not a server fault.",
    "ERR_INTERNET_DISCONNECTED": "The device is offline. Reconnect and retry.",
    "ERR_CONNECTION_REFUSED": "Nothing is listening at that address. Check the server is running and the URL/port is right.",
    "ERR_NAME_NOT_RESOLVED": "The host name could not be resolved. Check the URL and DNS.",
    "ERR_CERT": "The TLS certificate is invalid for this host.",
}


def _location_from_frames(frames: List[Tuple[str, int]], innermost_last: bool) -> Optional[Tuple[str, int]]:
    """The application frame closest to where the error was raised.

    Python prints the innermost frame last; JavaScript and Java print it first.
    Library and runtime frames are skipped when an application frame exists."""
    app = [f for f in frames if not LIB_PATH.search(f[0]) and "node_modules" not in f[0] and not f[0].startswith(("node:", "internal/"))]
    chosen = app or frames
    if not chosen:
        return None
    return chosen[-1] if innermost_last else chosen[0]


def analyze_log(lines: List[str], file: str, col: Collector) -> None:
    content = [strip_timestamp(l)[:MAX_LINE_CHARS] for l in lines]
    consumed = set()
    n = len(content)

    # ---- multi-line blocks: stack traces, npm error blocks
    i = 0
    while i < n:
        text = content[i]
        stripped = text.strip()

        # Python traceback (with or without the "Traceback" header line)
        if PY_TRACEBACK_START.match(text) or PY_FRAME.match(text):
            start = i
            frames: List[Tuple[str, int]] = []
            j = i
            exc_line = None
            while j < n:
                t = content[j]
                s = t.strip()
                frame = PY_FRAME.match(t)
                if frame:
                    frames.append((frame.group(1), int(frame.group(2))))
                elif PY_TRACEBACK_START.match(t) or PY_CHAIN.match(t) or not s or s.startswith("^"):
                    pass
                elif t[:1] in (" ", "\t"):
                    pass  # source line printed under a frame
                elif PY_EXCEPTION.match(s):
                    exc_line = j
                    break
                else:
                    break
                j += 1
            if exc_line is not None and frames:
                m = PY_EXCEPTION.match(content[exc_line].strip())
                exc_type, exc_msg = m.group(1), (m.group(2) or "").strip()
                loc = _location_from_frames(frames, innermost_last=True)
                where = f" at {loc[0]}:{loc[1]}" if loc else ""
                short = exc_type.split(".")[-1]
                hint = PY_HINTS.get(short, "Read the exception message and fix the code at the location shown.")
                col.add(file=file, line=exc_line + 1, severity="Critical", rule_id="LOG-PY-EXCEPTION",
                        category="Runtime error", title=f"Python exception {exc_type}",
                        detail=f"{exc_msg}{where}".strip(), recommendation=hint,
                        matched_line=content[exc_line], group=f"{exc_type}|{normalise_for_grouping(exc_msg)}|{where}",
                        context=[content[k].strip() for k in range(start, exc_line + 1) if PY_FRAME.match(content[k])][-6:],
                        priority=5)
                consumed.update(range(start, exc_line + 1))
                i = exc_line + 1
                continue

        # Go panic
        m = GO_PANIC.match(stripped)
        if m:
            j = i + 1
            frames = []
            while j < n:
                s = content[j]
                if not s.strip() or s.startswith(("goroutine ", "\t", "    ")) or re.match(r"^[\w./*()-]+\(.*\)$", s.strip()) or s.strip().startswith("created by"):
                    fm = GO_FRAME_FILE.match(s)
                    if fm:
                        frames.append((fm.group(1), int(fm.group(2))))
                    j += 1
                    continue
                break
            app = [f for f in frames if not f[0].startswith(("/usr/local/go/", "runtime/")) and "/go/pkg/mod/" not in f[0]]
            loc = (app or frames or [None])[0]
            where = f" at {loc[0]}:{loc[1]}" if loc else ""
            col.add(file=file, line=i + 1, severity="Critical", rule_id="LOG-GO-PANIC", category="Runtime error",
                    title="Go panic", detail=f"{m.group(1)}{where}",
                    recommendation="The program crashed. Fix the code at the location shown (check slice bounds and nil values).",
                    matched_line=stripped, priority=5)
            consumed.update(range(i, j))
            i = j
            continue

        # JavaScript / Java exception followed by stack frames
        m = EXC_HEADER.match(stripped)
        if m:
            j = i + 1
            js_frames: List[Tuple[str, int]] = []
            java_frames: List[Tuple[str, int]] = []
            causes: List[str] = []
            while j < n:
                t = content[j]
                jf = JS_FRAME.match(t)
                vf = JAVA_FRAME.match(t)
                if jf:
                    js_frames.append((jf.group(2), int(jf.group(3))))
                elif vf:
                    fm = re.match(r"([\w$.-]+\.(?:java|kt|scala)):(\d+)", vf.group(2))
                    if fm:
                        java_frames.append((fm.group(1), int(fm.group(2))))
                elif JAVA_CAUSE.match(t):
                    causes.append(JAVA_CAUSE.match(t).group(1).strip())
                elif JAVA_MORE.match(t) or t.strip() == "Require stack:" or t.strip().startswith("- "):
                    pass
                else:
                    break
                j += 1
            if js_frames or java_frames:
                is_java = bool(java_frames) and not js_frames
                frames = java_frames if is_java else js_frames
                loc = _location_from_frames(frames, innermost_last=False)
                where = f" at {loc[0]}:{loc[1]}" if loc else ""
                exc_type, exc_msg = m.group(1), (m.group(2) or "").strip()
                cause = f"; caused by {causes[-1]}" if causes else ""
                col.add(file=file, line=i + 1, severity="Critical",
                        rule_id="LOG-JAVA-EXCEPTION" if is_java else "LOG-JS-EXCEPTION",
                        category="Runtime error",
                        title=f"{'Java' if is_java else 'JavaScript'} exception {exc_type}",
                        detail=f"{exc_msg}{where}{cause}".strip(),
                        recommendation="Fix the code at the first application frame shown; the message says what went wrong.",
                        matched_line=stripped, group=f"{exc_type}|{normalise_for_grouping(exc_msg)}|{where}",
                        context=[content[k].strip() for k in range(i + 1, j)][:6], priority=5)
                consumed.update(range(i, j))
                i = j
                continue

        # npm error block
        m = NPM_ERR.match(stripped)
        if m:
            j = i
            block = []
            while j < n and NPM_ERR.match(content[j].strip()):
                block.append(NPM_ERR.match(content[j].strip()).group(1).strip())
                j += 1
            code = next((b.split(None, 1)[1] for b in block if b.startswith("code ") and len(b.split()) > 1), "")
            message = next((b for b in block if b and not re.match(r"^(code|errno|syscall|path)\b", b)), "")
            col.add(file=file, line=i + 1, severity="Critical", rule_id="LOG-BUILD-ERROR", category="Build failure",
                    title="npm command failed", detail=" — ".join(x for x in (code, message) if x),
                    recommendation="Read the npm error code: ERESOLVE = dependency conflict, ELIFECYCLE = a script failed (see the lines above), E404 = package not found.",
                    matched_line=stripped, context=block[:8], priority=4)
            consumed.update(range(i, j))
            i = j
            continue
        i += 1

    # ---- single-line rules
    failed_auth: "OrderedDict[str, List[int]]" = OrderedDict()
    for idx, text in enumerate(content):
        if idx in consumed:
            continue
        stripped = text.strip()
        if not stripped:
            continue
        ln = idx + 1

        for ip_match in [FAILED_AUTH.search(stripped)]:
            if ip_match:
                ip = IPV4.search(stripped)
                if ip:
                    failed_auth.setdefault(ip.group(1), []).append(ln)

        labelled_warning = bool(EXPLICIT_WARNING.match(stripped))
        resource_group = normalise_for_grouping(re.sub(r"'[^']*'|\"[^\"]*\"", "<path>", stripped))

        def add(rule: str, severity: str, category: str, title: str, detail: str = "", rec: str = "",
                group: Optional[str] = None, priority: int = 1) -> None:
            if labelled_warning and severity == "Critical":
                severity = "Warning"  # the tool itself reported this line as a warning
            col.add(file=file, line=ln, severity=severity, rule_id=rule, category=category, title=title,
                    detail=detail, recommendation=rec, matched_line=stripped, group=group, priority=priority)

        if OOM.search(stripped):
            add("LOG-OOM", "Critical", "Resource failure", "Out of memory", stripped[:200],
                "The process ran out of memory and was stopped. Reduce memory use or give the service more memory.",
                group=f"oom|{resource_group}", priority=4)
            continue
        if DISK.search(stripped):
            add("LOG-DISK", "Critical", "Resource failure", "Disk full", stripped[:200],
                "There is no free disk space. Remove old files/logs or enlarge the disk.", group=f"disk|{resource_group}", priority=4)
            continue
        if PERMISSION.search(stripped):
            add("LOG-PERMISSION", "Critical", "Resource failure", "Permission denied", stripped[:200],
                "The process is not allowed to read or write this path. Fix the file permissions or the user the service runs as.",
                group=f"perm|{resource_group}", priority=4)
            continue
        if CRASH.search(stripped):
            add("LOG-CRASH", "Critical", "Crash", "Process crashed", stripped[:200],
                "The program crashed at the native level. Look for the stack trace or core dump produced with it.", priority=4)
            continue
        net = NETWORK.search(stripped)
        if net:
            code = net.group(1) or net.group(2) or net.group(3)
            hint = next((v for k, v in NETWORK_HINTS.items() if code and code.startswith(k)), None)
            add("LOG-NETWORK", "Critical", "Network error", f"Network error: {code}", stripped[:200],
                hint or "A connection could not be made. Check the target service is running, the address is correct and the network allows it.",
                group=f"net|{code}", priority=4)
            continue
        ex = PROCESS_EXIT.search(stripped)
        if ex and int(ex.group(1)) != 0:
            add("LOG-PROCESS-EXIT", "Critical", "Crash", f"Process exited with code {ex.group(1)}", "",
                "The process stopped with an error. The cause is normally in the lines just above this one.", priority=3)
            continue

        ts = TS_ERROR.match(stripped)
        if ts:
            line_no = ts.group(2) or ts.group(4)
            add("LOG-BUILD-ERROR", "Critical", "Build failure", f"TypeScript error {ts.group(6)}",
                f"{ts.group(7)} at {ts.group(1).strip()}:{line_no}",
                "Fix the type error at the file and line shown; the build stops until it is fixed.", priority=4)
            continue
        ce = COMPILER_ERROR.match(stripped)
        if ce:
            add("LOG-BUILD-ERROR", "Critical", "Build failure", "Compiler error",
                f"{ce.group(4)} at {ce.group(1)}:{ce.group(2)}", "Fix the error at the file and line shown.", priority=4)
            continue
        if RUST_ERROR.match(stripped) or BUILD_FAILED.search(stripped):
            add("LOG-BUILD-ERROR", "Critical", "Build failure", "Build failed", stripped[:200],
                "The build failed; the first error above this line is the cause.", priority=3)
            continue
        tf = TEST_FAILED.match(stripped)
        if tf:
            name = tf.group(1) or tf.group(3) or tf.group(4) or tf.group(5)
            add("LOG-TEST-FAILURE", "Critical", "Test failure", f"Test failed: {name}",
                (tf.group(2) or "").strip(), "Run this test locally and fix the assertion or the code it checks.", priority=4)
            continue
        lint = ESLINT.match(text)
        if lint:
            sev = "Critical" if lint.group(3) == "error" else "Warning"
            add("LOG-LINT", sev, "Lint", f"Lint {lint.group(3)}: {lint.group(4)}",
                f"line {lint.group(1)}:{lint.group(2)}" + (f" ({lint.group(5)})" if lint.group(5) else ""),
                "Fix the lint issue at the line shown.", group=f"lint|{lint.group(4)}", priority=2)
            continue

        http = HTTP_ACCESS.search(stripped)
        console = None if http else HTTP_CONSOLE.search(stripped)
        if http or console:
            method = (http or console).group(1)
            target = (http or console).group(2)
            status = int((http or console).group(3))
            path = urlparse(target).path if console else target
            decoded = unquote_plus(unquote_plus(target))
            attack = next((name for name, rx in ATTACK_PATTERNS if rx.search(decoded)), None)
            if attack:
                add("LOG-ATTACK-PAYLOAD", "Critical", "Security event", f"{attack} attempt",
                    f"{method} {decoded[:160]} (HTTP {status})",
                    f"A request carried a {attack.lower()} payload. Block the source, and confirm the endpoint validates this input"
                    + (" — it was served with a success status, so verify it was not exploitable." if status < 400 else "."),
                    priority=4)
                continue
            route = path.split("?")[0]
            if status >= 500:
                add("LOG-HTTP-5XX", "Critical", "Server error", f"HTTP {status} server error",
                    f"{method} {route} returned {status}",
                    "The server failed while handling this request. Find the matching exception in the server log at the same time.",
                    group=f"{method}|{route}|{status}", priority=3)
                continue
            if status in (401, 403):
                reason = "Unauthorized" if status == 401 else "Forbidden"
                rec = ("The server rejected the request. On a sign-in endpoint this means the email/password is wrong or the account does not exist; "
                       "elsewhere it means the session is missing or expired." if status == 401
                       else "The signed-in user is not allowed to do this.")
                add("LOG-HTTP-AUTH", "Warning", "Request rejected", f"HTTP {status} {reason}",
                    f"{method} {route} returned {status}", rec, group=f"{method}|{route}|{status}", priority=2)
                continue
            if status == 429:
                add("LOG-HTTP-429", "Warning", "Request rejected", "HTTP 429 Too Many Requests",
                    f"{method} {route}", "Requests are being rate limited. Slow down the client or raise the limit.",
                    group=f"{method}|{route}|429", priority=2)
                continue
            if http and not LEVEL_BRACKET.search(stripped) and not LEVEL_PLAIN.search(stripped.split('"')[0]):
                continue  # a normal successful request; uvicorn writes "INFO:" so no level rule applies either

        if SYNTAX.search(stripped):
            add("LOG-SYNTAX-ERROR", "Critical", "Build failure", "Syntax / parse error", stripped[:200],
                "The source could not be parsed. Fix the syntax at the file and line mentioned.", priority=3)
            continue
        exc = EXC_HEADER.match(stripped)
        if exc and (exc.group(2) is not None or stripped == exc.group(1)):
            add("LOG-EXCEPTION", "Critical", "Runtime error", f"Exception {exc.group(1)}", (exc.group(2) or "").strip()[:200],
                "An exception was raised. Find where it is thrown and handle or fix the cause.",
                group=f"{exc.group(1)}|{normalise_for_grouping(exc.group(2) or '')}", priority=2)
            continue
        if DEPRECATION.search(stripped):
            add("LOG-DEPRECATION", "Warning", "Deprecation", "Deprecated API in use", stripped[:200],
                "Plan an upgrade before the deprecated API is removed.", group=f"dep|{normalise_for_grouping(stripped)}", priority=1)
            continue

        level, message = _detect_level(stripped)
        is_command_echo = stripped.startswith(("> ", "$ ", "+ ", "PS "))  # npm/yarn script echo, shell prompt or `set -x` trace
        if (not level and not is_command_echo and FAILURE_MESSAGE.search(stripped) and not NO_FAILURE.search(stripped)
                and not FAILED_AUTH.search(stripped) and not ERROR_COUNT.search(stripped)):
            add("LOG-FAILURE-MESSAGE", "Warning", "Reported failure", "Failure reported", stripped[:200],
                "This line reports that something failed but gives no error code or stack trace. Check the step it describes.",
                group=f"fail|{normalise_for_grouping(stripped)}", priority=0)
            continue
        if level:
            if level in FATAL_LEVELS:
                rule, sev, title = "LOG-LEVEL-FATAL", "Critical", f"{level.upper()} event"
            elif level in ERROR_LEVELS:
                rule, sev, title = "LOG-LEVEL-ERROR", "Critical", "Error logged"
            else:
                rule, sev, title = "LOG-LEVEL-WARNING", "Warning", "Warning logged"
            add(rule, sev, "Logged event", title, message[:200],
                "This line was logged at " + level.upper() + " level by the application; read the message for the cause.",
                group=f"{rule}|{normalise_for_grouping(message)}", priority=1)

    for ip, hits in failed_auth.items():
        if len(hits) >= BRUTE_FORCE_THRESHOLD:
            col.add_aggregate(file=file, line=hits[0], severity="Critical", rule_id="LOG-BRUTE-FORCE",
                              category="Security event", title="Possible brute-force attack",
                              detail=f"{len(hits)} failed sign-in attempts from {ip} (lines {hits[0]}-{hits[-1]})",
                              recommendation="Block or rate-limit this address and make sure the targeted account has a strong password and MFA.",
                              matched_line=content[hits[0] - 1], count=len(hits))

    # A summary such as "1 error" only matters when nothing more specific was found.
    has_critical = any(f["severity"] == "Critical" and f["file"] == file for f in col.by_line.values()) or any(
        a["file"] == file and a["severity"] == "Critical" for a in col.aggregates)
    if not has_critical:
        for idx, text in enumerate(content):
            m = ERROR_COUNT.search(text)
            if m and idx not in consumed:
                col.add(file=file, line=idx + 1, severity="Critical", rule_id="LOG-ERROR-COUNT", category="Build failure",
                        title=f"{m.group(1)} {m.group(2)} reported", detail=text.strip()[:200],
                        recommendation="The tool reported errors but did not print them here; run it with full output to see them.",
                        matched_line=text.strip(), priority=0)
                break


def _detect_level(line: str) -> Tuple[Optional[str], str]:
    if line.startswith("{"):
        m = LEVEL_JSON.search(line)
        if m:
            message = ""
            try:
                data = json.loads(line)
                message = str(data.get("msg") or data.get("message") or data.get("error") or "")
            except Exception:
                pass
            return m.group(1).lower(), message or line
    for rx in (LEVEL_BRACKET, LEVEL_KV, LEVEL_PLAIN):
        m = rx.search(line)
        if m:
            message = line[m.end():].strip(" :|]-")
            message = re.sub(r"^\[[^\]]*\]\s*", "", message)
            return m.group(1).lower(), message or line
    return None, ""


# --------------------------------------------------------------------------- secret rules (all file kinds)

TOKEN_FORMATS = [
    ("AWS access key", re.compile(r"\b((?:AKIA|ASIA)[0-9A-Z]{16})\b")),
    ("GitHub token", re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{60,})\b")),
    ("Google API key", re.compile(r"\b(AIza[0-9A-Za-z_\-]{35})\b")),
    ("Slack token", re.compile(r"\b(xox[abposr]-[A-Za-z0-9-]{10,})\b")),
    ("Stripe live key", re.compile(r"\b((?:sk|rk)_live_[0-9A-Za-z]{20,})\b")),
    ("Anthropic API key", re.compile(r"\b(sk-ant-[A-Za-z0-9_\-]{20,})\b")),
    ("OpenAI API key", re.compile(r"\b(sk-(?:proj-)?[A-Za-z0-9_\-]{32,})\b")),
    ("SendGrid API key", re.compile(r"\b(SG\.[\w-]{22}\.[\w-]{43})\b")),
    ("JSON Web Token", re.compile(r"\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b")),
]
PRIVATE_KEY = re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----")
SECRET_URL = re.compile(r"\b([a-z][a-z0-9+.-]{1,20})://([^\s:/@'\"`<>{}$]+):([^\s@/'\"`<>{}$]{3,})@([^\s/:'\"`<>]+)")
SECRET_WORD = (r"(?:passwords?|passwd|pwd|passphrase|secrets?|secret[_-]?key|private[_-]?key|api[_-]?keys?|apikey|(?<=[_-])pass(?:es)?"
               r"|access[_-]?key(?:[_-]?id)?|auth[_-]?token|access[_-]?token|refresh[_-]?token|bearer[_-]?token"
               r"|client[_-]?secret|token|credentials?|signing[_-]?key|encryption[_-]?key)")
QUOTED_ASSIGN = re.compile(
    r"(?i)\b([A-Za-z_][\w.-]*?" + SECRET_WORD + r")\b[\"']?\s*(?::\s*[\w\[\], .]+\s*)?(?::=|=|:)\s*[\(\[\{]?\s*[\"']([^\"'\s]{6,})[\"']")
UNQUOTED_ASSIGN = re.compile(
    r"(?i)^\s*(?:export\s+)?([A-Za-z_][\w.-]*?" + SECRET_WORD + r")\s*[=:]\s*([^\s#\"']{6,})\s*(?:#.*)?$")


SECRET_FALLBACK = re.compile(
    r"(?:getenv|environ\.get|env\.get)\s*\(\s*[\"'](?:[A-Z0-9_]*(?:SECRET|KEY|TOKEN|PASSWORD|PASSWD|PWD|CREDENTIAL)[A-Z0-9_]*)[\"']\s*,\s*[\"']([^\"'\s]{8,})[\"']"
    r"|process\.env\.(?:[A-Z0-9_]*(?:SECRET|KEY|TOKEN|PASSWORD|PASSWD|PWD|CREDENTIAL)[A-Z0-9_]*)\s*(?:\|\||\?\?)\s*[\"']([^\"'\s]{8,})[\"']")
PASSWORD_LITERAL_CALL = re.compile(
    r"\b(?:get_password_hash|hash_password|hashpw|set_password|make_password|check_password|verify_password|bcrypt\.hash(?:Sync)?|bcrypt\.compare(?:Sync)?|argon2\.hash)\s*\(\s*(?:b)?[\"']([^\"'\s]{6,})[\"']")
PASSWORD_COMPARE = re.compile(
    r"\b\w*(?:pass(?:word)?|passwd|pwd|secret|token)\w*\s*(?:===?|!==?)\s*[\"']([^\"'\s]{6,})[\"']", re.I)


def check_secrets(line: str, *, allow_assignments: bool, unquoted: bool, in_test: bool) -> List[Dict[str, Any]]:
    found: List[Dict[str, Any]] = []
    for label, rx in TOKEN_FORMATS:
        for m in rx.finditer(line):
            value = m.group(1)
            example = bool(DOC_EXAMPLE_VALUE.search(value))
            found.append({
                "severity": "Info" if example else ("Info" if in_test else "Critical"),
                "rule_id": "SEC-SECRET-TOKEN", "category": "Exposed secret",
                "title": f"{label} in source" if not example else f"{label} (documentation example)",
                "detail": ("This is a published documentation example key, not a live credential."
                           if example else f"{mask(value)}" + (" — in a test file" if in_test else "")),
                "recommendation": ("No action needed if this is only an example." if example else
                                   f"Revoke this {label} now (it must be treated as leaked), create a new one, and load it from an environment variable or secret manager."),
                "value": value, "priority": 5,
            })
    if PRIVATE_KEY.search(line):
        found.append({"severity": "Info" if in_test else "Critical", "rule_id": "SEC-PRIVATE-KEY", "category": "Exposed secret",
                      "title": "Private key in source", "detail": "",
                      "recommendation": "Remove the private key from the repository, revoke it and issue a new one.",
                      "value": "", "priority": 5})
    for m in SECRET_URL.finditer(line):
        password = m.group(3)
        if is_placeholder(password) or set(password) <= {"*"}:
            continue
        found.append({"severity": "Info" if in_test else "Critical", "rule_id": "SEC-SECRET-URL", "category": "Exposed secret",
                      "title": "Password inside a connection URL",
                      "detail": f"{m.group(1)}://{m.group(2)}:{mask(password)}@{m.group(4)}",
                      "recommendation": "Change this password, then move the full URL into an environment variable (for example DATABASE_URL).",
                      "value": password, "priority": 4})
    if allow_assignments and not found:
        for rx, title, rec in (
            (SECRET_FALLBACK, "Hard-coded fallback secret",
             "Remove the default value so a missing environment variable fails loudly instead of silently using a value everyone can read."),
            (PASSWORD_LITERAL_CALL, "Hard-coded password passed to an auth function",
             "Read the password from configuration; a password written in code is visible to everyone with the source."),
            (PASSWORD_COMPARE, "Credential compared with a hard-coded value",
             "Check credentials against the database or a secret store, never against values written in the code."),
        ):
            m = rx.search(line)
            value = next((g for g in m.groups() if g), "") if m else ""
            if m and value and not is_placeholder(value) and not in_string_literal(line, m.start()):
                found.append({"severity": "Info" if in_test else "Critical", "rule_id": "SEC-SECRET-ASSIGN",
                              "category": "Exposed secret", "title": title,
                              "detail": mask(value) + (" — in a test file" if in_test else ""),
                              "recommendation": rec, "value": value, "priority": 4})
                return found
        matches = list(QUOTED_ASSIGN.finditer(line))
        if unquoted:
            m = UNQUOTED_ASSIGN.match(line)
            if m:
                matches.append(m)
        for m in matches:
            name, value = m.group(1), m.group(2)
            if is_placeholder(value) or value.lower() in name.lower():
                continue
            if re.search(r"(?:^|_)(?:test|dummy|example|sample|mock|fake)(?:_|$)", name, re.I):
                continue  # deliberately fake credential named as such
            if re.match(r"(?:is|has|should|can|show|use|enable|allow)[A-Z_]", name):
                continue  # a boolean / flag named after a secret, not a secret
            if re.fullmatch(r"[a-z]+(?:_[a-z]+){1,3}", value) and re.search(r"secret|key|token|pass|pwd|credential", value):
                continue  # an identifier such as 'access_token' or 'secret_key' used as a label
            if value.startswith(("http://", "https://", "/", "./", "../", "~")) or value.endswith((".pem", ".key", ".json", ".txt")):
                continue
            if not (len(value) >= 16 or (len(value) >= 8 and char_classes(value) >= 2)) or shannon_entropy(value) < 2.5:
                continue
            found.append({"severity": "Info" if in_test else "Critical", "rule_id": "SEC-SECRET-ASSIGN", "category": "Exposed secret",
                          "title": f"Hard-coded credential in {name}",
                          "detail": mask(value) + (" — in a test file" if in_test else ""),
                          "recommendation": "Treat this value as leaked: rotate it, then read it from an environment variable or secret manager.",
                          "value": value, "priority": 4})
            break
    return found


# --------------------------------------------------------------------------- code rules

SQL_IN_STRING = re.compile(
    r"[\"'`]\s*(?:select\s[^\"'`]*?\bfrom\b|insert\s+into\b|update\s+[\w.\"`\[\]]+\s+set\b|delete\s+from\b)", re.I)
SQL_DYNAMIC = [
    re.compile(r"[\"'`]\s*\+\s*[A-Za-z_$(]"),           # "..." + value
    re.compile(r"[A-Za-z_$)\]]\s*\+\s*[\"'`]"),         # value + "..."
    re.compile(r"`[^`]*\$\{"),                           # JS template literal
    re.compile(r"\b[fF][rR]?([\"'])(?:(?!\1).)*\{"),     # Python f-string (may contain the other quote type)
    re.compile(r"[\"']\s*%\s*[\w(\[{]"),                 # "..." % value
    re.compile(r"[\"']\s*\.format\("),                   # "...".format(value)
]
PY_SHELL_CALL = re.compile(r"\bos\.(?:system|popen)\s*\((.*)")
PY_SUBPROCESS = re.compile(r"\bsubprocess\.(?:run|call|Popen|check_output|check_call|getoutput|getstatusoutput)\s*\((.*)")
JS_EXEC = re.compile(r"(?:\bchild_process\.|(?<![\w.$]))(?:exec|execSync)\s*\(\s*(?:`[^`]*\$\{|[\"'][^\"'\n]*[\"']\s*\+|[A-Za-z_$][\w.$]*\s*\+)")
EVAL_JS = re.compile(r"(?<![\w.$])eval\s*\(|\bnew\s+Function\s*\(|\bset(?:Timeout|Interval)\s*\(\s*[\"'`]")
EVAL_PY = re.compile(r"(?<![\w.$])(?:eval|exec)\s*\(")
XSS_ASSIGN = re.compile(r"\.(?:innerHTML|outerHTML)\s*\+?=\s*(.+)")
XSS_CALL = re.compile(r"\b(?:insertAdjacentHTML\s*\(\s*[^,]+,|document\.write(?:ln)?\s*\()\s*(.+)")
XSS_REACT = re.compile(r"dangerouslySetInnerHTML\s*=\s*\{\{\s*__html\s*:\s*(.+?)\s*\}\}")
XSS_PY = re.compile(r"\b(?:mark_safe|Markup)\s*\(\s*(?![\"'][^\"']*[\"']\s*\))")
DESERIALIZE = re.compile(r"\b(?:c?[Pp]ickle|marshal|dill)\.loads?\s*\(|\bjsonpickle\.decode\s*\(|\byaml\.(?:unsafe_)?load\s*\(|\bunserialize\s*\(|\bnew\s+ObjectInputStream\s*\(")
YAML_SAFE = re.compile(r"Loader\s*=\s*(?:yaml\.)?C?SafeLoader|safe_load")
TLS_OFF = re.compile(r"\bverify\s*=\s*False\b|rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*[\"']?0|InsecureSkipVerify\s*:\s*true|_create_unverified_context|\bCERT_NONE\b")
WEAK_HASH = re.compile(r"\bhashlib\.(?:md5|sha1)\s*\(|createHash\(\s*[\"'](?:md5|sha1)[\"']|MessageDigest\.getInstance\(\s*\"(?:MD5|SHA-?1)\"", re.I)
JWT_NO_VERIFY = re.compile(r"[\"']verify_signature[\"']\s*:\s*False|\bverify\s*=\s*False.*jwt|jwt\.decode\([^)]*verify\s*=\s*False|algorithms\s*=\s*\[\s*[\"']none[\"']", re.I)
DEBUG_PY = re.compile(r"^\s*DEBUG\s*=\s*True\b|\.run\([^)]*debug\s*=\s*True")
DEBUG_ENV = re.compile(r"^\s*(?:export\s+)?(?:DEBUG|FLASK_DEBUG|APP_DEBUG)\s*=\s*[\"']?(?:true|1|yes)[\"']?\s*$", re.I)
CORS_ANY = re.compile(r"allow_origins\s*=\s*\[\s*[\"']\*[\"']\s*\]|Access-Control-Allow-Origin[\"']?\s*[:,]\s*[\"']\*|\borigin\s*:\s*(?:[\"']\*[\"']|true)\b")
FILE_ACCESS = re.compile(r"(?<![\w.])open\s*\(|\b(?:send_file|FileResponse|readFileSync|readFile|createReadStream|sendFile|os\.remove|os\.unlink|unlinkSync|rmSync)\s*\(")
HTTP_CLIENT = re.compile(r"\b(?:requests\.(?:get|post|put|patch|delete|head|request)|httpx\.(?:get|post|put|patch|delete|request)|urlopen|fetch|axios(?:\.(?:get|post|put|patch|delete|request))?|http\.get|https\.get)\s*\(\s*([^,)]+)")
PURE_LITERAL_ARG = re.compile(r"^\s*([\"'])[^\"']*\1\s*[),]")


def _rhs_risk(rhs: str) -> Optional[str]:
    """Severity for a value written into HTML, or None when it is safe."""
    rhs = rhs.strip().rstrip(";")
    if re.fullmatch(r"([\"'])[^\"']*\1", rhs) or re.fullmatch(r"`[^`$]*`", rhs) or rhs in ("''", '""', "``"):
        return None
    if SANITIZED.search(rhs):
        return None
    if re.fullmatch(r"[A-Z][A-Z0-9_]*(?:\[[^\]]+\]|\.[A-Za-z_]\w*)*", rhs):
        return None  # a constant (by naming convention) defined in the code, not external data
    return "Critical" if USER_INPUT.search(rhs) else "Warning"


def analyze_code(lines: List[str], file: str, kind: str, lang: str, col: Collector) -> None:
    in_test = is_test_path(file)
    py = lang in ("py", "unknown")
    js = lang in ("js", "unknown")
    block_comment = False
    open_literal: Optional[str] = None   # '`', '"""' or "'''" while inside a multi-line string
    for idx, raw in enumerate(lines):
        ln = idx + 1
        if len(raw) > MINIFIED_LINE_CHARS and kind == "code":
            continue
        line = raw[:MAX_LINE_CHARS]
        stripped = line.strip()
        if not stripped:
            continue

        # track /* ... */ blocks in C-like languages
        if lang in ("js", "java", "go", "other", "unknown"):
            if block_comment:
                if "*/" in stripped:
                    block_comment = False
                comment = True
            elif stripped.startswith("/*") and "*/" not in stripped:
                block_comment = True
                comment = True
            else:
                comment = is_comment_line(stripped, lang)
        else:
            comment = is_comment_line(stripped, lang)

        inside_literal = open_literal is not None
        if kind == "code":
            open_literal = _track_multiline_literal(line, open_literal, py, js)
            inside_literal = inside_literal or open_literal is not None and not _opens_on_line(line, open_literal)

        candidates: List[Dict[str, Any]] = []
        for s in check_secrets(line, allow_assignments=not comment and not inside_literal and kind in ("code", "config"),
                               unquoted=kind == "config", in_test=in_test):
            candidates.append(s)

        if not comment and not inside_literal and kind == "code":
            candidates.extend(_code_candidates(line, stripped, py, js, lang, in_test))
        if not comment and kind == "config":
            if DEBUG_ENV.match(line):
                candidates.append(_cand("CFG-DEBUG-ON", "Warning", "Insecure configuration", "Debug mode enabled",
                                        "Debug mode exposes stack traces and internals. Turn it off in production.", in_test))
            if CORS_ANY.search(line):
                candidates.append(_cand("CFG-CORS-WILDCARD", "Warning", "Insecure configuration", "CORS allows any origin",
                                        "List the exact origins that may call the API instead of '*'.", in_test))

        for c in candidates:
            value = c.pop("value", "")
            shown = line.replace(value, mask(value)) if value else line
            col.add(file=file, line=ln, severity=c["severity"], rule_id=c["rule_id"], category=c["category"],
                    title=c["title"], detail=c.get("detail", ""), recommendation=c["recommendation"],
                    matched_line=shown, priority=c.get("priority", 1))


def _track_multiline_literal(line: str, state: Optional[str], py: bool, js: bool) -> Optional[str]:
    """Follows multi-line string literals across lines. Returns the delimiter still open after this line."""
    i = 0
    quote: Optional[str] = None
    while i < len(line):
        if state:
            if line.startswith(state, i) and (i == 0 or line[i - 1] != "\\"):
                i += len(state)
                state = None
                continue
            i += 1
            continue
        ch = line[i]
        if quote:
            if ch == "\\":
                i += 2
                continue
            if ch == quote:
                quote = None
            i += 1
            continue
        if ch == "#" and py and not js:
            break
        if py and line.startswith(('"""', "'''"), i):
            state = line[i:i + 3]
            i += 3
            continue
        if js and ch == "`":
            state = "`"
            i += 1
            continue
        if ch in ("'", '"'):
            quote = ch
        i += 1
    return state


def _opens_on_line(line: str, delimiter: Optional[str]) -> bool:
    """True when the literal that is open after this line started on this line (the line itself has code)."""
    return bool(delimiter) and delimiter in line


def _cand(rule: str, severity: str, category: str, title: str, rec: str, in_test: bool, detail: str = "", priority: int = 2) -> Dict[str, Any]:
    if in_test:
        severity = "Info"
        detail = (detail + " — " if detail else "") + "in a test file"
    return {"rule_id": rule, "severity": severity, "category": category, "title": title,
            "detail": detail, "recommendation": rec, "priority": priority}


def _code_candidates(line: str, stripped: str, py: bool, js: bool, lang: str, in_test: bool) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    user = bool(USER_INPUT.search(line))

    # SQL built from variables
    sql = SQL_IN_STRING.search(line)
    if sql and not in_string_literal(line, sql.start()) and any(rx.search(line) for rx in SQL_DYNAMIC):
        out.append(_cand("SEC-SQLI", "Critical", "Injection", "SQL query built from variables",
                         "Use parameterised queries (placeholders with a separate argument list) or the ORM; never join values into SQL text.",
                         in_test, priority=4))

    # command execution
    if py or lang == "shell":
        m = PY_SHELL_CALL.search(line)
        if m and not in_string_literal(line, m.start()) and not PURE_LITERAL_ARG.match(m.group(1)):
            out.append(_cand("SEC-CMDI", "Critical" if user else "Warning", "Injection", "Shell command built from variables",
                             "Use subprocess.run with a list of arguments and no shell; never put request data in a shell command.",
                             in_test, priority=4))
        m = PY_SUBPROCESS.search(line)
        if m and re.search(r"shell\s*=\s*True", line) and not in_string_literal(line, m.start()):
            if PURE_LITERAL_ARG.match(m.group(1)):
                out.append(_cand("SEC-SHELL-TRUE", "Warning", "Injection", "subprocess with shell=True",
                                 "Pass the command as a list and drop shell=True.", in_test))
            else:
                out.append(_cand("SEC-CMDI", "Critical", "Injection", "Shell command built from variables (shell=True)",
                                 "Pass the command as a list of arguments and drop shell=True so values cannot be run as shell code.",
                                 in_test, priority=4))
    if js:
        m = JS_EXEC.search(line)
        if m and not in_string_literal(line, m.start()):
            out.append(_cand("SEC-CMDI", "Critical", "Injection", "Shell command built from variables",
                             "Use execFile/spawn with an argument array instead of exec with a built string.", in_test, priority=4))

    # dynamic code evaluation
    for rx, enabled in ((EVAL_PY, py and lang != "js"), (EVAL_JS, js)):
        if not enabled:
            continue
        m = rx.search(line)
        if m and not in_string_literal(line, m.start()):
            out.append(_cand("SEC-CODE-EVAL", "Critical" if user else "Warning", "Injection", "Dynamic code evaluation",
                             "Do not evaluate strings as code. Parse the input explicitly (e.g. JSON.parse / ast.literal_eval) or map it to allowed actions.",
                             in_test, priority=3))
            break

    # HTML injection
    if js:
        for rx in (XSS_ASSIGN, XSS_CALL, XSS_REACT):
            m = rx.search(line)
            if m and not in_string_literal(line, m.start()):
                risk = _rhs_risk(m.group(1))
                if risk:
                    out.append(_cand("SEC-XSS", risk, "Injection", "HTML built from unescaped data",
                                     "Use textContent / JSX text, or sanitise the HTML with DOMPurify before inserting it.",
                                     in_test, priority=3))
                break
    if py:
        m = XSS_PY.search(line)
        if m and not in_string_literal(line, m.start()):
            out.append(_cand("SEC-XSS", "Critical" if user else "Warning", "Injection", "Value marked as safe HTML",
                             "Only mark trusted, escaped strings as safe.", in_test, priority=3))

    m = DESERIALIZE.search(line)
    if m and not in_string_literal(line, m.start()) and not (m.group(0).startswith("yaml") and YAML_SAFE.search(line)):
        out.append(_cand("SEC-DESERIALIZE", "Critical" if user else "Warning", "Injection", "Unsafe deserialization",
                         "Never unpickle/unserialize untrusted data; use JSON or yaml.safe_load.", in_test, priority=3))

    m = TLS_OFF.search(line)
    if m and not in_string_literal(line, m.start()):
        out.append(_cand("SEC-TLS-VERIFY-OFF", "Warning", "Insecure configuration", "TLS certificate checks disabled",
                         "Keep certificate verification on; fix the certificate or trust store instead.", in_test))
    m = WEAK_HASH.search(line)
    if m and not in_string_literal(line, m.start()) and "usedforsecurity=False" not in line:
        out.append(_cand("SEC-WEAK-HASH", "Warning", "Weak cryptography", "MD5/SHA-1 hash",
                         "Do not use MD5/SHA-1 for passwords, signatures or tokens; use bcrypt/argon2 for passwords and SHA-256+ elsewhere.",
                         in_test, priority=1))
    m = JWT_NO_VERIFY.search(line)
    if m and not in_string_literal(line, m.start()):
        out.append(_cand("SEC-JWT-NOVERIFY", "Critical", "Authentication", "JWT signature not verified",
                         "Always verify the token signature and pin the accepted algorithms.", in_test, priority=4))
    if py and DEBUG_PY.search(line):
        out.append(_cand("CFG-DEBUG-ON", "Warning", "Insecure configuration", "Debug mode enabled",
                         "Read DEBUG from the environment and keep it off in production.", in_test))
    m = CORS_ANY.search(line)
    if m and not in_string_literal(line, m.start()):
        out.append(_cand("CFG-CORS-WILDCARD", "Warning", "Insecure configuration", "CORS allows any origin",
                         "List the exact origins that may call the API instead of '*'.", in_test))
    if user:
        m = FILE_ACCESS.search(line)
        if m and not in_string_literal(line, m.start()) and "window.open" not in line:
            out.append(_cand("SEC-PATH-TRAVERSAL", "Critical", "Injection", "File path taken from request data",
                             "Resolve the path, check it stays inside an allowed folder, and reject '..' segments.", in_test, priority=3))
        m = HTTP_CLIENT.search(line)
        if m and USER_INPUT.search(m.group(1)) and not in_string_literal(line, m.start()):
            out.append(_cand("SEC-SSRF", "Warning", "Injection", "Server request to a URL from request data",
                             "Only call allow-listed hosts; never fetch arbitrary URLs supplied by users.", in_test, priority=2))
    return out


# --------------------------------------------------------------------------- entry point

def split_files(text: str, file_name: Optional[str]) -> List[Tuple[str, List[str]]]:
    lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    blocks: List[Tuple[str, List[str]]] = []
    current_name = (file_name or "").strip() or DEFAULT_SOURCE
    current: List[str] = []
    saw_header = False
    for line in lines:
        m = FILE_HEADER.match(line.rstrip())
        if m:
            if current and (saw_header or any(l.strip() for l in current)):
                blocks.append((current_name, current))
            current_name, current, saw_header = m.group(1).strip(), [], True
            continue
        current.append(line)
    if current or not blocks:
        blocks.append((current_name, current))
    return [(name, block) for name, block in blocks if any(l.strip() for l in block)]


def analyze_text(text: str, file_name: Optional[str] = None) -> Dict[str, Any]:
    col = Collector()
    inputs = []
    total_lines = 0
    for name, block in split_files(text or "", file_name):
        kind, lang = classify_file(name)
        if kind == "code" and name == (file_name or "").strip() and looks_like_log(block):
            kind, lang = "log", ""   # a log saved or labelled with a code-file name is still a log
        if kind == "unknown":
            kind, lang = ("code", "unknown") if looks_like_code(block) else ("log", "")
        shown_type = kind
        if kind == "log" and looks_like_git_history(block):
            kind, shown_type = "doc", "git history"   # commit messages: only leaked credentials are checked
        inputs.append({"file": name, "type": shown_type, "lines": len(block)})
        if kind == "skip":
            continue
        total_lines += len(block)
        if kind == "log":
            analyze_log(block, name, col)
            # credentials written into logs are exposed too
            for idx, raw in enumerate(block):
                for s in check_secrets(raw[:MAX_LINE_CHARS], allow_assignments=False, unquoted=False, in_test=False):
                    value = s.pop("value", "")
                    col.add(file=name, line=idx + 1, severity=s["severity"], rule_id=s["rule_id"], category=s["category"],
                            title=s["title"], detail=s.get("detail", ""), recommendation=s["recommendation"],
                            matched_line=raw.replace(value, mask(value)) if value else raw, priority=s.get("priority", 1))
        elif kind == "doc":
            analyze_code(block, name, "doc", "", col)
        else:
            analyze_code(block, name, kind, lang, col)

    findings = col.results()
    truncated = len(findings) > MAX_FINDINGS
    findings = findings[:MAX_FINDINGS]
    counts = {sev: sum(1 for f in findings if f["severity"] == sev) for sev in ("Critical", "Warning", "Info")}
    status = "Fail" if counts["Critical"] else "Warning" if counts["Warning"] else "Pass"
    analyzed = [i for i in inputs if i["type"] != "skip"]
    return {
        "status": status,
        "findings": findings,
        "summary": {
            "files_analyzed": len(analyzed),
            "files_skipped": len(inputs) - len(analyzed),
            "lines_analyzed": total_lines,
            "inputs": inputs[:200],
            "counts": counts,
            "truncated": truncated,
        },
    }
