"""Rule-based request inspection engine for the IDPS.

Replaces the original "loop over a flat list of regexes and return on the first
hit" approach, which fired on ordinary URLs: a bare ``--`` (Wikipedia article
titles), a ``#`` fragment, the word ``update`` in a query string, or any page
whose HTML happened to contain ``<img`` were all reported as attacks.

Design notes
------------
* Every rule carries a weight. A category is only reported once the summed
  weight of its matched rules crosses that category's threshold, so a single
  weak signal (the word ``select`` in a parameter) is not an incident on its own
  while a single unambiguous signal (``union select``) is.
* Input is normalised before matching -- percent-decoded repeatedly, HTML-entity
  decoded and NFKC-normalised -- so ``%3Cscript%3E`` and ``%252e%252e%252f`` are
  caught. The original engine missed every encoded payload.
* Rules match against URL *components*, never the scheme or host, so
  ``https://...`` no longer trips the remote-file-inclusion rules.
* Response bodies are not run through the rule set. Instead the engine checks
  whether the submitted payload is *reflected* in the body, which is the actual
  test for reflected XSS and does not flag every website that contains an
  ``<iframe>``.

This module is pure standard library so it can be unit tested without a running
web application.
"""

from __future__ import annotations

import html
import re
import unicodedata
from dataclasses import dataclass, field
from typing import Iterable, Sequence
from urllib.parse import unquote, urlsplit

# ─────────────────────────────────────────
# Severity
# ─────────────────────────────────────────
SEVERITY_ORDER = ("info", "low", "medium", "high", "critical")


def _max_severity(values: Iterable[str]) -> str:
    best = "info"
    for value in values:
        if SEVERITY_ORDER.index(value) > SEVERITY_ORDER.index(best):
            best = value
    return best


# ─────────────────────────────────────────
# Rules
# ─────────────────────────────────────────
# scope: "params" = query string + fragment, "path" = URL path,
#        "all" = path + query + fragment
@dataclass(frozen=True)
class Rule:
    id: str
    category: str
    description: str
    severity: str
    weight: int
    pattern: re.Pattern
    scope: str = "all"


def _rule(rule_id, category, description, severity, weight, pattern, scope="all"):
    return Rule(
        id=rule_id,
        category=category,
        description=description,
        severity=severity,
        weight=weight,
        pattern=re.compile(pattern, re.IGNORECASE),
        scope=scope,
    )


SQL = "SQL Injection"
XSS = "XSS Attack"
LFI = "Local File Inclusion"
RFI = "Remote File Inclusion"
CMDI = "Command Injection"
CSRF = "CSRF Attack"
BRUTE = "Brute Force"

# Weight a category must reach before it is reported.
THRESHOLDS = {
    SQL: 4,
    XSS: 4,
    LFI: 4,
    RFI: 5,
    CMDI: 4,
    CSRF: 4,
    BRUTE: 4,
}

# Order findings are reported in: most severe class of bug first.
CATEGORY_ORDER = (SQL, CMDI, RFI, LFI, XSS, CSRF, BRUTE)

RULES: tuple[Rule, ...] = (
    # ── SQL injection ──────────────────────────────────────────────
    _rule("sqli-union", SQL, "UNION-based injection", "high", 4,
          r"\bunion\b(?:[\s()]|/\*.*?\*/)+\b(?:all|select)\b"),
    _rule("sqli-tautology", SQL, "Boolean tautology (OR 1=1)", "high", 4,
          # The right-hand quote is allowed to be unterminated -- `id=1' OR '1'='1`
          # ends mid-string, which is the whole point of the payload.
          r"""['")\s]\s*\b(?:or|and)\b\s*(?:'[^']*'|"[^"]*"|\d+)\s*(?:=|<>|!=|<|>|\blike\b)\s*(?:'[^']*'?|"[^"]*"?|\d+)"""),
    _rule("sqli-comment-terminator", SQL, "Quote followed by SQL comment", "high", 4,
          r"""(?:'|"|\))\s*(?:--|#|/\*)"""),
    _rule("sqli-stacked-ddl", SQL, "Stacked destructive statement", "critical", 5,
          r";\s*(?:drop|truncate|alter|rename)\s+(?:table|database|schema)\b"),
    _rule("sqli-timing", SQL, "Time-based blind injection", "high", 4,
          r"\b(?:sleep|benchmark|pg_sleep|dbms_pipe\.receive_message)\s*\(|\bwaitfor\s+delay\b"),
    _rule("sqli-schema-probe", SQL, "Database metadata probe", "high", 4,
          r"\b(?:information_schema|sysobjects|syscolumns|pg_catalog|sqlite_master|msysobjects)\b"),
    _rule("sqli-file-primitive", SQL, "File read/write or OS primitive", "critical", 5,
          r"\b(?:load_file|xp_cmdshell|openrowset|utl_http)\s*\(|\binto\s+(?:out|dump)file\b"),
    _rule("sqli-quote-break", SQL, "Quote break into SQL keyword", "medium", 2,
          r"""['"]\s*(?:;|\)|\bselect\b|\bunion\b|\bor\b|\band\b|\bfrom\b)"""),
    _rule("sqli-concat", SQL, "String construction helper", "low", 2,
          r"\b(?:char|chr|concat|concat_ws|group_concat|unhex)\s*\(|\|\|\s*'"),
    _rule("sqli-keyword-in-param", SQL, "SQL verb in a parameter value", "low", 1,
          r"[?&][^=&]*=[^&]*\b(?:select|insert|update|delete|drop|exec|execute|declare|cast|convert|having)\b",
          scope="params"),

    # ── Cross-site scripting ───────────────────────────────────────
    _rule("xss-script-tag", XSS, "Inline <script> tag", "high", 5,
          r"<\s*/?\s*script\b"),
    _rule("xss-event-handler", XSS, "HTML tag with an event handler", "high", 5,
          r"<\s*[a-z][^>]{0,200}?\bon[a-z]{3,15}\s*="),
    _rule("xss-js-uri-attr", XSS, "javascript: URI in an attribute", "high", 5,
          r"\b(?:href|src|action|formaction|data|xlink:href)\s*=\s*['\"]?\s*(?:javascript|vbscript):"),
    _rule("xss-js-uri", XSS, "javascript: URI", "medium", 3,
          r"\b(?:javascript|vbscript):\s*[\w$]"),
    _rule("xss-risky-tag", XSS, "Injected markup tag", "medium", 3,
          r"<\s*(?:iframe|object|embed|svg|math|body|base|link|meta|form|textarea|template|style)\b"),
    _rule("xss-expression", XSS, "CSS expression() payload", "medium", 3,
          r"\bexpression\s*\(|@import\s+['\"]?javascript:"),
    _rule("xss-sink", XSS, "DOM sink or credential access", "low", 2,
          r"\b(?:document\.cookie|document\.write|document\.location|window\.location|innerHTML|outerHTML|eval\s*\(|Function\s*\(|srcdoc\s*=)"),
    _rule("xss-prober", XSS, "Classic XSS proof-of-concept call", "low", 2,
          r"\b(?:alert|confirm|prompt)\s*\(|\bString\.fromCharCode\b|\batob\s*\("),

    # ── Path traversal / local file inclusion ──────────────────────
    _rule("lfi-traversal-deep", LFI, "Repeated directory traversal", "high", 5,
          r"(?:\.\.[\\/]){2,}"),
    _rule("lfi-traversal", LFI, "Directory traversal segment", "low", 2,
          r"\.\.[\\/]"),
    _rule("lfi-sensitive-file", LFI, "Access to a sensitive system file", "critical", 5,
          r"(?:/|\\|^)(?:etc/(?:passwd|shadow|hosts|group)|proc/self/(?:environ|cmdline)|var/log/\w+|windows/win\.ini|boot\.ini|web\.config|\.env|\.git/config|id_rsa)\b"),
    _rule("lfi-php-wrapper", LFI, "PHP stream wrapper", "critical", 5,
          r"\b(?:php|zip|phar|expect|glob)://"),
    _rule("lfi-nullbyte", LFI, "Null-byte path truncation", "high", 3,
          r"\x00"),

    # ── Remote file inclusion ──────────────────────────────────────
    _rule("rfi-include-param", RFI, "Remote URL in an include-style parameter", "high", 5,
          r"[?&](?:file|page|inc|include|require|template|tpl|load|doc|document|path|conf|config|module|view|lang|theme|skin)\s*=\s*(?:https?|ftps?|php|data|file)://",
          scope="params"),
    _rule("rfi-remote-payload", RFI, "Remote script/shell payload", "medium", 2,
          r"://[^\s&\"']+\.(?:txt|php|phtml|phar|jsp|jspx|asp|aspx|py|pl|sh|cgi)\b"),
    _rule("rfi-data-html", RFI, "data: URI carrying HTML", "high", 4,
          r"[?&][^=&]+=\s*data:text/html", scope="params"),

    # ── Command injection ──────────────────────────────────────────
    _rule("cmdi-metachar-binary", CMDI, "Shell metacharacter followed by a command", "high", 5,
          r"[;|&`\n]\s*(?:cat|ls|dir|type|whoami|id|uname|hostname|env|curl|wget|nc|ncat|netcat|bash|sh|zsh|cmd|powershell|python\d?|perl|ruby|php|ping|nslookup|dig|chmod|rm)\b"),
    _rule("cmdi-substitution", CMDI, "Command substitution", "high", 4,
          r"\$\(\s*\w|`[^`]{1,80}`|\$\{IFS\}"),
    _rule("cmdi-absolute-path", CMDI, "Chained call into a system binary path", "high", 5,
          r"(?:\|\||&&|;|\|)\s*/(?:bin|sbin|usr/bin|usr/sbin|etc)/"),
    _rule("cmdi-reverse-shell", CMDI, "Reverse shell primitive", "critical", 5,
          r"\bnc\b[^&]{0,40}\s-[a-z]*e[a-z]*\b|/dev/tcp/|\bmkfifo\b|\bbash\s+-i\b"),

    # ── CSRF ───────────────────────────────────────────────────────
    _rule("csrf-bypass", CSRF, "Explicit CSRF bypass flag", "high", 5,
          r"csrf[_\-]?(?:bypass|skip|disable|off|none)|(?:no|missing|invalid|remove|disable)[_\-]?csrf"),
    _rule("csrf-named-attack", CSRF, "Named CSRF attack pattern", "medium", 4,
          r"cross[_.\-\s]?site[_.\-\s]?request[_.\-\s]?forgery|forged[_\-]?request|anti[_\-]?csrf[_\-]?(?:off|bypass|remove)"),

    # ── Brute force / automated tooling ────────────────────────────
    _rule("brute-tooling", BRUTE, "Known attack tool signature", "high", 5,
          r"\b(?:hydra|medusa|patator|ncrack|crowbar|sqlmap|nikto|dirb|dirbuster|gobuster|feroxbuster|wfuzz|ffuf|nuclei|acunetix|nessus)\b"),
    _rule("brute-named-attack", BRUTE, "Named credential attack", "high", 5,
          r"\b(?:brute[_\-\s]?force|credential[_\-\s]?stuffing|password[_\-\s]?spray(?:ing)?|account[_\-\s]?takeover)\b"),
    _rule("brute-wordlist", BRUTE, "Password wordlist reference", "medium", 3,
          r"\b(?:rockyou|wordlist|passlist|combolist|darkweb2017)\b"),
)

RULES_BY_CATEGORY: dict[str, tuple[Rule, ...]] = {
    category: tuple(r for r in RULES if r.category == category)
    for category in CATEGORY_ORDER
}

# Names accepted by the /api/analyze "type" field.
CHECK_ALIASES = {
    "sql": SQL,
    "sqli": SQL,
    "xss": XSS,
    "lfi": LFI,
    "rfi": RFI,
    "cmdi": CMDI,
    "cmd": CMDI,
    "csrf": CSRF,
    "brute": BRUTE,
}


# ─────────────────────────────────────────
# Normalisation
# ─────────────────────────────────────────
_MAX_INPUT = 8192          # ignore anything past this; regex cost is linear in length
_DECODE_ROUNDS = 3         # unwrap double/triple percent-encoding


def normalise(value: str, plus_is_space: bool = False) -> str:
    """Fold the many ways the same payload can be written into one form.

    Percent-decoding is applied repeatedly because attackers double-encode to
    slip past single-pass filters. HTML entities are decoded for the same
    reason, and NFKC folds full-width look-alikes (``＜script＞``) onto ASCII.
    """
    if not value:
        return ""
    text = str(value)[:_MAX_INPUT]
    if plus_is_space:
        text = text.replace("+", " ")
    for _ in range(_DECODE_ROUNDS):
        decoded = unquote(text)
        if decoded == text:
            break
        text = decoded
    text = html.unescape(text)
    text = unicodedata.normalize("NFKC", text)
    # Inline comments are deliberately left in place: `UNION/**/SELECT` is
    # matched by the sqli-union rule itself, and stripping `/*` would blind the
    # sqli-comment-terminator rule.
    return text


@dataclass
class Target:
    """A request broken into the pieces the rules are allowed to look at."""

    raw: str
    path: str = ""
    params: str = ""
    body: str = ""

    @property
    def all(self) -> str:
        return f"{self.path} {self.params}"

    def haystack(self, scope: str) -> str:
        if scope == "path":
            return self.path
        if scope == "params":
            return self.params
        return self.all


def build_target(url: str, body: str = "") -> Target:
    """Split a URL into normalised components, ignoring scheme and host.

    Keeping the host out of the haystack is what stops ``https://`` from firing
    the remote-file-inclusion rules on every single submission.
    """
    text = str(url or "")[:_MAX_INPUT]
    parts = urlsplit(text if "//" in text else "//" + text)
    path = normalise(parts.path)
    query = normalise(parts.query, plus_is_space=True)
    fragment = normalise(parts.fragment)
    # The query string is kept with its separators so scope="params" rules can
    # anchor on `?name=` / `&name=`.
    params = ""
    if parts.query:
        params = "?" + query
    if parts.fragment:
        params += ("&" if params else "?") + fragment
    return Target(raw=normalise(text), path=path, params=params, body=body or "")


# ─────────────────────────────────────────
# Findings
# ─────────────────────────────────────────
@dataclass
class Finding:
    category: str
    severity: str
    score: int
    threshold: int
    rules: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    reflected: bool = False

    def to_dict(self) -> dict:
        return {
            "category": self.category,
            "severity": self.severity,
            "score": self.score,
            "threshold": self.threshold,
            "rules": list(self.rules),
            "evidence": list(self.evidence),
            "reflected": self.reflected,
        }


@dataclass
class AnalysisResult:
    safe: bool
    severity: str
    categories: list[str]
    findings: list[Finding]
    summary: str

    def to_dict(self) -> dict:
        return {
            "safe": self.safe,
            "severity": self.severity,
            "categories": list(self.categories),
            "findings": [f.to_dict() for f in self.findings],
            "summary": self.summary,
        }

# ─────────────────────────────────────────
# Runtime signals
# ─────────────────────────────────────────
@dataclass
class RuntimeSignal:
    """Evidence the rules cannot see, contributed by the application.

    Brute force is the obvious case: it is a property of a *sequence* of
    requests from one client, not of any single URL string. The original engine
    tried to infer it from words like "login" and "admin" appearing in the URL,
    which flagged ``/admin/login?redirect=/dashboard`` as an attack. The app now
    passes in the real failed-login counter instead.
    """

    category: str
    id: str
    weight: int
    severity: str = "high"
    note: str = ""


def _resolve_categories(only: str | Sequence[str] | None) -> tuple[str, ...]:
    if only is None:
        return CATEGORY_ORDER
    if isinstance(only, str):
        key = only.strip().lower()
        if key in ("", "full", "all", "any"):
            return CATEGORY_ORDER
        resolved = CHECK_ALIASES.get(key)
        return (resolved,) if resolved else CATEGORY_ORDER
    wanted = {CHECK_ALIASES.get(str(o).strip().lower(), str(o)) for o in only}
    selected = tuple(c for c in CATEGORY_ORDER if c in wanted)
    return selected or CATEGORY_ORDER


def _is_reflected(snippet: str, body: str) -> bool:
    if not snippet or not body:
        return False
    if snippet in body:
        return True
    return snippet.lower() in normalise(body).lower()


def evaluate(
    url: str,
    body: str = "",
    only: str | Sequence[str] | None = None,
    runtime_signals: Iterable[RuntimeSignal] | None = None,
) -> AnalysisResult:
    """Score a request against the rule set.

    ``body`` is only used to test whether a payload was reflected back; it is
    never run through the rules, because normal HTML contains ``<iframe>``,
    ``onclick=`` and ``innerHTML`` and would otherwise be flagged as XSS.
    """
    target = build_target(url, body)
    wanted = _resolve_categories(only)
    signals_by_category: dict[str, list[RuntimeSignal]] = {}
    for signal in runtime_signals or ():
        signals_by_category.setdefault(signal.category, []).append(signal)

    findings: list[Finding] = []
    for category in CATEGORY_ORDER:
        if category not in wanted:
            continue
        score = 0
        severities: list[str] = []
        matched: list[str] = []
        evidence: list[str] = []

        for rule in RULES_BY_CATEGORY[category]:
            match = rule.pattern.search(target.haystack(rule.scope))
            if not match:
                continue
            score += rule.weight
            severities.append(rule.severity)
            matched.append(rule.id)
            snippet = match.group(0).strip()[:120]
            if snippet and snippet not in evidence:
                evidence.append(snippet)

        for signal in signals_by_category.get(category, ()):
            score += signal.weight
            severities.append(signal.severity)
            matched.append(signal.id)
            if signal.note:
                evidence.append(signal.note[:120])

        threshold = THRESHOLDS[category]
        if score < threshold:
            continue

        finding = Finding(
            category=category,
            severity=_max_severity(severities),
            score=score,
            threshold=threshold,
            rules=matched,
            evidence=evidence,
        )
        if category == XSS and body:
            if any(_is_reflected(snippet, body) for snippet in evidence):
                finding.reflected = True
                finding.severity = "critical"
        findings.append(finding)

    categories = [f.category for f in findings]
    safe = not findings
    return AnalysisResult(
        safe=safe,
        severity="info" if safe else _max_severity(f.severity for f in findings),
        categories=categories,
        findings=findings,
        summary="Safe" if safe else ", ".join(categories),
    )


def describe_rules() -> list[dict]:
    """Machine-readable rule inventory, for the admin UI or documentation."""
    return [
        {
            "id": r.id,
            "category": r.category,
            "description": r.description,
            "severity": r.severity,
            "weight": r.weight,
            "scope": r.scope,
            "threshold": THRESHOLDS[r.category],
        }
        for r in RULES
    ]


# ─────────────────────────────────────────
# Backwards-compatible single-category helpers
# ─────────────────────────────────────────
def _single(url: str, category: str) -> str | None:
    result = evaluate(url, only=(category,))
    return category if category in result.categories else None


def check_sql(url):   return _single(url, SQL)
def check_xss(url):   return _single(url, XSS)
def check_lfi(url):   return _single(url, LFI)
def check_rfi(url):   return _single(url, RFI)
def check_cmdi(url):  return _single(url, CMDI)
def check_csrf(url):  return _single(url, CSRF)
def check_brute(url): return _single(url, BRUTE)

