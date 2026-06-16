"""Build the triage prompt and redact secrets before anything leaves the machine."""

import re

from radar.scan.findings import owasp_tag

# Mask obvious secrets so a finding's snippet never exfiltrates a live credential.
_REDACTORS = [
    re.compile(r"AKIA[0-9A-Z]{16}"),  # AWS access key id
    re.compile(r"sk-[A-Za-z0-9_\-]{16,}"),  # OpenAI-style key
    re.compile(r"(?i)bearer\s+[A-Za-z0-9._\-]{12,}"),
    re.compile(r"(?i)(secret|token|password|passwd|api[_-]?key)\s*[:=]\s*['\"]?[^\s'\"]{6,}"),
    re.compile(r"\b[A-Fa-f0-9]{32,}\b"),  # long hex blobs (keys, hashes)
]
_MASK = "«redacted»"

_SYSTEM = (
    "You are a security triage assistant. You receive ONE static-analysis (Semgrep) "
    "finding with a code snippet and best-effort reachability from a call graph. "
    "Decide whether the finding is genuinely exploitable.\n"
    "RULES:\n"
    "- Reachability is BEST-EFFORT. 'reachable' means an untrusted route reaches this "
    "code. 'unknown' means NO route path was found — that is NOT proof the code is dead "
    "or safe (dynamic dispatch is missed). Do NOT downgrade severity solely because "
    "reachability is 'unknown'.\n"
    "- You are triaging, not censoring: you assess a finding, you never delete it.\n"
    "- Reply with JSON ONLY, no prose, matching exactly: "
    '{"exploitability": "exploitable|likely|unlikely|false_positive", '
    '"confidence": 0.0-1.0, "reasoning": "one or two sentences", '
    '"exploit_path": "one short sentence: where untrusted input enters and how it '
    'reaches this sink (or why it cannot)", "reachable": true|false}.'
)


def redact(snippet: str) -> str:
    out = snippet
    for pattern in _REDACTORS:
        out = pattern.sub(_MASK, out)
    return out


def _owasp_line(finding) -> str:
    """OWASP/CWE class line for the prompt — helps the model weigh the vuln type.

    Prefers the semgrep `metadata.owasp`/`cwe`; falls back to the rule-id keyword
    classifier so even bare custom rules carry a category.
    """
    meta = getattr(finding, "metadata", None) or {}
    owasp = meta.get("owasp")
    if isinstance(owasp, (list, tuple)):
        owasp = ", ".join(str(x) for x in owasp)
    if not owasp:
        code, label = owasp_tag(finding.rule)
        owasp = f"{code} {label}" if code != "A00" else ""
    cwe = meta.get("cwe")
    if isinstance(cwe, (list, tuple)):
        cwe = ", ".join(str(x) for x in cwe)
    parts = [p for p in (owasp, cwe) if p]
    return ("OWASP/CWE: " + " · ".join(str(p) for p in parts) + "\n") if parts else ""


def build_messages(finding, snippet: str, reach) -> list[dict]:
    routes = ", ".join(reach.routes) if reach.routes else "(none found)"
    user = (
        f"Rule: {finding.rule}\n"
        f"{_owasp_line(finding)}"
        f"Severity: {finding.severity}\n"
        f"Message: {finding.message}\n"
        f"Location: {finding.path}:{finding.line}\n"
        f"Reachability: {reach.status}; routes reaching this code: {routes}\n\n"
        f"Code snippet:\n```\n{snippet}\n```"
    )
    return [
        {"role": "system", "content": _SYSTEM},
        {"role": "user", "content": user},
    ]
