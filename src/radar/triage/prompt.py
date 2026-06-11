"""Build the triage prompt and redact secrets before anything leaves the machine."""

import re

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
    '"confidence": 0.0-1.0, "reasoning": "one or two sentences", "reachable": true|false}.'
)


def redact(snippet: str) -> str:
    out = snippet
    for pattern in _REDACTORS:
        out = pattern.sub(_MASK, out)
    return out


def build_messages(finding, snippet: str, reach) -> list[dict]:
    routes = ", ".join(reach.routes) if reach.routes else "(none found)"
    user = (
        f"Rule: {finding.rule}\n"
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
