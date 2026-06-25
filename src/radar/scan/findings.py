"""Normalize a Semgrep JSON report into sorted Finding records + a severity summary.

The field shape mirrors scripts/render-pr-comment.py (the CI renderer) so both
read Semgrep the same way — keep them in sync.
"""

from dataclasses import dataclass, field

SEVERITY_ORDER = {"ERROR": 0, "WARNING": 1, "INFO": 2}
FAIL_THRESHOLD = {"error": 0, "warning": 1, "info": 2}  # --fail-on choices

# OWASP category by rule-name keyword. Shared by the HTML report and risk scoring
# so both classify findings the same way. For preset/registry rules whose ids lack
# these keywords, risk scoring prefers the semgrep `metadata.owasp` field instead.
OWASP_MAP: dict[str, tuple[str, str]] = {
    "sql":             ("A03", "Injection"),
    "xss":             ("A03", "Injection"),
    "eval":            ("A03", "Injection"),
    "child-process":   ("A03", "Injection"),
    "command":         ("A03", "Injection"),
    "ssrf":            ("A10", "SSRF"),
    "path-traversal":  ("A01", "Broken Access Control"),
    "deserialization": ("A08", "Insecure Deserialization"),
    "jwt":             ("A02", "Cryptographic Failures"),
    "crypto":          ("A02", "Cryptographic Failures"),
    "hash":            ("A02", "Cryptographic Failures"),
    "flask":           ("A05", "Security Misconfiguration"),
    "debug":           ("A05", "Security Misconfiguration"),
    "secret":          ("A02", "Cryptographic Failures"),
}


def owasp_tag(rule: str) -> tuple[str, str]:
    """(code, label) OWASP category from a rule id by keyword; ('A00','Other') if none."""
    r = rule.lower()
    for key, val in OWASP_MAP.items():
        if key in r:
            return val
    return ("A00", "Other")


_OWASP_LABELS = {code: label for code, label in OWASP_MAP.values()}


def owasp_tag_for(finding: "Finding") -> tuple[str, str]:
    """OWASP category for a normalized finding, preferring engine metadata."""
    raw = str((finding.metadata or {}).get("owasp") or "").strip()
    if raw:
        code = raw.split(":", 1)[0].split("-", 1)[0].strip()
        if code:
            label = raw.split("-", 1)[-1].strip() if "-" in raw else _OWASP_LABELS.get(code, "Other")
            return code, label or "Other"
    return owasp_tag(finding.rule.rsplit(".", 1)[-1])


@dataclass
class Finding:
    severity: str  # ERROR | WARNING | INFO
    path: str
    line: int
    rule: str
    message: str
    metadata: dict = field(default_factory=dict)  # semgrep extra.metadata (owasp/cwe/…)


def parse(report: dict) -> list[Finding]:
    """semgrep JSON `results[]` -> Findings sorted by (severity, path, line)."""
    findings: list[Finding] = []
    for result in report.get("results", []):
        extra = result.get("extra", {})
        severity = str(extra.get("severity", "INFO")).upper()
        findings.append(
            Finding(
                severity=severity if severity in SEVERITY_ORDER else "INFO",
                path=result.get("path", "?"),
                line=result.get("start", {}).get("line", 0),
                rule=result.get("check_id", "?"),
                message=(extra.get("message") or "").strip(),
                metadata=extra.get("metadata") or {},
            )
        )
    findings.sort(key=lambda f: (SEVERITY_ORDER[f.severity], f.path, f.line))
    return findings


def summary(findings: list[Finding]) -> dict:
    counts = {sev: 0 for sev in SEVERITY_ORDER}
    for f in findings:
        counts[f.severity] += 1
    return {"error": counts["ERROR"], "warning": counts["WARNING"], "info": counts["INFO"], "total": len(findings)}


def exceeds_threshold(findings: list[Finding], fail_on: str) -> bool:
    """True if any finding is at or above the `fail_on` severity (for --error gating)."""
    limit = FAIL_THRESHOLD[fail_on]
    return any(SEVERITY_ORDER[f.severity] <= limit for f in findings)
