"""Normalize a Semgrep JSON report into sorted Finding records + a severity summary.

The field shape mirrors scripts/render-pr-comment.py (the CI renderer) so both
read Semgrep the same way — keep them in sync.
"""

from dataclasses import dataclass

SEVERITY_ORDER = {"ERROR": 0, "WARNING": 1, "INFO": 2}
FAIL_THRESHOLD = {"error": 0, "warning": 1, "info": 2}  # --fail-on choices


@dataclass
class Finding:
    severity: str  # ERROR | WARNING | INFO
    path: str
    line: int
    rule: str
    message: str


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
