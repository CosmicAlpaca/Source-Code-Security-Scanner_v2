"""Bandit engine — Python-specific SAST (AST-based).

Complements Semgrep with deep Python checks (B-test ids). Runs the native
`bandit` binary, or `python -m bandit` when installed as a library but not on
PATH. Bandit emits JSON on stdout; we parse it in memory (zero footprint) and
normalize each issue into a Finding.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

from radar.scan.engines.base import ScanEngine, register
from radar.scan.findings import Finding
from radar.scan.timeouts import scan_timeout

# Bandit severity (LOW/MEDIUM/HIGH) -> radar severity.
_SEV = {"HIGH": "ERROR", "MEDIUM": "WARNING", "LOW": "INFO"}

# Bandit test-id (plugin id) -> OWASP-2021 code. Set directly on the finding so
# Bandit results don't depend on the CWE→OWASP fallback. Exact ids first; any
# B6xx/B7xx not listed falls through to _BANDIT_PREFIX (the injection family).
_BANDIT_OWASP = {
    # Injection — code / command / SQL / template (A03)
    "B102": "A03", "B307": "A03", "B308": "A03",
    "B608": "A03", "B609": "A03", "B610": "A03", "B611": "A03",
    "B701": "A03", "B702": "A03", "B703": "A03",
    # Insecure deserialization / integrity (A08)
    "B301": "A08", "B302": "A08", "B506": "A08",
    # Cryptographic failures — weak hash/cipher/rng/cleartext/SSL (A02)
    "B303": "A02", "B304": "A02", "B305": "A02", "B311": "A02", "B312": "A02",
    "B321": "A02", "B323": "A02", "B324": "A02", "B413": "A02",
    "B502": "A02", "B503": "A02", "B504": "A02", "B505": "A02",
    # Identification & authentication failures (A07)
    "B105": "A07", "B106": "A07", "B107": "A07", "B501": "A07", "B507": "A07",
    # Security misconfiguration — bind-all, flask debug, XXE-prone XML (A05)
    "B104": "A05", "B201": "A05", "B411": "A05",
    "B313": "A05", "B314": "A05", "B315": "A05", "B316": "A05", "B317": "A05",
    "B318": "A05", "B319": "A05", "B320": "A05",
    "B405": "A05", "B406": "A05", "B407": "A05", "B408": "A05", "B409": "A05", "B410": "A05",
    # Broken access control — insecure file perms / temp files / tar extract (A01)
    "B103": "A01", "B108": "A01", "B306": "A01", "B202": "A01",
    # SSRF (A10)
    "B310": "A10",
}
# Prefix fallback for the injection-heavy ranges (subprocess/shell, XSS templates).
_BANDIT_PREFIX = {"B6": "A03", "B7": "A03"}


def _bandit_owasp(test_id: str) -> str | None:
    """OWASP-2021 code for a Bandit test id, or None if unmapped (then the engine
    leaves classification to the CWE / rule-name fallback)."""
    if test_id in _BANDIT_OWASP:
        return _BANDIT_OWASP[test_id]
    return _BANDIT_PREFIX.get(test_id[:2])


def parse_bandit(report: dict, target: Path) -> list[Finding]:
    """Bandit JSON `results[]` -> Findings (paths made repo-relative)."""
    findings: list[Finding] = []
    troot = target.resolve()
    for r in report.get("results", []) or []:
        sev = _SEV.get(str(r.get("issue_severity", "")).upper(), "INFO")
        raw = r.get("filename", "?")
        try:
            rel = Path(raw).resolve().relative_to(troot).as_posix()
        except (ValueError, OSError):
            rel = Path(raw).as_posix()
        cwe = (r.get("issue_cwe") or {}).get("id")
        test_id = r.get("test_id", "B000")
        meta = {
            "engine": "bandit",
            "cwe": f"CWE-{cwe}" if cwe else "",
            "confidence": r.get("issue_confidence", ""),
        }
        owasp = _bandit_owasp(test_id)
        if owasp:
            meta["owasp"] = owasp  # direct OWASP tag (no reliance on CWE fallback)
        findings.append(
            Finding(
                severity=sev,
                path=rel,
                line=r.get("line_number", 0) or 0,
                rule=f"bandit.{test_id}",
                message=(r.get("issue_text") or "").strip(),
                metadata=meta,
            )
        )
    return findings


class BanditEngine(ScanEngine):
    name = "bandit"
    description = "Bandit — Python-specific SAST (deep Python checks)"
    default = True

    def _cmd(self) -> list[str] | None:
        """Native `bandit`, else `python -m bandit`, else None."""
        if shutil.which("bandit"):
            return ["bandit"]
        try:
            r = subprocess.run(
                [sys.executable, "-m", "bandit", "--version"],
                capture_output=True, timeout=10,
            )
            if r.returncode == 0:
                return [sys.executable, "-m", "bandit"]
        except Exception:
            pass
        return None

    def detect(self) -> str | None:
        return "native" if self._cmd() else None

    def scan(self, target, *, rules_only=False, runtime=None, extra_config=None):
        cmd = self._cmd()
        if not cmd:
            return []
        target = Path(target)
        # -r recurse, -f json, -q quiet (no progress noise on stdout).
        argv = [*cmd, "-r", str(target), "-f", "json", "-q"]
        try:
            proc = subprocess.run(
                argv, capture_output=True, text=True,
                encoding="utf-8", errors="replace",
                timeout=scan_timeout(),
            )
        except (OSError, subprocess.TimeoutExpired):
            return []
        try:
            report = json.loads(proc.stdout or "{}")
        except json.JSONDecodeError:
            return []
        return parse_bandit(report, target)


register(BanditEngine())
