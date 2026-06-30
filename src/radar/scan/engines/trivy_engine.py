"""Trivy engine — dependency CVEs (SCA) + IaC misconfig + secrets.

This is the dimension Semgrep doesn't cover: known-vulnerable dependencies
(npm/pip/go.mod/…), infrastructure misconfig (Dockerfile/Terraform/K8s) and
embedded secrets. Runs the native `trivy` binary, or the official Docker image
as a fallback. Output is JSON on stdout, parsed in memory (zero footprint).
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

from radar.scan.engines.base import ScanEngine, register
from radar.scan.findings import Finding
from radar.scan.timeouts import scan_timeout

DOCKER_IMAGE = "aquasec/trivy:latest"
_SCANNERS = "vuln,misconfig,secret"

# Trivy severity (UNKNOWN/LOW/MEDIUM/HIGH/CRITICAL) -> radar severity.
_SEV = {
    "CRITICAL": "ERROR", "HIGH": "ERROR",
    "MEDIUM": "WARNING",
    "LOW": "INFO", "UNKNOWN": "INFO",
}


def parse_trivy(report: dict, target: Path) -> list[Finding]:
    """Trivy JSON `Results[]` -> Findings across vuln / misconfig / secret."""
    findings: list[Finding] = []
    for res in report.get("Results", []) or []:
        tgt = res.get("Target", "?")

        # Dependency CVEs (SCA) — A06 Vulnerable & Outdated Components.
        for v in res.get("Vulnerabilities", []) or []:
            sev = _SEV.get(str(v.get("Severity", "")).upper(), "INFO")
            pkg = v.get("PkgName", "?")
            msg = f"{v.get('VulnerabilityID', 'CVE')} in {pkg} {v.get('InstalledVersion', '')}".strip()
            if v.get("FixedVersion"):
                msg += f" — fix: {v['FixedVersion']}"
            if v.get("Title"):
                msg += f" ({v['Title']})"
            findings.append(
                Finding(
                    severity=sev, path=tgt, line=0,
                    rule=f"trivy.{v.get('VulnerabilityID', 'vuln')}",
                    message=msg[:300],
                    metadata={
                        "engine": "trivy",
                        "owasp": "A06:2021-Vulnerable and Outdated Components",
                        "pkg": pkg, "cve": v.get("VulnerabilityID", ""),
                    },
                )
            )

        # IaC misconfiguration — A05 Security Misconfiguration.
        for m in res.get("Misconfigurations", []) or []:
            sev = _SEV.get(str(m.get("Severity", "")).upper(), "INFO")
            line = (m.get("CauseMetadata") or {}).get("StartLine", 0) or 0
            title = m.get("Title", "Misconfiguration")
            desc = (m.get("Description") or "").strip()
            findings.append(
                Finding(
                    severity=sev, path=tgt, line=line,
                    rule=f"trivy.{m.get('ID', 'misconfig')}",
                    message=(f"{title}: {desc}" if desc else title)[:300],
                    metadata={
                        "engine": "trivy",
                        "owasp": "A05:2021-Security Misconfiguration",
                    },
                )
            )

        # Embedded secrets — A02 Cryptographic Failures.
        for s in res.get("Secrets", []) or []:
            findings.append(
                Finding(
                    severity="ERROR", path=tgt,
                    line=s.get("StartLine", 0) or 0,
                    rule=f"trivy.secret.{s.get('RuleID', 'secret')}",
                    message=(s.get("Title") or "Secret detected"),
                    metadata={
                        "engine": "trivy",
                        "owasp": "A02:2021-Cryptographic Failures",
                    },
                )
            )
    return findings


class TrivyEngine(ScanEngine):
    name = "trivy"
    description = "Trivy — dependency CVEs (SCA) + IaC misconfig + secrets"
    default = True

    def detect(self) -> str | None:
        if shutil.which("trivy"):
            return "native"
        if shutil.which("docker"):
            return "docker"
        return None

    def _argv(self, target: Path, runtime: str) -> list[str]:
        if runtime == "native":
            return [
                "trivy", "fs", "--quiet", "--format", "json",
                "--scanners", _SCANNERS, str(target),
            ]
        # docker: mount target read-only at /src, scan that.
        return [
            "docker", "run", "--rm",
            "-v", f"{target.as_posix()}:/src:ro",
            DOCKER_IMAGE, "fs", "--quiet", "--format", "json",
            "--scanners", _SCANNERS, "/src",
        ]

    def scan(self, target, *, rules_only=False, runtime=None, extra_config=None):
        target = Path(target)
        runtime = runtime or self.detect()
        if not runtime:
            return []
        try:
            proc = subprocess.run(
                self._argv(target, runtime), capture_output=True, text=True,
                encoding="utf-8", errors="replace",
                timeout=scan_timeout(),
            )
        except (OSError, subprocess.TimeoutExpired):
            return []
        try:
            report = json.loads(proc.stdout or "{}")
        except json.JSONDecodeError:
            return []
        return parse_trivy(report, target)


register(TrivyEngine())
