"""Deterministic risk score (0-100) for a finding — the axis that ranks output.

Always computable WITHOUT an API key: severity × reachability × OWASP-class.
When an AI verdict is present it acts as a multiplier that upgrades (or crushes)
the base score, so AI is a refinement of ranking, not a separate column.

Pure module: stdlib + the shared OWASP classifier only. No semgrep / no network.
"""

import re
from dataclasses import dataclass, field

from radar.scan.findings import owasp_tag

# ── Weights (module-level so they're easy to tune and assert in tests) ─────────
_SEVERITY_W = {"ERROR": 60.0, "WARNING": 35.0, "INFO": 15.0}

# OWASP-category multiplier: injection / deserialization weigh most.
_CLASS_W = {
    "A03": 1.3,  # Injection
    "A08": 1.3,  # Insecure Deserialization
    "A01": 1.1,  # Broken Access Control
    "A10": 1.1,  # SSRF
}
_DEFAULT_CLASS_W = 1.0

# AI verdict multiplier (and band floor for the extremes).
_VERDICT_MULT = {
    "exploitable": 1.0,
    "likely": 0.85,
    "unlikely": 0.5,
    "false_positive": 0.1,
}

# band thresholds (value >= cut -> band)
_BANDS = [(80, "critical"), (60, "high"), (35, "medium"), (15, "low")]
NOISE = "noise"


@dataclass
class RiskScore:
    value: int            # 0-100
    band: str             # critical | high | medium | low | noise
    factors: list[str] = field(default_factory=list)  # human-readable contributors


def _band(value: int) -> str:
    for cut, name in _BANDS:
        if value >= cut:
            return name
    return NOISE


def _owasp_code(finding) -> str:
    """OWASP code for the finding: prefer semgrep metadata, fall back to rule keyword.

    Preset/registry findings have arbitrary rule ids but carry `metadata.owasp`;
    custom rules are classified by id keyword via the shared `owasp_tag`.
    """
    meta = getattr(finding, "metadata", None) or {}
    raw = meta.get("owasp")
    if isinstance(raw, (list, tuple)):
        raw = " ".join(str(x) for x in raw)
    if raw:
        m = re.search(r"\bA0?(\d{1,2})\b", str(raw), re.IGNORECASE)
        if m:
            return "A" + m.group(1).zfill(2)
    return owasp_tag(finding.rule)[0]


def _class_weight(code: str) -> float:
    return _CLASS_W.get(code, _DEFAULT_CLASS_W)


def _routes(reach) -> list:
    """Reach.routes coerced to a list — tolerate None / non-list from external maps."""
    r = getattr(reach, "routes", None)
    return list(r) if isinstance(r, (list, tuple)) else []


def _reach_mult(reach) -> float:
    if getattr(reach, "status", "unknown") == "reachable":
        return 1.0 + 0.1 * min(len(_routes(reach)), 5)
    return 0.6


def risk_score(finding, reach, verdict: dict | None = None) -> RiskScore:
    """Finding (+reachability, +optional AI verdict) -> RiskScore. No key required."""
    sev = finding.severity if finding.severity in _SEVERITY_W else "INFO"
    code = _owasp_code(finding)
    base = _SEVERITY_W[sev] * _reach_mult(reach) * _class_weight(code)

    routes = _routes(reach)
    reach_txt = f"reachable({len(routes)} route{'s' if len(routes) != 1 else ''})" \
        if getattr(reach, "status", "unknown") == "reachable" else "unknown"
    factors = [sev, reach_txt, f"{code}(×{_class_weight(code):g})"]

    forced_band: str | None = None
    if verdict:
        exploit = str(verdict.get("exploitability", "")).lower()
        mult = _VERDICT_MULT.get(exploit)
        if mult is not None:
            base *= mult
            factors.append(f"ai:{exploit}")
            if exploit == "false_positive":
                forced_band = NOISE
            elif exploit == "exploitable":
                forced_band = "critical"

    value = int(round(min(base, 100.0)))
    # Keep value and a forced band consistent so the badge never reads "9 critical".
    if forced_band == "critical":
        value = max(value, 80)
    elif forced_band == NOISE:
        value = min(value, 14)
    band = forced_band or _band(value)
    return RiskScore(value=value, band=band, factors=factors)
