"""Deterministic risk scoring: severity × reachability × OWASP-class (+AI verdict)."""

from radar.scan.findings import Finding
from radar.triage.reachability import Reach
from radar.triage.risk import _band, _owasp_code, risk_score


def _reachable(n=1):
    return Reach(function_id="f", routes=[f"GET /r{i}" for i in range(n)], status="reachable")


def _unknown():
    return Reach(function_id=None, routes=[], status="unknown")


def _finding(sev="ERROR", rule="js-sql-string-concat", meta=None):
    return Finding(sev, "app.js", 10, rule, "msg", metadata=meta or {})


def test_band_boundaries():
    assert _band(80) == "critical"
    assert _band(79) == "high"
    assert _band(60) == "high"
    assert _band(35) == "medium"
    assert _band(15) == "low"
    assert _band(14) == "noise"


def test_reachable_injection_beats_unknown_weakhash():
    high = risk_score(_finding("ERROR", "js-sql-string-concat"), _reachable(3))
    low = risk_score(_finding("WARNING", "php-weak-hash-algorithm"), _unknown())
    assert high.value > low.value
    assert high.band == "critical"  # 60 × 1.3 × 1.3 = 101.4 -> capped 100


def test_no_verdict_still_scores():
    """No-key path: a finding always gets a usable score + band."""
    score = risk_score(_finding("ERROR", "js-sql-string-concat"), _reachable(1))
    assert 0 < score.value <= 100
    assert score.band in {"critical", "high", "medium", "low", "noise"}
    assert score.factors  # transparent contributors


def test_false_positive_is_noise_even_when_error():
    score = risk_score(_finding("ERROR", "js-sql-string-concat"), _reachable(3),
                       verdict={"exploitability": "false_positive"})
    assert score.band == "noise"
    assert "ai:false_positive" in score.factors


def test_exploitable_forced_to_critical():
    score = risk_score(_finding("INFO", "py-flask-debug-true"), _unknown(),
                       verdict={"exploitability": "exploitable"})
    assert score.band == "critical"
    assert score.value >= 80  # value raised so the badge never reads "9 critical"


def test_false_positive_value_capped_into_noise_range():
    score = risk_score(_finding("ERROR", "js-sql-string-concat"), _reachable(3),
                       verdict={"exploitability": "false_positive"})
    assert score.band == "noise"
    assert score.value <= 14


def test_likely_lowers_below_exploitable():
    base = risk_score(_finding("ERROR", "js-sql-string-concat"), _reachable(2))
    likely = risk_score(_finding("ERROR", "js-sql-string-concat"), _reachable(2),
                        verdict={"exploitability": "likely"})
    assert likely.value < base.value


def test_owasp_from_metadata_when_rule_id_has_no_keyword():
    """Preset rules: arbitrary id but metadata.owasp drives the class weight."""
    preset = _finding("ERROR", "python.lang.security.audit.dangerous-call",
                      meta={"owasp": "A03:2021 - Injection"})
    plain = _finding("ERROR", "python.lang.security.audit.dangerous-call")
    assert _owasp_code(preset) == "A03"
    assert _owasp_code(plain) == "A00"  # no keyword, no metadata -> Other
    assert risk_score(preset, _reachable(1)).value > risk_score(plain, _reachable(1)).value


def test_owasp_metadata_accepts_list():
    f = _finding(meta={"owasp": ["A01:2021", "A03:2021 - Injection"]})
    assert _owasp_code(f) == "A01"  # first match wins


def test_reachable_routes_increase_score():
    one = risk_score(_finding(), _reachable(1)).value
    many = risk_score(_finding(), _reachable(5)).value
    assert many >= one
