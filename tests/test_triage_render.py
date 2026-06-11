"""Triage rendering: JSON stays backward-compatible (+ai), terminal never crashes."""

import json

from radar.scan.findings import Finding
from radar.triage.engine import TriagedFinding
from radar.triage.reachability import Reach
from radar.triage.render import render_terminal_triage, to_json_triage


def _tf(verdict=None, error=None, status="reachable", routes=("POST /login",)):
    return TriagedFinding(
        finding=Finding("ERROR", "session.js", 5, "js.xss", "reflected xss"),
        reach=Reach("session.js::handleLogin", list(routes), status),
        verdict=verdict,
        cached=False,
        error=error,
    )


def test_json_keeps_deterministic_fields_and_adds_ai():
    tf = _tf(verdict={"exploitability": "exploitable", "confidence": 0.9,
                      "reasoning": "x", "reachable": True})
    payload = json.loads(to_json_triage([tf]))
    f = payload["findings"][0]
    # deterministic fields unchanged
    assert f["severity"] == "ERROR"
    assert f["path"] == "session.js"
    assert f["line"] == 5
    assert f["rule"] == "js.xss"
    # additive blocks
    assert f["reachability"]["status"] == "reachable"
    assert f["ai"]["exploitability"] == "exploitable"
    assert f["ai"]["cached"] is False
    assert payload["summary"]["total"] == 1


def test_json_renders_error_block():
    payload = json.loads(to_json_triage([_tf(error="OpenAI HTTP 429")]))
    assert payload["findings"][0]["ai"]["error"] == "OpenAI HTTP 429"


def test_terminal_handles_verdict_unknown_and_error(capsys):
    results = [
        _tf(verdict={"exploitability": "unlikely", "confidence": 0.2,
                     "reasoning": "no untrusted path", "reachable": False},
            status="unknown", routes=()),
        _tf(error="boom"),
        _tf(verdict=None),
    ]
    render_terminal_triage(results)  # must not raise
    out = capsys.readouterr().out
    assert "session.js:5" in out
