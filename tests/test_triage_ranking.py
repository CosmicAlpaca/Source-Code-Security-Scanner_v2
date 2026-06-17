"""Ranking teeth: risk in terminal/JSON, --top, --fail-on, --min-risk exit codes."""

import json

from click.testing import CliRunner

from radar import cli
from radar.scan.findings import Finding
from radar.triage.engine import TriagedFinding
from radar.triage.reachability import Reach
from radar.triage.render import render_terminal_triage, to_json_triage
from radar.triage.risk import risk_score


def _tf(sev="ERROR", rule="js-sql-string-concat", line=5, verdict=None,
        status="reachable", routes=("POST /login",)):
    return TriagedFinding(
        finding=Finding(sev, "app.js", line, rule, "msg"),
        reach=Reach("app.js::f", list(routes), status),
        verdict=verdict, cached=False,
    )


def _risk_map(results):
    return {id(tf): risk_score(tf.finding, tf.reach, tf.verdict) for tf in results}


# ── render adds risk (additive) ───────────────────────────────────────────────

def test_json_includes_risk_object():
    tf = _tf()
    payload = json.loads(to_json_triage([tf], _risk_map([tf])))
    f = payload["findings"][0]
    assert set(f["risk"]) == {"value", "band", "factors"}
    assert 0 < f["risk"]["value"] <= 100
    # deterministic fields untouched
    assert f["severity"] == "ERROR" and f["rule"] == "js-sql-string-concat"


def test_json_without_risk_map_omits_risk():
    payload = json.loads(to_json_triage([_tf()]))
    assert "risk" not in payload["findings"][0]


def test_terminal_renders_risk_column(capsys):
    results = [_tf()]
    render_terminal_triage(results, risk_map=_risk_map(results))
    out = capsys.readouterr().out
    assert "Risk" in out


# ── CLI gates ─────────────────────────────────────────────────────────────────

def _patch(monkeypatch, results):
    from radar.triage import engine
    monkeypatch.setattr(engine, "triage", lambda *a, **k: (list(results), 0))


def test_fail_on_exploitable_exits_1(monkeypatch, tmp_path):
    _patch(monkeypatch, [_tf(verdict={"exploitability": "exploitable", "confidence": 0.9, "reasoning": "x"})])
    res = CliRunner().invoke(cli.main, ["triage", str(tmp_path), "--fail-on", "exploitable"])
    assert res.exit_code == 1
    assert "--fail-on exploitable" in res.output


def test_fail_on_exploitable_passes_when_none(monkeypatch, tmp_path):
    _patch(monkeypatch, [_tf(verdict={"exploitability": "unlikely", "confidence": 0.2, "reasoning": "x"})])
    res = CliRunner().invoke(cli.main, ["triage", str(tmp_path), "--fail-on", "exploitable"])
    assert res.exit_code == 0


def test_fail_on_likely_also_trips_on_exploitable(monkeypatch, tmp_path):
    _patch(monkeypatch, [_tf(verdict={"exploitability": "exploitable", "confidence": 0.9, "reasoning": "x"})])
    res = CliRunner().invoke(cli.main, ["triage", str(tmp_path), "--fail-on", "likely"])
    assert res.exit_code == 1


def test_min_risk_gate_works_without_key(monkeypatch, tmp_path):
    # ERROR × reachable × injection -> high score; no verdict needed (offline gate).
    _patch(monkeypatch, [_tf()])
    res = CliRunner().invoke(cli.main, ["triage", str(tmp_path), "--min-risk", "50"])
    assert res.exit_code == 1
    assert "--min-risk 50" in res.output


def test_min_risk_below_threshold_passes(monkeypatch, tmp_path):
    _patch(monkeypatch, [_tf(sev="INFO", rule="py-x", status="unknown", routes=())])
    res = CliRunner().invoke(cli.main, ["triage", str(tmp_path), "--min-risk", "50"])
    assert res.exit_code == 0


def test_fail_on_fails_closed_when_verdict_errored(monkeypatch, tmp_path):
    """A CI gate must not pass silently when the model gave no verdict."""
    tf = TriagedFinding(
        finding=Finding("ERROR", "app.js", 5, "js-sql-string-concat", "msg"),
        reach=Reach("app.js::f", ["POST /x"], "reachable"),
        verdict=None, cached=False, error="OpenAI HTTP 429",
    )
    _patch(monkeypatch, [tf])
    res = CliRunner().invoke(cli.main, ["triage", str(tmp_path), "--fail-on", "exploitable"])
    assert res.exit_code == 2
    assert "failing closed" in res.output


def test_fail_on_fails_closed_when_no_key(monkeypatch, tmp_path):
    """Offline (no verdict, no error): --fail-on can't prove safe -> fail closed."""
    _patch(monkeypatch, [_tf(verdict=None)])  # no key path: reachability only
    res = CliRunner().invoke(cli.main, ["triage", str(tmp_path), "--fail-on", "exploitable"])
    assert res.exit_code == 2
    assert "failing closed" in res.output


def test_negative_top_rejected(monkeypatch, tmp_path):
    _patch(monkeypatch, [_tf()])
    res = CliRunner().invoke(cli.main, ["triage", str(tmp_path), "--top", "-5"])
    assert res.exit_code != 0  # click IntRange rejects before running


def test_top_hides_lower_risk(monkeypatch, tmp_path):
    results = [
        _tf(sev="INFO", rule="py-x", line=1, status="unknown", routes=()),
        _tf(sev="ERROR", rule="js-sql-string-concat", line=2),
        _tf(sev="WARNING", rule="py-weak-hash", line=3, status="unknown", routes=()),
    ]
    _patch(monkeypatch, results)
    res = CliRunner().invoke(cli.main, ["triage", str(tmp_path), "--top", "1"])
    assert res.exit_code == 0
    assert "2 lower-risk finding(s) hidden" in res.output
