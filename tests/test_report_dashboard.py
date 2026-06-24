"""Tests for the unified `radar report` dashboard (offline + AI-triage columns)."""

import types

import pytest
from click.testing import CliRunner

from radar import cli
from radar.scan.findings import Finding
from radar.scan.report import render_dashboard

F = Finding(severity="ERROR", path="app/db.php", line=7, rule="php-sql-injection", message="SQLi")


@pytest.fixture(autouse=True)
def _no_external_scan_side_effects(monkeypatch):
    from radar.scan import gitleaks_runner
    from radar.scan import history

    monkeypatch.setattr(gitleaks_runner, "run_gitleaks", lambda *a, **k: [])
    monkeypatch.setattr(history, "record", lambda *a, **k: None)
    monkeypatch.setattr(history, "load", lambda *a, **k: [])


# ── render_dashboard unit ─────────────────────────────────────────────────────

def test_offline_dashboard_has_five_columns_no_triage():
    html = render_dashboard("repo", [F], suppressed=0)
    assert "Reachability" not in html and "AI verdict" not in html
    assert 'colspan="6"' in html
    assert ">Tool<" in html and "Semgrep" in html
    assert 'class="finding-row"' in html


def test_triaged_dashboard_has_seven_columns():
    vm = {("app/db.php", 7, "php-sql-injection"): {
        "reach": "reachable", "routes": ["POST /login"],
        "verdict": {"exploitability": "likely", "confidence": 0.8, "reasoning": "user input → query"}}}
    html = render_dashboard("repo", [F], suppressed=0, verdict_map=vm)
    assert "Reachability" in html and "AI verdict" in html
    assert 'colspan="8"' in html
    assert "likely" in html and "reachable" in html and "80%" in html


def test_dashboard_shows_finding_engine():
    gitleaks = Finding(
        severity="ERROR",
        path=".env",
        line=1,
        rule="gitleaks.aws-access-token",
        message="secret",
    )
    html = render_dashboard("repo", [gitleaks], suppressed=0)
    assert "Gitleaks" in html


def test_reasoning_and_message_are_html_escaped():
    evil = Finding(severity="ERROR", path="x<b>.php", line=1,
                   rule="php-xss", message="<img src=x onerror=alert(1)>")
    vm = {("x<b>.php", 1, "php-xss"): {
        "reach": "reachable", "routes": [],
        "verdict": {"exploitability": "exploitable", "confidence": 0.5,
                    "reasoning": '"><script>alert(1)</script>'}}}
    html = render_dashboard("repo", [evil], suppressed=0, verdict_map=vm)
    # user-controlled payloads must be escaped, not injected raw
    assert "<img src=x" not in html              # message '<' escaped
    assert '"><script>alert' not in html         # no attribute breakout from reasoning
    assert "&lt;script&gt;" in html              # reasoning rendered as escaped text


def test_exploitable_renders_red():
    vm = {("app/db.php", 7, "php-sql-injection"): {
        "reach": "reachable", "routes": [],
        "verdict": {"exploitability": "exploitable", "confidence": 0.9, "reasoning": "x"}}}
    html = render_dashboard("repo", [F], suppressed=0, verdict_map=vm)
    assert "#c0392b" in html and "exploitable" in html


def test_verdict_cell_error_shows_error_badge():
    vm = {("app/db.php", 7, "php-sql-injection"): {"reach": "unknown", "routes": [], "verdict": None, "error": "rate limited"}}
    html = render_dashboard("repo", [F], suppressed=0, verdict_map=vm)
    assert "error" in html


def test_verdict_cell_missing_verdict_is_dash():
    vm = {("app/db.php", 7, "php-sql-injection"): {"reach": "unknown", "routes": [], "verdict": None}}
    html = render_dashboard("repo", [F], suppressed=0, verdict_map=vm)
    assert "—" in html and "unknown" in html


# ── risk ranking layout ───────────────────────────────────────────────────────

def test_dashboard_ranks_findings_by_risk_desc():
    from radar.triage.risk import RiskScore
    f_low = Finding(severity="INFO", path="a.py", line=1, rule="py-weak-hash", message="h")
    f_high = Finding(severity="ERROR", path="b.py", line=2, rule="py-sql", message="s")
    rm = {id(f_low): RiskScore(20, "low", ["INFO"]),
          id(f_high): RiskScore(95, "critical", ["ERROR"])}
    html = render_dashboard("repo", [f_low, f_high], suppressed=0, risk_map=rm)
    assert ">Risk<" in html
    assert "95 critical" in html and "20 low" in html
    # higher risk renders before lower risk regardless of input order
    assert html.index("b.py:2") < html.index("a.py:1")


def test_dashboard_folds_noise_into_details():
    from radar.triage.risk import RiskScore
    keep = Finding(severity="ERROR", path="a.py", line=1, rule="py-sql", message="s")
    junk = Finding(severity="INFO", path="b.py", line=9, rule="py-x", message="m")
    rm = {id(keep): RiskScore(90, "critical", ["ERROR"]),
          id(junk): RiskScore(5, "noise", ["INFO", "ai:false_positive"])}
    html = render_dashboard("repo", [keep, junk], suppressed=0, risk_map=rm)
    assert "<details" in html
    assert "1 low-risk / false-positive finding(s)" in html


# ── report CLI ────────────────────────────────────────────────────────────────

def _patch_scan(monkeypatch):
    from radar.scan import runner
    sample = {"results": [{"check_id": "rules.php-sql-injection", "path": "a.php",
                           "start": {"line": 3}, "extra": {"severity": "ERROR", "message": "bad"}}]}
    monkeypatch.setattr(runner, "detect_runtime", lambda: "native")
    monkeypatch.setattr(runner, "run_semgrep", lambda *a, **k: sample)


def test_report_offline_writes_dashboard(monkeypatch, tmp_path):
    _patch_scan(monkeypatch)
    out = tmp_path / "dash.html"
    res = CliRunner().invoke(cli.main, ["report", str(tmp_path), "--out", str(out)])
    assert res.exit_code == 0
    assert out.is_file()
    assert "Reachability" not in out.read_text(encoding="utf-8")


def test_report_triage_adds_columns(monkeypatch, tmp_path):
    fake = types.SimpleNamespace(
        finding=Finding(severity="ERROR", path="a.php", line=3, rule="php-sql-injection", message="bad"),
        reach=types.SimpleNamespace(status="reachable", routes=["POST /x"]),
        verdict={"exploitability": "likely", "confidence": 0.9, "reasoning": "tainted"})
    from radar.triage import engine
    monkeypatch.setattr(engine, "triage", lambda *a, **k: ([fake], 1))
    out = tmp_path / "dash.html"
    res = CliRunner().invoke(cli.main, ["report", str(tmp_path), "--triage", "--out", str(out)])
    assert res.exit_code == 0
    html = out.read_text(encoding="utf-8")
    assert "AI verdict" in html and "likely" in html


def test_report_auto_picks_function_by_finding_location(monkeypatch, tmp_path):
    """Auto blast-radius traces the function CONTAINING the finding (by file+line),
    not the rule name — regression guard for the old rule-name heuristic."""
    pytest.importorskip("tree_sitter_php")
    (tmp_path / "app.php").write_text(
        "<?php\nfunction handler() {\n  $x = md5($_GET['p']);\n  return $x;\n}\n",
        encoding="utf-8",
    )
    from radar.scan import runner
    sample = {"results": [{"check_id": "rules.php-weak-hash", "path": "app.php",
                           "start": {"line": 3}, "extra": {"severity": "WARNING", "message": "md5"}}]}
    monkeypatch.setattr(runner, "detect_runtime", lambda: "native")
    monkeypatch.setattr(runner, "run_semgrep", lambda *a, **k: sample)
    out = tmp_path / "d.html"
    res = CliRunner().invoke(cli.main, ["report", str(tmp_path), "--out", str(out)])
    assert res.exit_code == 0
    assert "finding site(s)" in res.output  # graph traced, not skipped
    assert "Blast Radius" in out.read_text(encoding="utf-8")


def test_report_triage_falls_back_when_unavailable(monkeypatch, tmp_path):
    _patch_scan(monkeypatch)
    from radar.triage import engine
    from radar.triage.llm_client import TriageError

    def boom(*a, **k):
        raise TriageError("No API key")

    monkeypatch.setattr(engine, "triage", boom)
    out = tmp_path / "dash.html"
    res = CliRunner().invoke(cli.main, ["report", str(tmp_path), "--triage", "--out", str(out)])
    assert res.exit_code == 0
    assert "triage unavailable" in res.output
    assert out.is_file()
    assert "Reachability" not in out.read_text(encoding="utf-8")  # rendered offline
