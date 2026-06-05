"""Tests for scripts/render-pr-comment.py (loaded by path — script has a dash in its name)."""

import importlib.util
import json
from pathlib import Path

import pytest

SCRIPT = Path(__file__).parent.parent / "scripts" / "render-pr-comment.py"
FIXTURE = Path(__file__).parent / "fixtures" / "semgrep-sample.json"

spec = importlib.util.spec_from_file_location("render_pr_comment", SCRIPT)
render_pr_comment = importlib.util.module_from_spec(spec)
spec.loader.exec_module(render_pr_comment)


def render(report_path: str) -> str:
    findings = render_pr_comment.load_findings(report_path)
    return "\n".join([render_pr_comment.MARKER] + render_pr_comment.render_findings_section(findings))


def test_renders_marker_and_table():
    out = render(str(FIXTURE))
    assert out.startswith("<!-- security-radar -->")
    assert "3 finding(s)" in out
    assert "2 error" in out and "1 warning" in out
    assert "`demo/app/services/db.js:12`" in out
    assert "js-sql-string-concat" in out


def test_severity_sorted_errors_first():
    out = render(str(FIXTURE))
    error_pos = out.index("js-sql-string-concat")
    warning_pos = out.index("py-flask-debug-true")
    assert error_pos < warning_pos


def test_escapes_pipes_and_html():
    out = render(str(FIXTURE))
    assert "&lt;Werkzeug&gt;" in out
    assert "concatenation \\| use" in out


def test_no_findings(tmp_path):
    empty = tmp_path / "empty.json"
    empty.write_text(json.dumps({"results": []}), encoding="utf-8")
    out = render(str(empty))
    assert "✅ No security findings." in out


def test_caps_findings_at_30(tmp_path):
    results = [
        {
            "check_id": f"rule-{i}",
            "path": f"src/f{i}.js",
            "start": {"line": i},
            "extra": {"severity": "ERROR", "message": "m"},
        }
        for i in range(40)
    ]
    big = tmp_path / "big.json"
    big.write_text(json.dumps({"results": results}), encoding="utf-8")
    out = render(str(big))
    assert "and 10 more finding(s)" in out
    assert out.count("| \U0001f534 ERROR |") == 30


def test_impact_section_renders():
    impact = {
        "changed": [
            {"id": "src/auth/validate.js::validateUser", "name": "validateUser",
             "feature": "Authentication", "routes": []}
        ],
        "affected": [
            {
                "name": "login",
                "kind": "function",
                "depth": 1,
                "via_changed": "src/auth/validate.js::validateUser",
                "confidence": "name-only",
            },
            {
                "name": "POST /api/login",
                "kind": "route",
                "depth": 2,
                "via_changed": "src/auth/validate.js::validateUser",
                "confidence": "resolved",
            },
        ],
        "apis": [{"route": "POST /api/login"}],
        "features": ["Authentication"],
    }
    lines = render_pr_comment.render_impact_section(impact)
    out = "\n".join(lines)
    assert "1 changed → 2 affected" in out
    assert "`validateUser`" in out
    assert "login (d1)" in out
    assert "POST /api/login" in out
    assert "1 edge(s) resolved by name only" in out


def test_impact_apis_scoped_per_changed_function():
    impact = {
        "changed": [
            {"id": "a.js::hot", "name": "hot", "routes": ["GET /direct"]},
            {"id": "b.js::cold", "name": "cold", "routes": []},
        ],
        "affected": [
            {"name": "POST /x", "kind": "route", "depth": 1, "via_changed": "a.js::hot"},
        ],
        "apis": [{"route": "POST /x"}, {"route": "GET /direct"}],
        "features": [],
    }
    out = "\n".join(render_pr_comment.render_impact_section(impact))
    hot_row = next(line for line in out.splitlines() if "`hot`" in line)
    cold_row = next(line for line in out.splitlines() if "`cold`" in line)
    assert "GET /direct" in hot_row and "POST /x" in hot_row
    assert "POST /x" not in cold_row and "GET /direct" not in cold_row


def test_escape_cell_neutralizes_backticks():
    assert "`" not in render_pr_comment.escape_cell("evil` | <img>`")


def test_impact_section_no_changes():
    out = "\n".join(render_pr_comment.render_impact_section({"changed": [], "affected": []}))
    assert "No function-level changes detected." in out
