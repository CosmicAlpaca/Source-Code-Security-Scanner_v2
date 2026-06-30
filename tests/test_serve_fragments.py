"""Tests for radar.scan.report fragment functions used by radar serve.

Covers:
- render_overview_fragment: non-empty HTML for various finding sets
- render_findings_fragment: with/without risk_map/verdict_map
- render_blast_fragment: empty state, with mermaid_src, with trace_res
- render_history_fragment: empty and populated
- render_dashboard: regression guard that full <!DOCTYPE html> is still valid
"""
from __future__ import annotations

import types

import pytest

from radar.scan.findings import Finding
from radar.scan.report import (
    render_blast_fragment,
    render_dashboard,
    render_findings_fragment,
    render_history_fragment,
    render_overview_fragment,
)


# ── Fixtures ──────────────────────────────────────────────────────────────────

F_ERROR = Finding(severity="ERROR", path="app/db.py", line=10,
                  rule="rules.py-sql-injection", message="SQLi detected")
F_WARN = Finding(severity="WARNING", path="app/auth.py", line=5,
                 rule="rules.py-weak-hash", message="MD5 is weak")
F_INFO = Finding(severity="INFO", path="app/config.py", line=1,
                 rule="rules.py-debug", message="Debug mode on")

ALL_FINDINGS = [F_ERROR, F_WARN, F_INFO]


# ── render_overview_fragment ──────────────────────────────────────────────────

class TestRenderOverviewFragment:
    def test_returns_non_empty_html_with_findings(self):
        html = render_overview_fragment(ALL_FINDINGS, suppressed=0)
        assert html.strip(), "Expected non-empty HTML"

    def test_contains_stat_row(self):
        html = render_overview_fragment(ALL_FINDINGS, suppressed=0)
        assert "stat-row" in html

    def test_shows_error_count(self):
        html = render_overview_fragment(ALL_FINDINGS, suppressed=0)
        assert 'data-count="1"' in html  # 1 ERROR

    def test_shows_suppressed_count(self):
        html = render_overview_fragment(ALL_FINDINGS, suppressed=3)
        assert 'data-count="3"' in html

    def test_empty_findings_still_returns_html(self):
        html = render_overview_fragment([], suppressed=0)
        assert html.strip(), "Empty findings should still produce overview HTML"
        assert "stat-row" in html

    def test_includes_chart_canvases_when_findings_present(self):
        html = render_overview_fragment(ALL_FINDINGS, suppressed=0)
        assert "owaspChart" in html
        assert "sevChart" in html

    def test_no_chart_canvases_when_no_findings(self):
        html = render_overview_fragment([], suppressed=0)
        assert "owaspChart" not in html

    def test_critical_risk_band_for_5_plus_errors(self):
        errors = [Finding("ERROR", f"f{i}.py", i, "rule", "msg") for i in range(6)]
        html = render_overview_fragment(errors, suppressed=0)
        assert "CRITICAL" in html

    def test_low_risk_band_when_no_errors_or_warnings(self):
        html = render_overview_fragment(
            [Finding("INFO", "f.py", 1, "rule", "msg")], suppressed=0
        )
        assert "LOW" in html

    def test_high_risk_band_for_1_error(self):
        html = render_overview_fragment([F_ERROR], suppressed=0)
        assert "HIGH" in html


# ── render_findings_fragment ──────────────────────────────────────────────────

class TestRenderFindingsFragment:
    def test_returns_non_empty_html(self):
        html = render_findings_fragment(ALL_FINDINGS)
        assert html.strip()

    def test_contains_panel_wrapper(self):
        html = render_findings_fragment(ALL_FINDINGS)
        assert 'class="panel"' in html

    def test_finding_rows_present(self):
        html = render_findings_fragment(ALL_FINDINGS)
        assert "finding-row" in html

    def test_empty_findings_returns_html(self):
        html = render_findings_fragment([])
        assert html.strip()
        # Should still have the toolbar and panel
        assert 'class="panel"' in html

    def test_with_risk_map_shows_risk_column(self):
        from radar.triage.risk import RiskScore
        risk_map = {
            id(F_ERROR): RiskScore(80, "high", ["ERROR", "reachable"]),
            id(F_WARN): RiskScore(40, "medium", ["WARNING"]),
            id(F_INFO): RiskScore(10, "low", ["INFO"]),
        }
        html = render_findings_fragment(ALL_FINDINGS, risk_map=risk_map)
        assert ">Risk<" in html
        assert "80 high" in html

    def test_with_verdict_map_shows_triage_columns(self):
        verdict_map = {
            (F_ERROR.path, F_ERROR.line, F_ERROR.rule): {
                "reach": "reachable",
                "routes": ["POST /api/query"],
                "verdict": {"exploitability": "exploitable", "confidence": 0.9,
                            "reasoning": "user input tainted"},
                "error": None,
            }
        }
        html = render_findings_fragment(ALL_FINDINGS, verdict_map=verdict_map)
        assert "Reachability" in html
        assert "AI verdict" in html

    def test_without_risk_map_no_risk_column(self):
        html = render_findings_fragment(ALL_FINDINGS, risk_map=None)
        assert ">Risk<" not in html

    def test_toolbar_search_input_present(self):
        html = render_findings_fragment(ALL_FINDINGS)
        assert "fSearch" in html

    def test_message_is_html_escaped(self):
        evil = Finding("ERROR", "f.py", 1, "rule", "<script>alert(1)</script>")
        html = render_findings_fragment([evil])
        assert "<script>alert(1)</script>" not in html
        assert "&lt;script&gt;" in html

    def test_path_is_html_escaped(self):
        evil = Finding("ERROR", '<b>evil</b>', 1, "rule", "msg")
        html = render_findings_fragment([evil])
        assert "<b>evil</b>" not in html


# ── render_blast_fragment ─────────────────────────────────────────────────────

class TestRenderBlastFragment:
    def test_no_args_returns_empty_state(self):
        html = render_blast_fragment()
        assert "No Blast Radius Data" in html

    def test_mermaid_src_renders_mermaid_block(self):
        html = render_blast_fragment(mermaid_src="graph LR\nA-->B")
        assert "mermaid" in html
        assert "graph LR" in html

    def test_empty_trace_res_none_returns_empty_state(self):
        html = render_blast_fragment(trace_res=None, mermaid_src="")
        assert "No Blast Radius Data" in html

    def test_traced_fn_label_appears(self):
        html = render_blast_fragment(mermaid_src="graph LR\nA-->B",
                                     traced_fn="handle_request")
        assert "handle_request" in html

    def test_repo_path_in_fragment(self):
        html = render_blast_fragment(mermaid_src="graph LR\nA-->B",
                                     repo_path="/code/myapp")
        # The function shouldn't crash with a repo_path
        assert html.strip()

    def test_with_fake_trace_res(self):
        """Fake trace_res with stats dict — should render without raising."""
        trace_res = types.SimpleNamespace(
            stats={"functions_affected": 3, "apis_affected": 1,
                   "features_affected": 0, "approximate": 0},
            changed=[],
            affected=[],
            apis=[],
        )
        html = render_blast_fragment(trace_res=trace_res, mermaid_src="graph LR\nA-->B")
        assert "Functions Affected" in html or "Changed Nodes" in html

    def test_d3_node_click_detail_panel_is_rendered(self):
        changed = types.SimpleNamespace(
            id="app.py::handler", name="handler", kind="function", file="app.py",
            line=10, feature="Auth", depth=0, via_changed="", parent="",
            confidence="resolved", routes=["POST /login"], findings=[],
        )
        affected = types.SimpleNamespace(
            id="routes.py::route:POST /login", name="POST /login", kind="route",
            file="routes.py", line=5, feature="", depth=1,
            via_changed="app.py::handler", parent="app.py::handler",
            confidence="resolved", routes=[], findings=[{"severity": "ERROR", "rule": "x"}],
        )
        trace_res = types.SimpleNamespace(
            stats={"functions_affected": 1, "apis_affected": 1,
                   "features_affected": 1, "approximate": 0},
            changed=[changed],
            affected=[affected],
            apis=[{"route": "POST /login", "file": "routes.py"}],
        )
        html = render_blast_fragment(trace_res=trace_res, repo_path="/code/app")
        assert "d3node-detail" in html
        assert "Selected Node" in html
        assert "showNodeDetail" in html
        assert "Changed entry points" in html
        assert "data-change-id" in html
        assert "applyChangeFilter" in html
        assert "fitActive" in html
        assert "app.py::handler" in html

    def test_returns_non_empty_string(self):
        html = render_blast_fragment()
        assert isinstance(html, str)
        assert len(html) > 0


# ── render_history_fragment ───────────────────────────────────────────────────

class TestRenderHistoryFragment:
    def test_empty_list_returns_empty_state(self):
        html = render_history_fragment([])
        assert "No History Yet" in html

    def test_none_returns_empty_state(self):
        html = render_history_fragment(None)
        assert "No History Yet" in html

    def test_populated_history_shows_chart(self):
        history = [
            {"ts": "2024-01-01T10:00", "error": 2, "warning": 3},
            {"ts": "2024-01-02T10:00", "error": 1, "warning": 2},
        ]
        html = render_history_fragment(history)
        assert "Scan History Trend" in html
        assert "hChart" in html

    def test_history_shows_scan_count(self):
        history = [{"ts": "2024-01-01", "error": 0, "warning": 1}] * 5
        html = render_history_fragment(history)
        assert "5 scan(s)" in html

    def test_returns_non_empty_string(self):
        html = render_history_fragment([])
        assert isinstance(html, str) and len(html) > 0


# ── render_dashboard regression guard ────────────────────────────────────────

class TestRenderDashboardRegression:
    """Ensure the full render_dashboard still returns a valid <!DOCTYPE html> page."""

    def test_dashboard_starts_with_doctype(self):
        html = render_dashboard("repo", ALL_FINDINGS, suppressed=0)
        assert html.lstrip().startswith("<!DOCTYPE html>")

    def test_dashboard_contains_all_panel_ids(self):
        html = render_dashboard("repo", ALL_FINDINGS, suppressed=0)
        assert 'id="tab-overview"' in html
        assert 'id="tab-findings"' in html
        assert 'id="tab-blast"' in html
        assert 'id="tab-history"' in html

    def test_dashboard_contains_panel_content_divs(self):
        html = render_dashboard("repo", ALL_FINDINGS, suppressed=0)
        assert 'id="panel-overview"' in html
        assert 'id="panel-findings"' in html
        assert 'id="panel-blast"' in html
        assert 'id="panel-history"' in html

    def test_dashboard_html_closes_body(self):
        html = render_dashboard("repo", ALL_FINDINGS, suppressed=0)
        assert "</body></html>" in html

    def test_dashboard_with_risk_map(self):
        from radar.triage.risk import RiskScore
        risk_map = {id(f): RiskScore(50, "medium", ["WARNING"]) for f in ALL_FINDINGS}
        html = render_dashboard("repo", ALL_FINDINGS, suppressed=0, risk_map=risk_map)
        assert html.lstrip().startswith("<!DOCTYPE html>")
        assert ">Risk<" in html

    def test_dashboard_with_verdict_map(self):
        verdict_map = {
            (F_ERROR.path, F_ERROR.line, F_ERROR.rule): {
                "reach": "reachable",
                "routes": ["POST /x"],
                "verdict": {"exploitability": "likely", "confidence": 0.8,
                            "reasoning": "user tainted"},
                "error": None,
            }
        }
        html = render_dashboard("repo", ALL_FINDINGS, suppressed=0, verdict_map=verdict_map)
        assert "AI verdict" in html
        assert "Reachability" in html

    def test_dashboard_empty_findings(self):
        html = render_dashboard("repo", [], suppressed=0)
        assert html.lstrip().startswith("<!DOCTYPE html>")

    def test_dashboard_with_history(self):
        history = [{"ts": "2024-01-01", "error": 1, "warning": 2}]
        html = render_dashboard("repo", ALL_FINDINGS, suppressed=2, history=history)
        assert html.lstrip().startswith("<!DOCTYPE html>")
        assert "hChart" in html

    def test_fragment_refactor_consistency(self):
        """The dashboard must compose the same fragment functions, not duplicate them."""
        html = render_dashboard("repo", ALL_FINDINGS, suppressed=1)
        # Overview fragment elements
        assert "stat-row" in html
        # Findings fragment elements
        assert "finding-row" in html
        # Blast fragment empty state
        assert "No Blast Radius Data" in html
        # History fragment empty state
        assert "No History Yet" in html
