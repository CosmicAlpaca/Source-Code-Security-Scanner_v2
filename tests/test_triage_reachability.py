"""Reachability mapping: finding -> enclosing function -> routes that reach it."""

from pathlib import Path

from radar.graph.builder import build_graph
from radar.scan.findings import Finding
from radar.triage.reachability import _norm_path, enclosing_function, reachability

FIXTURE = Path(__file__).parent / "fixtures" / "express-handler-object"


def _graph():
    return build_graph(FIXTURE)


def _handle_login_id(graph):
    return next(
        nid for nid, d in graph.nodes(data=True)
        if d["kind"] == "function" and d["name"] == "handleLogin"
    )


def test_norm_path_strips_dot_slash_and_backslashes():
    root = Path("/repo")
    assert _norm_path("./session.js", root) == "session.js"
    assert _norm_path("src\\a.js", root) == "src/a.js"


def test_norm_path_absolute_becomes_relative():
    root = FIXTURE
    abs_path = str((FIXTURE / "session.js").resolve())
    assert _norm_path(abs_path, root) == "session.js"


def test_enclosing_function_finds_handler_span():
    graph = _graph()
    hid = _handle_login_id(graph)
    line = graph.nodes[hid]["start_line"]
    assert enclosing_function(graph, "session.js", line) == hid


def test_finding_in_handler_is_reachable_from_route():
    graph = _graph()
    line = graph.nodes[_handle_login_id(graph)]["start_line"] + 1  # inside body
    finding = Finding("ERROR", "session.js", line, "js.xss", "reflected xss")
    reach = reachability(graph, finding, FIXTURE)
    assert reach.status == "reachable"
    assert "POST /login" in reach.routes


def test_top_level_line_is_unknown_not_dead():
    graph = _graph()
    finding = Finding("WARNING", "index.js", 1, "js.x", "top-level require")
    reach = reachability(graph, finding, FIXTURE)
    assert reach.function_id is None
    assert reach.status == "unknown"
    assert reach.routes == []
