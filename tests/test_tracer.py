"""Tracer tests on the js-app fixture graph."""

from pathlib import Path

import pytest

from radar.graph.builder import build_graph
from radar.impact.tracer import trace

FIXTURE = Path(__file__).parent / "fixtures" / "js-app"


@pytest.fixture(scope="module")
def graph():
    return build_graph(FIXTURE)


def test_validate_user_blast_radius(graph):
    result = trace(graph, ["utils/validate.js::validateUser"])
    affected_ids = {i.id for i in result.affected}
    assert "routes/auth.js::login" in affected_ids
    assert "routes/auth.js::register" in affected_ids
    assert "routes/auth.js::route:POST /login" in affected_ids
    assert "routes/auth.js::route:POST /register" in affected_ids


def test_depth_assignment(graph):
    result = trace(graph, ["utils/validate.js::validateUser"])
    by_id = {i.id: i for i in result.affected}
    assert by_id["routes/auth.js::login"].depth == 1
    assert by_id["routes/auth.js::route:POST /login"].depth == 2


def test_api_rollup(graph):
    result = trace(graph, ["utils/validate.js::validateUser"])
    routes = {a["route"] for a in result.apis}
    assert "POST /login" in routes
    assert "POST /register" in routes


def test_changed_function_lists_direct_routes(graph):
    result = trace(graph, ["routes/auth.js::login"])
    assert result.changed[0].routes == ["POST /login"]


def test_max_depth_limits_traversal(graph):
    result = trace(graph, ["utils/validate.js::validateUser"], max_depth=1)
    assert all(i.depth <= 1 for i in result.affected)
    assert any(i.id == "routes/auth.js::login" for i in result.affected)
    assert all(i.kind != "route" for i in result.affected)  # routes are at depth 2 here


def test_file_level_fallback_via_imports(graph):
    result = trace(graph, ["services/db.js"])  # top-level change in db.js
    affected_ids = {i.id for i in result.affected}
    assert "routes/auth.js" in affected_ids  # importer files affected
    assert "utils/validate.js" in affected_ids


def test_unknown_changed_node_ignored(graph):
    result = trace(graph, ["nope.js::missing"])
    assert result.changed == [] and result.affected == []


def test_cycle_terminates(graph):
    # services/db.js <-> utils/validate.js import cycle; calls go through sanitize
    result = trace(graph, ["utils/validate.js::sanitize"])
    assert len(result.affected) < 50  # finite, no infinite loop


def test_stats_consistency(graph):
    result = trace(graph, ["utils/validate.js::validateUser"])
    assert result.stats["functions_affected"] == sum(1 for i in result.affected if i.kind == "function")
    assert result.stats["apis_affected"] == len(result.apis)
