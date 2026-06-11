"""Integration tests: build the graph over the js-app fixture."""

import json
from pathlib import Path

import pytest

from radar.graph.builder import build_graph, graph_summary, load_graph, save_graph

FIXTURE = Path(__file__).parent / "fixtures" / "js-app"


@pytest.fixture(scope="module")
def graph():
    return build_graph(FIXTURE)


def test_function_nodes_exist(graph):
    for node_id in (
        "routes/auth.js::login",
        "routes/auth.js::register",
        "services/db.js::findUser",
        "utils/validate.js::validateUser",
    ):
        assert node_id in graph.nodes, node_id
        assert graph.nodes[node_id]["kind"] == "function"


def test_route_nodes_exist(graph):
    assert "routes/auth.js::route:POST /login" in graph.nodes
    assert "routes/users.js::route:GET /users" in graph.nodes
    assert graph.nodes["routes/auth.js::route:POST /login"]["kind"] == "route"


def test_resolved_call_via_named_import(graph):
    edge = graph.edges["routes/auth.js::login", "utils/validate.js::validateUser"]
    assert edge["kind"] == "calls"
    assert edge["confidence"] == "resolved"


def test_resolved_member_call_via_default_require(graph):
    edge = graph.edges["routes/auth.js::login", "services/db.js::findUser"]
    assert edge["confidence"] == "resolved"


def test_route_handles_edge(graph):
    edge = graph.edges["routes/auth.js::route:POST /login", "routes/auth.js::login"]
    assert edge["kind"] == "handles"


def test_file_import_edges(graph):
    assert graph.edges["routes/auth.js", "utils/validate.js"]["kind"] == "imports"
    # circular import does not crash and both directions exist
    assert graph.has_edge("services/db.js", "utils/validate.js")
    assert graph.has_edge("utils/validate.js", "services/db.js")


def test_inline_route_handler_synthetic_node(graph):
    assert "routes/users.js::<route DELETE /users/:id>" in graph.nodes
    edge = graph.edges[
        "routes/users.js::route:DELETE /users/:id",
        "routes/users.js::<route DELETE /users/:id>",
    ]
    assert edge["kind"] == "handles"


def test_save_load_round_trip_deterministic(graph, tmp_path):
    out1, out2 = tmp_path / "g1.json", tmp_path / "g2.json"
    save_graph(graph, out1)
    save_graph(load_graph(out1), out2)
    assert out1.read_text() == out2.read_text()
    payload = json.loads(out1.read_text())
    node_ids = [n["id"] for n in payload["nodes"]]
    assert node_ids == sorted(node_ids)


def test_windows_paths_normalized(graph):
    assert all("\\" not in node_id for node_id in graph.nodes)


def test_summary_counts(graph):
    s = graph_summary(graph)
    assert s["functions"] >= 8
    assert s["routes"] == 5  # /login /register /users /users/:id /health
    assert s["files"] == 5
    assert s["edges"] > 10
