"""Render-only graph transforms: aggregate-by-file, security focus, node cap."""

import networkx as nx

from radar.graph.graph_transform import aggregate_by_file, cap_nodes, focus_security


def _func_graph():
    g = nx.DiGraph()
    g.add_node("a.js::f1", kind="function", name="f1", file="a.js", start_line=1)
    g.add_node("a.js::f2", kind="function", name="f2", file="a.js", start_line=5)
    g.add_node("b.js::g1", kind="function", name="g1", file="b.js", start_line=2)
    g.add_edge("a.js::f1", "a.js::f2", kind="calls")   # same-file -> self-loop, dropped
    g.add_edge("a.js::f1", "b.js::g1", kind="calls")   # cross-file
    g.add_edge("a.js::f2", "b.js::g1", kind="imports")  # cross-file, merges onto a->b
    return g


def test_aggregate_collapses_functions_to_files():
    out = aggregate_by_file(_func_graph())
    assert set(out.nodes) == {"a.js", "b.js"}
    assert out.nodes["a.js"]["members"] == 2
    assert out.nodes["b.js"]["members"] == 1
    assert out.nodes["a.js"]["kind"] == "file"


def test_aggregate_drops_self_loops_and_merges_with_weight():
    out = aggregate_by_file(_func_graph())
    assert not any(s == d for s, d in out.edges)        # no self-loops
    assert out.number_of_edges() == 1                   # a->b only (two merged)
    assert out.edges["a.js", "b.js"]["weight"] == 2
    assert out.edges["a.js", "b.js"]["kind"] == "calls"  # calls outranks imports


def test_aggregate_does_not_mutate_input():
    g = _func_graph()
    before = g.number_of_nodes()
    aggregate_by_file(g)
    assert g.number_of_nodes() == before
    assert "a.js::f1" in g.nodes


def test_focus_security_keeps_route_reachable_only():
    g = nx.DiGraph()
    g.add_node("r", kind="route", name="GET /x", file="a.js")
    g.add_node("a", kind="function", name="a", file="a.js")
    g.add_node("b", kind="function", name="b", file="b.js")
    g.add_node("orphan", kind="function", name="orphan", file="c.js")
    g.add_edge("r", "a", kind="handles")
    g.add_edge("a", "b", kind="calls")
    out, had_routes = focus_security(g)
    assert had_routes is True
    assert set(out.nodes) == {"r", "a", "b"}            # orphan dropped


def test_focus_security_no_routes_returns_all():
    g = nx.DiGraph()
    g.add_node("a", kind="function", name="a", file="a.js")
    g.add_node("b", kind="function", name="b", file="b.js")
    out, had_routes = focus_security(g)
    assert had_routes is False
    assert set(out.nodes) == {"a", "b"}


def test_cap_keeps_top_degree_and_reports_dropped():
    g = nx.DiGraph()
    for n in "abcde":
        g.add_node(n, kind="function", name=n, file=f"{n}.js")
    # 'a' is a hub (degree 3), 'b' degree 1, others lower
    g.add_edge("a", "b")
    g.add_edge("a", "c")
    g.add_edge("a", "d")
    out, dropped = cap_nodes(g, 2)
    assert dropped == 3
    assert out.number_of_nodes() == 2
    assert "a" in out.nodes                              # highest-degree kept


def test_cap_is_noop_within_budget():
    g = nx.DiGraph()
    g.add_node("a")
    out, dropped = cap_nodes(g, 1500)
    assert dropped == 0
    assert out is g                                      # untouched, same object


def test_cap_zero_means_no_cap():
    g = nx.DiGraph()
    for n in "abc":
        g.add_node(n)
    out, dropped = cap_nodes(g, 0)
    assert dropped == 0
    assert out.number_of_nodes() == 3


def test_cap_is_deterministic():
    def build():
        g = nx.DiGraph()
        for n in "abcdef":
            g.add_node(n)
        g.add_edge("a", "b")
        g.add_edge("a", "c")
        return g

    first, _ = cap_nodes(build(), 3)
    second, _ = cap_nodes(build(), 3)
    assert set(first.nodes) == set(second.nodes)
