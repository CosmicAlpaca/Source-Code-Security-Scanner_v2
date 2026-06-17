"""Dependency-graph HTML must be self-contained (offline): D3 inlined, no CDN."""

import networkx as nx

from radar.graph import graph_viz
from radar.graph.graph_viz import to_dependency_html


def _graph():
    g = nx.DiGraph()
    g.add_node("a.js::foo", name="foo", file="a.js", kind="function", start_line=3)
    g.add_node("a.js::bar", name="bar", file="a.js", kind="function", start_line=9)
    g.add_edge("a.js::foo", "a.js::bar", kind="calls")
    return g


def test_html_inlines_d3_no_cdn():
    html = to_dependency_html(_graph(), repo_path="C:/repo")
    assert "cdn.jsdelivr" not in html          # no network dependency
    assert "d3js.org v7" in html               # real D3 source inlined
    assert "<script src=" not in html          # nothing loaded externally


def test_html_carries_graph_data():
    html = to_dependency_html(_graph(), repo_path="C:/repo")
    assert "const NODES" in html and "const EDGES" in html
    assert '"name": "foo"' in html


def test_falls_back_to_cdn_when_vendor_missing(monkeypatch, tmp_path):
    monkeypatch.setattr(graph_viz, "_VENDOR_D3", tmp_path / "missing.js")
    html = to_dependency_html(_graph())
    assert f'<script src="{graph_viz._CDN_D3}"></script>' in html
