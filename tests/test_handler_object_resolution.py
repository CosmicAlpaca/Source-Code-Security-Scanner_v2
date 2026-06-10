"""Route→handler resolution for the handler-object pattern (OWASP NodeGoat-style).

`app.post("/login", instance.method)` where `const instance = new Class()` must link
the route to the method def, and `new Class()` must create a call edge to the class.
"""

from pathlib import Path

from radar.graph.builder import build_graph
from radar.graph.model import CALLS, HANDLES, RESOLVED

FIXTURE = Path(__file__).parent / "fixtures" / "express-handler-object"


def _edges(graph, kind):
    return {(u, v) for u, v, d in graph.edges(data=True) if d.get("kind") == kind}


def test_route_links_to_object_handler():
    handles = _edges(build_graph(FIXTURE), HANDLES)
    assert ("index.js::route:POST /login", "session.js::handleLogin") in handles
    assert ("index.js::route:GET /login", "session.js::displayLogin") in handles


def test_new_expression_creates_call_edge():
    calls = _edges(build_graph(FIXTURE), CALLS)
    assert ("index.js", "session.js::SessionHandler") in calls


def test_object_handler_edges_are_resolved():
    graph = build_graph(FIXTURE)
    handles = [d for _, _, d in graph.edges(data=True) if d.get("kind") == HANDLES]
    assert handles and all(d.get("confidence") == RESOLVED for d in handles)
