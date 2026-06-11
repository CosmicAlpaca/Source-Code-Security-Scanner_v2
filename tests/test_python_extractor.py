"""Unit tests for the Python extractor + integration over the py-app fixture."""

from pathlib import Path

import pytest

from radar.config import load_config
from radar.graph.builder import build_graph
from radar.graph.languages.python import PythonExtractor
from radar.impact.tracer import trace

FIXTURES = Path(__file__).parent / "fixtures"
ext = PythonExtractor()


def extract(source: str, relpath: str = "app/sample.py"):
    return ext.extract(source.encode(), relpath)


def test_function_and_method_defs():
    facts = extract("def top():\n    pass\n\nclass Repo:\n    def find(self):\n        pass\n")
    assert {d.name for d in facts.defs} == {"top", "Repo.find"}


def test_async_def():
    facts = extract("async def handler():\n    pass\n")
    assert [d.name for d in facts.defs] == ["handler"]


def test_calls_with_caller_and_object():
    facts = extract("def a():\n    b()\n    db.query('x')\n")
    calls = {(c.caller, c.callee, c.object) for c in facts.calls}
    assert ("a", "b", None) in calls
    assert ("a", "query", "db") in calls


def test_imports():
    facts = extract(
        "import os\nimport app.services.db as db\nfrom .utils import validate_user\n"
        "from ..services.db import find_user as fu\n"
    )
    bindings = {(i.local_name, i.source, i.imported_name) for i in facts.imports}
    assert ("os", "os", "*") in bindings
    assert ("db", "app.services.db", "*") in bindings
    assert ("validate_user", ".utils", "validate_user") in bindings
    assert ("fu", "..services.db", "find_user") in bindings


def test_fastapi_route_decorator():
    facts = extract('@router.post("/api/login")\ndef login():\n    pass\n')
    route = facts.routes[0]
    assert (route.method, route.path, route.handler) == ("POST", "/api/login", "login")


def test_flask_route_decorator_with_methods():
    facts = extract('@app.route("/admin", methods=["DELETE", "POST"])\ndef admin():\n    pass\n')
    assert {(r.method, r.path) for r in facts.routes} == {("DELETE", "/admin"), ("POST", "/admin")}


def test_flask_route_default_get():
    facts = extract('@app.route("/home")\ndef home():\n    pass\n')
    assert [(r.method, r.path) for r in facts.routes] == [("GET", "/home")]


def test_non_route_decorator_ignored():
    facts = extract("@staticmethod\ndef util():\n    pass\n")
    assert facts.routes == []


def test_resolve_module():
    files = {"app/services/db.py", "app/utils/validate.py", "app/__init__.py"}
    assert ext.resolve_module("..services.db", "app/routes/auth.py", files) == "app/services/db.py"
    assert ext.resolve_module(".utils.validate", "app/main.py", files) == "app/utils/validate.py"
    assert ext.resolve_module("app.services.db", "app/routes/admin.py", files) == "app/services/db.py"
    assert ext.resolve_module("app", "x.py", files) == "app/__init__.py"
    assert ext.resolve_module("fastapi", "app/main.py", files) is None


# -- integration over the py-app fixture (feature map + cross-file impact) ----


@pytest.fixture(scope="module")
def py_graph():
    root = FIXTURES / "py-app"
    return build_graph(root, config=load_config(root))


def test_py_route_nodes(py_graph):
    assert "app/routes/auth.py::route:POST /api/login" in py_graph.nodes
    assert "app/routes/admin.py::route:DELETE /admin/users/<user_id>" in py_graph.nodes


def test_py_resolved_relative_import_call(py_graph):
    edge = py_graph.edges["app/routes/auth.py::login", "app/utils/validate.py::validate_user"]
    assert edge["confidence"] == "resolved"


def test_py_feature_assignment(py_graph):
    assert py_graph.nodes["app/routes/auth.py::login"]["feature"] == "Authentication"
    assert py_graph.nodes["app/routes/admin.py::delete_user"]["feature"] == "Administration"
    assert py_graph.nodes["app/services/db.py::find_user"]["feature"] is None


def test_py_impact_reaches_route_and_feature(py_graph):
    result = trace(py_graph, ["app/utils/validate.py::validate_user"])
    affected_ids = {i.id for i in result.affected}
    assert "app/routes/auth.py::login" in affected_ids
    assert "app/routes/auth.py::route:POST /api/login" in affected_ids
    assert "Authentication" in result.features


def test_mixed_language_single_graph():
    graph = build_graph(FIXTURES)
    languages = {graph.nodes[n]["language"] for n in graph.nodes if graph.nodes[n]["kind"] == "function"}
    assert {"javascript", "python"} <= languages
