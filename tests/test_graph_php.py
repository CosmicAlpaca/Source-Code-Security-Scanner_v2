"""Unit tests for the PHP extractor (defs, calls, imports, routes)."""

import pytest

pytest.importorskip("tree_sitter_php")

from radar.graph.languages.php import PHPExtractor

ext = PHPExtractor()


def extract(source: str, relpath: str = "src/sample.php"):
    return ext.extract(("<?php\n" + source).encode(), relpath)


def test_function_def():
    facts = extract("function helper($x) { return $x; }")
    assert [d.name for d in facts.defs] == ["helper"]


def test_method_qualified_by_class():
    facts = extract("class C { function index() {} }")
    assert "C.index" in [d.name for d in facts.defs]


def test_call_with_caller_attribution():
    facts = extract("function run() { work(); }")
    assert ("run", "work") in [(c.caller, c.callee) for c in facts.calls]


def test_member_call_records_object():
    facts = extract("class C { function i() { $this->load(); } }")
    match = [c for c in facts.calls if c.callee == "load"]
    assert match and match[0].object == "this" and match[0].caller == "C.i"


def test_namespace_use_import_and_alias():
    facts = extract("use App\\Http\\UserController;\nuse App\\Models\\User as U;")
    by_local = {i.local_name: i.source for i in facts.imports}
    assert by_local["UserController"] == "App\\Http\\UserController"
    assert by_local["U"] == "App\\Models\\User"


def test_laravel_route_array_handler():
    facts = extract('Route::get("/users", [UserController::class, "index"]);')
    assert len(facts.routes) == 1
    r = facts.routes[0]
    assert (r.method, r.path, r.handler) == ("GET", "/users", "UserController.index")


def test_laravel_route_string_handler():
    facts = extract('Route::put("/old", "UserController@load");')
    r = facts.routes[0]
    assert (r.method, r.path, r.handler) == ("PUT", "/old", "UserController.load")


def test_laravel_route_closure_handler_has_no_edge_target():
    facts = extract('Route::post("/login", function() { auth(); });')
    r = facts.routes[0]
    assert (r.method, r.path, r.handler) == ("POST", "/login", None)


def test_laravel_route_any_is_wildcard_method():
    facts = extract('Route::any("/x", "C@m");')
    assert facts.routes[0].method == "*"


def test_superglobal_marks_enclosing_function_entrypoint():
    facts = extract('function search() { $id = $_GET["id"]; }', relpath="app/s.php")
    entry = [r for r in facts.routes if r.handler == "search"]
    assert entry and entry[0].method == "*" and entry[0].path == "/app/s.php#search"


def test_two_superglobal_entrypoints_get_distinct_routes():
    src = 'function a() { $x = $_GET["x"]; }\nfunction b() { $y = $_POST["y"]; }'
    facts = extract(src, relpath="app/s.php")
    paths = {r.path for r in facts.routes}
    assert paths == {"/app/s.php#a", "/app/s.php#b"}


def test_non_route_static_call_is_a_callsite():
    facts = extract('function f() { Logger::info("x"); }')
    match = [c for c in facts.calls if c.callee == "info"]
    assert match and match[0].object == "Logger"
    assert facts.routes == []


def test_unavailable_returns_empty(monkeypatch):
    monkeypatch.setattr("radar.graph.languages.php._AVAILABLE", False)
    facts = PHPExtractor().extract(b"<?php function x() {}", "x.php")
    assert facts.defs == [] and facts.language == "php"
