"""Unit tests for the Go extractor (defs, calls, imports, routes)."""

import pytest

pytest.importorskip("tree_sitter_go")

from radar.graph.languages.go import GoExtractor

ext = GoExtractor()


def extract(source: str, relpath: str = "src/sample.go"):
    return ext.extract(source.encode(), relpath)


def test_function_declaration_def():
    facts = extract("package main\nfunc Hello(a int) int { return a }\n")
    assert [d.name for d in facts.defs] == ["Hello"]
    assert facts.defs[0].start_line == 2


def test_method_declaration_qualified_by_pointer_receiver():
    src = "package main\nfunc (h *Handler) ServeHTTP() { return }\n"
    facts = extract(src)
    assert [d.name for d in facts.defs] == ["Handler.ServeHTTP"]


def test_method_declaration_qualified_by_value_receiver():
    src = "package main\nfunc (s Service) Find() { return }\n"
    facts = extract(src)
    assert [d.name for d in facts.defs] == ["Service.Find"]


def test_call_with_caller_attribution():
    src = "package main\nfunc run() { helper() }\n"
    facts = extract(src)
    calls = [(c.caller, c.callee) for c in facts.calls]
    assert ("run", "helper") in calls


def test_selector_call_records_object():
    src = 'package main\nfunc q() { db.Query("SELECT 1") }\n'
    facts = extract(src)
    match = [c for c in facts.calls if c.callee == "Query"]
    assert match and match[0].object == "db"


def test_import_single_and_alias():
    src = 'package main\nimport (\n\t"net/http"\n\tm "github.com/gorilla/mux"\n)\n'
    facts = extract(src)
    by_local = {i.local_name: i.source for i in facts.imports}
    assert by_local["http"] == "net/http"
    assert by_local["m"] == "github.com/gorilla/mux"


def test_route_handlefunc_wildcard_method():
    src = 'package main\nfunc setup() { http.HandleFunc("/api", index) }\n'
    facts = extract(src)
    assert len(facts.routes) == 1
    r = facts.routes[0]
    assert (r.method, r.path, r.handler) == ("*", "/api", "index")


def test_route_gorilla_mux_method():
    src = 'package main\nfunc setup() { router.Get("/users", listUsers) }\n'
    facts = extract(src)
    assert len(facts.routes) == 1
    r = facts.routes[0]
    assert (r.method, r.path, r.handler) == ("GET", "/users", "listUsers")


def test_route_ignores_unknown_object():
    src = 'package main\nfunc setup() { thing.Get("/x", h) }\n'
    facts = extract(src)
    assert facts.routes == []


def test_unavailable_returns_empty(monkeypatch):
    monkeypatch.setattr("radar.graph.languages.go._AVAILABLE", False)
    facts = GoExtractor().extract(b"package main\nfunc X() {}\n", "x.go")
    assert facts.defs == [] and facts.language == "go"
