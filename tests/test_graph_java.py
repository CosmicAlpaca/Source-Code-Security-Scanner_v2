"""Unit tests for the Java extractor (defs, calls, imports, routes)."""

import pytest

pytest.importorskip("tree_sitter_java")

from radar.graph.languages.java import JavaExtractor

ext = JavaExtractor()


def extract(source: str, relpath: str = "src/Sample.java"):
    return ext.extract(source.encode(), relpath)


def test_method_qualified_by_class():
    facts = extract("class Foo { void bar() {} }")
    assert [d.name for d in facts.defs] == ["Foo.bar"]


def test_interface_method_qualified():
    facts = extract("interface Svc { void run(); }")
    assert [d.name for d in facts.defs] == ["Svc.run"]


def test_constructor_qualified():
    facts = extract("class Foo { Foo() {} }")
    assert "Foo.Foo" in [d.name for d in facts.defs]


def test_method_invocation_object_and_caller():
    facts = extract("class Foo { void bar() { db.query(); } }")
    match = [c for c in facts.calls if c.callee == "query"]
    assert match and match[0].caller == "Foo.bar" and match[0].object == "db"


def test_import_scoped_identifier():
    facts = extract("import com.example.Bar;\nclass Foo {}")
    imp = [i for i in facts.imports if i.local_name == "Bar"]
    assert imp and imp[0].source == "com.example.Bar"


def test_spring_get_mapping():
    src = 'class C { @GetMapping("/users") public void list() {} }'
    facts = extract(src)
    assert len(facts.routes) == 1
    r = facts.routes[0]
    assert (r.method, r.path, r.handler) == ("GET", "/users", "C.list")


def test_spring_request_mapping_with_method():
    src = 'class C { @RequestMapping(value = "/x", method = RequestMethod.POST) void h() {} }'
    facts = extract(src)
    assert len(facts.routes) == 1
    r = facts.routes[0]
    assert (r.method, r.path) == ("POST", "/x")


def test_jaxrs_get_and_path():
    src = 'class C { @GET @Path("/ping") public String ping() { return ""; } }'
    facts = extract(src)
    assert len(facts.routes) == 1
    r = facts.routes[0]
    assert (r.method, r.path, r.handler) == ("GET", "/ping", "C.ping")


def test_method_without_route_annotation_has_no_route():
    facts = extract("class C { void plain() {} }")
    assert facts.routes == []


def test_unavailable_returns_empty(monkeypatch):
    monkeypatch.setattr("radar.graph.languages.java._AVAILABLE", False)
    facts = JavaExtractor().extract(b"class C { void m() {} }", "C.java")
    assert facts.defs == [] and facts.language == "java"
