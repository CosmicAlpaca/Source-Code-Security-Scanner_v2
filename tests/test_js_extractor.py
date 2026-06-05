"""Unit tests for the JS/TS extractor (defs, calls, imports, routes)."""

from radar.graph.languages.javascript import JavaScriptExtractor

ext = JavaScriptExtractor()


def extract(source: str, relpath: str = "src/sample.js"):
    return ext.extract(source.encode(), relpath)


def test_function_declaration_def():
    facts = extract("function hello(a) { return a; }")
    assert [d.name for d in facts.defs] == ["hello"]
    assert facts.defs[0].start_line == 1


def test_arrow_and_function_expression_defs():
    facts = extract("const f = () => 1;\nconst g = function (x) { return x; };")
    assert {d.name for d in facts.defs} == {"f", "g"}


def test_class_method_qualified_name():
    facts = extract("class UserService { find(id) { return id; } }")
    assert [d.name for d in facts.defs] == ["UserService.find"]


def test_exports_assignment_def():
    facts = extract("exports.handler = async () => { run(); };")
    assert [d.name for d in facts.defs] == ["handler"]
    assert facts.calls[0].caller == "handler"


def test_calls_with_caller_attribution():
    facts = extract("function a() { b(); obj.c(); }\ntopLevel();")
    calls = {(c.caller, c.callee) for c in facts.calls}
    assert ("a", "b") in calls
    assert ("a", "c") in calls
    assert (None, "topLevel") in calls


def test_member_call_records_object():
    facts = extract("function a() { db.query('x'); }")
    call = next(c for c in facts.calls if c.callee == "query")
    assert call.object == "db"


def test_dynamic_call_skipped():
    facts = extract("function a() { obj[name](); }")
    assert all(c.callee != "name" for c in facts.calls)


def test_es_imports():
    facts = extract(
        "import def from './a';\nimport { x, y as z } from './b';\nimport * as ns from './c';",
        "src/sample.js",
    )
    bindings = {(i.local_name, i.source, i.imported_name) for i in facts.imports}
    assert ("def", "./a", "default") in bindings
    assert ("x", "./b", "x") in bindings
    assert ("z", "./b", "y") in bindings
    assert ("ns", "./c", "*") in bindings


def test_require_imports():
    facts = extract("const db = require('./db');\nconst { exec, spawn: sp } = require('child_process');")
    bindings = {(i.local_name, i.source, i.imported_name) for i in facts.imports}
    assert ("db", "./db", "default") in bindings
    assert ("exec", "child_process", "exec") in bindings
    assert ("sp", "child_process", "spawn") in bindings


def test_route_with_identifier_handler():
    facts = extract("function login() {}\nrouter.post('/api/login', login);")
    assert len(facts.routes) == 1
    route = facts.routes[0]
    assert (route.method, route.path, route.handler) == ("POST", "/api/login", "login")


def test_route_with_inline_arrow_handler():
    facts = extract("app.get('/health', (req, res) => { check(); });")
    assert facts.routes[0].handler == "<route GET /health>"
    assert any(d.name == "<route GET /health>" for d in facts.defs)
    assert any(c.caller == "<route GET /health>" and c.callee == "check" for c in facts.calls)


def test_route_call_not_recorded_as_plain_call():
    facts = extract("router.get('/x', h);")
    assert all(c.callee != "get" for c in facts.calls)


def test_typescript_parses():
    facts = extract(
        "export function greet(name: string): string { return hi(name); }",
        "src/sample.ts",
    )
    assert [d.name for d in facts.defs] == ["greet"]
    assert facts.calls[0].callee == "hi"


def test_resolve_module_relative():
    files = {"src/utils/validate.js", "src/services/db.js", "src/lib/index.js"}
    assert ext.resolve_module("../utils/validate", "src/routes/auth.js", files) == "src/utils/validate.js"
    assert ext.resolve_module("./db", "src/services/api.js", files) == "src/services/db.js"
    assert ext.resolve_module("../lib", "src/routes/auth.js", files) == "src/lib/index.js"
    assert ext.resolve_module("express", "src/app.js", files) is None
