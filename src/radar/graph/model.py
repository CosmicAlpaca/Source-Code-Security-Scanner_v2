"""Graph data model: nodes/edges of the call graph + raw per-file extraction facts.

Node id convention (always posix paths):
  function  "src/auth/validate.js::validateUser"
  route     "src/routes/auth.js::route:POST /api/login"
  file      "src/auth/validate.js"
"""

from dataclasses import dataclass, field, asdict

# Node kinds
FUNCTION = "function"
ROUTE = "route"
FILE = "file"

# Edge kinds
CALLS = "calls"
IMPORTS = "imports"
HANDLES = "handles"

# Edge confidence
RESOLVED = "resolved"
NAME_ONLY = "name-only"


@dataclass(frozen=True)
class Node:
    id: str
    kind: str
    name: str
    file: str
    start_line: int = 0
    end_line: int = 0
    language: str = ""
    feature: str | None = None


@dataclass(frozen=True)
class Edge:
    src: str
    dst: str
    kind: str
    confidence: str = RESOLVED


def function_id(relpath: str, qualified_name: str) -> str:
    return f"{relpath}::{qualified_name}"


def route_id(relpath: str, method: str, path: str) -> str:
    return f"{relpath}::route:{method} {path}"


# ---------------------------------------------------------------------------
# Raw facts extracted from a single file (language-plugin output)
# ---------------------------------------------------------------------------


@dataclass
class FunctionDef:
    name: str  # qualified within file, e.g. "UserService.find" or "<route POST /login>"
    start_line: int
    end_line: int


@dataclass
class CallSite:
    caller: str | None  # enclosing function name within file; None = top-level code
    callee: str  # callee name as written (last property for member calls)
    line: int
    object: str | None = None  # receiver name for member calls, e.g. "db" in db.query()


@dataclass
class ImportBinding:
    local_name: str  # name bound in this file
    source: str  # module specifier as written ("./utils", "express", "app.services")
    imported_name: str  # exported name at the source ("default", "*", or identifier)


@dataclass
class RouteDef:
    method: str  # "GET", "POST", ...
    path: str  # "/api/login"
    handler: str | None  # handler name (method name when handler_object is set; may be synthetic)
    line: int
    handler_object: str | None = None  # receiver for `app.post(p, obj.method)` handlers


@dataclass
class FileFacts:
    file: str  # posix relpath
    language: str
    defs: list[FunctionDef] = field(default_factory=list)
    calls: list[CallSite] = field(default_factory=list)
    imports: list[ImportBinding] = field(default_factory=list)
    routes: list[RouteDef] = field(default_factory=list)
    instantiations: dict = field(default_factory=dict)  # local var -> class name (`const x = new C()`)


def node_to_dict(node: Node) -> dict:
    return asdict(node)


def edge_to_dict(edge: Edge) -> dict:
    return asdict(edge)


def node_from_dict(data: dict) -> Node:
    return Node(**data)


def edge_from_dict(data: dict) -> Edge:
    return Edge(**data)
