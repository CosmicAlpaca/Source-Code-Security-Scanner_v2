"""Map a Semgrep finding to the routes that reach it (reachability for triage).

Reuses impact.tracer: reverse-BFS from the finding's enclosing function already
yields every transitive caller, so any route among them is an untrusted entrypoint
that reaches the vulnerable code. We never assert "unreachable" — the call graph
misses dynamic dispatch, so absence of a route path is `unknown`, not proof of safety.
"""

from dataclasses import dataclass, field
from pathlib import Path

import networkx as nx

from radar.graph.model import FUNCTION
from radar.impact.tracer import trace

REACHABLE = "reachable"
UNKNOWN = "unknown"


@dataclass
class Reach:
    function_id: str | None  # enclosing function node id; None if top-level / not found
    routes: list[str] = field(default_factory=list)
    status: str = UNKNOWN  # REACHABLE (>=1 route) | UNKNOWN


def _norm_path(finding_path: str, root: Path) -> str:
    """Semgrep finding path -> posix relpath matching graph node.file.

    The scan runner forces repo-relative paths, but stay defensive about a stray
    `./` prefix, backslashes, or an absolute path from a native semgrep build.
    """
    candidate = Path(finding_path)
    if candidate.is_absolute():
        try:
            return candidate.resolve().relative_to(root).as_posix()
        except ValueError:
            return finding_path.replace("\\", "/").lstrip("/")
    return finding_path.replace("\\", "/").removeprefix("./")


def enclosing_function(graph: nx.DiGraph, relpath: str, line: int) -> str | None:
    """Narrowest function node whose span contains (relpath, line); None if none."""
    enclosing: list[tuple[int, str]] = []
    for node_id, data in graph.nodes(data=True):
        if data.get("kind") != FUNCTION or data.get("file") != relpath:
            continue
        start, end = data.get("start_line", 0), data.get("end_line", 0)
        if start <= line <= end:
            enclosing.append((end - start, node_id))
    if not enclosing:
        return None
    return min(enclosing, key=lambda s: s[0])[1]  # narrowest span wins


def reachability(graph: nx.DiGraph, finding, root: Path) -> Reach:
    """Finding -> Reach(function_id, routes, status). Best-effort: never reports 'dead'."""
    relpath = _norm_path(finding.path, root)
    fid = enclosing_function(graph, relpath, finding.line)
    if fid is None:
        return Reach(None, [], UNKNOWN)
    routes = sorted({api["route"] for api in trace(graph, [fid]).apis})
    return Reach(fid, routes, REACHABLE if routes else UNKNOWN)
