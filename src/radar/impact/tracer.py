"""Reverse BFS over the call graph: changed nodes -> everything that depends on them.

Traverses incoming `calls` and `handles` edges (who calls / routes to me), plus
incoming `imports` edges for changed file nodes (file-level fallback). An
affected node is "name-only" (approximate) when any edge on its discovery path
was resolved by global name matching.
"""

from collections import deque
from dataclasses import dataclass, field

import networkx as nx

from radar.graph.model import CALLS, HANDLES, IMPORTS, NAME_ONLY, RESOLVED

_TRAVERSE_KINDS = {CALLS, HANDLES}


@dataclass
class ImpactItem:
    id: str
    name: str
    kind: str  # function | route | file
    file: str
    line: int
    feature: str | None = None
    depth: int = 0
    via_changed: str = ""  # changed node id this impact traces back to
    parent: str = ""  # node id it was discovered from (BFS predecessor)
    confidence: str = RESOLVED
    routes: list[str] = field(default_factory=list)  # route names handling this node


@dataclass
class ImpactResult:
    changed: list[ImpactItem]
    affected: list[ImpactItem]
    apis: list[dict]  # [{"route": "POST /api/login", "file": ...}]
    features: list[str]
    stats: dict


def _item(graph: nx.DiGraph, node_id: str, **extra) -> ImpactItem:
    data = graph.nodes[node_id]
    return ImpactItem(
        id=node_id,
        name=data["name"],
        kind=data["kind"],
        file=data["file"],
        line=data.get("start_line", 0),
        feature=data.get("feature"),
        **extra,
    )


def _direct_routes(graph: nx.DiGraph, node_id: str) -> list[str]:
    return sorted(
        graph.nodes[pred]["name"]
        for pred in graph.predecessors(node_id)
        if graph.nodes[pred]["kind"] == "route" and graph.edges[pred, node_id]["kind"] == HANDLES
    )


def trace(graph: nx.DiGraph, changed_ids: list[str], max_depth: int | None = None,
          include_name_only: bool = True) -> ImpactResult:
    changed_items = [_item(graph, c, routes=_direct_routes(graph, c)) for c in changed_ids if c in graph.nodes]
    visited: dict[str, ImpactItem] = {}
    queue: deque[tuple[str, int, str, bool]] = deque(
        (c.id, 0, c.id, False) for c in changed_items
    )
    changed_set = {c.id for c in changed_items}

    while queue:
        node_id, depth, origin, approx = queue.popleft()
        if max_depth is not None and depth >= max_depth:
            continue
        node_is_file = graph.nodes[node_id]["kind"] == "file"
        for pred in graph.predecessors(node_id):
            edge = graph.edges[pred, node_id]
            kind = edge["kind"]
            if kind not in _TRAVERSE_KINDS and not (kind == IMPORTS and node_is_file):
                continue
            edge_approx = edge.get("confidence") == NAME_ONLY
            if edge_approx and not include_name_only:
                continue
            path_approx = approx or edge_approx
            if pred in changed_set:
                continue
            seen = visited.get(pred)
            if seen is not None and (seen.depth < depth + 1 or (seen.depth == depth + 1 and not seen.confidence == NAME_ONLY)):
                continue
            item = _item(
                graph, pred,
                depth=depth + 1,
                via_changed=origin,
                parent=node_id,
                confidence=NAME_ONLY if path_approx else RESOLVED,
                routes=_direct_routes(graph, pred),
            )
            visited[pred] = item
            queue.append((pred, depth + 1, origin, path_approx))

    affected = sorted(visited.values(), key=lambda i: (i.depth, i.id))
    api_nodes = {i.id: i for i in [*changed_items, *affected] if i.kind == "route"}
    apis = [{"route": i.name, "file": i.file} for i in sorted(api_nodes.values(), key=lambda i: i.name)]
    features = sorted({i.feature for i in [*changed_items, *affected] if i.feature})
    stats = {
        "functions_affected": sum(1 for i in affected if i.kind == "function"),
        "apis_affected": len(apis),
        "features_affected": len(features),
        "approximate": sum(1 for i in affected if i.confidence == NAME_ONLY),
    }
    return ImpactResult(changed_items, affected, apis, features, stats)
