"""Pure graph transforms for the `radar graph` render path.

These shape the graph for VISUALISATION only (aggregate / focus / cap). They
never mutate the input and are never persisted — `graph.json` and every other
command (impact, report, triage, …) keep the full function-level graph.
"""

from __future__ import annotations

import networkx as nx

from radar.graph.model import CALLS, FILE, HANDLES, IMPORTS, ROUTE

# Edge-kind precedence when several kinds collapse onto one file→file edge.
_KIND_RANK = {CALLS: 3, HANDLES: 2, IMPORTS: 1}


def aggregate_by_file(graph: nx.DiGraph) -> nx.DiGraph:
    """Collapse function/route nodes into one node per file.

    The file node carries ``members`` (how many original nodes it represents).
    Edges are remapped file→file: self-loops dropped, duplicates merged with a
    summed ``weight``, keeping the highest-precedence edge kind for colour.
    Returns a brand-new graph; the input is untouched.
    """
    out = nx.DiGraph()
    node_file: dict[str, str] = {}
    members: dict[str, int] = {}

    for nid, data in graph.nodes(data=True):
        f = data.get("file") or nid
        node_file[nid] = f
        members[f] = members.get(f, 0) + 1

    for f, count in members.items():
        out.add_node(
            f,
            id=f,
            kind=FILE,
            name=f.rsplit("/", 1)[-1],
            file=f,
            start_line=0,
            members=count,
        )

    merged: dict[tuple[str, str], dict] = {}
    for src, dst, data in graph.edges(data=True):
        sf, df = node_file.get(src), node_file.get(dst)
        if sf is None or df is None or sf == df:
            continue  # skip dangling + same-file (self-loop) edges
        kind = data.get("kind", CALLS)
        cur = merged.get((sf, df))
        if cur is None:
            merged[(sf, df)] = {"kind": kind, "weight": 1}
        else:
            cur["weight"] += 1
            if _KIND_RANK.get(kind, 0) > _KIND_RANK.get(cur["kind"], 0):
                cur["kind"] = kind

    for (sf, df), attrs in merged.items():
        out.add_edge(sf, df, **attrs)
    return out


def focus_security(graph: nx.DiGraph) -> tuple[nx.DiGraph, bool]:
    """Keep only the subgraph reachable forward from route nodes (attack surface).

    Returns ``(subgraph, had_routes)``. With no route nodes there is no defined
    entry point, so the graph is returned unchanged and ``had_routes`` is False
    so the caller can warn instead of silently emptying the view.
    """
    roots = [n for n, d in graph.nodes(data=True) if d.get("kind") == ROUTE]
    if not roots:
        return graph, False
    keep: set = set(roots)
    for r in roots:
        keep |= nx.descendants(graph, r)
    return graph.subgraph(keep).copy(), True


def cap_nodes(graph: nx.DiGraph, max_nodes: int | None) -> tuple[nx.DiGraph, int]:
    """Keep the top ``max_nodes`` nodes by degree; return ``(subgraph, dropped)``.

    Deterministic: ties broken by node id. No-op (dropped=0) when already within
    budget or when ``max_nodes`` is falsy.
    """
    n = graph.number_of_nodes()
    if not max_nodes or n <= max_nodes:
        return graph, 0
    ranked = sorted(graph.nodes, key=lambda nid: (-graph.degree(nid), str(nid)))
    keep = set(ranked[:max_nodes])
    return graph.subgraph(keep).copy(), n - max_nodes
