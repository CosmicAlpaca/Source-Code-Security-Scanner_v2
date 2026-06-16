"""Walk a codebase, run language extractors, resolve, save/load graph.json.

graph.json is deterministic (sorted nodes/edges) and carries the git HEAD hash
so `radar impact` can detect a stale graph.
"""

import json
import subprocess
from pathlib import Path

import networkx as nx

from radar.graph.languages import extractor_for
from radar.graph.model import Edge, FileFacts, Node, edge_to_dict, node_to_dict

GRAPH_VERSION = 2  # bump when builder changes graph shape → invalidates old caches
SKIP_DIRS = {
    "node_modules", ".git", "dist", "build", "out", "coverage",
    ".venv", "venv", "__pycache__", ".radar", ".tox", ".next",
}


def git_head(root: Path) -> str | None:
    try:
        proc = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=root, capture_output=True, text=True, timeout=10
        )
        return proc.stdout.strip() if proc.returncode == 0 else None
    except (OSError, subprocess.TimeoutExpired):
        return None


def iter_source_files(root: Path, is_excluded=None):
    """Yield posix relpaths of files we have an extractor for."""
    stack = [root]
    while stack:
        current = stack.pop()
        for entry in sorted(current.iterdir(), key=lambda p: p.name):
            if entry.is_dir():
                if entry.name not in SKIP_DIRS and not entry.name.startswith("."):
                    stack.append(entry)
                continue
            relpath = entry.relative_to(root).as_posix()
            if is_excluded is not None and is_excluded(relpath):
                continue
            if extractor_for(relpath) is not None:
                yield relpath


def extract_all(root: Path, is_excluded=None) -> list[FileFacts]:
    all_facts = []
    for relpath in iter_source_files(root, is_excluded):
        extractor = extractor_for(relpath)
        try:
            source = (root / relpath).read_bytes()
        except OSError:
            continue
        all_facts.append(extractor.extract(source, relpath))
    return all_facts


def build_graph(root: Path, config=None) -> nx.DiGraph:
    """config: radar.config.RadarConfig | None (exclude globs + feature map)."""
    from radar.graph.resolver import resolve

    is_excluded = config.is_excluded if config is not None else None
    all_facts = extract_all(root, is_excluded)
    nodes, edges, stats = resolve(all_facts)
    if config is not None:
        nodes = [
            n if n.feature else Node(**{**node_to_dict(n), "feature": config.feature_for(n.file)})
            for n in nodes
        ]
    graph = nx.DiGraph(head=git_head(root), root=str(root), stats=stats)
    for node in nodes:
        graph.add_node(node.id, **node_to_dict(node))
    for edge in edges:
        graph.add_edge(edge.src, edge.dst, **edge_to_dict(edge))
    return graph


def save_graph(graph: nx.DiGraph, out_path: Path) -> None:
    out_path = out_path.resolve()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "version": GRAPH_VERSION,
        "head": graph.graph.get("head"),
        "stats": graph.graph.get("stats", {}),
        "nodes": [graph.nodes[n] for n in sorted(graph.nodes)],
        "edges": [
            graph.edges[s, t]
            for s, t in sorted(graph.edges, key=lambda e: (e[0], e[1], graph.edges[e].get("kind", "")))
        ],
    }
    out_path.write_text(json.dumps(payload, indent=1, sort_keys=True), encoding="utf-8")


def load_graph(path: Path) -> nx.DiGraph:
    payload = json.loads(path.read_text(encoding="utf-8"))
    graph = nx.DiGraph(
        head=payload.get("head"),
        version=payload.get("version"),
        stats=payload.get("stats", {}),
    )
    for node in payload["nodes"]:
        graph.add_node(node["id"], **node)
    for edge in payload["edges"]:
        graph.add_edge(edge["src"], edge["dst"], **edge)
    return graph


def graph_summary(graph: nx.DiGraph) -> dict:
    kinds = {}
    for node_id in graph.nodes:
        kinds[graph.nodes[node_id]["kind"]] = kinds.get(graph.nodes[node_id]["kind"], 0) + 1
    approx = sum(1 for _, _, d in graph.edges(data=True) if d.get("confidence") == "name-only")
    return {
        "functions": kinds.get("function", 0),
        "routes": kinds.get("route", 0),
        "files": kinds.get("file", 0),
        "edges": graph.number_of_edges(),
        "approximate_edges": approx,
        **graph.graph.get("stats", {}),
    }
