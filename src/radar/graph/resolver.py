"""2-pass call resolution: FileFacts from all files -> nodes + edges.

Resolution order per call site (first hit wins):
  1. def with same name in the same file            -> confidence "resolved"
  2. callee (or its receiver object) in import map  -> confidence "resolved"
  3. global name index across all files             -> confidence "name-only"
Dynamic calls were already dropped by extractors; file-level import edges act
as the coarse fallback.
"""

from collections import defaultdict

from radar.graph.languages import extractor_for
from radar.graph.model import (
    CALLS,
    FILE,
    HANDLES,
    IMPORTS,
    NAME_ONLY,
    RESOLVED,
    ROUTE,
    FUNCTION,
    Edge,
    FileFacts,
    Node,
    function_id,
    route_id,
)

MAX_NAME_ONLY_TARGETS = 5  # same-name defs in more files than this -> too ambiguous, skip


class _Index:
    def __init__(self, all_facts: list[FileFacts]):
        self.files: set[str] = {f.file for f in all_facts}
        self.defs_by_file: dict[str, dict[str, str]] = defaultdict(dict)  # file -> name -> node_id
        self.global_defs: dict[str, list[str]] = defaultdict(list)  # name -> [node_id]
        self.imports_by_file: dict[str, dict[str, tuple[str, str]]] = defaultdict(dict)
        self.instances_by_file: dict[str, dict[str, str]] = defaultdict(dict)  # file -> var -> class
        for facts in all_facts:
            for d in facts.defs:
                node_id = function_id(facts.file, d.name)
                self.defs_by_file[facts.file].setdefault(d.name, node_id)
                self.global_defs[d.name].append(node_id)
            for imp in facts.imports:
                self.imports_by_file[facts.file][imp.local_name] = (imp.source, imp.imported_name)
            self.instances_by_file[facts.file].update(getattr(facts, "instantiations", {}))


def _resolve_via_imports(name: str, call_object: str | None, facts: FileFacts, index: _Index):
    """Try the import map: direct named import, or member call on an imported module."""
    imports = index.imports_by_file[facts.file]
    extractor = extractor_for(facts.file)
    for local, lookup in ((name, None), (call_object, name)):
        if local is None or local not in imports:
            continue
        source, imported_name = imports[local]
        target_file = extractor.resolve_module(source, facts.file, index.files) if extractor else None
        if target_file is None:
            continue
        target_name = lookup or (name if imported_name in ("default", "*") else imported_name)
        node_id = index.defs_by_file[target_file].get(target_name)
        if node_id:
            return node_id
    return None


def _resolve_via_receiver(method: str, receiver: str | None, facts: FileFacts, index: _Index):
    """`obj.method` where `obj = new Class()` -> the method def on Class (same or imported file)."""
    cls = index.instances_by_file[facts.file].get(receiver) if receiver else None
    if not cls:
        return None
    if cls in index.defs_by_file[facts.file]:
        cls_file = facts.file
    else:
        source_imp = index.imports_by_file[facts.file].get(cls)
        extractor = extractor_for(facts.file)
        cls_file = extractor.resolve_module(source_imp[0], facts.file, index.files) if source_imp and extractor else None
    return index.defs_by_file[cls_file].get(method) if cls_file else None


def _resolve_callee(name: str, call_object: str | None, facts: FileFacts, index: _Index):
    """Returns (targets, confidence) — empty targets if unresolved/ambiguous."""
    same_file = index.defs_by_file[facts.file].get(name)
    if same_file:
        return [same_file], RESOLVED
    via_import = _resolve_via_imports(name, call_object, facts, index)
    if via_import:
        return [via_import], RESOLVED
    via_receiver = _resolve_via_receiver(name, call_object, facts, index)
    if via_receiver:
        return [via_receiver], RESOLVED
    candidates = index.global_defs.get(name, [])
    if 0 < len(candidates) <= MAX_NAME_ONLY_TARGETS:
        return list(candidates), NAME_ONLY
    return [], NAME_ONLY


def resolve(all_facts: list[FileFacts]) -> tuple[list[Node], list[Edge], dict]:
    index = _Index(all_facts)
    nodes: dict[str, Node] = {}
    edges: dict[tuple[str, str, str], Edge] = {}
    stats = {"unresolved_calls": 0, "ambiguous_skipped": 0}

    def add_edge(src: str, dst: str, kind: str, confidence: str) -> None:
        key = (src, dst, kind)
        prev = edges.get(key)
        if prev is None or (prev.confidence == NAME_ONLY and confidence == RESOLVED):
            edges[key] = Edge(src, dst, kind, confidence)

    for facts in all_facts:
        nodes[facts.file] = Node(facts.file, FILE, facts.file, facts.file, language=facts.language)
        for d in facts.defs:
            nid = function_id(facts.file, d.name)
            nodes[nid] = Node(nid, FUNCTION, d.name, facts.file, d.start_line, d.end_line, facts.language)
        for r in facts.routes:
            rid = route_id(facts.file, r.method, r.path)
            nodes[rid] = Node(rid, ROUTE, f"{r.method} {r.path}", facts.file, r.line, r.line, facts.language)

    for facts in all_facts:
        extractor = extractor_for(facts.file)
        seen_sources = set()
        for imp in facts.imports:
            if imp.source in seen_sources:
                continue
            seen_sources.add(imp.source)
            target = extractor.resolve_module(imp.source, facts.file, index.files) if extractor else None
            if target:
                add_edge(facts.file, target, IMPORTS, RESOLVED)

        for call in facts.calls:
            src = function_id(facts.file, call.caller) if call.caller else facts.file
            if src not in nodes:
                src = facts.file
            targets, confidence = _resolve_callee(call.callee, call.object, facts, index)
            if not targets:
                stats["unresolved_calls"] += 1
                if len(index.global_defs.get(call.callee, [])) > MAX_NAME_ONLY_TARGETS:
                    stats["ambiguous_skipped"] += 1
                continue
            for dst in targets:
                if dst != src:
                    add_edge(src, dst, CALLS, confidence)

        for r in facts.routes:
            if r.handler is None:
                continue
            rid = route_id(facts.file, r.method, r.path)
            targets, confidence = _resolve_callee(r.handler, r.handler_object, facts, index)
            for dst in targets:
                add_edge(rid, dst, HANDLES, confidence)

    return sorted(nodes.values(), key=lambda n: n.id), sorted(
        edges.values(), key=lambda e: (e.src, e.dst, e.kind)
    ), stats
