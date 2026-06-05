"""git diff -> changed lines -> graph nodes containing those lines.

Uses `git diff -U0` hunk headers (@@ -a,b +c,d @@). For pure deletions (d=0)
the anchor line c is used so the enclosing function is still found. Lines that
fall outside every function map to the file node (file-level fallback).
"""

import re
import subprocess
from collections import defaultdict
from pathlib import Path

import networkx as nx

_HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")


def _run_git_diff(root: Path, rev: str | None, staged: bool) -> str:
    cmd = ["git", "-c", "core.quotepath=false", "diff", "-U0", "--no-color"]
    cmd.append("--cached" if staged else (rev or "HEAD~1"))
    proc = subprocess.run(cmd, cwd=root, capture_output=True, text=True, encoding="utf-8", timeout=60)
    if proc.returncode not in (0, 1):  # 1 = differences found with some flags; >1 = error
        raise RuntimeError(f"git diff failed: {proc.stderr.strip()}")
    return proc.stdout


def changed_lines(root: Path, rev: str | None = None, staged: bool = False) -> dict[str, set[int]]:
    """posix relpath -> set of changed line numbers (new side of the diff)."""
    changes: dict[str, set[int]] = defaultdict(set)
    current_file: str | None = None
    for line in _run_git_diff(root, rev, staged).splitlines():
        if line.startswith("+++ "):
            target = line[4:].strip()
            current_file = None if target == "/dev/null" else target.removeprefix("b/")
            continue
        match = _HUNK_RE.match(line)
        if match and current_file:
            start = int(match.group(1))
            count = int(match.group(2)) if match.group(2) is not None else 1
            if count == 0:  # pure deletion — anchor on the surrounding line
                changes[current_file].add(max(start, 1))
            else:
                changes[current_file].update(range(start, start + count))
    return dict(changes)


def map_to_nodes(graph: nx.DiGraph, changes: dict[str, set[int]]) -> list[str]:
    """Changed (file, lines) -> node ids: narrowest enclosing function, else file node."""
    functions_by_file: dict[str, list[tuple[int, int, str]]] = defaultdict(list)
    file_nodes: set[str] = set()
    for node_id, data in graph.nodes(data=True):
        if data["kind"] == "function":
            functions_by_file[data["file"]].append((data["start_line"], data["end_line"], node_id))
        elif data["kind"] == "file":
            file_nodes.add(node_id)

    changed: set[str] = set()
    for file, lines in changes.items():
        spans = functions_by_file.get(file, [])
        for line in lines:
            enclosing = [s for s in spans if s[0] <= line <= s[1]]
            if enclosing:
                changed.add(min(enclosing, key=lambda s: s[1] - s[0])[2])
            elif file in file_nodes:
                changed.add(file)  # top-level / non-function change
    return sorted(changed)


def find_function_nodes(graph: nx.DiGraph, name: str) -> list[str]:
    """Match --function argument: exact node id, or function name across files."""
    if name in graph.nodes:
        return [name]
    return sorted(
        node_id
        for node_id, data in graph.nodes(data=True)
        if data["kind"] == "function" and data["name"] == name
    )
