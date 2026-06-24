"""Tests for the impact-first Blast tab in radar.serve.orchestrator.

Covers the mode-aware blast-radius trace (changes / file / findings / function),
the cheap state-based findings overlay, and the /api/impact endpoint.
Graph + trace + map_to_nodes run for real on a tiny in-memory graph; only git
(changed_lines) is mocked so tests stay fast and offline.
"""
from __future__ import annotations

import json
import threading
from pathlib import Path
from unittest.mock import patch

import networkx as nx
import pytest

from radar.graph.model import CALLS, HANDLES, RESOLVED
from radar.scan.findings import Finding
from radar.serve.orchestrator import Orchestrator
from radar.serve.server import Broadcaster


class _RecordingStream:
    def __init__(self) -> None:
        self._frames: list[bytes] = []

    def write(self, data: bytes) -> None:
        self._frames.append(data)

    def flush(self) -> None:
        pass

    def events(self) -> list[str]:
        out = []
        for f in self._frames:
            for line in f.split(b"\n"):
                if line.startswith(b"event: "):
                    out.append(line[7:].decode())
        return out

    def blast_payloads(self) -> list[dict]:
        out = []
        frames = b"".join(self._frames).decode().split("\n\n")
        for fr in frames:
            if "event: blast" in fr and "data: " in fr:
                out.append(json.loads(fr.split("data: ", 1)[1].strip()))
        return out


def _graph() -> nx.DiGraph:
    """route(POST /login) -handles-> login -calls-> helper, all in app.js."""
    g = nx.DiGraph()
    g.add_node("app.js::login", name="login", kind="function", file="app.js",
               start_line=1, end_line=5)
    g.add_node("app.js::helper", name="helper", kind="function", file="app.js",
               start_line=7, end_line=9)
    g.add_node("app.js::r", name="POST /login", kind="route", file="app.js", start_line=1)
    g.add_edge("app.js::r", "app.js::login", kind=HANDLES, confidence=RESOLVED)
    g.add_edge("app.js::login", "app.js::helper", kind=CALLS, confidence=RESOLVED)
    return g


def _orch(tmp_path: Path):
    bc = Broadcaster()
    stream = _RecordingStream()
    bc.register(stream)
    orch = Orchestrator(bc, tmp_path)
    orch.state.graph = _graph()
    orch.state.repo_path = str(tmp_path)
    return orch, stream


# ── _nodes_in_file ──────────────────────────────────────────────────────────

def test_nodes_in_file_returns_function_nodes(tmp_path):
    orch, _ = _orch(tmp_path)
    ids = orch._nodes_in_file(orch.state.graph, "app.js")
    assert "app.js::login" in ids and "app.js::helper" in ids
    assert "app.js::r" not in ids  # routes excluded


def test_nodes_in_file_unknown_file_empty(tmp_path):
    orch, _ = _orch(tmp_path)
    assert orch._nodes_in_file(orch.state.graph, "missing.js") == []


# ── _impact_ids per mode ────────────────────────────────────────────────────

def test_impact_ids_file_mode(tmp_path):
    orch, _ = _orch(tmp_path)
    ids, label = orch._impact_ids(orch.state.graph, [], "file", "app.js")
    assert "app.js::login" in ids
    assert "file: app.js" in label


def test_impact_ids_file_mode_no_target(tmp_path):
    orch, _ = _orch(tmp_path)
    ids, label = orch._impact_ids(orch.state.graph, [], "file", None)
    assert ids == [] and "save a file" in label


def test_impact_ids_findings_mode(tmp_path):
    orch, _ = _orch(tmp_path)
    findings = [Finding(severity="ERROR", path="app.js", line=8, rule="x.weak", message="m")]
    ids, label = orch._impact_ids(orch.state.graph, findings, "findings", None)
    assert "app.js::helper" in ids  # line 8 is inside helper (7-9)
    assert "finding site" in label


def test_impact_ids_changes_mode_uses_git_diff(tmp_path):
    orch, _ = _orch(tmp_path)
    with patch("radar.impact.diff_mapper.changed_lines", return_value={"app.js": {2}}):
        ids, label = orch._impact_ids(orch.state.graph, [], "changes", None)
    assert "app.js::login" in ids  # line 2 is inside login (1-5)
    assert "changed file" in label


def test_impact_ids_changes_mode_no_diff(tmp_path):
    orch, _ = _orch(tmp_path)
    with patch("radar.impact.diff_mapper.changed_lines", return_value={}):
        ids, label = orch._impact_ids(orch.state.graph, [], "changes", None)
    assert ids == [] and "no uncommitted changes" in label


def test_impact_ids_function_mode(tmp_path):
    orch, _ = _orch(tmp_path)
    ids, label = orch._impact_ids(orch.state.graph, [], "function", "login")
    assert ids == ["app.js::login"]
    assert "function: login" in label


# ── recompute_impact + push ─────────────────────────────────────────────────

def test_recompute_impact_sets_trace_and_pushes_blast(tmp_path):
    orch, stream = _orch(tmp_path)
    orch.state.impact_mode = "file"
    orch.recompute_impact(changed_path="app.js")
    assert orch.state.trace_res is not None
    # reverse BFS from app.js functions reaches the route handler
    apis = [a["route"] for a in orch.state.trace_res.apis]
    assert "POST /login" in apis
    assert "blast" in stream.events()


def test_recompute_impact_no_graph_empty_state(tmp_path):
    orch, stream = _orch(tmp_path)
    orch.state.graph = None
    orch.recompute_impact()
    assert orch.state.trace_res is None
    assert "blast" in stream.events()


# ── findings overlay (no re-scan) ───────────────────────────────────────────

def test_overlay_findings_from_state_tags_nodes(tmp_path):
    orch, _ = _orch(tmp_path)
    from radar.impact.tracer import trace
    res = trace(orch.state.graph, ["app.js::helper"])
    findings = [Finding(severity="ERROR", path="app.js", line=8, rule="x.weak-hash", message="m")]
    orch._overlay_findings_from_state(orch.state.graph, res, findings)
    tagged = [i for i in (*res.changed, *res.affected) if i.findings]
    assert any(i.id == "app.js::helper" for i in tagged)
    assert tagged[0].findings[0]["rule"] == "weak-hash"


# ── set_impact_mode ─────────────────────────────────────────────────────────

def test_set_impact_mode_switches_and_pushes(tmp_path):
    orch, stream = _orch(tmp_path)
    orch.set_impact_mode("findings")
    assert orch.state.impact_mode == "findings"
    assert "blast" in stream.events()


def test_set_impact_mode_invalid_defaults_changes(tmp_path):
    orch, _ = _orch(tmp_path)
    with patch("radar.impact.diff_mapper.changed_lines", return_value={}):
        orch.set_impact_mode("bogus")
    assert orch.state.impact_mode == "changes"
