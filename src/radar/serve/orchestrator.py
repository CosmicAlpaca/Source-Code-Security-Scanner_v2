"""Orchestrator — bridges the file watcher to SSE pushes for `radar serve`.

Tiered update model (see brainstorm doc):
  * on_change  → FAST  : re-scan only the changed file, patch the findings set,
                         push `findings` + `overview` + a `status` event (<1s).
  * heavy      → SLOW  : debounced ~2s, runs the full pipeline to correct drift
                         and refresh graph / blast / history.
  * run_triage → on-demand only (button) : AI verdicts, push `findings`.

Everything is offline-safe; a missing OPENAI_API_KEY degrades to a `status`
warning instead of crashing.
"""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path

from radar.scan import report as report_mod
from radar.scan.findings import SEVERITY_ORDER, Finding, owasp_tag, summary
from radar.scan.runner import RULES_DIR
from radar.scan.watcher import scan_file
from radar.serve.pipeline import compute_full_state

_HEAVY_DEBOUNCE = 2.0  # seconds — coalesce rapid saves before the full rebuild


class State:
    """In-memory snapshot of the current dashboard. Guarded by the orchestrator lock."""

    def __init__(self) -> None:
        self.findings: list[Finding] = []
        self.suppressed: int = 0
        self.risk_map: dict = {}
        self.verdict_map: dict | None = None
        self.history: list = []
        self.graph = None
        self.trace_res = None
        self.mermaid_src: str = ""
        self.trace_label: str | None = None
        self.repo_path: str = ""
        # Impact (blast-radius) tracking — impact-first live view.
        self.impact_mode: str = "changes"  # changes | file | findings | function
        self.impact_target: str | None = None  # last-saved file (file mode) / fn name

    def to_json(self) -> str:
        """JSON snapshot for GET /api/state. Prefer Orchestrator.state_json() in the
        server, which snapshots under the lock first; this renders an unlocked State
        directly (used in tests / where no concurrency exists)."""
        return _render_state_json(self.snapshot())

    def snapshot(self) -> dict:
        """Shallow copy of every field needed to render. Call under the lock."""
        return {
            "findings": list(self.findings),
            "suppressed": self.suppressed,
            "risk_map": self.risk_map,
            "verdict_map": self.verdict_map,
            "history": list(self.history),
            "graph": self.graph,
            "trace_res": self.trace_res,
            "mermaid_src": self.mermaid_src,
            "trace_label": self.trace_label,
            "repo_path": self.repo_path,
            "impact_mode": self.impact_mode,
        }


def _render_state_json(snap: dict) -> str:
    """JSON for GET /api/state from a consistent State snapshot (rendered off-lock)."""
    from radar.graph.graph_viz import render_graph_fragment

    findings = snap["findings"]
    graph_payload = None
    if snap["graph"] is not None:
        try:
            graph_payload = render_graph_fragment(snap["graph"], repo_path=snap["repo_path"])
        except Exception:
            graph_payload = None
    return json.dumps({
        "panels": {
            "overview": report_mod.render_overview_fragment(findings, snap["suppressed"]),
            "findings": report_mod.render_findings_fragment(
                findings, snap["risk_map"] or None, snap["verdict_map"]),
            "blast": report_mod.render_blast_fragment(
                snap["trace_res"], snap["mermaid_src"], snap["trace_label"], snap["repo_path"]),
            "history": report_mod.render_history_fragment(snap["history"]),
        },
        "charts": _chart_data(findings, snap["history"]),
        "graph": graph_payload,
        "summary": summary(findings),
        "impact_mode": snap.get("impact_mode", "changes"),
    })


def _chart_data(findings: list[Finding], history: list) -> dict:
    """OWASP/severity/history series so the client can draw Chart.js canvases."""
    owasp_labels, owasp_vals = report_mod._owasp_breakdown(findings)
    s = summary(findings)
    return {
        "owasp_labels": owasp_labels,
        "owasp_vals": owasp_vals,
        "sev": [s["error"], s["warning"], s["info"]],
        "history": [
            {"ts": e.get("ts"), "error": e.get("error", 0), "warning": e.get("warning", 0)}
            for e in (history or [])
        ],
    }


class Orchestrator:
    """Owns State, recomputes on file change, and pushes SSE events."""

    def __init__(self, broadcaster, root: Path, *, rules_only: bool = False,
                 use_docker: bool = False, engines: list[str] | None = None) -> None:
        self.bc = broadcaster
        self.root = root
        self.rules_only = rules_only
        self.use_docker = use_docker
        self.engines = engines
        self.state = State()
        self.state.repo_path = str(root)
        self._lock = threading.Lock()
        self._heavy_timer: threading.Timer | None = None

    # ── Initial / heavy full rebuild ─────────────────────────────────────────
    def compute_full(self) -> None:
        """Run the whole pipeline and push every panel. Called at startup + heavy."""
        self._push_status("scanning…", "busy")
        data = compute_full_state(
            self.root,
            rules_only=self.rules_only,
            engines=self.engines,
        )
        with self._lock:
            self.state.findings = data["findings"]
            self.state.suppressed = data["suppressed"]
            self.state.risk_map = data["risk_map"]
            self.state.graph = data["graph"]
            self.state.history = data["history"]
        # Blast radius is mode-aware (changes / file / findings) → trace after the
        # graph + findings are set. Cheap (cached graph + BFS, no semgrep).
        self._compute_impact()
        self._push_all_panels()
        if data.get("engine_summary"):
            self._push_status(f"idle · {data['engine_summary']}", "ok")
        else:
            self._push_status("idle", "ok")

    # ── Fast path: a single file changed ─────────────────────────────────────
    def on_change(self, path: Path) -> None:
        """FAST: re-scan the changed file, patch findings, push findings+overview."""
        try:
            rel = str(path.relative_to(self.root)) if path.is_absolute() else str(path)
        except ValueError:
            rel = str(path)
        rel = rel.replace("\\", "/")
        self._push_status(f"scanning {rel}…", "busy")

        raw = scan_file(path, RULES_DIR, use_docker=self.use_docker, repo_root=self.root)
        new_findings = [
            Finding(severity=d["severity"], path=rel, line=d["line"],
                    rule=d["rule"], message=d["message"])
            for d in raw
        ]
        with self._lock:
            kept = [f for f in self.state.findings if f.path != rel]
            kept.extend(new_findings)
            kept.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 3), f.path, f.line))
            self.state.findings = kept
            # Fast path can't recompute reachability cheaply; rebuild a best-effort
            # risk_map so the ranked table still renders. Heavy pass corrects it.
            self.state.risk_map = self._best_effort_risk_map(kept)
            self.state.verdict_map = None  # findings changed → stale AI verdicts dropped

        self._push_findings()
        self._push_overview()
        # Impact-first: remember the file just saved and, if the Blast tab is
        # tracking edits, refresh the blast radius cheaply (cached graph + BFS,
        # no semgrep) so impact updates live with your changes.
        with self._lock:
            mode = self.state.impact_mode
            if mode != "function":  # don't clobber a pinned function name
                self.state.impact_target = rel
        if mode in ("changes", "file"):
            try:
                self.recompute_impact(changed_path=rel)
            except Exception as exc:
                self._push_status(f"impact refresh failed: {exc}", "warn")
        self._push_status("idle", "ok")
        self.schedule_heavy()

    # ── Impact (blast radius) — mode-aware ───────────────────────────────────
    def recompute_impact(self, changed_path: str | None = None) -> None:
        """Recompute the blast radius for the current mode and push the blast panel."""
        if changed_path is not None:
            with self._lock:
                self.state.impact_target = changed_path
        self._compute_impact()
        self._push_blast()

    def set_impact_mode(self, mode: str, function: str | None = None) -> None:
        """Switch the Blast tab's trace source, recompute, and push."""
        mode = mode if mode in ("changes", "file", "findings", "function") else "changes"
        with self._lock:
            self.state.impact_mode = mode
            if mode == "function":
                self.state.impact_target = function
        self.recompute_impact()
        self._push_status(f"impact: {mode}", "ok")

    def _compute_impact(self) -> None:
        """Set state.trace_res / mermaid_src / trace_label for the current mode.
        No push — callers push blast. Reuses impact.tracer + diff_mapper."""
        from radar.impact.tracer import trace
        from radar.report.exporters import to_mermaid

        with self._lock:
            graph = self.state.graph
            findings = list(self.state.findings)
            mode = self.state.impact_mode
            target = self.state.impact_target

        if graph is None:
            with self._lock:
                self.state.trace_res = None
                self.state.mermaid_src = ""
                self.state.trace_label = "building dependency graph…"
            return

        ids, label = self._impact_ids(graph, findings, mode, target)
        trace_res = trace(graph, ids) if ids else None
        if trace_res is not None:
            self._overlay_findings_from_state(graph, trace_res, findings)
            mermaid = to_mermaid(trace_res)
        else:
            mermaid = ""
        with self._lock:
            self.state.trace_res = trace_res
            self.state.mermaid_src = mermaid
            self.state.trace_label = label

    def _impact_ids(self, graph, findings, mode, target):
        """Return (changed_node_ids, label) for the active impact mode."""
        from radar.impact.diff_mapper import (changed_lines, find_function_nodes,
                                              map_to_nodes)

        if mode == "findings":
            sev_rank = {"ERROR": 0, "WARNING": 1, "INFO": 2}
            ranked = sorted(findings, key=lambda f: sev_rank.get(f.severity, 3))
            changes: dict = {}
            for f in ranked[:15]:
                changes.setdefault(f.path, set()).add(f.line)
            ids = map_to_nodes(graph, changes) if changes else []
            return ids, (f"{len(ids)} finding site(s)" if ids else "no findings to trace")

        if mode == "function":
            ids = find_function_nodes(graph, target) if target else []
            return ids, (f"function: {target}" if ids else f"no function '{target}'")

        if mode == "file":
            if not target:
                return [], "save a file to trace it"
            ids = self._nodes_in_file(graph, target)
            return ids, (f"file: {target}" if ids else f"no traceable nodes in {target}")

        # changes (default): blast radius of all uncommitted changes vs HEAD.
        try:
            changes = changed_lines(self.root, rev="HEAD")
        except Exception:
            return [], "not a git repo / no diff against HEAD"
        ids = map_to_nodes(graph, changes) if changes else []
        return ids, (f"{len(changes)} changed file(s) vs HEAD" if ids
                     else "no uncommitted changes")

    @staticmethod
    def _nodes_in_file(graph, rel: str):
        """All function node ids in a file (fallback: the file node) — for 'this file' mode."""
        rel = rel.replace("\\", "/")
        fns = sorted(n for n, d in graph.nodes(data=True)
                     if d.get("kind") == "function" and d.get("file") == rel)
        if fns:
            return fns
        return sorted(n for n, d in graph.nodes(data=True)
                      if d.get("kind") == "file" and d.get("file") == rel)

    @staticmethod
    def _overlay_findings_from_state(graph, result, findings) -> None:
        """Tag blast-radius nodes that carry a finding — using already-scanned
        state.findings (NO re-scan), unlike cli._overlay_findings."""
        from collections import defaultdict

        from radar.impact.diff_mapper import map_to_nodes

        by_node: dict = defaultdict(list)
        for f in findings:
            for nid in map_to_nodes(graph, {f.path: {f.line}}):
                by_node[nid].append({"severity": f.severity, "rule": f.rule.rsplit(".", 1)[-1]})
        for item in (*result.changed, *result.affected):
            if item.id in by_node:
                item.findings = by_node[item.id]

    def _best_effort_risk_map(self, items: list[Finding]) -> dict:
        from radar.triage.reachability import Reach
        from radar.triage.risk import risk_score

        graph = self.state.graph
        out: dict = {}
        for f in items:
            try:
                if graph is not None:
                    from radar.triage.reachability import reachability
                    reach = reachability(graph, f, self.root)
                else:
                    reach = Reach(None, [], "unknown")
            except Exception:
                reach = Reach(None, [], "unknown")
            out[id(f)] = risk_score(f, reach, None)
        return out

    # ── Heavy path: debounced full rebuild ───────────────────────────────────
    def schedule_heavy(self) -> None:
        """Debounce: coalesce rapid saves, then run compute_full once."""
        with self._lock:
            if self._heavy_timer is not None:
                self._heavy_timer.cancel()
            self._heavy_timer = threading.Timer(_HEAVY_DEBOUNCE, self._run_heavy)
            self._heavy_timer.daemon = True
            self._heavy_timer.start()

    def _run_heavy(self) -> None:
        try:
            self.compute_full()
        except Exception as exc:  # never let the timer thread die silently
            self._push_status(f"refresh failed: {exc}", "warn")

    # ── On-demand AI triage ──────────────────────────────────────────────────
    def run_triage(self) -> None:
        """Button-triggered. Offline-safe: missing key → status warning, no crash."""
        self._push_status("running AI triage…", "busy")
        try:
            from radar.triage import engine
            results, _calls = engine.triage(self.root, rules_only=self.rules_only)
        except Exception as exc:
            self._push_status(f"triage unavailable: {exc}", "warn")
            return

        items = [r.finding for r in results]
        verdict_map = {
            (r.finding.path, r.finding.line, r.finding.rule):
                {"reach": r.reach.status, "routes": r.reach.routes,
                 "verdict": r.verdict, "error": getattr(r, "error", None)}
            for r in results
        }
        from radar.triage.risk import build_risk_map
        with self._lock:
            graph = self.state.graph
        risk_map = build_risk_map(self.root, graph, items, verdict_map)
        with self._lock:
            self.state.findings = items
            self.state.verdict_map = verdict_map
            self.state.risk_map = risk_map
        self._push_findings()
        self._push_overview()
        triaged = any(v.get("verdict") for v in verdict_map.values())
        self._push_status("triage complete" if triaged else "triage: no API key — reachability only",
                          "ok" if triaged else "warn")

    def state_json(self) -> str:
        """Consistent JSON for GET /api/state: snapshot under lock, render outside."""
        with self._lock:
            snap = self.state.snapshot()
        return _render_state_json(snap)

    # ── SSE push helpers ─────────────────────────────────────────────────────
    def _push_all_panels(self) -> None:
        self._push_findings()
        self._push_overview()
        self._push_blast()
        self._push_history()
        self._push_graph()

    def _push_findings(self) -> None:
        # Snapshot the consistent triple under the lock, render outside it so a
        # concurrent recompute can't tear findings ↔ risk_map ↔ verdict_map apart.
        with self._lock:
            findings = list(self.state.findings)
            risk_map = self.state.risk_map
            verdict_map = self.state.verdict_map
        html = report_mod.render_findings_fragment(findings, risk_map or None, verdict_map)
        self.bc.push("findings", json.dumps({"html": html}))

    def _push_overview(self) -> None:
        with self._lock:
            findings = list(self.state.findings)
            suppressed = self.state.suppressed
            history = list(self.state.history)
        html = report_mod.render_overview_fragment(findings, suppressed)
        self.bc.push("overview", json.dumps({
            "html": html,
            "charts": _chart_data(findings, history),
        }))

    def _push_blast(self) -> None:
        with self._lock:
            trace_res = self.state.trace_res
            mermaid_src = self.state.mermaid_src
            trace_label = self.state.trace_label
            repo_path = self.state.repo_path
        html = report_mod.render_blast_fragment(trace_res, mermaid_src, trace_label, repo_path)
        self.bc.push("blast", json.dumps({"html": html}))

    def _push_history(self) -> None:
        with self._lock:
            findings = list(self.state.findings)
            history = list(self.state.history)
        html = report_mod.render_history_fragment(history)
        self.bc.push("history", json.dumps({
            "html": html,
            "charts": _chart_data(findings, history),
        }))

    def _push_graph(self) -> None:
        with self._lock:
            graph = self.state.graph
            repo_path = self.state.repo_path
        if graph is None:
            return
        try:
            from radar.graph.graph_viz import render_graph_fragment
            payload = render_graph_fragment(graph, repo_path=repo_path)
        except Exception:
            return
        self.bc.push("graph", json.dumps(payload))

    def _push_status(self, text: str, level: str = "ok") -> None:
        self.bc.push("status", json.dumps({"text": text, "level": level,
                                           "ts": time.strftime("%H:%M:%S")}))
