"""Full-state computation for `radar serve` — the same scan→graph→risk→history
pipeline the `report` CLI command runs, factored out so the live server reuses it
verbatim (DRY) instead of duplicating ~80 lines of orchestration.

Returns a plain dict the Orchestrator copies into its in-memory State.
"""

from __future__ import annotations

from pathlib import Path


def compute_full_state(root: Path, *, rules_only: bool = False) -> dict:
    """Run the whole offline pipeline once and return a state dict.

    Keys: findings (list[Finding]), suppressed (int), risk_map (id->RiskScore),
    graph (nx.DiGraph|None), trace_res, mermaid_src (str), trace_label (str|None),
    history (list). AI triage is NOT run here (on-demand only via the orchestrator).
    """
    from radar.scan import findings as findings_mod
    from radar.scan.findings import SEVERITY_ORDER
    from radar.scan.gitleaks_runner import run_gitleaks
    from radar.scan.history import load as load_history
    from radar.scan.history import record
    from radar.scan.runner import ScanError, detect_runtime, run_semgrep
    from radar.scan.suppress import filter_findings

    # ── 1. Scan (offline; AI triage is on-demand, not here) ──────────────────
    try:
        runtime = detect_runtime()
        raw = run_semgrep(root, rules_only=rules_only, sarif=False, extra_config=[], runtime=runtime)
        items = findings_mod.parse(raw)
        items.extend(run_gitleaks(root))
        items.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 3), f.path, f.line))
        items, suppressed = filter_findings(items, root)
    except ScanError:
        items, suppressed = [], []

    smry = findings_mod.summary(items)
    try:
        record(path=str(root), rules_only=rules_only,
               error=smry["error"], warning=smry["warning"], info=smry["info"],
               suppressed=len(suppressed))
    except Exception:
        pass

    # ── 2. Dependency graph ──────────────────────────────────────────────────
    # Build the graph only; the blast-radius trace is computed mode-aware in the
    # orchestrator (changes / file / findings) so it can follow your edits.
    graph = None
    try:
        from radar.config import load_config
        from radar.graph.builder import build_graph

        graph = build_graph(root, config=load_config(root))
    except Exception:
        graph = None
    mermaid_src = ""
    trace_label = None
    trace_res = None

    # ── 3. Risk ranking (works without AI) ───────────────────────────────────
    from radar.triage.risk import build_risk_map

    risk_map = build_risk_map(root, graph, items, None)

    # ── 4. History trend ─────────────────────────────────────────────────────
    history = load_history(path_filter=str(root), limit=20)

    # ── 5. Normalize finding paths to repo-relative forward-slash ─────────────
    # Semgrep emits absolute, OS-native paths; the fast-path on_change uses
    # repo-relative forward-slash. Canonicalize here (in place, preserving object
    # identity so the id()-keyed risk_map stays valid) so the orchestrator's
    # per-file replacement matches and edits clear/update correctly. Done AFTER
    # graph/impact/risk so their original-path mapping is untouched.
    import os as _os
    root_abs = root.resolve()
    for f in items:
        try:
            p = Path(f.path)
            f.path = (str(p.relative_to(root_abs)) if p.is_absolute()
                      else f.path).replace(_os.sep, "/")
        except (ValueError, OSError):
            f.path = f.path.replace(_os.sep, "/")

    return {
        "findings": items,
        "suppressed": len(suppressed),
        "risk_map": risk_map,
        "graph": graph,
        "trace_res": trace_res,
        "mermaid_src": mermaid_src,
        "trace_label": trace_label,
        "history": history,
    }
