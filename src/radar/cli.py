"""radar CLI — `radar build` indexes a codebase, `radar impact` traces blast radius."""

import sys
from pathlib import Path

import click
from rich.console import Console

from radar import __version__

for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure") and getattr(_stream, "encoding", "").lower() != "utf-8":
        _stream.reconfigure(encoding="utf-8", errors="replace")

console = Console()
err_console = Console(stderr=True)  # progress/warnings — keeps --format json|mermaid stdout clean


@click.group()
@click.version_option(version=__version__, prog_name="radar")
def main() -> None:
    """security-radar: function-level impact graph for code changes."""


@main.command()
@click.argument("path", type=click.Path(exists=True, file_okay=False), default=".")
@click.option("--out", "out_path", default=None, help="Output graph path (default: <path>/.radar/graph.json)")
def build(path: str, out_path: str | None) -> None:
    """Index PATH and write the call graph to .radar/graph.json."""
    from radar.config import load_config
    from radar.graph.builder import build_graph, graph_summary, save_graph

    root = Path(path).resolve()
    graph = build_graph(root, config=load_config(root))
    out = Path(out_path).resolve() if out_path else root / ".radar" / "graph.json"
    save_graph(graph, out)
    s = graph_summary(graph)
    console.print(
        f"[bold green]✓[/] graph saved to [cyan]{out}[/]\n"
        f"  {s['functions']} functions · {s['routes']} routes · {s['files']} files · "
        f"{s['edges']} edges ({s['approximate_edges']} approximate, "
        f"{s.get('unresolved_calls', 0)} unresolved calls)"
    )


def _overlay_findings(root: Path, graph, result, *, rules_only: bool) -> None:
    """Scan for findings and tag each blast-radius node that carries one (in place)."""
    from collections import defaultdict

    from radar.impact.diff_mapper import map_to_nodes
    from radar.scan import findings as fm
    from radar.scan.runner import ScanError, detect_runtime, run_semgrep
    from radar.scan.suppress import filter_findings

    try:
        raw = run_semgrep(root, rules_only=rules_only, sarif=False, runtime=detect_runtime())
    except ScanError as exc:
        err_console.print(f"[yellow]⚠ findings overlay skipped:[/] {exc}")
        return

    items, _suppressed = filter_findings(fm.parse(raw), root)
    findings_by_node: dict[str, list] = defaultdict(list)
    for f in items:
        for nid in map_to_nodes(graph, {f.path: {f.line}}):
            findings_by_node[nid].append({"severity": f.severity, "rule": f.rule.rsplit(".", 1)[-1]})

    for item in (*result.changed, *result.affected):
        if item.id in findings_by_node:
            item.findings = findings_by_node[item.id]


def _build_risk_map(root: Path, graph, items, verdict_map: dict | None) -> dict:
    """Deprecated alias — risk-map construction now lives in radar.triage.risk."""
    from radar.triage.risk import build_risk_map

    return build_risk_map(root, graph, items, verdict_map)


@main.command()
@click.option("--diff", "rev", default=None, help="Git revision to diff against (default: HEAD~1)")
@click.option("--staged", is_flag=True, help="Use staged changes instead of a revision")
@click.option("--function", "function_name", default=None, help="Trace impact of a single function by name")
@click.option("--path", "path", type=click.Path(exists=True, file_okay=False), default=".", help="Repo root")
@click.option("--depth", "max_depth", type=int, default=None, help="Limit traversal depth")
@click.option("--no-name-only", is_flag=True, help="Skip approximate (name-only) edges")
@click.option("--findings", "do_findings", is_flag=True,
              help="Overlay security findings on the blast radius (runs a Semgrep scan)")
@click.option("--rules-only", is_flag=True, help="With --findings: only bundled custom rules (offline)")
@click.option("--graph", "graph_path", type=click.Path(exists=True, dir_okay=False), default=None,
              help="Use an existing graph.json (skip auto-build)")
@click.option("--format", "output_format", type=click.Choice(["terminal", "json", "mermaid", "html"]),
              default="terminal", help="Output format")
@click.option("--out", "out_file", default=None, help="Write output to file (auto-named when --format html)")
def impact(rev, staged, function_name, path, max_depth, no_name_only, do_findings, rules_only,
           graph_path, output_format, out_file) -> None:
    """Show functions/APIs/features affected by a change.

    Add --findings to mark which affected functions carry security findings
    (answers "does my change touch / ripple into vulnerable code?").
    """
    from radar.impact.diff_mapper import changed_lines, find_function_nodes, map_to_nodes
    from radar.impact.tracer import trace
    from radar.report.terminal import render_impact

    root = Path(path).resolve()
    graph = _load_or_build_graph(root, Path(graph_path).resolve() if graph_path else None)

    if function_name:
        changed_ids = find_function_nodes(graph, function_name)
        if not changed_ids:
            console.print(f"[red]No function named '{function_name}' in the graph.[/]")
            return
    else:
        changes = changed_lines(root, rev=rev, staged=staged)
        changed_ids = map_to_nodes(graph, changes)

    result = trace(graph, changed_ids, max_depth=max_depth, include_name_only=not no_name_only)

    if do_findings:
        _overlay_findings(root, graph, result, rules_only=rules_only)
    if output_format == "terminal":
        render_impact(result, console)
    else:
        from radar.report import exporters

        renderer = {"json": exporters.to_json, "mermaid": exporters.to_mermaid, "html": exporters.to_html}
        content = renderer[output_format](result)
        if output_format == "html":
            dest = Path(out_file).resolve() if out_file else root / "radar-impact.html"
            dest.write_text(content, encoding="utf-8")
            console.print(f"[green]✓[/] impact report → [bold]{dest}[/]")
        else:
            click.echo(content)


@main.command()
@click.argument("path", type=click.Path(exists=True, file_okay=False), default=".")
@click.option("--rules-only", is_flag=True, help="Skip registry presets — only bundled custom rules (offline)")
@click.option("--config", "extra", multiple=True, help="Extra semgrep --config (repeatable)")
@click.option("--format", "output_format", type=click.Choice(["terminal", "json", "sarif", "html"]),
              default="terminal", help="Output format")
@click.option("--out-file", "out_file", default=None, help="Write output to file (used with --format html)")
@click.option("--error", "gate", is_flag=True, help="Exit non-zero when findings reach --fail-on severity")
@click.option("--fail-on", type=click.Choice(["error", "warning", "info"]), default="error",
              help="Severity threshold for --error (default: error)")
def scan(path, rules_only, extra, output_format, out_file, gate, fail_on) -> None:
    """Run a Semgrep security scan on PATH (local, zero footprint on the target)."""
    from radar.scan import findings as findings_mod
    from radar.scan.runner import ScanError, detect_runtime, run_semgrep

    root = Path(path).resolve()
    try:
        runtime = detect_runtime()
        if output_format in ("terminal", "html"):
            console.print(f"[dim]scanning {root} via semgrep ({runtime})…[/]", highlight=False)
        report = run_semgrep(
            root, rules_only=rules_only, sarif=(output_format == "sarif"), extra_config=list(extra),
            runtime=runtime,
        )
    except ScanError as exc:
        console.print(f"[red]scan failed:[/] {exc}")
        sys.exit(2)

    if output_format == "sarif":
        import json as _json
        click.echo(_json.dumps(report, indent=1))
        return

    items = findings_mod.parse(report)

    # Apply suppression (inline radar-ignore comments + .radar-ignore file)
    from radar.scan.suppress import filter_findings
    items, suppressed = filter_findings(items, root)
    if suppressed and output_format == "terminal":
        console.print(f"[dim]{len(suppressed)} finding(s) suppressed (radar-ignore)[/]")

    if output_format == "json":
        from radar.scan.report import to_json
        click.echo(to_json(items))
    elif output_format == "html":
        from radar.scan.report import to_html
        html = to_html(items, repo_path=str(root), suppressed=len(suppressed))
        dest = out_file or str(root / "radar-report.html")
        with open(dest, "w", encoding="utf-8") as fh:
            fh.write(html)
        console.print(f"[bold green]✓[/] HTML report → [cyan]{dest}[/]")
    else:
        from radar.scan.report import render_terminal
        render_terminal(items, console)

    # Save to scan history
    from radar.scan.history import record
    smry = findings_mod.summary(items)
    record(
        path=str(root),
        rules_only=rules_only,
        error=smry["error"],
        warning=smry["warning"],
        info=smry["info"],
        suppressed=len(suppressed),
    )

    if gate and findings_mod.exceeds_threshold(items, fail_on):
        sys.exit(1)


@main.command()
@click.argument("path", type=click.Path(exists=True, file_okay=False), default=".")
@click.option("--floor", type=click.Choice(["error", "warning", "info"]), default="warning",
              help="Only triage findings at/above this severity (default: warning)")
@click.option("--all", "only_all", is_flag=True, help="Triage every finding (ignore --floor)")
@click.option("--dry-run", is_flag=True, help="Print exactly what would be sent; make no API calls")
@click.option("--force", is_flag=True, help="Ignore cached verdicts and re-query the model")
@click.option("--rules-only", is_flag=True, help="Skip registry presets — only bundled custom rules")
@click.option("--config", "extra", multiple=True, help="Extra semgrep --config (repeatable)")
@click.option("--top", type=click.IntRange(min=0), default=0, help="Show only the N highest-risk findings (0 = all)")
@click.option("--fail-on", "fail_on", type=click.Choice(["exploitable", "likely"]), default=None,
              help="Exit non-zero if any finding's AI verdict is at/above this (needs a key)")
@click.option("--min-risk", "min_risk", type=click.IntRange(min=0, max=100), default=0,
              help="Exit non-zero if any finding's risk score is ≥ N (works without a key)")
@click.option("--format", "output_format", type=click.Choice(["terminal", "json"]),
              default="terminal", help="Output format")
def triage(path, floor, only_all, dry_run, force, rules_only, extra, top, fail_on, min_risk, output_format) -> None:
    """AI-triage Semgrep findings, ranked by risk (severity × reachability × class).

    Opt-in: sends a redacted code snippet per finding to OpenAI. Never alters
    `radar scan` output — this is an additive verdict layer. Needs OPENAI_API_KEY
    (env or a repo-root .env). Use --dry-run to preview exactly what would be sent.

    Gate CI on the ranking: `--min-risk N` works offline; `--fail-on exploitable`
    needs a key (it reads the AI verdict).
    """
    from radar.scan.findings import SEVERITY_ORDER
    from radar.scan.runner import ScanError
    from radar.triage import engine, llm_client, render
    from radar.triage.llm_client import TriageError
    from radar.triage.risk import risk_score

    root = Path(path).resolve()

    # Offline ranking (reachability + risk) needs no key; only --fail-on reads the
    # AI verdict (enforced fail-closed in _triage_gate). Everything else runs offline.
    llm_client.load_dotenv(root)
    has_key = llm_client.resolve_key() is not None

    try:
        results, calls = engine.triage(
            root, rules_only=rules_only, extra_config=list(extra), floor=floor,
            only_all=only_all, force=force, dry_run=dry_run, allow_offline=True,
            emit=(lambda m: console.print(m, highlight=False)) if dry_run else None,
        )
    except ScanError as exc:
        console.print(f"[red]scan failed:[/] {exc}")
        sys.exit(2)
    except TriageError as exc:
        console.print(f"[red]triage unavailable:[/] {exc}")
        sys.exit(2)

    if dry_run:
        console.print(f"[dim]dry-run: {len(results)} finding(s) prepared, 0 API calls.[/]")
        return

    if not has_key:
        console.print("[dim]No API key — offline ranking only (risk score, no AI verdicts).[/]")

    # Rank by risk desc (tie: severity, path, line) — the output axis.
    risk_map = {id(tf): risk_score(tf.finding, tf.reach, tf.verdict) for tf in results}
    results.sort(key=lambda tf: (
        -risk_map[id(tf)].value, SEVERITY_ORDER.get(tf.finding.severity, 3),
        tf.finding.path, tf.finding.line,
    ))
    hidden = 0
    if top and top > 0:
        hidden = max(0, len(results) - top)
        results = results[:top]

    if output_format == "json":
        click.echo(render.to_json_triage(results, risk_map))
    else:
        render.render_terminal_triage(results, console, risk_map)
        if hidden:
            console.print(f"[dim]… {hidden} lower-risk finding(s) hidden (--top {top}).[/]")
        console.print(f"[dim]{calls} API call(s) this run; the rest served from cache.[/]")

    _triage_gate(results, risk_map, fail_on, min_risk)


def _triage_gate(results, risk_map, fail_on, min_risk) -> None:
    """Exit non-zero when ranking crosses a threshold; print the trigger first."""
    _FAIL_RANK = {"exploitable": 0, "likely": 1}
    if fail_on:
        # Fail closed: --fail-on reads the AI verdict, so any finding lacking one
        # (no API key, or the model errored) means we can't prove it safe — a CI
        # gate must not pass silently.
        missing = [tf for tf in results if not (tf.verdict or {}).get("exploitability")]
        if missing:
            console.print(
                f"[red]✗ --fail-on {fail_on}:[/] {len(missing)} finding(s) have no AI verdict "
                "(no API key or model unavailable) — cannot prove safe, failing closed."
            )
            sys.exit(2)
        limit = _FAIL_RANK[fail_on]
        for tf in results:
            verd = (tf.verdict or {}).get("exploitability", "")
            if verd in _FAIL_RANK and _FAIL_RANK[verd] <= limit:
                console.print(
                    f"[red]✗ --fail-on {fail_on}:[/] {tf.finding.path}:{tf.finding.line} "
                    f"[{tf.finding.rule.rsplit('.', 1)[-1]}] → {verd}"
                )
                sys.exit(1)
    if min_risk and min_risk > 0:
        for tf in results:
            score = risk_map[id(tf)]
            if score.value >= min_risk:
                console.print(
                    f"[red]✗ --min-risk {min_risk}:[/] {tf.finding.path}:{tf.finding.line} "
                    f"[{tf.finding.rule.rsplit('.', 1)[-1]}] → risk {score.value} ({score.band})"
                )
                sys.exit(1)


@main.command()
@click.option("--path", "path", default=None, help="Filter by repo path (substring match)")
@click.option("--limit", default=20, help="Number of entries to show (default: 20)")
@click.option("--format", "output_format", type=click.Choice(["terminal", "html"]),
              default="terminal", help="Output format")
def history(path, limit, output_format) -> None:
    """Show scan history and trend for a repository."""
    from radar.scan.history import load, render_history_html

    entries = load(path_filter=path, limit=limit)
    if not entries:
        console.print("[yellow]No scan history found.[/] Run [cyan]radar scan[/] first.")
        return

    if output_format == "html":
        click.echo(render_history_html(entries, repo_path=path or ""))
        return

    from rich.table import Table
    table = Table(title=f"Scan history ({len(entries)} entries)", show_lines=True)
    table.add_column("Time", style="dim")
    table.add_column("ERROR", style="red bold")
    table.add_column("WARN", style="yellow bold")
    table.add_column("Total", style="bold")
    table.add_column("Suppressed", style="dim")
    table.add_column("Repo", style="cyan", no_wrap=False, max_width=40)

    for e in reversed(entries):
        table.add_row(
            e["ts"], str(e["error"]), str(e["warning"]),
            str(e["total"]), str(e.get("suppressed", 0)),
            e["path"].replace(str(Path.home()), "~"),
        )
    console.print(table)

    if len(entries) >= 2:
        delta = entries[-1]["total"] - entries[-2]["total"]
        arrow = "↑" if delta > 0 else ("↓" if delta < 0 else "→")
        color = "red" if delta > 0 else ("green" if delta < 0 else "dim")
        console.print(f"Trend vs previous scan: [{color}]{arrow} {abs(delta):+d} findings[/]")


def _load_or_build_graph(root: Path, graph_override: Path | None = None):
    """Resolve a graph without writing into the target repo."""
    from radar.cache import graph_cache_path
    from radar.config import load_config
    from radar.graph.builder import GRAPH_VERSION, build_graph, git_head, load_graph, save_graph

    if graph_override is not None:
        return load_graph(graph_override)

    head = git_head(root)

    def _fresh(path: Path):
        if not path.is_file():
            return None
        graph = load_graph(path)
        # Fresh requires BOTH the repo HEAD and the builder version to match — a
        # cache built by an older radar (different graph shape) is stale even if
        # the target repo is unchanged.
        if (
            graph.graph.get("head")
            and graph.graph["head"] == head
            and graph.graph.get("version") == GRAPH_VERSION
        ):
            return graph
        return None

    in_repo = _fresh(root / ".radar" / "graph.json")
    if in_repo is not None:
        return in_repo

    cache_path = graph_cache_path(root)
    cached = _fresh(cache_path)
    if cached is not None:
        return cached

    err_console.print("[dim]building graph (cached outside the repo)…[/]")
    graph = build_graph(root, config=load_config(root))
    save_graph(graph, cache_path)
    return graph


@main.command()
@click.argument("path", type=click.Path(exists=True, file_okay=False), default=".")
@click.option("--ext", "extra_exts", multiple=True,
              help="Extra file extensions to watch (e.g. --ext .rb --ext .php)")
def watch(path, extra_exts) -> None:
    """Live security linter — scan files on save, show NEW/FIXED findings instantly."""
    import shutil
    from radar.scan.runner import RULES_DIR
    from radar.scan.watcher import WATCHED_EXTENSIONS, run_watch

    root = Path(path).resolve()
    use_docker = not shutil.which("semgrep") and shutil.which("docker")

    exts = WATCHED_EXTENSIONS | {e if e.startswith(".") else f".{e}" for e in extra_exts}
    run_watch(root, rules_dir=RULES_DIR, use_docker=use_docker, extensions=exts)


@main.command()
@click.argument("path", type=click.Path(exists=True, file_okay=False), default=".")
@click.option("--port", type=int, default=None, help="Port to bind (default: auto-pick a free one)")
@click.option("--open", "open_browser", is_flag=True, help="Open the dashboard in your browser")
@click.option("--rules-only", is_flag=True, help="Offline scan — only bundled custom rules")
@click.option("--ext", "extra_exts", multiple=True,
              help="Extra file extensions to watch (e.g. --ext .rb --ext .php)")
def serve(path, port, open_browser, rules_only, extra_exts) -> None:
    """Live localhost dashboard — auto-updates as you edit.

    Findings instant, graph/impact debounced, AI triage on-demand.
    """
    import shutil

    from radar.scan.watcher import WATCHED_EXTENSIONS
    from radar.serve import serve as serve_dashboard

    root = Path(path).resolve()
    use_docker = not shutil.which("semgrep") and shutil.which("docker")
    exts = WATCHED_EXTENSIONS | {e if e.startswith(".") else f".{e}" for e in extra_exts}

    serve_dashboard(
        root, port=port, open_browser=open_browser, extensions=exts,
        rules_only=rules_only, use_docker=use_docker,
    )


@main.command()
@click.argument("path", type=click.Path(exists=True, file_okay=False), default=".")
@click.option("--rules-only", is_flag=True, help="Offline scan — only bundled custom rules")
@click.option("--function", "function_name", default=None,
              help="Function to trace blast radius for (default: auto-pick top ERROR finding)")
@click.option("--diff", default=None, help="Trace blast radius from git diff (e.g. origin/main...HEAD)")
@click.option("--triage", "do_triage", is_flag=True,
              help="Add AI-triage columns (reachability + verdict). Needs OPENAI_API_KEY; opt-in.")
@click.option("--floor", type=click.Choice(["error", "warning", "info"]), default="warning",
              help="With --triage: only triage findings at/above this severity (default: warning)")
@click.option("--force", is_flag=True, help="With --triage: ignore cached verdicts and re-query the model")
@click.option("--out", "out_file", default=None,
              help="Output HTML path (default: <path>/radar-dashboard.html)")
def report(path, rules_only, function_name, diff, do_triage, floor, force, out_file) -> None:
    """Generate a unified HTML dashboard: findings + impact graph + history trend.

    Add --triage to enrich each finding with reachability + an AI verdict column
    (opt-in: needs OPENAI_API_KEY). Without it the dashboard is fully offline.
    """
    from radar.scan import findings as findings_mod
    from radar.scan.history import load as load_history
    from radar.scan.report import render_dashboard
    from radar.scan.runner import ScanError, detect_runtime, run_semgrep
    from radar.scan.suppress import filter_findings

    root = Path(path).resolve()
    dest = Path(out_file).resolve() if out_file else root / "radar-dashboard.html"

    items: list = []
    suppressed: list = []
    verdict_map: dict | None = None

    # ── 1. Scan (+ optional AI triage) ───────────────────────────────────────
    if do_triage:
        from radar.triage import engine
        from radar.triage.llm_client import TriageError
        console.print("[dim]① scanning + AI triage…[/]")
        try:
            results, calls = engine.triage(
                root, rules_only=rules_only, floor=floor, force=force,
            )
            items = [r.finding for r in results]
            verdict_map = {
                (r.finding.path, r.finding.line, r.finding.rule):
                    {"reach": r.reach.status, "routes": r.reach.routes,
                     "verdict": r.verdict, "error": getattr(r, "error", None)}
                for r in results
            }
            console.print(f"[dim]   {calls} API call(s) this run; rest served from cache.[/]")
        except (ScanError, TriageError) as exc:
            console.print(f"[yellow]⚠ triage unavailable:[/] {exc}")
            console.print("[dim]   rendering offline dashboard instead.[/]")
            do_triage = False
            verdict_map = None

    if not do_triage:
        console.print("[dim]① scanning…[/]")
        try:
            runtime = detect_runtime()
            raw = run_semgrep(root, rules_only=rules_only, sarif=False, extra_config=[], runtime=runtime)
        except ScanError as exc:
            console.print(f"[red]scan failed:[/] {exc}")
            raise SystemExit(2)
        items = findings_mod.parse(raw)
        
        from radar.scan.gitleaks_runner import run_gitleaks
        items.extend(run_gitleaks(root))
        
        from radar.scan.findings import SEVERITY_ORDER
        items.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 3), f.path, f.line))
        
        items, suppressed = filter_findings(items, root)

    smry = findings_mod.summary(items)

    from radar.scan.history import record
    record(path=str(root), rules_only=rules_only,
           error=smry["error"], warning=smry["warning"], info=smry["info"],
           suppressed=len(suppressed))

    # ── 2. Impact graph (blast radius) ───────────────────────────────────────
    mermaid_src = ""
    trace_label = None
    graph = None
    trace_res = None
    console.print("[dim]② building call graph…[/]")
    try:
        from radar.config import load_config
        from radar.graph.builder import build_graph
        from radar.impact.diff_mapper import find_function_nodes, map_to_nodes
        from radar.impact.tracer import trace
        from radar.report.exporters import to_mermaid

        graph = build_graph(root, config=load_config(root))
        if function_name:
            node_ids = find_function_nodes(graph, function_name)
            trace_label = "function: " + function_name
        elif diff:
            from radar.impact.diff_mapper import changed_lines
            changes = changed_lines(root, rev=diff)
            node_ids = map_to_nodes(graph, changes) if changes else []
            if node_ids:
                trace_label = "diff: " + diff
            else:
                trace_label = "diff: " + diff + " (no changed functions found)"
        else:
            # Auto: blast radius of the functions that CONTAIN the findings
            # (severity-first, capped) — by location, not by rule name.
            sev_rank = {"ERROR": 0, "WARNING": 1, "INFO": 2}
            ranked = sorted(items, key=lambda f: sev_rank.get(f.severity, 3))
            changes: dict = {}
            for f in ranked[:15]:
                changes.setdefault(f.path, set()).add(f.line)
            node_ids = map_to_nodes(graph, changes) if changes else []
            if node_ids:
                trace_label = str(len(node_ids)) + " finding site(s)"
        if node_ids:
            trace_res = trace(graph, node_ids)
            mermaid_src = to_mermaid(trace_res)
    except Exception as exc:
        console.print(f"[dim yellow]⚠ impact graph skipped: {exc}[/]")

    # ── 3. Risk ranking (the output axis; works with or without AI) ───────────
    risk_map = _build_risk_map(root, graph, items, verdict_map)

    # ── 4. History trend ─────────────────────────────────────────────────────
    history = load_history(path_filter=str(root), limit=20)

    # ── 5. Render single-file HTML ───────────────────────────────────────────
    html = render_dashboard(
        repo_path=str(root), findings=items, suppressed=len(suppressed),
        mermaid_src=mermaid_src, traced_fn=trace_label, history=history,
        verdict_map=verdict_map, risk_map=risk_map, trace_res=trace_res,
    )
    dest.write_text(html, encoding="utf-8")

    console.print(f"[bold green]✓[/] Dashboard → [cyan]{dest}[/]")
    console.print(
        f"   {smry['error']} error · {smry['warning']} warning · {len(suppressed)} suppressed"
        + (" · AI-triaged" if verdict_map is not None else "")
        + (f" · impact graph: {trace_label}" if mermaid_src else " · impact graph: skipped")
    )


@main.command("graph")
@click.argument("path", type=click.Path(exists=True, file_okay=False), default=".")
@click.option("--graph", "graph_path", type=click.Path(exists=True, dir_okay=False), default=None,
              help="Use existing graph.json (skip auto-build)")
@click.option("--out", "out_file", default=None,
              help="Output HTML path (default: <path>/radar-graph.html)")
@click.option("--level", type=click.Choice(["file", "function"]), default="file",
              help="Aggregation level: 'file' (default, scales to big repos) or 'function'")
@click.option("--focus", type=click.Choice(["none", "security"]), default="none",
              help="'security' keeps only the subgraph reachable from route entrypoints")
@click.option("--max-nodes", "max_nodes", type=int, default=1500,
              help="Cap rendered nodes (keeps highest-degree; 0 = no cap). Default 1500")
def graph_cmd(path, graph_path, out_file, level, focus, max_nodes) -> None:
    """Render the dependency/call graph as an interactive HTML page.

    Defaults to a file-level view so large repos stay responsive. Use
    --level function for the full call graph, --focus security to see only the
    route-reachable attack surface.
    """
    from radar.graph.graph_transform import aggregate_by_file, cap_nodes, focus_security
    from radar.graph.graph_viz import to_dependency_html

    root = Path(path).resolve()
    dest = Path(out_file).resolve() if out_file else root / "radar-graph.html"

    g = _load_or_build_graph(root, Path(graph_path).resolve() if graph_path else None)

    # Render-only transforms — applied to a copy, never persisted. Order matters:
    # focus first (on the full function graph), then aggregate, then cap.
    if focus == "security":
        g, had_routes = focus_security(g)
        if not had_routes:
            console.print("[yellow]⚠ no route nodes found — showing full graph[/]")
    if level == "file":
        g = aggregate_by_file(g)
    g, dropped = cap_nodes(g, max_nodes)
    if dropped:
        console.print(
            f"[yellow]⚠ capped to {max_nodes} nodes ({dropped} dropped, lowest-degree first)[/]"
        )

    console.print("[dim]rendering dependency graph…[/]")
    html = to_dependency_html(g, repo_path=str(root))
    dest.write_text(html, encoding="utf-8")

    n = g.number_of_nodes()
    e = g.number_of_edges()
    console.print(
        f"[bold green]✓[/] Graph → [cyan]{dest}[/]\n"
        f"   {n} nodes · {e} edges · level={level} focus={focus}"
        " — open in browser, zoom/pan/click to explore"
    )


@main.command("analyze")
@click.argument("url", type=str)
@click.option("--branch", default=None, help="Branch to analyze")
@click.option("--function", "function_name", default=None, help="Function name for impact trace")
@click.option("--out", "out_file", default=None, help="Output HTML path")
@click.pass_context
def analyze(ctx, url: str, branch: str | None, function_name: str | None, out_file: str | None) -> None:
    """End-to-end: Clone a GitHub repo, run scan, AI triage, and generate dashboard."""
    import re
    import subprocess
    import os

    _URL_RE = re.compile(r"^https://(www\.)?github\.com/[\w.-]+/[\w.-]+(\.git)?$")
    if not _URL_RE.match(url):
        console.print(f"[red]Invalid GitHub URL:[/] {url}")
        sys.exit(1)

    repo_name = url.rstrip("/").rsplit("/", 1)[-1]
    if repo_name.endswith(".git"):
        repo_name = repo_name[:-4]

    repo_dir = Path("analysis_repos") / repo_name
    repo_dir.parent.mkdir(parents=True, exist_ok=True)

    console.print(f"\n[bold blue]1.[/] Synchronizing repository [cyan]{url}[/]...")
    if repo_dir.exists():
        console.print(f"   [dim]Updating existing clone at {repo_dir}...[/]")
        subprocess.run(["git", "fetch", "--all"], cwd=repo_dir, check=False)
        if branch:
            subprocess.run(["git", "checkout", branch], cwd=repo_dir, check=False)
        else:
            subprocess.run(["git", "pull"], cwd=repo_dir, check=False)
    else:
        console.print(f"   [dim]Cloning to {repo_dir}...[/]")
        subprocess.run(["git", "clone", url, str(repo_dir)], check=True)
        if branch:
            subprocess.run(["git", "checkout", branch], cwd=repo_dir, check=False)

    diff_target = None
    if not function_name and branch:
        default_branch = "master"
        try:
            res = subprocess.run(
                ["git", "symbolic-ref", "refs/remotes/origin/HEAD"],
                cwd=repo_dir, capture_output=True, text=True, check=True
            )
            default_branch = res.stdout.strip().rsplit("/", 1)[-1]
        except Exception:
            pass

        try:
            subprocess.run(["git", "fetch", "origin", default_branch], cwd=repo_dir, check=True, capture_output=True)
            diff_target = f"origin/{default_branch}...HEAD"
        except subprocess.CalledProcessError:
            diff_target = "HEAD~1"

    dest_html = out_file or str(Path("analysis_results") / f"{repo_name}_unified_dashboard.html")
    Path(dest_html).parent.mkdir(parents=True, exist_ok=True)

    do_triage = bool(os.environ.get("OPENAI_API_KEY"))

    console.print("\n[bold blue]2.[/] Running full security pipeline (Scan + Gitleaks + Graph + Dashboard)...")
    # Call report command directly within the same process
    ctx.invoke(
        report,
        path=str(repo_dir),
        rules_only=False,
        function_name=function_name,
        diff=diff_target,
        do_triage=do_triage,
        floor="warning",
        force=False,
        out_file=dest_html
    )

if __name__ == "__main__":
    main()
