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


@main.command()
@click.option("--diff", "rev", default=None, help="Git revision to diff against (default: HEAD~1)")
@click.option("--staged", is_flag=True, help="Use staged changes instead of a revision")
@click.option("--function", "function_name", default=None, help="Trace impact of a single function by name")
@click.option("--path", "path", type=click.Path(exists=True, file_okay=False), default=".", help="Repo root")
@click.option("--depth", "max_depth", type=int, default=None, help="Limit traversal depth")
@click.option("--no-name-only", is_flag=True, help="Skip approximate (name-only) edges")
@click.option("--graph", "graph_path", type=click.Path(exists=True, dir_okay=False), default=None,
              help="Use an existing graph.json (skip auto-build)")
@click.option("--format", "output_format", type=click.Choice(["terminal", "json", "mermaid", "html"]),
              default="terminal", help="Output format")
@click.option("--out", "out_file", default=None, help="Write output to file (auto-named when --format html)")
def impact(rev, staged, function_name, path, max_depth, no_name_only, graph_path, output_format, out_file) -> None:
    """Show functions/APIs/features affected by a change."""
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
@click.option("--format", "output_format", type=click.Choice(["terminal", "json"]),
              default="terminal", help="Output format")
def triage(path, floor, only_all, dry_run, force, rules_only, extra, output_format) -> None:
    """AI-triage Semgrep findings with impact-graph reachability.

    Opt-in: sends a redacted code snippet per finding to OpenAI. Never alters
    `radar scan` output — this is an additive verdict layer. Needs OPENAI_API_KEY
    (env or a repo-root .env). Use --dry-run to preview exactly what would be sent.
    """
    from radar.scan.runner import ScanError
    from radar.triage import engine, render
    from radar.triage.llm_client import TriageError

    root = Path(path).resolve()
    try:
        results, calls = engine.triage(
            root, rules_only=rules_only, extra_config=list(extra), floor=floor,
            only_all=only_all, force=force, dry_run=dry_run,
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
    if output_format == "json":
        click.echo(render.to_json_triage(results))
    else:
        render.render_terminal_triage(results, console)
        console.print(f"[dim]{calls} API call(s) this run; the rest served from cache.[/]")


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

    console.print("[dim]building graph (cached outside the repo)…[/]")
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
@click.option("--rules-only", is_flag=True, help="Offline scan — only bundled custom rules")
@click.option("--function", "function_name", default=None,
              help="Function to trace blast radius for (default: auto-pick top ERROR finding)")
@click.option("--out", "out_file", default=None,
              help="Output HTML path (default: <path>/radar-dashboard.html)")
def report(path, rules_only, function_name, out_file) -> None:
    """Generate a unified HTML dashboard: findings + impact graph + history trend."""
    import json as _json

    from radar.scan import findings as findings_mod
    from radar.scan.history import load as load_history
    from radar.scan.runner import ScanError, detect_runtime, run_semgrep
    from radar.scan.suppress import filter_findings

    root = Path(path).resolve()
    dest = Path(out_file).resolve() if out_file else root / "radar-dashboard.html"

    # ── 1. Scan ──────────────────────────────────────────────────────────────
    console.print("[dim]① scanning…[/]")
    try:
        runtime = detect_runtime()
        raw = run_semgrep(root, rules_only=rules_only, sarif=False, extra_config=[], runtime=runtime)
    except ScanError as exc:
        console.print(f"[red]scan failed:[/] {exc}")
        raise SystemExit(2)

    items = findings_mod.parse(raw)
    items, suppressed = filter_findings(items, root)
    smry = findings_mod.summary(items)

    from radar.scan.history import record
    record(path=str(root), rules_only=rules_only,
           error=smry["error"], warning=smry["warning"], info=smry["info"],
           suppressed=len(suppressed))

    # ── 2. Impact graph ──────────────────────────────────────────────────────
    mermaid_src = ""
    impact_stats: dict = {}
    console.print("[dim]② building call graph…[/]")
    try:
        from radar.config import load_config
        from radar.graph.builder import build_graph
        from radar.impact.diff_mapper import find_function_nodes
        from radar.impact.tracer import trace
        from radar.report.exporters import to_mermaid

        graph = build_graph(root, config=load_config(root))

        # Pick function to trace: explicit arg > first ERROR finding > first any finding
        fn = function_name
        if not fn and items:
            errors = [f for f in items if f.severity == "ERROR"]
            candidate = errors[0] if errors else items[0]
            # Use rule name as function hint (rough heuristic)
            fn = candidate.rule.rsplit(".", 1)[-1]

        if fn:
            node_ids = find_function_nodes(graph, fn)
            if node_ids:
                result = trace(graph, node_ids)
                mermaid_src = to_mermaid(result)
                impact_stats = result.stats.__dict__ if hasattr(result.stats, "__dict__") else {}
    except Exception as exc:
        console.print(f"[dim yellow]⚠ impact graph skipped: {exc}[/]")

    # ── 3. History trend ─────────────────────────────────────────────────────
    history = load_history(path_filter=str(root), limit=20)

    # ── 4. Render HTML ───────────────────────────────────────────────────────
    from radar.scan.report import _OWASP, _SEV_BG, _SEV_COLOR, _badge, _owasp_chip, _owasp_tag
    from collections import defaultdict

    by_file: dict = defaultdict(list)
    for f in items:
        by_file[f.path].append(f)

    rows_html = ""
    for fpath, ffindings in sorted(by_file.items()):
        rows_html += (
            '<tr class="file-row"><td colspan="5" style="background:#f0f3f7;padding:8px 14px;'
            'font-weight:700;font-size:13px;color:#34495e;border-top:2px solid #d5dce8">'
            "📄 " + fpath + " (" + str(len(ffindings)) + ")</td></tr>\n"
        )
        for f in sorted(ffindings, key=lambda x: x.line):
            rule_short = f.rule.rsplit(".", 1)[-1]
            oc, ol = _owasp_tag(rule_short)
            sev = f.severity
            rows_html += (
                '<tr class="finding-row" data-sev="' + sev + '">'
                '<td style="padding:8px 12px;text-align:center">' + _badge(sev, _SEV_COLOR[sev], _SEV_BG[sev]) + '</td>'
                '<td style="padding:8px 12px;font-family:monospace;color:#2471a3">' + str(f.line) + '</td>'
                '<td style="padding:8px 12px;font-family:monospace;font-size:12px;color:#6c3483">' + rule_short + '</td>'
                '<td style="padding:8px 12px">' + _owasp_chip(oc, ol) + '</td>'
                '<td style="padding:8px 12px;font-size:13px">' + f.message[:160] + '</td>'
                '</tr>\n'
            )

    # history chart data
    h_labels = _json.dumps([e["ts"] for e in history])
    h_errors  = _json.dumps([e["error"] for e in history])
    h_warns   = _json.dumps([e["warning"] for e in history])

    mermaid_section = ""
    if mermaid_src:
        mermaid_section = (
            '<div class="panel" style="margin-top:20px">'
            '<div class="panel-header">🔗 Blast Radius — Call Graph'
            + (' <span style="font-size:12px;color:#7f8c8d;font-weight:400">function: ' + fn + '</span>' if fn else '')
            + '</div>'
            '<div style="padding:1.5rem;overflow-x:auto;background:#fafafa">'
            '<pre class="mermaid">\n' + mermaid_src + '\n</pre>'
            '</div></div>'
        )

    history_section = ""
    if history:
        history_section = (
            '<div class="panel" style="margin-top:20px">'
            '<div class="panel-header">📈 Scan History Trend</div>'
            '<div style="padding:1.5rem"><canvas id="hChart" height="70"></canvas></div>'
            '</div>'
        )

    html = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>security-radar — Dashboard</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4/dist/chart.umd.min.js"></script>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:system-ui,-apple-system,sans-serif;background:#f5f7fa;color:#2c3e50;padding:2rem}
.header{background:linear-gradient(135deg,#0d2137 0%,#1a5276 100%);color:white;padding:24px 32px;border-radius:10px;margin-bottom:24px}
.header h1{font-size:1.6rem;margin-bottom:4px}
.header .meta{font-size:13px;opacity:.7}
.cards{display:flex;gap:16px;flex-wrap:wrap;margin-bottom:24px}
.panel{background:white;border-radius:8px;box-shadow:0 1px 4px rgba(0,0,0,.08);overflow:hidden}
.panel-header{padding:14px 20px;border-bottom:1px solid #e8ecf0;font-weight:700;font-size:15px}
table{width:100%;border-collapse:collapse}
th,td{border-bottom:1px solid #eef1f5;padding:9px 12px;text-align:left;font-size:13px}
th{background:#f0f3f7;font-size:11px;text-transform:uppercase;color:#7f8c8d;font-weight:700}
tr:hover{background:#f8fafc}
.hidden{display:none}
footer{text-align:center;color:#95a5a6;font-size:12px;margin-top:28px}
</style>
</head>
<body>

<div class="header">
  <h1>⚡ security-radar — Dashboard</h1>
  <div class="meta">""" + str(root) + """ &nbsp;·&nbsp; offline scan &nbsp;·&nbsp; 17 OWASP rules</div>
</div>

<div class="cards">
  <div style="background:#fdf2f2;border-left:5px solid #c0392b;border-radius:6px;padding:16px 24px;text-align:center">
    <div style="font-size:2rem;font-weight:800;color:#c0392b">""" + str(smry['error']) + """</div>
    <div style="font-size:12px;color:#c0392b;font-weight:600">ERROR</div>
  </div>
  <div style="background:#fefaf0;border-left:5px solid #d68910;border-radius:6px;padding:16px 24px;text-align:center">
    <div style="font-size:2rem;font-weight:800;color:#d68910">""" + str(smry['warning']) + """</div>
    <div style="font-size:12px;color:#d68910;font-weight:600">WARNING</div>
  </div>
  <div style="background:#f4f6f7;border-left:5px solid #7f8c8d;border-radius:6px;padding:16px 24px;text-align:center">
    <div style="font-size:2rem;font-weight:800;color:#7f8c8d">""" + str(len(suppressed)) + """</div>
    <div style="font-size:12px;color:#7f8c8d;font-weight:600">SUPPRESSED</div>
  </div>
</div>

<div class="panel">
  <div class="panel-header">
    🛡 Findings
    <span style="margin-left:12px">
      <button onclick="fs('ALL')" style="padding:3px 12px;border:2px solid #34495e;background:#34495e;color:white;border-radius:20px;cursor:pointer;font-size:12px;font-weight:600">ALL</button>
      <button onclick="fs('ERROR')" style="padding:3px 12px;border:2px solid #e74c3c;background:white;color:#e74c3c;border-radius:20px;cursor:pointer;font-size:12px;font-weight:600">ERROR</button>
      <button onclick="fs('WARNING')" style="padding:3px 12px;border:2px solid #f39c12;background:white;color:#f39c12;border-radius:20px;cursor:pointer;font-size:12px;font-weight:600">WARNING</button>
    </span>
  </div>
  <table><thead><tr><th style="width:100px">Severity</th><th style="width:70px">Line</th><th style="width:200px">Rule</th><th style="width:150px">OWASP</th><th>Message</th></tr></thead>
  <tbody id="tbody">""" + rows_html + """</tbody></table>
</div>
""" + mermaid_section + history_section + """

<footer>Generated by security-radar v0.2.2</footer>

<script>
function fs(sev){
  document.querySelectorAll('#tbody tr.finding-row').forEach(r=>{r.classList.toggle('hidden',sev!=='ALL'&&r.dataset.sev!==sev)});
  document.querySelectorAll('#tbody tr.file-row').forEach(fr=>{
    var n=fr.nextElementSibling,ok=false;
    while(n&&n.classList.contains('finding-row')){if(!n.classList.contains('hidden'))ok=true;n=n.nextElementSibling;}
    fr.classList.toggle('hidden',!ok);
  });
}
</script>
""" + ("""
<script>
new Chart(document.getElementById('hChart'),{
  type:'line',
  data:{
    labels:""" + h_labels + """,
    datasets:[
      {label:'ERROR',data:""" + h_errors + """,borderColor:'#c0392b',backgroundColor:'rgba(192,57,43,0.08)',tension:0.3,fill:true},
      {label:'WARNING',data:""" + h_warns + """,borderColor:'#d68910',backgroundColor:'rgba(214,137,16,0.08)',tension:0.3,fill:true}
    ]
  },
  options:{responsive:true,plugins:{legend:{position:'top'}},scales:{y:{beginAtZero:true,ticks:{stepSize:1}}}}
});
</script>
""" if history else "") + ("""
<script type="module">
  import mermaid from "https://cdn.jsdelivr.net/npm/mermaid@11/dist/mermaid.esm.min.mjs";
  mermaid.initialize({startOnLoad:true,theme:'default'});
</script>
""" if mermaid_src else "") + """
</body></html>"""

    dest.write_text(html, encoding="utf-8")
    console.print(f"[bold green]✓[/] Dashboard → [cyan]{dest}[/]")
    console.print(
        f"   {smry['error']} error · {smry['warning']} warning · "
        f"{len(suppressed)} suppressed"
        + (f" · impact graph: {fn}" if mermaid_src else " · impact graph: skipped (run radar build first)")
    )


@main.command("graph")
@click.argument("path", type=click.Path(exists=True, file_okay=False), default=".")
@click.option("--graph", "graph_path", type=click.Path(exists=True, dir_okay=False), default=None,
              help="Use existing graph.json (skip auto-build)")
@click.option("--out", "out_file", default=None,
              help="Output HTML path (default: <path>/radar-graph.html)")
def graph_cmd(path, graph_path, out_file) -> None:
    """Render the full dependency/call graph as an interactive HTML page."""
    from radar.graph.graph_viz import to_dependency_html

    root = Path(path).resolve()
    dest = Path(out_file).resolve() if out_file else root / "radar-graph.html"

    g = _load_or_build_graph(root, Path(graph_path).resolve() if graph_path else None)

    console.print("[dim]rendering dependency graph…[/]")
    html = to_dependency_html(g, repo_path=str(root))
    dest.write_text(html, encoding="utf-8")

    n = g.number_of_nodes()
    e = g.number_of_edges()
    console.print(
        f"[bold green]✓[/] Graph → [cyan]{dest}[/]\n"
        f"   {n} nodes · {e} edges — open in browser, zoom/pan/click to explore"
    )


if __name__ == "__main__":
    main()
