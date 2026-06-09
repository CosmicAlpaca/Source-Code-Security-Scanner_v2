"""radar CLI — `radar build` indexes a codebase, `radar impact` traces blast radius."""

import sys
from pathlib import Path

import click
from rich.console import Console

from radar import __version__

# On Windows (and any system whose locale isn't UTF-8) the default codec for
# stdout/stderr can be cp932, cp1252, cp936, etc. — all too narrow for the
# Unicode glyphs rich uses. Upgrade to UTF-8 with lossy fallback so the CLI
# never crashes regardless of the machine's locale setting.
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
def impact(rev, staged, function_name, path, max_depth, no_name_only, graph_path, output_format) -> None:
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
        click.echo(renderer[output_format](result))


@main.command()
@click.argument("path", type=click.Path(exists=True, file_okay=False), default=".")
@click.option("--rules-only", is_flag=True, help="Skip registry presets — only bundled custom rules (offline)")
@click.option("--config", "extra", multiple=True, help="Extra semgrep --config (repeatable)")
@click.option("--format", "output_format", type=click.Choice(["terminal", "json", "sarif"]),
              default="terminal", help="Output format")
@click.option("--error", "gate", is_flag=True, help="Exit non-zero when findings reach --fail-on severity")
@click.option("--fail-on", type=click.Choice(["error", "warning", "info"]), default="error",
              help="Severity threshold for --error (default: error)")
def scan(path, rules_only, extra, output_format, gate, fail_on) -> None:
    """Run a Semgrep security scan on PATH (local, zero footprint on the target)."""
    from radar.scan import findings as findings_mod
    from radar.scan.runner import ScanError, detect_runtime, run_semgrep

    root = Path(path).resolve()
    try:
        runtime = detect_runtime()
        if output_format == "terminal":  # json/sarif stay pure for machines
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
    if output_format == "json":
        from radar.scan.report import to_json

        click.echo(to_json(items))
    else:
        from radar.scan.report import render_terminal

        render_terminal(items, console)

    if gate and findings_mod.exceeds_threshold(items, fail_on):
        sys.exit(1)


def _load_or_build_graph(root: Path, graph_override: Path | None = None):
    """Resolve a graph without writing into the target repo.

    Order: explicit --graph → in-repo .radar/graph.json (if fresh, for `radar build`
    users) → external cache (if fresh) → build into external cache. The auto-build
    never touches the target repo, so `radar impact --path <other>` is zero-footprint.
    """
    from radar.cache import graph_cache_path
    from radar.config import load_config
    from radar.graph.builder import build_graph, git_head, load_graph, save_graph

    if graph_override is not None:
        return load_graph(graph_override)

    head = git_head(root)

    def _fresh(path: Path):
        if not path.is_file():
            return None
        graph = load_graph(path)
        if graph.graph.get("head") and graph.graph["head"] == head:
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


if __name__ == "__main__":
    main()
