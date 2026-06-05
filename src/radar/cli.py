"""radar CLI — `radar build` indexes a codebase, `radar impact` traces blast radius."""

import sys
from pathlib import Path

import click
from rich.console import Console

from radar import __version__

# Legacy Windows consoles (cp1252) crash on unicode glyphs — degrade gracefully.
if sys.platform == "win32" and hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(errors="replace")

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
@click.option("--format", "output_format", type=click.Choice(["terminal", "json", "mermaid", "html"]),
              default="terminal", help="Output format")
def impact(rev, staged, function_name, path, max_depth, no_name_only, output_format) -> None:
    """Show functions/APIs/features affected by a change."""
    from radar.impact.diff_mapper import changed_lines, find_function_nodes, map_to_nodes
    from radar.impact.tracer import trace
    from radar.report.terminal import render_impact

    root = Path(path).resolve()
    graph = _load_or_build_graph(root)

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


def _load_or_build_graph(root: Path):
    """Load .radar/graph.json; (re)build when missing or stale vs git HEAD."""
    from radar.config import load_config
    from radar.graph.builder import build_graph, git_head, load_graph, save_graph

    graph_path = root / ".radar" / "graph.json"
    if graph_path.is_file():
        graph = load_graph(graph_path)
        if graph.graph.get("head") and graph.graph["head"] == git_head(root):
            return graph
        console.print("[dim]graph stale — rebuilding…[/]")
    else:
        console.print("[dim]no graph found — building…[/]")
    graph = build_graph(root, config=load_config(root))
    save_graph(graph, graph_path)
    return graph


if __name__ == "__main__":
    main()
