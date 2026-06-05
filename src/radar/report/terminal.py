"""Rich terminal rendering of an ImpactResult (tree per changed node)."""

from rich.console import Console
from rich.markup import escape
from rich.tree import Tree

from radar.graph.model import NAME_ONLY
from radar.impact.tracer import ImpactItem, ImpactResult


def _label(item: ImpactItem) -> str:
    name = escape(item.name)
    location = escape(f"{item.file}:{item.line}")
    parts = [f"[bold]{name}[/]" if item.kind != "route" else f"[magenta]{name}[/]", f"[dim]{location}[/]"]
    if item.routes:
        parts.append("← " + ", ".join(f"[magenta]{escape(r)}[/]" for r in item.routes))
    if item.depth:
        approx = ", [yellow]⚠ approx[/]" if item.confidence == NAME_ONLY else ""
        parts.append(f"[dim]\\[depth {item.depth}{approx}][/]")
    if item.feature:
        parts.append(f"[green]feature: {escape(item.feature)}[/]")
    return "  ".join(parts)


def render_impact(result: ImpactResult, console: Console | None = None) -> None:
    console = console or Console()
    if not result.changed:
        console.print("[yellow]No changed functions found in the graph.[/]")
        return

    by_origin: dict[str, list[ImpactItem]] = {}
    for item in result.affected:
        by_origin.setdefault(item.via_changed, []).append(item)

    for changed in result.changed:
        tree = Tree(f"[red]Changed:[/] {_label(changed)}")
        _attach_children(tree, changed.id, by_origin.get(changed.id, []))
        console.print(tree)

    s = result.stats
    approx = f" ({s['approximate']} approximate)" if s["approximate"] else ""
    console.print(
        f"[bold]Summary:[/] {s['functions_affected']} functions, "
        f"{s['apis_affected']} APIs, {s['features_affected']} features affected{approx}"
    )


def _attach_children(tree: Tree, origin_id: str, items: list[ImpactItem]) -> None:
    """Nest items under their BFS discovery parent (depth order guarantees parents exist)."""
    branches: dict[str, Tree] = {origin_id: tree}
    for item in sorted(items, key=lambda i: (i.depth, i.id)):
        parent = branches.get(item.parent, tree)
        branches[item.id] = parent.add(_label(item))
