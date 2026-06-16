"""Rich terminal rendering of an ImpactResult (tree per changed node)."""

from rich.console import Console
from rich.markup import escape
from rich.tree import Tree

from radar.graph.model import NAME_ONLY
from radar.impact.tracer import ImpactItem, ImpactResult


_SEV_EMOJI = {"ERROR": "🔴", "WARNING": "🟡", "INFO": "🔵"}


def _finding_tag(item: ImpactItem) -> str:
    """'🔴 (2 findings: php-sql-injection, …)' — empty when no overlay."""
    if not item.findings:
        return ""
    order = {"ERROR": 0, "WARNING": 1, "INFO": 2}
    top = min((f["severity"] for f in item.findings), key=lambda s: order.get(s, 3))
    rules = ", ".join(sorted({f["rule"] for f in item.findings}))
    n = len(item.findings)
    return f' {_SEV_EMOJI.get(top, "")} [red]({n} finding{"s" if n != 1 else ""}: {escape(rules)})[/]'


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
    return "  ".join(parts) + _finding_tag(item)


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

    flagged = [it for it in (*result.changed, *result.affected) if it.findings]
    if flagged:
        total = sum(len(it.findings) for it in flagged)
        errors = sum(1 for it in flagged for f in it.findings if f["severity"] == "ERROR")
        err_note = f", {errors} error" if errors else ""
        console.print(
            f"[red]⚠ Blast radius touches {total} finding(s){err_note} across {len(flagged)} function(s).[/]"
        )


def _attach_children(tree: Tree, origin_id: str, items: list[ImpactItem]) -> None:
    """Nest items under their BFS discovery parent (depth order guarantees parents exist)."""
    branches: dict[str, Tree] = {origin_id: tree}
    for item in sorted(items, key=lambda i: (i.depth, i.id)):
        parent = branches.get(item.parent, tree)
        branches[item.id] = parent.add(_label(item))
