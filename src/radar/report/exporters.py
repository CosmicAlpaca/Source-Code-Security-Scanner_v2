"""ImpactResult exporters: stable JSON, Mermaid flowchart, static HTML.

The JSON schema is consumed by scripts/render-pr-comment.py in CI — keep it
backwards compatible.
"""

import json
import re
from dataclasses import asdict
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from radar.graph.model import NAME_ONLY
from radar.impact.tracer import ImpactResult

MERMAID_MAX_NODES = 50
_TEMPLATES_DIR = Path(__file__).parent / "templates"


def to_json(result: ImpactResult) -> str:
    payload = {
        "schema": 1,
        "changed": [asdict(i) for i in result.changed],
        "affected": [asdict(i) for i in result.affected],
        "apis": result.apis,
        "features": result.features,
        "stats": result.stats,
    }
    return json.dumps(payload, indent=1, sort_keys=True)


_MERMAID_SAFE = re.compile(r"[^\w \-./:@'?‹›]")


def _mermaid_escape(label: str) -> str:
    """Whitelist-sanitize untrusted names so they cannot break Mermaid syntax."""
    return _MERMAID_SAFE.sub("", label.replace("<", "‹").replace(">", "›"))


def to_mermaid(result: ImpactResult) -> str:
    """flowchart TD — changed nodes red, routes green, approximate edges dashed."""
    items = [*result.changed, *result.affected][:MERMAID_MAX_NODES]
    ids = {item.id: f"n{i}" for i, item in enumerate(items)}
    lines = ["flowchart TD"]
    for item in items:
        shape = ("([", "])") if item.kind == "route" else ("[", "]")
        lines.append(f'    {ids[item.id]}{shape[0]}"{_mermaid_escape(item.name)}"{shape[1]}')
    for item in result.affected:
        if item.id not in ids or item.parent not in ids:
            continue
        arrow = "-.->" if item.confidence == NAME_ONLY else "-->"
        lines.append(f"    {ids[item.parent]} {arrow} {ids[item.id]}")  # impact propagates outward
    for changed in result.changed:
        if changed.id in ids:
            lines.append(f"    style {ids[changed.id]} fill:#f88,stroke:#c00")
    for item in items:
        if item.kind == "route" and item.id in ids and item not in result.changed:
            lines.append(f"    style {ids[item.id]} fill:#8f8,stroke:#080")
    hidden = len(result.changed) + len(result.affected) - len(items)
    if hidden > 0:
        lines.append(f'    more["…{hidden} nodes hidden"]')
    return "\n".join(lines)


def to_html(result: ImpactResult) -> str:
    env = Environment(
        loader=FileSystemLoader(_TEMPLATES_DIR),
        autoescape=select_autoescape(["html", "j2"]),
    )
    template = env.get_template("impact.html.j2")
    return template.render(result=result, mermaid=to_mermaid(result), name_only=NAME_ONLY)
