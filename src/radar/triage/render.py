"""Additive rendering of triage results: deterministic findings + an AI verdict column.

Never mutates the scan's own output — `to_json_triage` keeps every deterministic
field and only ADDS `reachability` + `ai`, so existing consumers stay compatible.
"""

import json

from rich.console import Console
from rich.markup import escape
from rich.table import Table

from radar.scan.findings import summary
from radar.scan.report import SEVERITY_EMOJI

EXPLOIT_STYLE = {
    "exploitable": "bold red",
    "likely": "yellow",
    "unlikely": "dim",
    "false_positive": "dim strike",
}
MAX_REASON = 120


def _verdict_cell(tf) -> str:
    if tf.error:
        return "[dim]error[/]"
    if not tf.verdict:
        return "[dim]—[/]"
    exploit = tf.verdict.get("exploitability", "unlikely")
    style = EXPLOIT_STYLE.get(exploit, "white")
    conf = tf.verdict.get("confidence", 0.0)
    cached = " [dim]⟳[/]" if tf.cached else ""
    return f"[{style}]{exploit}[/] [dim]{conf:.2f}[/]{cached}"


def _reach_cell(reach) -> str:
    if reach.status == "reachable":
        suffix = f" [dim]←{len(reach.routes)}[/]" if reach.routes else ""
        return f"[green]reachable[/]{suffix}"
    return "[dim]unknown[/]"


def render_terminal_triage(results, console: Console | None = None) -> None:
    console = console or Console()
    if not results:
        console.print("[green]✓ No findings to triage.[/]")
        return

    table = Table(show_lines=False, expand=False)
    table.add_column("Sev")
    table.add_column("Location", style="cyan", no_wrap=True)
    table.add_column("Rule", style="magenta")
    table.add_column("Reach")
    table.add_column("AI verdict")
    table.add_column("Why")
    for tf in results:
        f = tf.finding
        if tf.verdict:
            why = escape(tf.verdict.get("reasoning", "")[:MAX_REASON])
        elif tf.error:
            why = f"[dim]{escape(tf.error[:MAX_REASON])}[/]"
        else:
            why = ""
        table.add_row(
            SEVERITY_EMOJI.get(f.severity, ""),
            escape(f"{f.path}:{f.line}"),
            escape(f.rule.rsplit(".", 1)[-1]),
            _reach_cell(tf.reach),
            _verdict_cell(tf),
            why,
        )
    console.print(table)


def to_json_triage(results) -> str:
    findings = []
    for tf in results:
        f = tf.finding
        obj = {
            "severity": f.severity,
            "path": f.path,
            "line": f.line,
            "rule": f.rule,
            "message": f.message,
            "reachability": {"status": tf.reach.status, "routes": tf.reach.routes},
        }
        if tf.verdict:
            obj["ai"] = {**tf.verdict, "cached": tf.cached}
        elif tf.error:
            obj["ai"] = {"error": tf.error}
        findings.append(obj)
    payload = {
        "schema": 1,
        "summary": summary([tf.finding for tf in results]),
        "findings": findings,
    }
    return json.dumps(payload, indent=1, sort_keys=True)
