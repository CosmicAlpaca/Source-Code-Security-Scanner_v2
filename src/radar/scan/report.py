"""Render scan Findings: rich terminal table or stable JSON."""

import json

from rich.console import Console
from rich.markup import escape
from rich.table import Table

from radar.scan.findings import Finding, summary

MAX_MESSAGE = 200
SEVERITY_STYLE = {"ERROR": "red", "WARNING": "yellow", "INFO": "blue"}
SEVERITY_EMOJI = {"ERROR": "🔴", "WARNING": "🟡", "INFO": "🔵"}


def render_terminal(findings: list[Finding], console: Console | None = None) -> None:
    console = console or Console()
    s = summary(findings)
    if not findings:
        console.print("[green]✓ No security findings.[/]")
        return

    parts = [f"{n} {sev}" for sev, n in (("error", s["error"]), ("warning", s["warning"]), ("info", s["info"])) if n]
    console.print(f"[bold]{s['total']} finding(s)[/] ({', '.join(parts)})")

    table = Table(show_lines=False, expand=False)
    table.add_column("Severity")
    table.add_column("Location", style="cyan", no_wrap=True)
    table.add_column("Rule", style="magenta")
    table.add_column("Message")
    for f in findings:
        style = SEVERITY_STYLE.get(f.severity, "white")
        sev = f"{SEVERITY_EMOJI.get(f.severity, '')} [{style}]{f.severity}[/]"
        rule = escape(f.rule.rsplit(".", 1)[-1])
        message = escape(f.message[:MAX_MESSAGE])
        table.add_row(sev, escape(f"{f.path}:{f.line}"), rule, message)
    console.print(table)


def to_json(findings: list[Finding]) -> str:
    payload = {
        "schema": 1,
        "summary": summary(findings),
        "findings": [
            {"severity": f.severity, "path": f.path, "line": f.line, "rule": f.rule, "message": f.message}
            for f in findings
        ],
    }
    return json.dumps(payload, indent=1, sort_keys=True)
