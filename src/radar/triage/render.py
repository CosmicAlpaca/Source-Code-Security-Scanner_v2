"""Additive rendering of triage results: deterministic findings + an AI verdict column.

Never mutates the scan's own output — `to_json_triage` keeps every deterministic
field and only ADDS `reachability` + `ai`, so existing consumers stay compatible.
"""

import json

from rich.console import Console
from rich.markup import escape
from rich.table import Table

from radar.scan.findings import summary
from radar.scan.report import SEVERITY_EMOJI, finding_engine

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


BAND_STYLE = {
    "critical": "bold red",
    "high": "yellow",
    "medium": "cyan",
    "low": "dim",
    "noise": "dim strike",
}


def _risk_cell(score) -> str:
    if score is None:
        return ""
    style = BAND_STYLE.get(score.band, "white")
    return f"[{style}]{score.value}[/] [dim]{score.band}[/]"


def render_terminal_triage(results, console: Console | None = None, risk_map: dict | None = None) -> None:
    console = console or Console()
    if not results:
        console.print("[green]✓ No findings to triage.[/]")
        return

    table = Table(show_lines=False, expand=False)
    table.add_column("Risk")
    table.add_column("Sev")
    table.add_column("Tool")
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
        score = risk_map.get(id(tf)) if risk_map else None
        table.add_row(
            _risk_cell(score),
            SEVERITY_EMOJI.get(f.severity, ""),
            escape(finding_engine(f)),
            escape(f"{f.path}:{f.line}"),
            escape(f.rule.rsplit(".", 1)[-1]),
            _reach_cell(tf.reach),
            _verdict_cell(tf),
            why,
        )
    console.print(table)


def to_json_triage(results, risk_map: dict | None = None) -> str:
    findings = []
    for tf in results:
        f = tf.finding
        obj = {
            "severity": f.severity,
            "engine": finding_engine(f).lower(),
            "path": f.path,
            "line": f.line,
            "rule": f.rule,
            "message": f.message,
            "reachability": {"status": tf.reach.status, "routes": tf.reach.routes},
        }
        score = risk_map.get(id(tf)) if risk_map else None
        if score is not None:
            obj["risk"] = {"value": score.value, "band": score.band, "factors": score.factors}
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
