"""Render scan Findings: rich terminal table, stable JSON, or HTML report."""

import json
from collections import defaultdict
from datetime import datetime

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


# ── OWASP category mapping ────────────────────────────────────────────────────
_OWASP: dict[str, tuple[str, str]] = {
    "sql":             ("A03", "Injection"),
    "xss":             ("A03", "Injection"),
    "eval":            ("A03", "Injection"),
    "child-process":   ("A03", "Injection"),
    "ssrf":            ("A10", "SSRF"),
    "path-traversal":  ("A01", "Broken Access Control"),
    "deserialization": ("A08", "Insecure Deserialization"),
    "jwt":             ("A02", "Cryptographic Failures"),
    "crypto":          ("A02", "Cryptographic Failures"),
    "hash":            ("A02", "Cryptographic Failures"),
    "flask":           ("A05", "Security Misconfiguration"),
    "debug":           ("A05", "Security Misconfiguration"),
    "secret":          ("A02", "Cryptographic Failures"),
}

_SEV_COLOR = {"ERROR": "#c0392b", "WARNING": "#d68910", "INFO": "#1a5276"}
_SEV_BG    = {"ERROR": "#fdf2f2", "WARNING": "#fefaf0", "INFO": "#eaf4fb"}
_SEV_BADGE = {"ERROR": "#e74c3c", "WARNING": "#f39c12", "INFO": "#3498db"}


def _owasp_tag(rule: str) -> tuple[str, str]:
    r = rule.lower()
    for key, val in _OWASP.items():
        if key in r:
            return val
    return ("A00", "Other")


def _badge(text: str, color: str, bg: str = "white") -> str:
    return (
        '<span style="background:' + bg + ';color:' + color + ';border:1px solid ' + color + ';'
        'border-radius:4px;padding:2px 8px;font-size:12px;font-weight:700">' + text + '</span>'
    )


def _owasp_chip(code: str, label: str) -> str:
    return (
        '<span style="background:#eaf0ff;color:#1a3a8f;border:1px solid #b0c4f0;'
        'border-radius:12px;padding:2px 9px;font-size:11px;font-weight:600">'
        + code + " · " + label + '</span>'
    )


def _card(count: int, label: str, color: str, bg: str) -> str:
    return (
        '<div style="background:' + bg + ';border-left:5px solid ' + color + ';border-radius:6px;'
        'padding:16px 24px;min-width:110px;text-align:center">'
        '<div style="font-size:2rem;font-weight:800;color:' + color + '">' + str(count) + '</div>'
        '<div style="font-size:13px;color:' + color + ';opacity:.8;font-weight:600">' + label + '</div>'
        '</div>'
    )


_CSS = """
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:system-ui,-apple-system,sans-serif;background:#f5f7fa;color:#2c3e50;padding:2rem}
.header{background:linear-gradient(135deg,#1a3a6f 0%,#2471a3 100%);color:white;padding:24px 32px;border-radius:10px;margin-bottom:24px}
.header h1{font-size:1.5rem;margin-bottom:4px}
.header .meta{font-size:13px;opacity:.75}
.cards{display:flex;gap:16px;flex-wrap:wrap;margin-bottom:24px}
.panel{background:white;border-radius:8px;box-shadow:0 1px 4px rgba(0,0,0,.08);overflow:hidden}
.panel-header{padding:14px 20px;border-bottom:1px solid #e8ecf0;display:flex;align-items:center;gap:12px;flex-wrap:wrap}
.panel-title{font-weight:700;font-size:15px;flex:1}
table{width:100%;border-collapse:collapse}
tr:hover{background:#f8fafc}
td,th{border-bottom:1px solid #eef1f5;vertical-align:top}
th{padding:10px 14px;background:#f0f3f7;font-size:12px;text-transform:uppercase;color:#7f8c8d;font-weight:700;text-align:left}
.hidden{display:none}
footer{text-align:center;color:#95a5a6;font-size:12px;margin-top:24px}
"""

_JS = """
function filterSev(sev) {
  document.querySelectorAll('#tbody tr.finding-row').forEach(function(row) {
    row.classList.toggle('hidden', sev !== 'ALL' && row.dataset.sev !== sev);
  });
  document.querySelectorAll('#tbody tr.file-row').forEach(function(fr) {
    var next = fr.nextElementSibling;
    var hasVisible = false;
    while (next && next.classList.contains('finding-row')) {
      if (!next.classList.contains('hidden')) hasVisible = true;
      next = next.nextElementSibling;
    }
    fr.classList.toggle('hidden', !hasVisible);
  });
}
"""


def to_html(findings: list[Finding], repo_path: str = "", suppressed: int = 0) -> str:
    s = summary(findings)
    ts = datetime.now().strftime("%Y-%m-%d %H:%M")

    by_file: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        by_file[f.path].append(f)

    sevs_present = sorted(
        {f.severity for f in findings},
        key=lambda x: {"ERROR": 0, "WARNING": 1, "INFO": 2}.get(x, 3),
    )

    # Build table rows
    rows_html = ""
    for path, file_findings in sorted(by_file.items()):
        rows_html += (
            '<tr class="file-row">'
            '<td colspan="5" style="background:#f0f3f7;padding:8px 14px;font-weight:700;'
            'font-size:13px;color:#34495e;border-top:2px solid #d5dce8">'
            "📄 " + path + ' <span style="color:#7f8c8d;font-weight:400">('
            + str(len(file_findings)) + " finding" + ("s" if len(file_findings) != 1 else "") + ")"
            "</span></td></tr>\n"
        )
        for f in sorted(file_findings, key=lambda x: x.line):
            rule_short = f.rule.rsplit(".", 1)[-1]
            owasp_code, owasp_label = _owasp_tag(rule_short)
            sev = f.severity
            rows_html += (
                '<tr class="finding-row" data-sev="' + sev + '">'
                '<td style="padding:10px 14px;text-align:center">'
                + _badge(sev, _SEV_COLOR[sev], _SEV_BG[sev]) +
                '</td><td style="padding:10px 14px;font-family:monospace;color:#2471a3">'
                '<span style="color:#7f8c8d">line </span>' + str(f.line) +
                '</td><td style="padding:10px 14px;font-family:monospace;font-size:13px;color:#6c3483">'
                + rule_short +
                '</td><td style="padding:10px 14px">'
                + _owasp_chip(owasp_code, owasp_label) +
                '</td><td style="padding:10px 14px;font-size:13px;color:#2c3e50">'
                + f.message[:180] +
                "</td></tr>\n"
            )

    # Cards row
    cards_html = (
        _card(s["error"],   "ERROR",      "#c0392b", "#fdf2f2") +
        _card(s["warning"], "WARNING",    "#d68910", "#fefaf0") +
        _card(s["info"],    "INFO",       "#1a5276", "#eaf4fb") +
        _card(suppressed,   "SUPPRESSED", "#7f8c8d", "#f4f6f7")
    )

    # Filter buttons
    btn_all = (
        '<button onclick="filterSev(\'ALL\')" '
        'style="margin:0 4px;padding:4px 14px;border:2px solid #34495e;'
        'background:#34495e;color:white;border-radius:20px;cursor:pointer;font-weight:600">ALL</button>'
    )
    filter_btns = btn_all + "".join(
        '<button onclick="filterSev(\'' + sev + '\')" '
        'style="margin:0 4px;padding:4px 14px;border:2px solid ' + _SEV_BADGE[sev] + ';'
        'background:white;color:' + _SEV_BADGE[sev] + ';border-radius:20px;cursor:pointer;font-weight:600">'
        + sev + "</button>"
        for sev in sevs_present
    )

    repo_meta = ("<strong>" + repo_path + "</strong> &nbsp;·&nbsp; ") if repo_path else ""
    suppressed_note = (
        '<p style="margin-top:12px;color:#7f8c8d;font-size:13px">'
        "ℹ " + str(suppressed) + " additional finding(s) suppressed via radar-ignore</p>"
        if suppressed else ""
    )
    empty_msg = (
        '<p style="padding:24px;color:#7f8c8d;text-align:center">✓ No findings — codebase looks clean!</p>'
        if not findings else ""
    )
    table_html = (
        "" if not findings else
        "<table><thead><tr>"
        '<th style="width:110px">Severity</th>'
        '<th style="width:80px">Line</th>'
        '<th style="width:220px">Rule</th>'
        '<th style="width:160px">OWASP</th>'
        "<th>Message</th>"
        '</tr></thead><tbody id="tbody">\n' + rows_html + "</tbody></table>"
    )

    return (
        "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n"
        '<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width,initial-scale=1">\n'
        "<title>security-radar — Scan Report</title>\n"
        "<style>" + _CSS + "</style>\n"
        "</head>\n<body>\n\n"
        '<div class="header">\n'
        "  <h1>⚡ security-radar — Scan Report</h1>\n"
        '  <div class="meta">' + repo_meta + "Scanned " + ts +
        " &nbsp;·&nbsp; 17 custom OWASP rules &nbsp;·&nbsp; offline scan</div>\n"
        "</div>\n\n"
        '<div class="cards">' + cards_html + "</div>\n\n"
        '<div class="panel">\n'
        '  <div class="panel-header">\n'
        '    <span class="panel-title">Findings</span>\n'
        "    <div>" + filter_btns + "</div>\n"
        "  </div>\n"
        + empty_msg + table_html +
        "\n</div>\n"
        + suppressed_note +
        "\n<footer>Generated by security-radar v0.2.2</footer>\n\n"
        "<script>" + _JS + "</script>\n"
        "</body></html>"
    )


# Keep old name for backward compat
to_html_report = to_html
