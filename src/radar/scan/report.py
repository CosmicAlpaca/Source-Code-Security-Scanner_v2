"""Render scan Findings: rich terminal table, stable JSON, or HTML report."""

import html
import json
from collections import defaultdict
from datetime import datetime


def _esc(s) -> str:
    """HTML-escape any dynamic value (text + attribute contexts)."""
    return html.escape(str(s), quote=True)

from rich.console import Console
from rich.markup import escape
from rich.table import Table

from radar.scan.findings import Finding, owasp_tag, summary

_owasp_tag = owasp_tag  # shared classifier (defined in findings.py for reuse by risk scoring)

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


_SEV_COLOR = {"ERROR": "#c0392b", "WARNING": "#d68910", "INFO": "#1a5276"}
_SEV_BG    = {"ERROR": "#fdf2f2", "WARNING": "#fefaf0", "INFO": "#eaf4fb"}
_SEV_BADGE = {"ERROR": "#e74c3c", "WARNING": "#f39c12", "INFO": "#3498db"}


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


# ── Unified dashboard (scan + impact + history + optional AI triage) ───────────

# Matches the exploitability vocabulary in triage/llm_client.py
_EXPLOIT_COLOR = {
    "exploitable": "#c0392b",   # red — most severe
    "likely": "#d68910",        # orange
    "unlikely": "#7f8c8d",      # gray
    "false_positive": "#95a5a6",
}


def _reach_cell(entry: dict) -> str:
    """Reachability badge. reachability.py only emits 'reachable' or 'unknown'."""
    routes = entry.get("routes") or []
    if entry.get("reach") == "reachable":
        suffix = (" via " + str(len(routes)) + " route" + ("s" if len(routes) != 1 else "")) if routes else ""
        return _badge("reachable" + suffix, "#1e8449", "#eafaf1")
    return _badge("unknown", "#b9770e", "#fef9e7")


def _verdict_cell(entry: dict) -> str:
    """AI verdict badge (exploitability + confidence) with reasoning tooltip."""
    if entry.get("error"):
        return _badge("error", "#7f8c8d", "#f4f6f7")
    v = entry.get("verdict")
    if not v:
        return '<span style="color:#b0b8c0">—</span>'
    exploit = str(v.get("exploitability", "unlikely")).lower()
    conf = v.get("confidence", 0.0)
    try:
        conf_pct = str(round(float(conf) * 100)) + "%"
    except (TypeError, ValueError):
        conf_pct = "—"
    color = _EXPLOIT_COLOR.get(exploit, "#7f8c8d")
    reason_txt = str(v.get("reasoning", ""))
    path_txt = str(v.get("exploit_path", ""))
    tip = (reason_txt + (" — path: " + path_txt if path_txt else ""))[:400]
    reasoning = _esc(tip)
    return (
        '<span title="' + reasoning + '">'
        + _badge(_esc(exploit), color, "white")
        + ' <span style="color:#7f8c8d;font-size:11px">' + conf_pct + "</span></span>"
    )


# ── Risk ranking (the output axis) ─────────────────────────────────────────────
_BAND_COLOR = {
    "critical": "#c0392b",
    "high": "#d68910",
    "medium": "#b7950b",
    "low": "#7f8c8d",
    "noise": "#95a5a6",
}
_SEV_RANK = {"ERROR": 0, "WARNING": 1, "INFO": 2}


def _risk_cell(score) -> str:
    """Risk badge `value band` with the contributing factors as a tooltip."""
    color = _BAND_COLOR.get(score.band, "#7f8c8d")
    title = _esc(" · ".join(score.factors))
    return '<span title="' + title + '">' + _badge(str(score.value) + " " + score.band, color, "white") + "</span>"


def _ranked_row(f: Finding, score, verdict_map: dict | None) -> str:
    sev = f.severity
    rule_short = f.rule.rsplit(".", 1)[-1]
    oc, ol = _owasp_tag(rule_short)
    cells = (
        '<td style="padding:8px 12px;text-align:center">' + _risk_cell(score) + "</td>"
        '<td style="padding:8px 12px;text-align:center">' + _badge(_esc(sev), _SEV_COLOR.get(sev, "#7f8c8d"), _SEV_BG.get(sev, "white")) + "</td>"
        '<td style="padding:8px 12px;font-family:monospace;font-size:12px;color:#2471a3">' + _esc(f.path) + ":" + str(f.line) + "</td>"
        '<td style="padding:8px 12px;font-family:monospace;font-size:12px;color:#6c3483">' + _esc(rule_short) + "</td>"
        '<td style="padding:8px 12px">' + _owasp_chip(oc, ol) + "</td>"
        '<td style="padding:8px 12px;font-size:13px">' + _esc(f.message[:160]) + "</td>"
    )
    if verdict_map is not None:
        entry = verdict_map.get((f.path, f.line, f.rule), {})
        cells += (
            '<td style="padding:8px 12px">' + _reach_cell(entry) + "</td>"
            '<td style="padding:8px 12px">' + _verdict_cell(entry) + "</td>"
        )
    return '<tr class="finding-row" data-sev="' + sev + '">' + cells + "</tr>\n"


def _ranked_table(rows_html: str, verdict_map: dict | None) -> str:
    extra = "<th>Reachability</th><th>AI verdict</th>" if verdict_map is not None else ""
    return (
        "<table><thead><tr>"
        '<th style="width:110px">Risk</th><th style="width:90px">Severity</th>'
        '<th style="width:200px">Location</th><th style="width:170px">Rule</th>'
        '<th style="width:140px">OWASP</th><th>Message</th>' + extra
        + '</tr></thead><tbody id="tbody">' + rows_html + "</tbody></table>"
    )


def _ranked_findings_html(findings: list[Finding], risk_map: dict, verdict_map: dict | None) -> str:
    """Findings ranked by risk desc; band=noise folded into a collapsible section.

    risk_map is keyed by object identity (id(finding)) so duplicate findings at the
    same (path,line,rule) keep distinct scores.
    """
    ordered = sorted(
        findings,
        key=lambda f: (-risk_map[id(f)].value, _SEV_RANK.get(f.severity, 3), f.path, f.line),
    )
    main_rows = noise_rows = ""
    noise_n = 0
    for f in ordered:
        score = risk_map[id(f)]
        if score.band == "noise":
            noise_rows += _ranked_row(f, score, verdict_map)
            noise_n += 1
        else:
            main_rows += _ranked_row(f, score, verdict_map)

    html_out = _ranked_table(main_rows, verdict_map) if main_rows else (
        '<p style="padding:20px;color:#7f8c8d">No higher-risk findings — see folded low-risk below.</p>'
        if noise_n else '<p style="padding:24px;color:#7f8c8d;text-align:center">✓ No findings — codebase looks clean!</p>'
    )
    if noise_n:
        html_out += (
            '<details style="margin-top:6px"><summary style="cursor:pointer;padding:10px 16px;'
            'color:#7f8c8d;font-weight:600">▸ ' + str(noise_n)
            + " low-risk / false-positive finding(s) (click to expand)</summary>"
            + _ranked_table(noise_rows, verdict_map) + "</details>"
        )
    return html_out


def _dashboard_rows(findings: list[Finding], verdict_map: dict | None) -> str:
    """Findings table rows; +2 cells per row (reachability, AI verdict) when triaged."""
    triage = verdict_map is not None
    span = 7 if triage else 5
    by_file: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        by_file[f.path].append(f)

    rows = ""
    for fpath, ff in sorted(by_file.items()):
        rows += (
            '<tr class="file-row"><td colspan="' + str(span) + '" style="background:#f0f3f7;'
            'padding:8px 14px;font-weight:700;font-size:13px;color:#34495e;border-top:2px solid #d5dce8">'
            "📄 " + _esc(fpath) + " (" + str(len(ff)) + ")</td></tr>\n"
        )
        for f in sorted(ff, key=lambda x: x.line):
            rule_short = f.rule.rsplit(".", 1)[-1]
            oc, ol = _owasp_tag(rule_short)
            sev = f.severity
            cells = (
                '<td style="padding:8px 12px;text-align:center">' + _badge(_esc(sev), _SEV_COLOR.get(sev, "#7f8c8d"), _SEV_BG.get(sev, "white")) + "</td>"
                '<td style="padding:8px 12px;font-family:monospace;color:#2471a3">' + str(f.line) + "</td>"
                '<td style="padding:8px 12px;font-family:monospace;font-size:12px;color:#6c3483">' + _esc(rule_short) + "</td>"
                '<td style="padding:8px 12px">' + _owasp_chip(oc, ol) + "</td>"
                '<td style="padding:8px 12px;font-size:13px">' + _esc(f.message[:160]) + "</td>"
            )
            if triage:
                entry = verdict_map.get((f.path, f.line, f.rule), {})
                cells += (
                    '<td style="padding:8px 12px">' + _reach_cell(entry) + "</td>"
                    '<td style="padding:8px 12px">' + _verdict_cell(entry) + "</td>"
                )
            rows += '<tr class="finding-row" data-sev="' + sev + '">' + cells + "</tr>\n"
    return rows


def render_dashboard(
    repo_path: str,
    findings: list[Finding],
    suppressed: int,
    mermaid_src: str = "",
    traced_fn: str | None = None,
    history: list | None = None,
    verdict_map: dict | None = None,
    risk_map: dict | None = None,
) -> str:
    """One-file HTML dashboard: cards + risk-ranked findings (+optional AI triage cols) + blast radius + history."""
    history = history or []
    s = summary(findings)
    triage = verdict_map is not None

    cards = (
        _card(s["error"], "ERROR", "#c0392b", "#fdf2f2")
        + _card(s["warning"], "WARNING", "#d68910", "#fefaf0")
        + _card(s["info"], "INFO", "#1a5276", "#eaf4fb")
        + _card(suppressed, "SUPPRESSED", "#7f8c8d", "#f4f6f7")
    )

    if risk_map is not None:
        # Risk-ranked layout: findings sorted by risk desc, noise folded.
        table = _ranked_findings_html(findings, risk_map, verdict_map)
    else:
        extra_head = "<th>Reachability</th><th>AI verdict</th>" if triage else ""
        table = (
            "<table><thead><tr>"
            '<th style="width:90px">Severity</th><th style="width:60px">Line</th>'
            '<th style="width:180px">Rule</th><th style="width:140px">OWASP</th><th>Message</th>'
            + extra_head
            + '</tr></thead><tbody id="tbody">' + _dashboard_rows(findings, verdict_map) + "</tbody></table>"
        )

    mermaid_section = ""
    if mermaid_src:
        fn_note = (' <span style="font-size:12px;color:#7f8c8d;font-weight:400">' + _esc(traced_fn) + "</span>") if traced_fn else ""
        mermaid_section = (
            '<div class="panel" style="margin-top:20px"><div class="panel-header">'
            '<span class="panel-title">🔗 Blast Radius — Call Graph' + fn_note + "</span></div>"
            '<div style="padding:1.5rem;overflow-x:auto;background:#fafafa">'
            '<pre class="mermaid">\n' + mermaid_src + "\n</pre></div></div>"
        )

    history_section = ""
    chart_script = ""
    if history:
        history_section = (
            '<div class="panel" style="margin-top:20px"><div class="panel-header">'
            '<span class="panel-title">📈 Scan History Trend</span></div>'
            '<div style="padding:1.5rem"><canvas id="hChart" height="70"></canvas></div></div>'
        )
        chart_script = (
            '<script src="https://cdn.jsdelivr.net/npm/chart.js@4/dist/chart.umd.min.js"></script>'
            "<script>new Chart(document.getElementById('hChart'),{type:'line',data:{labels:"
            + json.dumps([e["ts"] for e in history])
            + ",datasets:[{label:'ERROR',data:" + json.dumps([e["error"] for e in history])
            + ",borderColor:'#c0392b',backgroundColor:'rgba(192,57,43,0.08)',tension:0.3,fill:true},"
            + "{label:'WARNING',data:" + json.dumps([e["warning"] for e in history])
            + ",borderColor:'#d68910',backgroundColor:'rgba(214,137,16,0.08)',tension:0.3,fill:true}]},"
            + "options:{responsive:true,plugins:{legend:{position:'top'}},scales:{y:{beginAtZero:true,ticks:{stepSize:1}}}}});</script>"
        )

    mermaid_script = (
        '<script type="module">import mermaid from "https://cdn.jsdelivr.net/npm/mermaid@11/dist/mermaid.esm.min.mjs";'
        "mermaid.initialize({startOnLoad:true,theme:'default'});</script>"
        if mermaid_src else ""
    )

    mode = "AI-triaged" if triage else "offline scan"
    ts = datetime.now().strftime("%Y-%m-%d %H:%M")
    return (
        '<!DOCTYPE html>\n<html lang="en">\n<head>\n<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width,initial-scale=1">\n'
        "<title>security-radar — Dashboard</title>\n<style>" + _CSS + "</style>\n</head>\n<body>\n"
        '<div class="header"><h1>⚡ security-radar — Dashboard</h1>'
        '<div class="meta">' + _esc(repo_path) + " &nbsp;·&nbsp; " + mode + " &nbsp;·&nbsp; " + ts + "</div></div>\n"
        '<div class="cards">' + cards + "</div>\n"
        '<div class="panel"><div class="panel-header"><span class="panel-title">🛡 Findings</span>'
        "<div>"
        "<button onclick=\"filterSev('ALL')\" style=\"margin:0 4px;padding:4px 12px;border:2px solid #34495e;background:#34495e;color:white;border-radius:20px;cursor:pointer;font-weight:600\">ALL</button>"
        "<button onclick=\"filterSev('ERROR')\" style=\"margin:0 4px;padding:4px 12px;border:2px solid #e74c3c;background:white;color:#e74c3c;border-radius:20px;cursor:pointer;font-weight:600\">ERROR</button>"
        "<button onclick=\"filterSev('WARNING')\" style=\"margin:0 4px;padding:4px 12px;border:2px solid #f39c12;background:white;color:#f39c12;border-radius:20px;cursor:pointer;font-weight:600\">WARNING</button>"
        "</div></div>" + table + "</div>\n"
        + mermaid_section + history_section
        + "\n<footer>Generated by security-radar</footer>\n"
        "<script>" + _JS + "</script>\n" + chart_script + mermaid_script
        + "\n</body></html>"
    )
