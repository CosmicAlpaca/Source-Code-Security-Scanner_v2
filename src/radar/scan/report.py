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
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&display=swap');
*{box-sizing:border-box;margin:0;padding:0}
:root{--bg:#0a0f1e;--surface:rgba(17,25,45,.85);--border:rgba(255,255,255,.07);--text:#e2e8f0;--muted:#64748b;--blue:#3b82f6;--red:#ef4444;--orange:#f97316;--green:#22c55e;--purple:#a78bfa}
body{font-family:'Inter',system-ui,sans-serif;background:var(--bg);color:var(--text);min-height:100vh;line-height:1.5}
/* ── Header ─── */
.header{background:linear-gradient(135deg,#0d1b3e 0%,#1a3a8f 45%,#6d28d9 100%);padding:28px 40px;position:relative;overflow:hidden}
.header::after{content:'';position:absolute;top:-60px;right:-60px;width:280px;height:280px;background:radial-gradient(circle,rgba(139,92,246,.3),transparent 70%);pointer-events:none}
.header h1{font-size:1.65rem;font-weight:900;color:#fff;letter-spacing:-.03em;position:relative}
.header .meta{font-size:12px;color:rgba(255,255,255,.5);margin-top:6px;position:relative}
.header .badge-mode{display:inline-block;background:rgba(255,255,255,.12);border:1px solid rgba(255,255,255,.2);border-radius:20px;padding:2px 10px;font-size:11px;font-weight:600;color:rgba(255,255,255,.8);margin-left:8px}
/* ── Tab bar ─── */
.tabs{display:flex;gap:0;padding:0 40px;background:rgba(10,15,30,.8);border-bottom:1px solid var(--border);backdrop-filter:blur(10px)}
.tab-btn{background:transparent;border:none;border-bottom:2px solid transparent;color:var(--muted);font-size:13px;font-weight:600;padding:14px 22px;cursor:pointer;transition:all .2s;font-family:inherit;display:flex;align-items:center;gap:6px}
.tab-btn .cnt{background:rgba(255,255,255,.1);border-radius:10px;padding:1px 7px;font-size:10px;font-weight:700}
.tab-btn:hover{color:rgba(255,255,255,.85);background:rgba(255,255,255,.04)}
.tab-btn.active{color:#fff;border-bottom-color:var(--blue)}
.tab-btn.active .cnt{background:rgba(59,130,246,.3);color:#93c5fd}
/* ── Tab content ─── */
.tab-content{display:none;padding:32px 40px;animation:fi .25s ease}
.tab-content.active{display:block}
@keyframes fi{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:none}}
/* ── Overview grid ─── */
.ov-grid{display:grid;grid-template-columns:1fr 1fr 1fr;gap:18px;margin-bottom:24px}
.ov-grid-full{display:grid;grid-template-columns:1fr 1fr;gap:18px}
.ov-card{background:var(--surface);border:1px solid var(--border);border-radius:14px;padding:24px 28px;backdrop-filter:blur(8px);transition:.2s;position:relative;overflow:hidden}
.ov-card:hover{border-color:rgba(59,130,246,.3);transform:translateY(-2px)}
.ov-card::before{content:'';position:absolute;top:0;left:0;right:0;height:3px;background:var(--accent,#3b82f6);opacity:.6}
.ov-card h3{font-size:10px;color:var(--muted);font-weight:700;text-transform:uppercase;letter-spacing:.08em;margin-bottom:12px}
.ov-card .big{font-size:3rem;font-weight:900;line-height:1;margin-bottom:6px}
.ov-card .sub{font-size:12px;color:var(--muted)}
.ov-card .trend{font-size:11px;margin-top:8px;padding:3px 8px;border-radius:6px;display:inline-block}
/* ── Stat cards row ─── */
.stat-row{display:flex;gap:14px;flex-wrap:wrap;margin-bottom:24px}
.stat-card{flex:1;min-width:120px;background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:16px 20px;text-align:center;transition:.2s;cursor:default}
.stat-card:hover{border-color:rgba(59,130,246,.3);transform:translateY(-2px)}
.stat-card .num{font-size:2.4rem;font-weight:900;line-height:1}
.stat-card .lbl{font-size:10px;font-weight:700;opacity:.5;margin-top:5px;text-transform:uppercase;letter-spacing:.07em}
/* ── Panel ─── */
.panel{background:var(--surface);border:1px solid var(--border);border-radius:14px;overflow:hidden;margin-bottom:18px;backdrop-filter:blur(8px)}
.panel-header{padding:14px 20px;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:10px;flex-wrap:wrap;background:rgba(10,15,30,.5)}
.panel-title{font-weight:700;font-size:14px;flex:1;color:var(--text)}
/* ── Table ─── */
table{width:100%;border-collapse:collapse}
tr:hover td{background:rgba(255,255,255,.025)}
td,th{border-bottom:1px solid rgba(255,255,255,.05);vertical-align:top}
th{padding:10px 14px;background:rgba(10,15,30,.6);font-size:10px;text-transform:uppercase;color:var(--muted);font-weight:700;text-align:left;letter-spacing:.06em;cursor:pointer;user-select:none;white-space:nowrap}
th:hover{color:#93c5fd}
th.sort-asc::after{content:' ↑'}
th.sort-desc::after{content:' ↓'}
td{padding:10px 14px;font-size:12.5px;color:#cbd5e1}
.file-row td{background:rgba(10,15,30,.5)!important;color:#94a3b8;font-weight:700;font-size:11px;letter-spacing:.02em}
.hidden{display:none}
/* ── Filter / search bar ─── */
.toolbar{display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.search-box{background:rgba(255,255,255,.06);border:1px solid var(--border);border-radius:8px;padding:5px 12px;color:var(--text);font-size:12px;font-family:inherit;outline:none;width:200px;transition:.2s}
.search-box:focus{border-color:var(--blue);background:rgba(59,130,246,.08)}
.search-box::placeholder{color:var(--muted)}
.fbtn{background:rgba(255,255,255,.05);border:1px solid var(--border);color:var(--muted);font-size:11px;font-weight:700;padding:4px 13px;border-radius:20px;cursor:pointer;transition:.15s;font-family:inherit;letter-spacing:.03em}
.fbtn:hover,.fbtn.on{background:rgba(59,130,246,.2);border-color:var(--blue);color:#93c5fd}
/* ── Charts area ─── */
.chart-grid{display:grid;grid-template-columns:1fr 1fr;gap:18px;margin-bottom:18px}
.chart-box{background:var(--surface);border:1px solid var(--border);border-radius:14px;padding:20px 24px}
.chart-box h4{font-size:12px;font-weight:700;color:var(--muted);text-transform:uppercase;letter-spacing:.06em;margin-bottom:16px}
/* ── Mermaid ─── */
.mermaid-wrap{padding:24px;overflow-x:auto;background:rgba(10,15,30,.5);min-height:160px}
/* ── Scrollbar ─── */
::-webkit-scrollbar{width:6px;height:6px}
::-webkit-scrollbar-track{background:rgba(255,255,255,.03)}
::-webkit-scrollbar-thumb{background:rgba(255,255,255,.1);border-radius:3px}
::-webkit-scrollbar-thumb:hover{background:rgba(255,255,255,.2)}
/* ── Footer ─── */
footer{text-align:center;color:#1e293b;font-size:12px;padding:20px 40px}
footer a{color:var(--blue);text-decoration:none}
/* ── OWASP chip ─── */
.owasp-chip{display:inline-block;background:rgba(59,130,246,.12);color:#93c5fd;border:1px solid rgba(59,130,246,.25);border-radius:20px;padding:2px 8px;font-size:10px;font-weight:700;letter-spacing:.03em;white-space:nowrap}
/* ── Severity badge (dark version) ─── */
.sev-e{background:rgba(239,68,68,.15);color:#fca5a5;border:1px solid rgba(239,68,68,.3);border-radius:4px;padding:2px 7px;font-size:10px;font-weight:700}
.sev-w{background:rgba(249,115,22,.15);color:#fdba74;border:1px solid rgba(249,115,22,.3);border-radius:4px;padding:2px 7px;font-size:10px;font-weight:700}
.sev-i{background:rgba(59,130,246,.15);color:#93c5fd;border:1px solid rgba(59,130,246,.3);border-radius:4px;padding:2px 7px;font-size:10px;font-weight:700}
/* ── Risk band ─── */
.risk-critical{color:#f87171;font-weight:800}.risk-high{color:#fb923c;font-weight:800}
.risk-medium{color:#fbbf24;font-weight:700}.risk-low{color:#4ade80;font-weight:600}
.risk-noise{color:var(--muted);font-weight:500}
"""

_DASHBOARD_JS = """
// Tab switching
function showTab(id){
  document.querySelectorAll('.tab-content').forEach(function(e){e.classList.remove('active');});
  document.querySelectorAll('.tab-btn').forEach(function(e){e.classList.remove('active');});
  document.getElementById('tab-'+id).classList.add('active');
  document.querySelector('[data-tab="'+id+'"]').classList.add('active');
}
// Severity filter
function filterSev(sev,btn){
  var q=document.getElementById('fSearch');
  var qv=q?q.value.toLowerCase():'';
  document.querySelectorAll('.finding-row').forEach(function(row){
    var sevOk=sev==='ALL'||row.dataset.sev===sev;
    var txtOk=!qv||row.textContent.toLowerCase().includes(qv);
    row.classList.toggle('hidden',!(sevOk&&txtOk));
  });
  _syncFileRows();
  document.querySelectorAll('.fbtn').forEach(function(b){b.classList.remove('on');});
  if(btn) btn.classList.add('on');
}
// Search
function searchFindings(){
  var q=document.getElementById('fSearch').value.toLowerCase();
  var active=document.querySelector('.fbtn.on');
  var sev=active?active.dataset.sev:'ALL';
  document.querySelectorAll('.finding-row').forEach(function(row){
    var sevOk=sev==='ALL'||row.dataset.sev===sev;
    var txtOk=!q||row.textContent.toLowerCase().includes(q);
    row.classList.toggle('hidden',!(sevOk&&txtOk));
  });
  _syncFileRows();
}
function _syncFileRows(){
  document.querySelectorAll('.file-row').forEach(function(fr){
    var next=fr.nextElementSibling,vis=false;
    while(next&&next.classList.contains('finding-row')){
      if(!next.classList.contains('hidden')) vis=true;
      next=next.nextElementSibling;
    }
    fr.classList.toggle('hidden',!vis);
  });
}
// Animated counter
function animateCount(el,target){
  var start=0,dur=800,step=target/dur*16;
  function tick(){
    start=Math.min(start+step,target);
    el.textContent=Math.round(start);
    if(start<target) requestAnimationFrame(tick);
  }
  requestAnimationFrame(tick);
}
document.addEventListener('DOMContentLoaded',function(){
  document.querySelectorAll('[data-count]').forEach(function(el){
    animateCount(el,parseInt(el.dataset.count)||0);
  });
});
"""

# Keep _JS alias for to_html (scan-only, not dashboard)
_JS = _DASHBOARD_JS


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
    trace_res=None,
) -> str:
    """One-file HTML dashboard with tabbed UI: Overview · Findings · Blast Radius · History."""
    history = history or []
    s = summary(findings)
    triage = verdict_map is not None
    ts = datetime.now().strftime("%Y-%m-%d %H:%M")
    mode = "AI-triaged" if triage else "offline scan"
    repo_short = _esc(repo_path.split("/")[-1] or repo_path.split("\\")[-1] or "Dashboard")

    # ── Findings table ────────────────────────────────────────────────────────
    if risk_map is not None:
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

    # ── TAB 1: Overview — premium stat cards + OWASP donut chart ─────────────
    total = s["error"] + s["warning"] + s["info"]
    risk_band = "CRITICAL" if s["error"] >= 5 else ("HIGH" if s["error"] >= 1 else ("MEDIUM" if s["warning"] >= 3 else "LOW"))
    band_color = {"CRITICAL": "#ef4444", "HIGH": "#f97316", "MEDIUM": "#eab308", "LOW": "#22c55e"}.get(risk_band, "#94a3b8")
    band_accent = {"CRITICAL": "#ef4444", "HIGH": "#f97316", "MEDIUM": "#eab308", "LOW": "#22c55e"}.get(risk_band, "#3b82f6")

    # OWASP category breakdown for donut chart
    from collections import Counter
    owasp_counts: Counter = Counter()
    for f in findings:
        tag, _ = _owasp_tag(f.rule.rsplit(".", 1)[-1])
        owasp_counts[tag] += 1
    owasp_labels = list(owasp_counts.keys())
    owasp_vals = list(owasp_counts.values())
    donut_colors = ["#ef4444","#f97316","#eab308","#22c55e","#3b82f6","#8b5cf6","#ec4899","#14b8a6","#f59e0b","#6366f1"]

    ov_html = (
        f'<div class="stat-row">'
        f'<div class="stat-card" style="--accent:{band_accent};border-top:3px solid {band_accent}">'
        f'<div class="num" style="color:{band_color}">{risk_band}</div>'
        f'<div class="lbl">Overall Risk</div></div>'
        f'<div class="stat-card" style="border-top:3px solid #ef4444">'
        f'<div class="num" style="color:#ef4444" data-count="{s["error"]}">0</div>'
        f'<div class="lbl">Errors</div></div>'
        f'<div class="stat-card" style="border-top:3px solid #f97316">'
        f'<div class="num" style="color:#f97316" data-count="{s["warning"]}">0</div>'
        f'<div class="lbl">Warnings</div></div>'
        f'<div class="stat-card" style="border-top:3px solid #3b82f6">'
        f'<div class="num" style="color:#3b82f6" data-count="{s["info"]}">0</div>'
        f'<div class="lbl">Info</div></div>'
        f'<div class="stat-card" style="border-top:3px solid #64748b">'
        f'<div class="num" style="color:#64748b" data-count="{suppressed}">0</div>'
        f'<div class="lbl">Suppressed</div></div>'
        f'</div>'
        + ('<div class="chart-grid">' if owasp_labels else '')
        + (
            '<div class="chart-box"><h4>OWASP Category Breakdown</h4><canvas id="owaspChart" height="180"></canvas></div>'
            '<div class="chart-box"><h4>Severity Distribution</h4><canvas id="sevChart" height="180"></canvas></div>'
            if owasp_labels else ''
        )
        + ('</div>' if owasp_labels else '')
        + f'<div style="margin-top:12px;color:#475569;font-size:12px;padding:4px 0">'
          f'Scanned: <b style="color:#94a3b8">{_esc(repo_path)}</b> &nbsp;·&nbsp; {mode} &nbsp;·&nbsp; {ts}'
          + (' &nbsp;·&nbsp; <span style="color:#a78bfa">✦ AI triage enabled</span>' if triage else '')
          + '</div>'
    )

    # ── TAB 2: Findings — with search + filter toolbar ────────────────────────
    toolbar = (
        '<div class="toolbar">'
        '<input class="search-box" id="fSearch" type="text" placeholder="🔍 Search findings…" oninput="searchFindings()">'
        '<button class="fbtn on" data-sev="ALL" onclick="filterSev(\'ALL\',this)">ALL</button>'
        f'<button class="fbtn" data-sev="ERROR" onclick="filterSev(\'ERROR\',this)" style="color:#fca5a5">ERROR ({s["error"]})</button>'
        f'<button class="fbtn" data-sev="WARNING" onclick="filterSev(\'WARNING\',this)" style="color:#fdba74">WARNING ({s["warning"]})</button>'
        f'<button class="fbtn" data-sev="INFO" onclick="filterSev(\'INFO\',this)" style="color:#93c5fd">INFO ({s["info"]})</button>'
        '</div>'
    )
    findings_tab = (
        '<div class="panel">'
        '<div class="panel-header"><span class="panel-title">🛡 Security Findings</span>' + toolbar + '</div>'
        + table + '</div>'
    )

    # ── TAB 3: Blast Radius — D3 interactive graph from graph_viz.py ─────────
    fn_note = (f' <span style="font-size:11px;color:#64748b">{_esc(traced_fn)}</span>') if traced_fn else ""

    # Build stats panel from trace_res
    trace_info = ""
    d3_graph_html = ""
    if trace_res is not None:
        st = trace_res.stats
        trace_info = (
            f'<div style="display:flex;gap:12px;margin:16px 24px;flex-wrap:wrap">'
            f'<div style="background:rgba(255,255,255,.05);padding:8px 14px;border-radius:8px;font-size:12px"><b style="font-size:1.4rem;display:block;color:#a78bfa">{len(trace_res.changed)}</b> Changed Nodes</div>'
            f'<div style="background:rgba(255,255,255,.05);padding:8px 14px;border-radius:8px;font-size:12px"><b style="font-size:1.4rem;display:block;color:#f97316">{st.get("functions_affected",0)}</b> Functions Affected</div>'
            f'<div style="background:rgba(255,255,255,.05);padding:8px 14px;border-radius:8px;font-size:12px"><b style="font-size:1.4rem;display:block;color:#ef4444">{st.get("apis_affected",0)}</b> APIs Exposed</div>'
            f'<div style="background:rgba(255,255,255,.05);padding:8px 14px;border-radius:8px;font-size:12px"><b style="font-size:1.4rem;display:block;color:#22c55e">{st.get("features_affected",0)}</b> Features Touched</div>'
            f'<div style="background:rgba(255,255,255,.05);padding:8px 14px;border-radius:8px;font-size:12px"><b style="font-size:1.4rem;display:block;color:#64748b">{st.get("approximate",0)}</b> Approximate</div>'
            f'</div>'
        )
        if trace_res.apis:
            api_items = "".join(
                f'<div style="padding:5px 0;border-bottom:1px solid rgba(255,255,255,.05);font-size:12px;font-family:monospace;color:#93c5fd">'
                f'⚡ {_esc(a["route"])} <span style="color:#64748b;float:right;font-size:11px">{_esc(a["file"])}</span></div>'
                for a in trace_res.apis
            )
            trace_info += (
                f'<div style="margin:0 24px 16px 24px;padding:12px 16px;background:rgba(10,15,30,.5);'
                f'border:1px solid rgba(255,255,255,.05);border-radius:8px">'
                f'<div style="font-size:11px;font-weight:700;color:#cbd5e1;text-transform:uppercase;margin-bottom:8px;letter-spacing:.06em">Affected Endpoints / Routes</div>'
                f'{api_items}</div>'
            )

        # Try to generate D3 interactive graph
        try:
            from radar.graph.graph_viz import to_dependency_html
            # Build a subgraph: only changed + affected node IDs
            import networkx as nx
            all_ids = {item.id for item in trace_res.changed + trace_res.affected}
            # We need the original nx.DiGraph — trace_res doesn't hold it, so we
            # reconstruct a minimal graph from the ImpactItems for visualization
            sub = nx.DiGraph()
            for item in trace_res.changed + trace_res.affected:
                sub.add_node(item.id, name=item.name, kind=item.kind,
                             file=item.file, start_line=item.line)
            # Add edges from parent relationships
            for item in trace_res.affected:
                if item.parent and item.parent in all_ids:
                    sub.add_edge(item.parent, item.id, kind="calls")
            d3_graph_html = to_dependency_html(sub, repo_path=repo_path)
        except Exception as _d3_exc:
            d3_graph_html = ""

    if d3_graph_html:
        # Extract nodes/edges JSON from subgraph and embed D3 inline
        # (srcdoc iframe breaks JS due to HTML entity escaping)
        try:
            import json as _json
            from radar.graph.graph_viz import _file_color, _short_name

            _PALETTE = [
                "#3498db","#e74c3c","#2ecc71","#f39c12","#9b59b6",
                "#1abc9c","#e67e22","#34495e","#e91e63","#00bcd4",
                "#8bc34a","#ff5722","#607d8b","#795548","#ffc107",
                "#673ab7","#009688","#ff9800","#4caf50","#f44336",
            ]
            _fc: dict = {}
            def _col(f):
                if f not in _fc:
                    _fc[f] = _PALETTE[len(_fc) % len(_PALETTE)]
                return _fc[f]

            nidx: dict = {}
            ns_out = []
            for i, nid in enumerate(sorted(sub.nodes)):
                d = sub.nodes[nid]
                kind = d.get("kind", "function")
                ns_out.append({
                    "id": i, "nid": nid,
                    "name": _short_name(d.get("name", nid)),
                    "full": d.get("name", nid),
                    "file": d.get("file", ""),
                    "kind": kind,
                    "line": d.get("start_line", 0),
                    "color": _col(d.get("file", "")),
                    "r": 10 if kind == "route" else (7 if kind == "function" else 5),
                })
                nidx[nid] = i
            es_out = []
            for src, dst, edata in sub.edges(data=True):
                if src in nidx and dst in nidx:
                    k = edata.get("kind", "calls")
                    es_out.append({"source": nidx[src], "target": nidx[dst], "kind": k, "dashed": k != "calls"})

            from radar.graph.graph_viz import _d3_script_tag
            d3_script = _d3_script_tag()

            nodes_js = _json.dumps(ns_out)
            edges_js = _json.dumps(es_out)

            blast_graph_section = f"""
<div style="margin:0 24px 24px 24px;border:1px solid rgba(255,255,255,.08);border-radius:10px;overflow:hidden">
  <div style="padding:10px 16px;background:rgba(10,15,30,.6);font-size:11px;color:#64748b;font-weight:700;text-transform:uppercase;letter-spacing:.06em">
    🕸 Interactive D3 Force Graph &nbsp;·&nbsp; {len(ns_out)} nodes &nbsp;·&nbsp; {len(es_out)} edges &nbsp;·&nbsp; drag · scroll · hover · search
  </div>
  {d3_script}
  <div style="position:relative;background:#0f1923">
    <input id="d3search" placeholder="Search function / file…"
      style="position:absolute;top:10px;left:50%;transform:translateX(-50%);z-index:5;
             background:rgba(255,255,255,.08);border:1px solid rgba(255,255,255,.15);
             border-radius:6px;color:#cdd6e0;padding:5px 12px;font-size:12px;width:220px;outline:none">
    <svg id="d3canvas" style="width:100%;height:580px;display:block"></svg>
    <div id="d3tip" style="position:absolute;background:rgba(10,18,28,.95);border:1px solid rgba(74,158,218,.3);
         border-radius:6px;padding:10px 14px;font-size:12px;line-height:1.6;
         pointer-events:none;display:none;z-index:20;max-width:320px;color:#cdd6e0"></div>
  </div>
  <script>
  (function(){{
    var NODES={nodes_js};
    var EDGES={edges_js};
    var svg=d3.select('#d3canvas');
    var W=svg.node().getBoundingClientRect().width||900,H=580;
    svg.attr('width',W).attr('height',H);
    var g=svg.append('g');
    var zoom=d3.zoom().scaleExtent([.05,8]).on('zoom',function(e){{g.attr('transform',e.transform);}});
    svg.call(zoom);
    var sim=d3.forceSimulation(NODES)
      .force('link',d3.forceLink(EDGES).id(function(d){{return d.id;}}).distance(function(d){{return d.dashed?90:55;}}).strength(0.5))
      .force('charge',d3.forceManyBody().strength(-160))
      .force('center',d3.forceCenter(W/2,H/2))
      .force('collide',d3.forceCollide(function(d){{return d.r+5;}}));
    var defs=svg.append('defs');
    ['calls','imports','handles'].forEach(function(k){{
      var col=k==='calls'?'#4a9eda':k==='imports'?'#f39c12':'#2ecc71';
      defs.append('marker').attr('id','d3arr-'+k)
        .attr('viewBox','0 -4 8 8').attr('refX',14).attr('refY',0)
        .attr('markerWidth',6).attr('markerHeight',6).attr('orient','auto')
        .append('path').attr('d','M0,-4L8,0L0,4').attr('fill',col).attr('opacity',.7);
    }});
    var link=g.append('g').selectAll('line').data(EDGES).enter().append('line')
      .attr('stroke',function(d){{return d.kind==='calls'?'#4a9eda':d.kind==='imports'?'#f39c12':'#2ecc71';}})
      .attr('stroke-opacity',.55).attr('stroke-width',function(d){{return d.kind==='handles'?1.4:1.2;}})
      .attr('stroke-dasharray',function(d){{return d.dashed?'4,3':null;}})
      .attr('marker-end',function(d){{return 'url(#d3arr-'+d.kind+')';}});
    var node=g.append('g').selectAll('g').data(NODES).enter().append('g')
      .call(d3.drag()
        .on('start',function(e,d){{if(!e.active)sim.alphaTarget(.3).restart();d.fx=d.x;d.fy=d.y;}})
        .on('drag',function(e,d){{d.fx=e.x;d.fy=e.y;}})
        .on('end',function(e,d){{if(!e.active)sim.alphaTarget(0);d.fx=null;d.fy=null;}}));
    node.append('circle')
      .attr('r',function(d){{return d.r;}})
      .attr('fill',function(d){{return d.color;}})
      .attr('stroke',function(d){{return d.kind==='route'?'#fff':'#0f1923';}})
      .attr('stroke-width',function(d){{return d.kind==='route'?2:1.5;}});
    node.filter(function(d){{return d.r>=7;}}).append('text')
      .attr('dy',function(d){{return d.r+10;}})
      .attr('text-anchor','middle')
      .style('font-size','9px').style('fill','#cdd6e0').style('pointer-events','none')
      .text(function(d){{return d.name.length>18?d.name.slice(0,17)+'\\u2026':d.name;}});
    var tip=document.getElementById('d3tip');
    node.on('mousemove',function(e,d){{
      tip.style.display='block';
      tip.style.left=(e.offsetX+14)+'px';
      tip.style.top=(e.offsetY-10)+'px';
      tip.innerHTML='<b style="color:#4a9eda">'+d.full+'</b><br><span style="color:#7f9db0">File: '+d.file+'</span><br><span style="color:#7f9db0">Kind: '+d.kind+' | Line: '+d.line+'</span>';
    }}).on('mouseleave',function(){{tip.style.display='none';}});
    sim.on('tick',function(){{
      link.attr('x1',function(d){{return d.source.x;}}).attr('y1',function(d){{return d.source.y;}})
          .attr('x2',function(d){{return d.target.x;}}).attr('y2',function(d){{return d.target.y;}});
      node.attr('transform',function(d){{return 'translate('+d.x+','+d.y+')';}});
    }});
    sim.on('end',function(){{
      var b=g.node().getBBox();
      if(!b.width||!b.height)return;
      var pad=40,sc=Math.min((W-pad*2)/b.width,(H-pad*2)/b.height,1.5);
      var tx=W/2-sc*(b.x+b.width/2),ty=H/2-sc*(b.y+b.height/2);
      svg.transition().duration(600).call(zoom.transform,d3.zoomIdentity.translate(tx,ty).scale(sc));
    }});
    document.getElementById('d3search').addEventListener('input',function(){{
      var q=this.value.trim().toLowerCase();
      node.selectAll('circle').attr('opacity',function(d){{
        return (!q||d.name.toLowerCase().includes(q)||d.file.toLowerCase().includes(q))?1:.08;
      }});
    }});
  }})();
  </script>
</div>"""
        except Exception as _inline_exc:
            # Fallback: srcdoc iframe
            import html as _html_mod
            blast_graph_section = (
                f'<div style="margin:0 24px 24px;border:1px solid rgba(255,255,255,.08);border-radius:10px;overflow:hidden">'
                f'<iframe srcdoc="{_html_mod.escape(d3_graph_html, quote=True)}" style="width:100%;height:580px;border:none"></iframe>'
                f'</div>'
            )
    elif mermaid_src:
        blast_graph_section = '<div class="mermaid-wrap"><pre class="mermaid">' + mermaid_src + '</pre></div>'
    else:
        blast_graph_section = ""

    if mermaid_src or d3_graph_html:
        blast_tab = (
            '<div class="panel"><div class="panel-header">'
            f'<span class="panel-title">🔗 Blast Radius — Impact Graph{fn_note}</span>'
            '<span style="font-size:11px;color:#64748b">Functions and routes affected by the change</span></div>'
            + trace_info
            + blast_graph_section
            + '</div>'
        )
    else:
        blast_tab = (
            '<div style="display:flex;flex-direction:column;align-items:center;justify-content:center;padding:80px 40px;gap:16px;color:#475569">'
            '<div style="font-size:3rem">🔗</div>'
            '<div style="font-weight:700;font-size:16px;color:#64748b">No Blast Radius Data</div>'
            '<div style="font-size:13px;text-align:center">Specify <code style="color:#60a5fa;background:rgba(59,130,246,.1);padding:2px 6px;border-radius:4px">--function</code> or '
            '<code style="color:#60a5fa;background:rgba(59,130,246,.1);padding:2px 6px;border-radius:4px">--diff</code> when running the analysis.</div>'
            '</div>'
        )

    # ── TAB 4: History — Chart.js line chart ─────────────────────────────────
    chart_script = ""
    if history:
        hist_tab = (
            '<div class="panel"><div class="panel-header"><span class="panel-title">📈 Scan History Trend</span>'
            f'<span style="font-size:11px;color:#64748b">{len(history)} scan(s) recorded</span></div>'
            '<div style="padding:24px"><canvas id="hChart" height="90"></canvas></div></div>'
        )
        chart_script = '<script src="https://cdn.jsdelivr.net/npm/chart.js@4/dist/chart.umd.min.js"></script><script>'
        chart_script += (
            "var _cjsDefaults={color:'#94a3b8',borderColor:'rgba(255,255,255,.05)'};"
            "Chart.defaults.color=_cjsDefaults.color;"
            "new Chart(document.getElementById('hChart'),{type:'line',data:{labels:"
            + json.dumps([e["ts"] for e in history])
            + ",datasets:[{label:'ERROR',data:" + json.dumps([e["error"] for e in history])
            + ",borderColor:'#ef4444',backgroundColor:'rgba(239,68,68,.08)',tension:.4,fill:true,pointBackgroundColor:'#ef4444'},"
            + "{label:'WARNING',data:" + json.dumps([e["warning"] for e in history])
            + ",borderColor:'#f97316',backgroundColor:'rgba(249,115,22,.08)',tension:.4,fill:true,pointBackgroundColor:'#f97316'}]},"
            + "options:{responsive:true,interaction:{intersect:false,mode:'index'},plugins:{legend:{position:'top',"
            + "labels:{color:'#94a3b8',usePointStyle:true}}},"
            + "scales:{x:{ticks:{color:'#64748b'},grid:{color:'rgba(255,255,255,.04)'}},"
            + "y:{beginAtZero:true,ticks:{color:'#64748b',stepSize:1},grid:{color:'rgba(255,255,255,.04)'}}}}});"
        )
        if owasp_labels:
            chart_script += (
                "new Chart(document.getElementById('owaspChart'),{type:'doughnut',data:{labels:"
                + json.dumps(owasp_labels)
                + ",datasets:[{data:" + json.dumps(owasp_vals)
                + ",backgroundColor:" + json.dumps(donut_colors[:len(owasp_labels)])
                + ",borderWidth:0,hoverOffset:6}]},"
                + "options:{responsive:true,plugins:{legend:{position:'right',labels:{color:'#94a3b8',font:{size:11},usePointStyle:true,padding:12}},"
                + "tooltip:{callbacks:{label:function(c){return c.label+': '+c.raw+' finding'+(c.raw!==1?'s':'');}}}},"
                + "cutout:'68%'}});"
                + "new Chart(document.getElementById('sevChart'),{type:'doughnut',data:{labels:['ERROR','WARNING','INFO'],"
                + "datasets:[{data:" + json.dumps([s["error"], s["warning"], s["info"]])
                + ",backgroundColor:['#ef4444','#f97316','#3b82f6'],borderWidth:0,hoverOffset:6}]},"
                + "options:{responsive:true,plugins:{legend:{position:'right',labels:{color:'#94a3b8',font:{size:11},usePointStyle:true,padding:12}}},"
                + "cutout:'68%'}});"
            )
        chart_script += "</script>"
    else:
        hist_tab = (
            '<div style="display:flex;flex-direction:column;align-items:center;justify-content:center;padding:80px 40px;gap:16px;color:#475569">'
            '<div style="font-size:3rem">📈</div>'
            '<div style="font-weight:700;font-size:16px;color:#64748b">No History Yet</div>'
            '<div style="font-size:13px">Run <code style="color:#60a5fa;background:rgba(59,130,246,.1);padding:2px 6px;border-radius:4px">radar report</code> again after future scans to see trends.</div>'
            '</div>'
        )
        # Still build donut charts on overview even without history
        if owasp_labels:
            chart_script = '<script src="https://cdn.jsdelivr.net/npm/chart.js@4/dist/chart.umd.min.js"></script><script>'
            chart_script += (
                "new Chart(document.getElementById('owaspChart'),{type:'doughnut',data:{labels:"
                + json.dumps(owasp_labels)
                + ",datasets:[{data:" + json.dumps(owasp_vals)
                + ",backgroundColor:" + json.dumps(donut_colors[:len(owasp_labels)])
                + ",borderWidth:0,hoverOffset:6}]},"
                + "options:{responsive:true,plugins:{legend:{position:'right',labels:{color:'#94a3b8',font:{size:11},usePointStyle:true,padding:12}},"
                + "tooltip:{callbacks:{label:function(c){return c.label+': '+c.raw+' finding'+(c.raw!==1?'s':'');}}}},"
                + "cutout:'68%'}});"
                + "new Chart(document.getElementById('sevChart'),{type:'doughnut',data:{labels:['ERROR','WARNING','INFO'],"
                + "datasets:[{data:" + json.dumps([s["error"], s["warning"], s["info"]])
                + ",backgroundColor:['#ef4444','#f97316','#3b82f6'],borderWidth:0,hoverOffset:6}]},"
                + "options:{responsive:true,plugins:{legend:{position:'right',labels:{color:'#94a3b8',font:{size:11},usePointStyle:true,padding:12}}},"
                + "cutout:'68%'}});"
                + "</script>"
            )

    mermaid_script = (
        '<script type="module">import mermaid from "https://cdn.jsdelivr.net/npm/mermaid@11/dist/mermaid.esm.min.mjs";'
        "mermaid.initialize({startOnLoad:true,theme:'dark'});</script>"
        if mermaid_src else ""
    )

    # ── Assemble tab bar with finding count badges ────────────────────────────
    tabs = [
        ("overview", "📊 Overview", ""),
        ("findings", "🛡 Findings", f'<span class="cnt">{total}</span>'),
        ("blast",    "🔗 Blast Radius", ""),
        ("history",  "📈 History", f'<span class="cnt">{len(history)}</span>' if history else ""),
    ]
    tab_bar = '<div class="tabs">' + "".join(
        f'<button class="tab-btn{" active" if i == 0 else ""}" data-tab="{tid}" onclick="showTab(\'{tid}\')">{label}{badge}</button>'
        for i, (tid, label, badge) in enumerate(tabs)
    ) + "</div>"

    tab_contents = (
        f'<div id="tab-overview" class="tab-content active">{ov_html}</div>'
        f'<div id="tab-findings" class="tab-content">{findings_tab}</div>'
        f'<div id="tab-blast" class="tab-content">{blast_tab}</div>'
        f'<div id="tab-history" class="tab-content">{hist_tab}</div>'
    )

    return (
        '<!DOCTYPE html>\n<html lang="en">\n<head>\n'
        '<meta charset="utf-8">\n<meta name="viewport" content="width=device-width,initial-scale=1">\n'
        f"<title>security-radar — {repo_short}</title>\n"
        f"<style>{_CSS}</style>\n</head>\n<body>\n"
        f'<div class="header">'
        f'<h1>⚡ security-radar</h1>'
        f'<div class="meta">{_esc(repo_path)}'
        f'<span class="badge-mode">{mode}</span></div></div>\n'
        + tab_bar
        + tab_contents
        + '<footer>Generated by <b>security-radar</b> &nbsp;·&nbsp; '
          f'<a href="#" onclick="showTab(\'overview\');return false">↑ top</a></footer>\n'
        + f"<script>{_DASHBOARD_JS}</script>\n"
        + chart_script + mermaid_script
        + "\n</body></html>"
    )


