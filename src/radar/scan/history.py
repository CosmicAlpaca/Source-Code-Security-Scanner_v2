"""Scan history — persist scan results as JSON lines for trend tracking.

Each scan appends one record to  ~/.cache/radar/scan-history.jsonl
(or %LOCALAPPDATA%/radar/scan-history.jsonl on Windows).

Schema per line:
  {
    "ts":      "2026-06-11T10:30:00",   # ISO timestamp
    "path":    "/abs/path/to/repo",
    "rules_only": false,
    "total":   8,
    "error":   5,
    "warning": 3,
    "info":    0,
    "suppressed": 2
  }
"""

from __future__ import annotations

import json
import os
from datetime import datetime
from pathlib import Path


def _history_file() -> Path:
    if os.name == "nt":
        base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
    else:
        base = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache"))
    hist = base / "radar" / "scan-history.jsonl"
    hist.parent.mkdir(parents=True, exist_ok=True)
    return hist


def record(
    *,
    path: str,
    rules_only: bool,
    error: int,
    warning: int,
    info: int,
    suppressed: int = 0,
) -> None:
    """Append one scan result to the history file."""
    entry = {
        "ts": datetime.now().isoformat(timespec="seconds"),
        "path": path,
        "rules_only": rules_only,
        "total": error + warning + info,
        "error": error,
        "warning": warning,
        "info": info,
        "suppressed": suppressed,
    }
    with _history_file().open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry) + "\n")


def load(path_filter: str | None = None, limit: int = 50) -> list[dict]:
    """Load the most recent *limit* entries, optionally filtered by repo path."""
    hist = _history_file()
    if not hist.exists():
        return []
    entries: list[dict] = []
    for line in hist.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        if path_filter and path_filter not in entry.get("path", ""):
            continue
        entries.append(entry)
    return entries[-limit:]


def render_history_html(entries: list[dict], repo_path: str = "") -> str:
    """Generate a standalone HTML page with a trend chart (Chart.js CDN)."""
    if not entries:
        return "<p>No scan history found.</p>"

    labels = [e["ts"] for e in entries]
    errors = [e["error"] for e in entries]
    warnings = [e["warning"] for e in entries]
    suppressed = [e.get("suppressed", 0) for e in entries]
    totals = [e["total"] for e in entries]

    latest = entries[-1]
    delta_total = latest["total"] - entries[-2]["total"] if len(entries) >= 2 else 0
    trend_icon = "📈" if delta_total > 0 else ("📉" if delta_total < 0 else "➡️")
    trend_color = "#c00" if delta_total > 0 else ("#28a745" if delta_total < 0 else "#666")

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>security-radar — Scan History</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4/dist/chart.umd.min.js"></script>
<style>
body{{font-family:system-ui,sans-serif;margin:2rem auto;max-width:1000px;color:#222}}
h1{{font-size:1.4rem;border-bottom:2px solid #36c;padding-bottom:.4rem}}
.summary{{background:#f8f8f8;border-left:4px solid #36c;padding:10px 16px;margin:.5rem 0 1.5rem;font-size:14px}}
.chart-box{{background:#fafafa;border:1px solid #e0e0e0;border-radius:6px;padding:1rem;margin:1rem 0}}
table{{border-collapse:collapse;width:100%;font-size:13px;margin-top:1.5rem}}
th,td{{border:1px solid #ddd;padding:6px 10px;text-align:left}}
th{{background:#f5f5f5;font-weight:600}}
.err{{color:#c00;font-weight:700}}
.warn{{color:#b60;font-weight:700}}
</style>
</head>
<body>
<h1>📊 security-radar — Scan History{f': <code>{repo_path}</code>' if repo_path else ''}</h1>
<p class="summary">
  <strong>{len(entries)} scans</strong> recorded &nbsp;&middot;&nbsp;
  Latest: <strong>{latest['total']} findings</strong>
  ({latest['error']} error · {latest['warning']} warning) &nbsp;&middot;&nbsp;
  Trend: <span style="color:{trend_color}">{trend_icon} {abs(delta_total):+d} vs previous</span>
</p>

<div class="chart-box">
  <canvas id="trendChart" height="80"></canvas>
</div>

<table>
<tr><th>Time</th><th>ERROR</th><th>WARNING</th><th>INFO</th><th>Suppressed</th><th>Total</th></tr>
{''.join(
    f'<tr>'
    f'<td>{e["ts"]}</td>'
    f'<td class="err">{e["error"]}</td>'
    f'<td class="warn">{e["warning"]}</td>'
    f'<td>{e["info"]}</td>'
    f'<td style="color:#999">{e.get("suppressed",0)}</td>'
    f'<td><strong>{e["total"]}</strong></td>'
    f'</tr>'
    for e in reversed(entries)
)}
</table>

<script>
new Chart(document.getElementById('trendChart'), {{
  type: 'line',
  data: {{
    labels: {json.dumps(labels)},
    datasets: [
      {{label:'ERROR', data:{json.dumps(errors)}, borderColor:'#c00', backgroundColor:'rgba(204,0,0,0.08)', tension:0.3, fill:true}},
      {{label:'WARNING', data:{json.dumps(warnings)}, borderColor:'#e08000', backgroundColor:'rgba(224,128,0,0.08)', tension:0.3, fill:true}},
      {{label:'Suppressed', data:{json.dumps(suppressed)}, borderColor:'#999', backgroundColor:'transparent', borderDash:[5,5], tension:0.3}},
    ]
  }},
  options:{{
    responsive:true,
    plugins:{{legend:{{position:'top'}},title:{{display:true,text:'Findings over time'}}}},
    scales:{{y:{{beginAtZero:true,ticks:{{stepSize:1}}}}}}
  }}
}});
</script>
</body></html>"""
