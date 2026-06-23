"""Interactive D3.js force-directed dependency graph for security-radar.

Usage:
    from radar.graph.graph_viz import to_dependency_html
    html = to_dependency_html(graph, repo_path="C:/MyRepo")
    open("dep-graph.html","w").write(html)
"""

from __future__ import annotations

import json
from pathlib import Path

import networkx as nx

# Bundled D3 so the graph renders offline (zero-footprint promise). Falls back to
# the CDN only if the vendored file is missing from the install.
_VENDOR_D3 = Path(__file__).resolve().parent / "vendor" / "d3.v7.min.js"
_CDN_D3 = "https://cdn.jsdelivr.net/npm/d3@7/dist/d3.min.js"


def _d3_script_tag() -> str:
    """Inline the vendored D3 source; fall back to a CDN <script src> if absent."""
    try:
        src = _VENDOR_D3.read_text(encoding="utf-8")
    except OSError:
        return f'<script src="{_CDN_D3}"></script>'
    return "<script>\n" + src + "\n</script>"

# Edge kind constants (mirrors model.py)
CALLS   = "calls"
IMPORTS = "imports"
HANDLES = "handles"


# ── Color palette: one color per unique file (up to 20, then cycle) ──────────
_PALETTE = [
    "#3498db","#e74c3c","#2ecc71","#f39c12","#9b59b6",
    "#1abc9c","#e67e22","#34495e","#e91e63","#00bcd4",
    "#8bc34a","#ff5722","#607d8b","#795548","#ffc107",
    "#673ab7","#009688","#ff9800","#4caf50","#f44336",
]


def _file_color(file: str, cache: dict) -> str:
    if file not in cache:
        cache[file] = _PALETTE[len(cache) % len(_PALETTE)]
    return cache[file]


def _short_name(name: str, max_len: int = 30) -> str:
    return name if len(name) <= max_len else "…" + name[-(max_len - 1):]


def _radius(kind: str, members: int) -> float:
    """Node radius. File nodes scale with member count so big files read bigger."""
    if kind == "route":
        return 10
    if kind == "function":
        return 7
    if kind == "file":
        return round(min(8 + members ** 0.5 * 1.6, 26), 1)
    return 5


def _build_graph_data(graph: nx.DiGraph) -> tuple[list[dict], list[dict], list[dict], dict]:
    """Build the D3 payload (nodes, edges, legend rows, stats) from an nx graph.

    Single source of truth for both the full HTML page and the live fragment so
    they stay in lockstep. Pure — no I/O.
    """
    file_colors: dict[str, str] = {}

    # ── Build node list ───────────────────────────────────────────────────────
    node_index: dict[str, int] = {}
    nodes_json: list[dict] = []
    for i, nid in enumerate(sorted(graph.nodes)):
        data = graph.nodes[nid]
        file = data.get("file", "")
        kind = data.get("kind", "function")
        nodes_json.append({
            "id":    i,
            "nid":   nid,
            "name":  _short_name(data.get("name", nid)),
            "full":  data.get("name", nid),
            "file":  file,
            "kind":  kind,
            "line":  data.get("start_line", 0),
            "color": _file_color(file, file_colors),
            "members": data.get("members", 0),
            "r":     _radius(kind, data.get("members", 0)),
        })
        node_index[nid] = i

    # ── Build edge list ───────────────────────────────────────────────────────
    edges_json: list[dict] = []
    for src, dst, data in graph.edges(data=True):
        if src not in node_index or dst not in node_index:
            continue
        kind = data.get("kind", CALLS)
        edges_json.append({
            "source": node_index[src],
            "target": node_index[dst],
            "kind":   kind,
            "dashed": kind != CALLS,
        })

    # ── Legend: file → color (top 15 files by function count) ───────────────
    # `members` (file-level nodes) counts the functions a file owns; fall back to
    # 1 per node for the function-level view where each node is one function.
    file_count: dict[str, int] = {}
    for n in nodes_json:
        file_count[n["file"]] = file_count.get(n["file"], 0) + max(n.get("members", 0), 1)
    top_files = sorted(file_count, key=lambda f: -file_count[f])[:15]
    legend = [
        {"file": f, "color": file_colors.get(f, "#999"), "count": file_count[f]}
        for f in top_files
    ]

    stats = {
        "nodes":  len(nodes_json),
        "edges":  len(edges_json),
        "files":  len(file_colors),
        "routes": sum(1 for n in nodes_json if n["kind"] == "route"),
    }
    return nodes_json, edges_json, legend, stats


def to_dependency_html(graph: nx.DiGraph, repo_path: str = "") -> str:
    """Return a self-contained HTML page with an interactive D3 force graph."""
    nodes_json, edges_json, legend, stats = _build_graph_data(graph)
    return _render(nodes_json, edges_json, json.dumps(legend), stats, repo_path)


def render_graph_fragment(graph: nx.DiGraph, repo_path: str = "") -> dict:
    """Return the D3 payload to (re)initialize the graph WITHOUT the page shell.

    For the live `radar serve` dashboard: the server pushes this JSON over SSE
    and the browser re-seeds the existing D3 simulation in place rather than
    reloading a whole HTML document. The frozen-layout positions are computed
    client-side from this data (same as the full page), so no <head>/CSS/D3
    bundle is included here.

    Returns:
        {
          "nodes":   [{id, nid, name, full, file, kind, line, color, members, r}, ...],
          "edges":   [{source, target, kind, dashed}, ...],
          "legend":  [{file, color, count}, ...],
          "stats":   {nodes, edges, files, routes},
          "repo_path": str,
        }
    """
    nodes_json, edges_json, legend, stats = _build_graph_data(graph)
    return {
        "nodes": nodes_json,
        "edges": edges_json,
        "legend": legend,
        "stats": stats,
        "repo_path": repo_path.replace("\\", "/"),
    }


# ── HTML template (raw string — no f-string to avoid brace conflicts) ─────────
_HTML_TEMPLATE = (
    '<!DOCTYPE html>\n'
    '<html lang="en">\n'
    '<head>\n'
    '<meta charset="utf-8">\n'
    '<meta name="viewport" content="width=device-width,initial-scale=1">\n'
    '<title>security-radar — Dependency Graph</title>\n'
    'D3_SCRIPT_TAG\n'
    '<style>\n'
    '*{box-sizing:border-box;margin:0;padding:0}\n'
    'body{font-family:system-ui,sans-serif;background:#0f1923;color:#cdd6e0;overflow:hidden}\n'
    '#canvas{width:100vw;height:100vh}\n'
    '.node circle{cursor:pointer;stroke:#0f1923;stroke-width:1.5px;transition:opacity .2s}\n'
    '.node text{font-size:10px;fill:#cdd6e0;pointer-events:none;text-anchor:middle;dominant-baseline:central}\n'
    '.link{stroke-opacity:.55}\n'
    '.link.calls{stroke:#4a9eda;stroke-width:1.2px}\n'
    '.link.imports{stroke:#f39c12;stroke-width:1px;stroke-dasharray:4,3}\n'
    '.link.handles{stroke:#2ecc71;stroke-width:1.4px}\n'
    '.dim{opacity:.08!important}\n'
    '#hud{position:fixed;top:0;left:0;right:0;display:flex;align-items:center;\n'
    '     background:rgba(15,25,35,.88);backdrop-filter:blur(6px);\n'
    '     padding:10px 20px;gap:18px;z-index:10;border-bottom:1px solid rgba(255,255,255,.06)}\n'
    '#hud h1{font-size:14px;font-weight:700;color:#4a9eda;white-space:nowrap}\n'
    '.stat{font-size:12px;color:#7f9db0}\n'
    '.stat b{color:#cdd6e0}\n'
    '#search{background:rgba(255,255,255,.06);border:1px solid rgba(255,255,255,.12);\n'
    '        border-radius:6px;color:#cdd6e0;padding:5px 10px;font-size:12px;width:200px;outline:none}\n'
    '#search::placeholder{color:#4a6070}\n'
    '.pill{display:inline-flex;align-items:center;gap:5px;font-size:11px;padding:3px 8px;\n'
    '      border-radius:10px;cursor:pointer;border:1px solid rgba(255,255,255,.1);background:rgba(255,255,255,.05)}\n'
    '.pill span{width:8px;height:8px;border-radius:50%;display:inline-block}\n'
    '#tip{position:fixed;background:rgba(10,18,28,.95);border:1px solid rgba(74,158,218,.3);\n'
    '     border-radius:6px;padding:10px 14px;font-size:12px;line-height:1.6;\n'
    '     pointer-events:none;display:none;z-index:20;max-width:320px}\n'
    '#tip .tip-name{font-weight:700;color:#4a9eda;margin-bottom:4px;word-break:break-all}\n'
    '#tip .tip-row{color:#7f9db0}\n'
    '#tip .tip-row b{color:#cdd6e0}\n'
    '#legend{position:fixed;bottom:16px;left:16px;background:rgba(10,18,28,.88);\n'
    '        border:1px solid rgba(255,255,255,.08);border-radius:8px;padding:12px 16px;\n'
    '        max-height:40vh;overflow-y:auto;z-index:10;min-width:180px}\n'
    '#legend h3{font-size:11px;text-transform:uppercase;color:#4a6070;margin-bottom:8px;letter-spacing:.05em}\n'
    '.leg-row{display:flex;align-items:center;gap:8px;font-size:11px;color:#9db0c0;margin:3px 0;cursor:pointer}\n'
    '.leg-row:hover{color:#cdd6e0}\n'
    '.leg-dot{width:10px;height:10px;border-radius:50%;flex-shrink:0}\n'
    '#controls{position:fixed;bottom:16px;right:16px;display:flex;flex-direction:column;gap:6px;z-index:10}\n'
    '.ctrl-btn{background:rgba(10,18,28,.88);border:1px solid rgba(255,255,255,.1);border-radius:6px;\n'
    '          color:#cdd6e0;font-size:18px;width:34px;height:34px;cursor:pointer;\n'
    '          display:flex;align-items:center;justify-content:center}\n'
    '.ctrl-btn:hover{background:rgba(74,158,218,.2);border-color:#4a9eda}\n'
    '</style>\n'
    '</head>\n'
    '<body>\n'
    '<div id="hud">\n'
    '  <h1>⚡ Dependency Graph</h1>\n'
    '  <span class="stat"><b>REPO_PATH</b></span>\n'
    '  <span class="stat"><b>NODE_COUNT</b> nodes</span>\n'
    '  <span class="stat"><b>EDGE_COUNT</b> edges</span>\n'
    '  <span class="stat"><b>FILE_COUNT</b> files</span>\n'
    '  <input id="search" placeholder="Search function / file…" autocomplete="off">\n'
    '  <div style="display:flex;gap:8px;margin-left:auto">\n'
    '    <span class="pill"><span style="background:#4a9eda"></span>calls</span>\n'
    '    <span class="pill"><span style="background:#f39c12"></span>imports</span>\n'
    '    <span class="pill"><span style="background:#2ecc71"></span>handles</span>\n'
    '  </div>\n'
    '</div>\n'
    '<svg id="canvas"></svg>\n'
    '<div id="tip"></div>\n'
    '<div id="legend"><h3>Files</h3><div id="legend-body"></div></div>\n'
    '<div id="controls">\n'
    '  <button class="ctrl-btn" id="btn-fit" title="Fit to screen">⊟</button>\n'
    '  <button class="ctrl-btn" id="btn-reset" title="Reset selection">✕</button>\n'
    '</div>\n'
    '<script>\n'
    'const NODES = NODES_DATA;\n'
    'const EDGES = EDGES_DATA;\n'
    'const LEGEND = LEGEND_DATA;\n'
    '\n'
    'const svg = d3.select(\'#canvas\');\n'
    'svg.attr(\'width\', window.innerWidth).attr(\'height\', window.innerHeight);\n'
    'const g = svg.append(\'g\');\n'
    '\n'
    '// FIX 1: viewport dims always fresh\n'
    'const vw = () => window.innerWidth;\n'
    'const vh = () => window.innerHeight;\n'
    '\n'
    'const zoom = d3.zoom().scaleExtent([.05,8]).on(\'zoom\', e => g.attr(\'transform\', e.transform));\n'
    'svg.call(zoom);\n'
    '\n'
    'function fitView() {\n'
    '  const bounds = g.node().getBBox();\n'
    '  if (!bounds.width || !bounds.height) return;\n'
    '  const pad = 60, W = vw(), H = vh();\n'
    '  const scale = Math.min((W-pad*2)/bounds.width, (H-pad*2)/bounds.height, 1.5);\n'
    '  const tx = W/2 - scale*(bounds.x + bounds.width/2);\n'
    '  const ty = H/2 - scale*(bounds.y + bounds.height/2);\n'
    '  svg.transition().duration(600).call(zoom.transform, d3.zoomIdentity.translate(tx,ty).scale(scale));\n'
    '}\n'
    '\n'
    '// FIX 4: pan camera to a node or centroid\n'
    'function panToNode(d) {\n'
    '  if (d.x == null || d.y == null) return;\n'
    '  const W = vw(), H = vh(), scale = 1.5;\n'
    '  svg.transition().duration(500).call(zoom.transform,\n'
    '    d3.zoomIdentity.translate(W/2 - scale*d.x, H/2 - scale*d.y).scale(scale));\n'
    '}\n'
    '\n'
    'document.getElementById(\'btn-fit\').addEventListener(\'click\', fitView);\n'
    'document.getElementById(\'btn-reset\').addEventListener(\'click\', () => {\n'
    '  setHighlight(null, null); document.getElementById(\'search\').value = \'\';\n'
    '});\n'
    '\n'
    'const sim = d3.forceSimulation(NODES)\n'
    '  .force(\'link\', d3.forceLink(EDGES).id(d=>d.id).distance(d=>d.dashed?90:55).strength(0.5))\n'
    '  .force(\'charge\', d3.forceManyBody().strength(-180))\n'
    '  .force(\'center\', d3.forceCenter(vw()/2, vh()/2))\n'
    '  .force(\'collide\', d3.forceCollide(d=>d.r+6));\n'
    '\n'
    'const defs = svg.append(\'defs\');\n'
    '[\'calls\',\'imports\',\'handles\'].forEach(k => {\n'
    '  const col = k===\'calls\'?\'#4a9eda\':k===\'imports\'?\'#f39c12\':\'#2ecc71\';\n'
    '  defs.append(\'marker\').attr(\'id\',\'arr-\'+k)\n'
    '    .attr(\'viewBox\',\'0 -4 8 8\').attr(\'refX\',14).attr(\'refY\',0)\n'
    '    .attr(\'markerWidth\',6).attr(\'markerHeight\',6).attr(\'orient\',\'auto\')\n'
    '    .append(\'path\').attr(\'d\',\'M0,-4L8,0L0,4\').attr(\'fill\',col).attr(\'opacity\',.7);\n'
    '});\n'
    '\n'
    'const link = g.append(\'g\').selectAll(\'line\').data(EDGES).enter().append(\'line\')\n'
    '  .attr(\'class\', d => \'link \'+d.kind)\n'
    '  .attr(\'stroke\', d => d.kind===\'calls\'?\'#4a9eda\':d.kind===\'imports\'?\'#f39c12\':\'#2ecc71\')\n'
    '  .attr(\'stroke-dasharray\', d => d.dashed?\'4,3\':null)\n'
    '  .attr(\'marker-end\', d => \'url(#arr-\'+d.kind+\')\');\n'
    '\n'
    'const node = g.append(\'g\').selectAll(\'g\').data(NODES).enter().append(\'g\')\n'
    '  .attr(\'class\',\'node\')\n'
    '  .call(d3.drag()\n'
    '    .on(\'drag\', (e,d)=>{ d.x=e.x; d.y=e.y; drawPositions(); }));\n'
    '\n'
    'node.append(\'circle\')\n'
    '  .attr(\'r\', d=>d.r).attr(\'fill\', d=>d.color)\n'
    '  .attr(\'stroke\', d=>d.kind===\'route\'?\'#fff\':\'#0f1923\')\n'
    '  .attr(\'stroke-width\', d=>d.kind===\'route\'?2:1.5);\n'
    '\n'
    'node.filter(d=>d.r>=7).append(\'text\')\n'
    '  .attr(\'dy\', d=>d.r+10).style(\'font-size\',\'9px\')\n'
    '  .text(d=>d.name.length>16?d.name.slice(0,15)+\'\\u2026\':d.name);\n'
    '\n'
    '// FIX 2: precompute adjacency map — O(1) neighbor lookup\n'
    'const adjMap = new Map();\n'
    'NODES.forEach(n => adjMap.set(n.id, new Set()));\n'
    'let adjReady = false;\n'
    'function buildAdj() {\n'
    '  if (adjReady) return;\n'
    '  EDGES.forEach(l => {\n'
    '    const s = typeof l.source===\'object\'?l.source.id:l.source;\n'
    '    const t = typeof l.target===\'object\'?l.target.id:l.target;\n'
    '    if (adjMap.has(s)) adjMap.get(s).add(t);\n'
    '    if (adjMap.has(t)) adjMap.get(t).add(s);\n'
    '  });\n'
    '  adjReady = true;\n'
    '}\n'
    '\n'
    'const tip = document.getElementById(\'tip\');\n'
    'node.on(\'mousemove\', function(e,d) {\n'
    '  buildAdj();\n'
    '  const nbrs = adjMap.get(d.id)||new Set();\n'
    '  tip.style.display=\'block\';\n'
    '  tip.style.left=(e.clientX+14)+\'px\';\n'
    '  tip.style.top=(e.clientY-10)+\'px\';\n'
    '  tip.textContent=\'\';\n'
    '  const _nm=document.createElement(\'div\'); _nm.className=\'tip-name\'; _nm.textContent=d.full; tip.appendChild(_nm);\n'
    '  const _mkr=(lab,val)=>{const r=document.createElement(\'div\');r.className=\'tip-row\';const b=document.createElement(\'b\');b.textContent=lab;r.appendChild(b);r.appendChild(document.createTextNode(\' \'+val));return r;};\n'
    '  tip.appendChild(_mkr(\'File:\',d.file));\n'
    '  const _kr=document.createElement(\'div\'); _kr.className=\'tip-row\';\n'
    '  const _kb=document.createElement(\'b\'); _kb.textContent=\'Kind:\'; _kr.appendChild(_kb); _kr.appendChild(document.createTextNode(\' \'+d.kind+\'  \'));\n'
    '  const _lnb=document.createElement(\'b\'); _lnb.textContent=\'Line:\'; _kr.appendChild(_lnb); _kr.appendChild(document.createTextNode(\' \'+d.line)); tip.appendChild(_kr);\n'
    '  tip.appendChild(_mkr(\'Connections:\',nbrs.size));\n'
    '}).on(\'mouseleave\', ()=>tip.style.display=\'none\');\n'
    '\n'
    'let selected = null;\n'
    '// FIX 2+3: highlight uses adjMap; fileNodes = Set of ids for legend\n'
    'function setHighlight(d, fileNodes) {\n'
    '  selected = d;\n'
    '  if (!d && !fileNodes) {\n'
    '    node.selectAll(\'circle\').classed(\'dim\',false);\n'
    '    link.classed(\'dim\',false); return;\n'
    '  }\n'
    '  buildAdj();\n'
    '  let ids;\n'
    '  if (fileNodes) {\n'
    '    ids = new Set(fileNodes);\n'
    '    fileNodes.forEach(id => (adjMap.get(id)||new Set()).forEach(n=>ids.add(n)));\n'
    '  } else {\n'
    '    ids = new Set([d.id, ...(adjMap.get(d.id)||new Set())]);\n'
    '  }\n'
    '  node.selectAll(\'circle\').classed(\'dim\', n=>!ids.has(n.id));\n'
    '  link.classed(\'dim\', l=>{\n'
    '    const s=typeof l.source===\'object\'?l.source.id:l.source;\n'
    '    const t=typeof l.target===\'object\'?l.target.id:l.target;\n'
    '    return !ids.has(s)||!ids.has(t);\n'
    '  });\n'
    '}\n'
    '\n'
    'node.on(\'click\',(e,d)=>{ e.stopPropagation(); setHighlight(selected===d?null:d,null); });\n'
    'svg.on(\'click\',()=>setHighlight(null,null));\n'
    '\n'
    '// Frozen layout: compute positions headless once, render statically. No\n'
    '// per-frame animation -> large graphs open without locking the tab.\n'
    'function drawPositions(){\n'
    '  link.attr(\'x1\',d=>d.source.x).attr(\'y1\',d=>d.source.y)\n'
    '      .attr(\'x2\',d=>d.target.x).attr(\'y2\',d=>d.target.y);\n'
    '  node.attr(\'transform\',d=>\'translate(\'+d.x+\',\'+d.y+\')\');\n'
    '}\n'
    'sim.stop();\n'
    'for(let i=0;i<300;i++) sim.tick();\n'
    'drawPositions();\n'
    'fitView();\n'
    '\n'
    '// FIX 4: search highlights + pans camera\n'
    'document.getElementById(\'search\').addEventListener(\'input\',function(){\n'
    '  const q=this.value.trim().toLowerCase();\n'
    '  if(!q){setHighlight(null,null);return;}\n'
    '  const m=NODES.find(n=>n.name.toLowerCase().includes(q)||n.file.toLowerCase().includes(q)||n.full.toLowerCase().includes(q));\n'
    '  if(m){setHighlight(m,null);panToNode(m);}\n'
    '});\n'
    '\n'
    '// FIX 3: legend highlights ALL nodes in file + pans to centroid\n'
    'const lb=document.getElementById(\'legend-body\');\n'
    'LEGEND.forEach(row=>{\n'
    '  const el=document.createElement(\'div\');\n'
    '  el.className=\'leg-row\';\n'
    '  const _dot=document.createElement(\'span\'); _dot.className=\'leg-dot\'; _dot.style.background=row.color; el.appendChild(_dot);\n'
    '  const _nm2=document.createElement(\'span\'); _nm2.textContent=row.file.split(\'/\').pop(); el.appendChild(_nm2);\n'
    '  const _ct=document.createElement(\'span\'); _ct.style.cssText=\'margin-left:auto;color:#4a6070\'; _ct.textContent=row.count; el.appendChild(_ct);\n'
    '  el.addEventListener(\'click\',()=>{\n'
    '    const ids=new Set(NODES.filter(n=>n.file===row.file).map(n=>n.id));\n'
    '    setHighlight(null,ids);\n'
    '    const fn=NODES.filter(n=>n.file===row.file&&n.x!=null);\n'
    '    if(fn.length) panToNode({x:fn.reduce((s,n)=>s+n.x,0)/fn.length,y:fn.reduce((s,n)=>s+n.y,0)/fn.length});\n'
    '  });\n'
    '  lb.appendChild(el);\n'
    '});\n'
    '\n'
    '// Resize only updates the SVG viewport; layout is frozen so no re-simulation.\n'
    'window.addEventListener(\'resize\',()=>{\n'
    '  svg.attr(\'width\',vw()).attr(\'height\',vh());\n'
    '});\n'
    '</script>\n'
    '</body>\n'
    '</html>\n'
)


def _render(
    nodes: list[dict],
    edges: list[dict],
    legend_items: str,
    stats: dict,
    repo_path: str,
) -> str:
    html = _HTML_TEMPLATE
    html = html.replace("NODES_DATA", json.dumps(nodes))
    html = html.replace("EDGES_DATA", json.dumps(edges))
    html = html.replace("LEGEND_DATA", legend_items)
    html = html.replace("REPO_PATH", repo_path.replace("\\", "/") or "—")
    html = html.replace("NODE_COUNT", str(stats["nodes"]))
    html = html.replace("EDGE_COUNT", str(stats["edges"]))
    html = html.replace("FILE_COUNT", str(stats["files"]))
    # D3 inlined last: its minified source must not be re-scanned for placeholders.
    html = html.replace("D3_SCRIPT_TAG", _d3_script_tag())
    return html
