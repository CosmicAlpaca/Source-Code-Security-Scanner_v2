/* radar serve — live dashboard client (vanilla JS, no framework).
 *
 * - EventSource('/events') streams panel updates; we swap each panel's innerHTML.
 * - /api/state fills panels on first load (before any SSE event arrives).
 * - Chart.js draws the overview donuts + history line from pushed `charts` data.
 * - D3 (re)seeds the force graph in place from the `graph` payload.
 * - The triage button POSTs /api/triage; results stream back over SSE.
 */
(function () {
  "use strict";

  var _charts = {}; // id -> Chart instance (destroyed before redraw)
  var _graphState = null; // remembered D3 positions so nodes don't jump on refresh

  // ── status banner ─────────────────────────────────────────────────────────
  function setStatus(text, level) {
    var banner = document.getElementById("status-banner");
    banner.dataset.level = level || "ok";
    document.getElementById("status-text").textContent = text;
  }

  // ── chart rendering (overview + history) ───────────────────────────────────
  function destroyChart(id) {
    if (_charts[id]) { _charts[id].destroy(); delete _charts[id]; }
  }
  var DONUT = ["#ef4444","#f97316","#eab308","#22c55e","#3b82f6","#8b5cf6","#ec4899","#14b8a6","#f59e0b","#6366f1"];

  function drawOverviewCharts(c) {
    if (typeof Chart === "undefined" || !c) return;
    document.querySelectorAll("[data-count]").forEach(function (el) {
      el.textContent = el.dataset.count;
    });
    var ow = document.getElementById("owaspChart");
    if (ow && c.owasp_labels && c.owasp_labels.length) {
      destroyChart("owasp");
      _charts.owasp = new Chart(ow, {
        type: "doughnut",
        data: { labels: c.owasp_labels, datasets: [{ data: c.owasp_vals, backgroundColor: DONUT.slice(0, c.owasp_labels.length), borderWidth: 0, hoverOffset: 6 }] },
        options: { responsive: true, plugins: { legend: { position: "right", labels: { color: "#94a3b8", font: { size: 11 }, usePointStyle: true, padding: 12 } } }, cutout: "68%" }
      });
    }
    var sv = document.getElementById("sevChart");
    if (sv && c.sev) {
      destroyChart("sev");
      _charts.sev = new Chart(sv, {
        type: "doughnut",
        data: { labels: ["ERROR", "WARNING", "INFO"], datasets: [{ data: c.sev, backgroundColor: ["#ef4444", "#f97316", "#3b82f6"], borderWidth: 0, hoverOffset: 6 }] },
        options: { responsive: true, plugins: { legend: { position: "right", labels: { color: "#94a3b8", font: { size: 11 }, usePointStyle: true, padding: 12 } } }, cutout: "68%" }
      });
    }
  }

  function drawHistoryChart(c) {
    if (typeof Chart === "undefined" || !c || !c.history || !c.history.length) return;
    var h = document.getElementById("hChart");
    if (!h) return;
    destroyChart("hist");
    Chart.defaults.color = "#94a3b8";
    _charts.hist = new Chart(h, {
      type: "line",
      data: {
        labels: c.history.map(function (e) { return e.ts; }),
        datasets: [
          { label: "ERROR", data: c.history.map(function (e) { return e.error; }), borderColor: "#ef4444", backgroundColor: "rgba(239,68,68,.08)", tension: .4, fill: true, pointBackgroundColor: "#ef4444" },
          { label: "WARNING", data: c.history.map(function (e) { return e.warning; }), borderColor: "#f97316", backgroundColor: "rgba(249,115,22,.08)", tension: .4, fill: true, pointBackgroundColor: "#f97316" }
        ]
      },
      options: { responsive: true, interaction: { intersect: false, mode: "index" }, plugins: { legend: { position: "top", labels: { color: "#94a3b8", usePointStyle: true } } }, scales: { x: { ticks: { color: "#64748b" }, grid: { color: "rgba(255,255,255,.04)" } }, y: { beginAtZero: true, ticks: { color: "#64748b", stepSize: 1 }, grid: { color: "rgba(255,255,255,.04)" } } } }
    });
  }

  // ── D3 force graph (re-seeds in place; remembers positions) ─────────────────
  function renderGraph(payload) {
    if (typeof d3 === "undefined" || !payload || !payload.nodes) return;
    var stats = payload.stats || {};
    document.getElementById("graph-stats").textContent =
      (stats.nodes || 0) + " nodes · " + (stats.edges || 0) + " edges · " + (stats.routes || 0) + " routes";

    var prev = {};
    if (_graphState) { _graphState.forEach(function (n) { prev[n.nid] = { x: n.x, y: n.y }; }); }

    var NODES = payload.nodes.map(function (n) {
      var p = prev[n.nid];
      return Object.assign({}, n, p ? { x: p.x, y: p.y } : {});
    });
    var EDGES = payload.edges.map(function (e) { return { source: e.source, target: e.target, kind: e.kind, dashed: e.dashed }; });
    _graphState = NODES;

    var svg = d3.select("#graph-canvas");
    svg.selectAll("*").remove();
    var W = svg.node().getBoundingClientRect().width || 900, H = 600;
    svg.attr("width", W).attr("height", H);
    var g = svg.append("g");
    var zoom = d3.zoom().scaleExtent([.05, 8]).on("zoom", function (e) { g.attr("transform", e.transform); });
    svg.call(zoom);

    var sim = d3.forceSimulation(NODES)
      .force("link", d3.forceLink(EDGES).id(function (d) { return d.id; }).distance(function (d) { return d.dashed ? 90 : 55; }).strength(0.5))
      .force("charge", d3.forceManyBody().strength(-160))
      .force("center", d3.forceCenter(W / 2, H / 2))
      .force("collide", d3.forceCollide(function (d) { return d.r + 5; }));

    var defs = svg.append("defs");
    ["calls", "imports", "handles"].forEach(function (k) {
      var col = k === "calls" ? "#4a9eda" : k === "imports" ? "#f39c12" : "#2ecc71";
      defs.append("marker").attr("id", "garr-" + k).attr("viewBox", "0 -4 8 8").attr("refX", 14).attr("refY", 0)
        .attr("markerWidth", 6).attr("markerHeight", 6).attr("orient", "auto")
        .append("path").attr("d", "M0,-4L8,0L0,4").attr("fill", col).attr("opacity", .7);
    });

    var link = g.append("g").selectAll("line").data(EDGES).enter().append("line")
      .attr("stroke", function (d) { return d.kind === "calls" ? "#4a9eda" : d.kind === "imports" ? "#f39c12" : "#2ecc71"; })
      .attr("stroke-opacity", .55).attr("stroke-width", function (d) { return d.kind === "handles" ? 1.4 : 1.2; })
      .attr("stroke-dasharray", function (d) { return d.dashed ? "4,3" : null; })
      .attr("marker-end", function (d) { return "url(#garr-" + d.kind + ")"; });

    var node = g.append("g").selectAll("g").data(NODES).enter().append("g")
      .call(d3.drag()
        .on("start", function (e, d) { if (!e.active) sim.alphaTarget(.3).restart(); d.fx = d.x; d.fy = d.y; })
        .on("drag", function (e, d) { d.fx = e.x; d.fy = e.y; })
        .on("end", function (e, d) { if (!e.active) sim.alphaTarget(0); d.fx = null; d.fy = null; }));
    node.append("circle").attr("r", function (d) { return d.r; }).attr("fill", function (d) { return d.color; })
      .attr("stroke", function (d) { return d.kind === "route" ? "#fff" : "#0f1923"; })
      .attr("stroke-width", function (d) { return d.kind === "route" ? 2 : 1.5; });
    node.filter(function (d) { return d.r >= 7; }).append("text")
      .attr("dy", function (d) { return d.r + 10; }).attr("text-anchor", "middle")
      .style("font-size", "9px").style("fill", "#cdd6e0").style("pointer-events", "none")
      .text(function (d) { return d.name.length > 18 ? d.name.slice(0, 17) + "…" : d.name; });

    var tip = document.getElementById("graph-tip");
    node.on("mousemove", function (e, d) {
      tip.style.display = "block"; tip.style.left = (e.offsetX + 14) + "px"; tip.style.top = (e.offsetY - 10) + "px";
      // textContent — node name/file come from the scanned (untrusted) repo, never innerHTML.
      tip.textContent = "";
      var name = document.createElement("b"); name.style.color = "#4a9eda"; name.textContent = d.full;
      var file = document.createElement("span"); file.style.color = "#7f9db0"; file.textContent = "File: " + d.file;
      var meta = document.createElement("span"); meta.style.color = "#7f9db0";
      meta.textContent = "Kind: " + d.kind + " | Line: " + d.line;
      tip.appendChild(name); tip.appendChild(document.createElement("br"));
      tip.appendChild(file); tip.appendChild(document.createElement("br")); tip.appendChild(meta);
    }).on("mouseleave", function () { tip.style.display = "none"; });

    sim.on("tick", function () {
      link.attr("x1", function (d) { return d.source.x; }).attr("y1", function (d) { return d.source.y; })
        .attr("x2", function (d) { return d.target.x; }).attr("y2", function (d) { return d.target.y; });
      node.attr("transform", function (d) { return "translate(" + d.x + "," + d.y + ")"; });
    });
    sim.on("end", function () {
      var b = g.node().getBBox(); if (!b.width || !b.height) return;
      var pad = 40, sc = Math.min((W - pad * 2) / b.width, (H - pad * 2) / b.height, 1.5);
      var tx = W / 2 - sc * (b.x + b.width / 2), ty = H / 2 - sc * (b.y + b.height / 2);
      svg.transition().duration(600).call(zoom.transform, d3.zoomIdentity.translate(tx, ty).scale(sc));
    });

    var search = document.getElementById("graph-search");
    if (search) {
      search.oninput = function () {
        var q = this.value.trim().toLowerCase();
        node.selectAll("circle").attr("opacity", function (d) {
          return (!q || d.name.toLowerCase().includes(q) || (d.file || "").toLowerCase().includes(q)) ? 1 : .08;
        });
      };
    }
  }

  // ── panel swap helpers ──────────────────────────────────────────────────────
  function swap(id, html) {
    var el = document.getElementById(id);
    if (el) el.innerHTML = html;
  }
  function updateFindingCount() {
    var n = document.querySelectorAll("#panel-findings .finding-row").length;
    var c = document.getElementById("cnt-findings");
    if (c) c.textContent = n;
  }

  function applyState(s) {
    if (!s) return;
    if (s.panels) {
      swap("panel-overview", s.panels.overview || "");
      swap("panel-findings", s.panels.findings || "");
      swap("panel-blast", s.panels.blast || "");
      swap("panel-history", s.panels.history || "");
    }
    if (s.charts) { drawOverviewCharts(s.charts); drawHistoryChart(s.charts); }
    if (s.graph) renderGraph(s.graph);
    updateFindingCount();
  }

  // ── SSE wiring ──────────────────────────────────────────────────────────────
  function connect() {
    var es = new EventSource("/events");

    es.addEventListener("findings", function (ev) {
      swap("panel-findings", JSON.parse(ev.data).html); updateFindingCount();
    });
    es.addEventListener("overview", function (ev) {
      var d = JSON.parse(ev.data); swap("panel-overview", d.html); drawOverviewCharts(d.charts);
    });
    es.addEventListener("blast", function (ev) {
      swap("panel-blast", JSON.parse(ev.data).html);
    });
    es.addEventListener("history", function (ev) {
      var d = JSON.parse(ev.data); swap("panel-history", d.html); drawHistoryChart(d.charts);
    });
    es.addEventListener("graph", function (ev) { renderGraph(JSON.parse(ev.data)); });
    es.addEventListener("status", function (ev) {
      var d = JSON.parse(ev.data); setStatus(d.text + (d.ts ? "  ·  " + d.ts : ""), d.level);
    });
    es.onerror = function () { setStatus("reconnecting…", "warn"); };
    es.onopen = function () { setStatus("idle", "ok"); };
  }

  // ── triage button ───────────────────────────────────────────────────────────
  window.runTriage = function () {
    var btn = document.getElementById("triage-btn");
    btn.disabled = true; setStatus("running AI triage…", "busy");
    fetch("/api/triage", { method: "POST" })
      .catch(function () { setStatus("triage request failed", "err"); })
      .finally(function () { setTimeout(function () { btn.disabled = false; }, 2000); });
  };

  // ── boot ─────────────────────────────────────────────────────────────────────
  function boot() {
    fetch("/api/state").then(function (r) { return r.json(); })
      .then(function (s) {
        var rp = document.getElementById("repo-path");
        if (rp && s.graph && s.graph.repo_path) rp.textContent = s.graph.repo_path;
        applyState(s);
      })
      .catch(function () { /* events will fill in */ })
      .finally(connect);
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", boot);
  else boot();
})();
