import sys
from pathlib import Path

# Thêm thư mục gốc vào sys.path để có thể import radar
root_dir = Path(__file__).parent.parent.parent.resolve()
sys.path.insert(0, str(root_dir))

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import subprocess

# Import kiến trúc multi-engine mà bạn vừa bàn giao
from radar.scan.engines import all_engines

app = FastAPI(title="Radar Security Dashboard API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/api/engines")
def get_engines():
    """Lấy danh sách các công cụ quét đang được đăng ký (Semgrep, Gitleaks...)"""
    engines = all_engines()
    return [
        {
            "name": getattr(eng, 'name', type(eng).__name__), 
            "default": getattr(eng, 'default', True), 
            "description": getattr(eng, 'description', '')
        } 
        for eng in engines
    ]

@app.get("/api/repos")
def get_repos():
    """Lấy danh sách các repository đã tải về trong thư mục analysis_repos"""
    repo_dir = root_dir / "analysis_repos"
    if not repo_dir.exists():
        return []
    repos = []
    for d in repo_dir.iterdir():
        if d.is_dir() and (d / ".git").exists():
            repos.append(d.name)
    return repos

@app.get("/api/branches")
def get_branches(repo: str):
    """Lấy danh sách các nhánh (branch) của một repository"""
    repo_dir = root_dir / "analysis_repos" / repo
    if not repo_dir.exists():
        return {"error": "Repo not found"}
    try:
        out = subprocess.check_output(["git", "branch", "-a"], cwd=repo_dir, text=True)
        branches = [line.strip().replace("* ", "").split(" -> ")[0] for line in out.splitlines() if line.strip()]
        # Lọc nhánh trùng lặp và bỏ remote tracking "remotes/origin/"
        clean_branches = list(set(b.replace("remotes/origin/", "") for b in branches if "HEAD" not in b))
        return {"branches": sorted(clean_branches)}
    except Exception as e:
        return {"error": str(e)}

class ScanRequest(BaseModel):
    repo_url_or_name: str
    branch: str = ""
    engines: list[str]
    target_type: str = "none"  # none, diff, function, node
    target_value: str = ""

import queue
import threading
import uuid
import re
import asyncio
import os
import shutil
from sse_starlette.sse import EventSourceResponse
from fastapi.responses import JSONResponse

streams = {}
results_db = {}

@app.post("/api/scan")
def run_scan(req: ScanRequest):
    """Kích hoạt quét thật, hỗ trợ clone github và trả về JSON thô"""
    scan_id = str(uuid.uuid4())
    log_queue = queue.Queue()
    streams[scan_id] = log_queue
    
    def emit(msg):
        clean_msg = re.sub(r'\[/?.*?\]', '', msg)
        log_queue.put(clean_msg)
        
    def _run():
        try:
            repo_dir = root_dir / "analysis_repos"
            repo_dir.mkdir(exist_ok=True)
            
            # Xử lý Clone GitHub hoặc dùng Repo Local
            is_url = req.repo_url_or_name.startswith("http") or req.repo_url_or_name.startswith("git@")
            if is_url:
                repo_name = req.repo_url_or_name.rstrip("/").split("/")[-1]
                if repo_name.endswith(".git"):
                    repo_name = repo_name[:-4]
                target = repo_dir / repo_name
                
                if not target.exists():
                    emit(f"> Đang clone từ GitHub: {req.repo_url_or_name}...")
                    subprocess.run(["git", "clone", req.repo_url_or_name, str(target)], check=True, capture_output=True)
                else:
                    emit(f"> Repo {repo_name} đã tồn tại, đang fetch update...")
                    subprocess.run(["git", "fetch", "--all"], cwd=target, check=True, capture_output=True)
            else:
                target = repo_dir / req.repo_url_or_name
                if not target.exists():
                    emit(f"> Lỗi: Không tìm thấy thư mục {req.repo_url_or_name}")
                    log_queue.put("DONE")
                    return
            
            # Checkout nhánh
            if req.branch:
                emit(f"> Chuyển sang nhánh '{req.branch}'...")
                subprocess.run(["git", "checkout", req.branch], cwd=target, capture_output=True)
            
            emit(f"> Nạp các engine: {', '.join(req.engines)}")
            
            from radar.scan.engines import scan_all
            findings, runs = scan_all(target, engines=req.engines, emit=emit)
            emit(f"> Hoàn tất quét! Phát hiện tổng cộng {len(findings)} vấn đề.")
            emit(f"> Trạng thái engine: " + " ".join([f"[{r.name}:{r.status}]" for r in runs]))
            
            emit("> Đang dựng bản đồ mã nguồn (Graph) - Quá trình này có thể tốn vài phút...")
            from radar.impact.diff_mapper import changed_lines, map_to_nodes, find_function_nodes
            from radar.impact.tracer import trace
            from radar.graph.builder import build_graph
            
            g = build_graph(target)
            trace_res = None
            
            try:
                if req.target_type == "none":
                    pass # Không phân tích Blast Radius
                elif req.target_type == "function" and req.target_value:
                    emit(f"> Tracing hàm cụ thể: {req.target_value}...")
                    node_ids = find_function_nodes(g, req.target_value)
                    if node_ids:
                        trace_res = trace(g, node_ids)
                elif req.target_type == "node" and req.target_value:
                    emit(f"> Tracing Node/File cụ thể: {req.target_value}...")
                    matches = [n for n in g.nodes if req.target_value in n]
                    if matches:
                        trace_res = trace(g, matches)
                elif req.target_type == "diff": 
                    # Tự động dò nhánh chính
                    try:
                        subprocess.run(["git", "rev-parse", "--verify", "origin/main"], cwd=target, check=True, capture_output=True)
                        base = "origin/main"
                    except:
                        try:
                            subprocess.run(["git", "rev-parse", "--verify", "origin/master"], cwd=target, check=True, capture_output=True)
                            base = "origin/master"
                        except:
                            base = "HEAD~1"
                    
                    rev = req.target_value or f"{base}...HEAD"
                    emit(f"> Phân tích ảnh hưởng của các thay đổi (Diff: {rev})...")
                    
                    try:
                        changes = changed_lines(target, rev=rev)
                        if changes:
                            node_ids = map_to_nodes(g, changes)
                            if node_ids:
                                trace_res = trace(g, node_ids)
                            else:
                                emit("> Các thay đổi không nằm trong node/hàm nào cụ thể.")
                        else:
                            emit("> Không phát hiện thay đổi nào giữa 2 nhánh.")
                    except Exception as diff_err:
                        emit(f"> Lỗi lệnh git diff ({rev}): {diff_err}")
            except Exception as e:
                emit(f"> Cảnh báo: Lỗi tính toán Blast Radius: {e}")
            
            # Chuẩn bị JSON trả về
            # Trích xuất dữ liệu thô để Frontend tự vẽ
            findings_data = [
                {
                    "severity": f.severity,
                    "engine": f.metadata.get("engine", "unknown"),
                    "rule": f.rule,
                    "path": f.path,
                    "line": f.line,
                    "message": f.message,
                    "cwe": f.metadata.get("cwe", ""),
                    "owasp": f.metadata.get("owasp", "")
                } for f in findings
            ]
            
            blast_data = {"nodes": [], "edges": [], "stats": {}, "affected": [], "changed": [], "apis": [], "features": []}
            if trace_res:
                blast_data["stats"] = trace_res.stats
                blast_data["stats"]["changed_nodes"] = len(trace_res.changed)
                blast_data["apis"] = trace_res.apis
                blast_data["features"] = trace_res.features
                blast_data["changed"] = [
                    {"id": i.id, "name": i.name, "kind": i.kind, "file": i.file, "line": i.line}
                    for i in trace_res.changed
                ]
                blast_data["affected"] = [
                    {"id": i.id, "name": i.name, "kind": i.kind, "file": i.file, "line": i.line, "confidence": i.confidence}
                    for i in trace_res.affected
                ]
                
                # Dựng mảng D3 nodes và edges
                import networkx as nx
                from radar.graph.graph_viz import _short_name
                
                all_ids = {item.id for item in trace_res.changed + trace_res.affected}
                sub = nx.DiGraph()
                for item in trace_res.changed + trace_res.affected:
                    sub.add_node(item.id, name=item.name, kind=item.kind, file=item.file, start_line=item.line)
                for item in trace_res.affected:
                    if item.parent and item.parent in all_ids:
                        sub.add_edge(item.parent, item.id, kind="calls")

                _PALETTE = [
                    "#3498db","#e74c3c","#2ecc71","#f39c12","#9b59b6",
                    "#1abc9c","#e67e22","#34495e","#e91e63","#00bcd4",
                    "#8bc34a","#ff5722","#607d8b","#795548","#ffc107",
                    "#673ab7","#009688","#ff9800","#4caf50","#f44336",
                ]
                _fc = {}
                def _col(f):
                    if f not in _fc:
                        _fc[f] = _PALETTE[len(_fc) % len(_PALETTE)]
                    return _fc[f]

                nidx = {}
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
                
                blast_data["nodes"] = ns_out
                blast_data["edges"] = es_out
            
            results_db[scan_id] = {
                "findings": findings_data,
                "blast_radius": blast_data,
                "summary": {
                    "total": len(findings),
                    "repo": str(target.name)
                }
            }
            
            emit("READY")
            log_queue.put("DONE")
        except Exception as e:
            emit(f"> LỖI HỆ THỐNG QUÉT: {str(e)}")
            log_queue.put("DONE")
            
    threading.Thread(target=_run, daemon=True).start()
    return {"scan_id": scan_id}

@app.get("/api/results/{scan_id}")
def get_results(scan_id: str):
    data = results_db.get(scan_id)
    if data:
        return JSONResponse(content=data)
    return JSONResponse(content={"error": "Results not found"}, status_code=404)

@app.get("/api/stream/{scan_id}")
async def stream_logs(scan_id: str):
    """Truyền log dạng SSE xuống frontend"""
    log_queue = streams.get(scan_id)
    if not log_queue:
        return {"error": "Mã quét không hợp lệ"}
        
    async def event_generator():
        while True:
            try:
                msg = log_queue.get_nowait()
                if msg == "DONE":
                    break
                yield {"data": msg}
            except queue.Empty:
                await asyncio.sleep(0.1)
                
    return EventSourceResponse(event_generator())
