"""Stdlib HTTP + SSE server for `radar serve` — zero new dependencies.

Routes (bound to 127.0.0.1 ONLY):
    GET  /            → dashboard shell HTML
    GET  /events      → Server-Sent-Events stream (kept open, fed by Broadcaster)
    GET  /api/state   → JSON snapshot of current State
    POST /api/triage  → trigger on-demand AI triage (never 500s)
    POST /api/impact  → switch Blast trace mode (changes/file/findings/function)
    GET  /static/*    → package assets (app.js/app.css) + vendored D3
"""

from __future__ import annotations

import importlib.resources as resources
import socket
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from radar.serve.orchestrator import Orchestrator

_HOST = "127.0.0.1"


def _log(msg: str) -> None:
    """Console print that never crashes on a non-UTF-8 terminal (Windows cp1252)."""
    try:
        print(msg)
    except UnicodeEncodeError:
        import sys
        sys.stdout.buffer.write(msg.encode("utf-8", "replace") + b"\n")
        sys.stdout.flush()

_CONTENT_TYPES = {
    ".js": "application/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".html": "text/html; charset=utf-8",
    ".json": "application/json; charset=utf-8",
}


class Broadcaster:
    """Thread-safe registry of open SSE client streams."""

    def __init__(self) -> None:
        self._clients: list = []  # list of wfile (BufferedWriter)
        self._lock = threading.Lock()

    def register(self, wfile) -> None:
        with self._lock:
            self._clients.append(wfile)

    def unregister(self, wfile) -> None:
        with self._lock:
            if wfile in self._clients:
                self._clients.remove(wfile)

    def push(self, event: str, data: str) -> None:
        """Write one SSE frame to every client; prune any that have died.

        `data` is sent on a single `data:` line (callers JSON-encode it so it
        never contains a raw newline that would split the frame).
        """
        frame = f"event: {event}\ndata: {data}\n\n".encode("utf-8")
        with self._lock:
            dead = []
            for wfile in self._clients:
                try:
                    wfile.write(frame)
                    wfile.flush()
                except (BrokenPipeError, ConnectionError, ValueError, OSError):
                    dead.append(wfile)
            for d in dead:
                self._clients.remove(d)


def _load_static(name: str) -> tuple[bytes, str] | None:
    """Return (bytes, content_type) for a /static asset, or None if not found.

    Serves files packaged under radar.serve.static plus the vendored D3 from
    radar.graph.vendor. Path-traversal safe: only a bare filename is honoured.
    """
    # Reject traversal / nesting — only flat filenames are valid asset names.
    if not name or "/" in name or "\\" in name or ".." in name:
        return None
    ctype = _CONTENT_TYPES.get(Path(name).suffix, "application/octet-stream")

    if name == "d3.v7.min.js":
        try:
            data = (resources.files("radar.graph") / "vendor" / "d3.v7.min.js").read_bytes()
            return data, ctype
        except (FileNotFoundError, ModuleNotFoundError, OSError):
            return None
    try:
        res = resources.files("radar.serve") / "static" / name
        if not res.is_file():
            return None
        return res.read_bytes(), ctype
    except (FileNotFoundError, ModuleNotFoundError, OSError):
        return None


def _shell_html() -> bytes:
    """Shell page with report.py's shared CSS + tab JS inlined (DRY — one source)."""
    from radar.scan import report as report_mod

    tpl = (resources.files("radar.serve") / "templates" / "shell.html").read_text(encoding="utf-8")
    tpl = tpl.replace("/*__SHARED_CSS__*/", report_mod._CSS)
    tpl = tpl.replace("/*__SHARED_JS__*/", report_mod._DASHBOARD_JS)
    return tpl.encode("utf-8")


def make_handler(broadcaster: Broadcaster, orch: Orchestrator):
    """Build a request-handler class closed over the broadcaster + orchestrator."""

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args) -> None:  # silence default stderr spam
            pass

        # ── helpers ──────────────────────────────────────────────────────────
        def _send(self, code: int, body: bytes, ctype: str) -> None:
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        # ── routing ──────────────────────────────────────────────────────────
        def do_GET(self) -> None:  # noqa: N802
            path = self.path.split("?", 1)[0]
            if path == "/":
                try:
                    self._send(200, _shell_html(), "text/html; charset=utf-8")
                except OSError:
                    self._send(500, b"shell template missing", "text/plain; charset=utf-8")
            elif path == "/events":
                self._serve_events()
            elif path == "/api/state":
                self._send(200, orch.state_json().encode("utf-8"),
                           "application/json; charset=utf-8")
            elif path.startswith("/static/"):
                self._serve_static(path[len("/static/"):])
            else:
                self._send(404, b"not found", "text/plain; charset=utf-8")

        def do_POST(self) -> None:  # noqa: N802
            from urllib.parse import parse_qs, urlsplit

            path = self.path.split("?", 1)[0]
            if path == "/api/triage":
                # Triage runs in a worker so the response returns immediately;
                # results stream back over SSE. Never 500s on a missing key.
                threading.Thread(target=orch.run_triage, daemon=True).start()
                self._send(202, b'{"status":"started"}', "application/json; charset=utf-8")
            elif path == "/api/impact":
                # Switch the Blast tab's trace source (changes / file / findings /
                # function). Cheap (cached graph + BFS) — runs in a worker, streams
                # the blast panel back over SSE. Never 500s.
                qs = parse_qs(urlsplit(self.path).query)
                mode = (qs.get("mode") or ["changes"])[0]
                fn = (qs.get("function") or [None])[0]
                threading.Thread(target=orch.set_impact_mode, args=(mode, fn),
                                 daemon=True).start()
                self._send(202, b'{"status":"started"}', "application/json; charset=utf-8")
            else:
                self._send(404, b"not found", "text/plain; charset=utf-8")

        # ── SSE ──────────────────────────────────────────────────────────────
        def _serve_events(self) -> None:
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "keep-alive")
            self.send_header("X-Accel-Buffering", "no")
            self.end_headers()
            try:
                self.wfile.write(b": connected\n\n")
                self.wfile.flush()
            except OSError:
                return
            broadcaster.register(self.wfile)
            try:
                # Block this worker thread, keeping the socket open. The
                # Broadcaster writes frames from other threads. Heartbeat keeps
                # proxies/sockets from idling out and detects a dead client.
                while not self.server._stop.is_set():
                    if not self.server._stop.wait(15):
                        try:
                            self.wfile.write(b": ping\n\n")
                            self.wfile.flush()
                        except OSError:
                            break
            finally:
                broadcaster.unregister(self.wfile)

        def _serve_static(self, name: str) -> None:
            loaded = _load_static(name)
            if loaded is None:
                self._send(404, b"not found", "text/plain; charset=utf-8")
                return
            body, ctype = loaded
            self._send(200, body, ctype)

    return Handler


class _DashboardServer(ThreadingHTTPServer):
    """ThreadingHTTPServer that swallows benign client-disconnect tracebacks."""

    daemon_threads = True

    def handle_error(self, request, client_address) -> None:  # noqa: D401
        import sys
        exc = sys.exc_info()[1]
        if isinstance(exc, (BrokenPipeError, ConnectionError, ConnectionResetError)):
            return  # client closed the SSE stream — expected, not an error
        super().handle_error(request, client_address)


def _pick_port(preferred: int | None) -> int:
    """Return `preferred` if free, else an OS-assigned free port on 127.0.0.1."""
    if preferred:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                s.bind((_HOST, preferred))
                return preferred
            except OSError:
                pass
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((_HOST, 0))
        return s.getsockname()[1]


def serve(root: Path, *, port: int | None = None, open_browser: bool = False,
          extensions: set[str] | None = None, rules_only: bool = False,
          use_docker: bool = False, engines: list[str] | None = None) -> None:
    """Start the live dashboard server. Blocks until Ctrl-C.

    Binds 127.0.0.1 only, auto-picks a free port when `port` is None/busy,
    starts the file watcher (degrades to static mode if watchdog is absent),
    and shuts everything down cleanly on KeyboardInterrupt.
    """
    from radar.scan.watcher import WATCHED_EXTENSIONS, watch_loop

    root = Path(root).resolve()
    exts = extensions or WATCHED_EXTENSIONS
    chosen = _pick_port(port)

    broadcaster = Broadcaster()
    orch = Orchestrator(
        broadcaster,
        root,
        rules_only=rules_only,
        use_docker=use_docker,
        engines=engines,
    )
    handler_cls = make_handler(broadcaster, orch)

    httpd = _DashboardServer((_HOST, chosen), handler_cls)
    httpd.daemon_threads = True
    httpd._stop = threading.Event()  # shared with SSE worker loops

    url = f"http://{_HOST}:{chosen}/"
    _log(f"\n[radar serve] live dashboard at \033[36m{url}\033[0m")
    _log(f"   Watching {root}")
    _log("   Press Ctrl-C to stop\n")

    stop_event = threading.Event()

    def _watch() -> None:
        ok = watch_loop(root, exts, orch.on_change, stop_event=stop_event)
        if not ok:
            _log("\033[33m[radar serve] watchdog missing - auto-update disabled "
                 "(static dashboard only). pip install 'security-radar[watch]'\033[0m")

    # Initial full compute (so /api/state is populated before the first request).
    threading.Thread(target=orch.compute_full, daemon=True).start()
    threading.Thread(target=_watch, daemon=True).start()
    server_thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    server_thread.start()

    if open_browser:
        try:
            webbrowser.open(url)
        except Exception:
            pass

    try:
        while server_thread.is_alive():
            server_thread.join(0.5)
    except KeyboardInterrupt:
        _log("\n\033[2m[radar serve] stopping...\033[0m")
    finally:
        stop_event.set()
        httpd._stop.set()
        httpd.shutdown()
        httpd.server_close()
