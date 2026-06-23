"""Smoke tests for the HTTP endpoints exposed by `radar serve`.

Spins up a real _DashboardServer on an ephemeral 127.0.0.1 port in a background
thread, fires requests via http.client (stdlib — no extra deps), and asserts:

  GET  /                  → 200, text/html,  contains panel-* ids
  GET  /api/state         → 200, application/json, keys: panels/charts/graph/summary
  GET  /events            → 200, text/event-stream  (headers only; connection closed)
  GET  /static/app.js     → 200, application/javascript
  GET  /static/d3.v7.min.js → 200
  GET  /static/..         path traversal → 404
  GET  /nonexistent       → 404
  POST /api/triage        → 202, never 500

All threads + sockets are shut down cleanly in teardown.
"""
from __future__ import annotations

import http.client
import json
import socket
import threading
import time
from pathlib import Path

import pytest

from radar.serve.orchestrator import Orchestrator
from radar.serve.server import Broadcaster, _DashboardServer, make_handler


# ── Server fixture ────────────────────────────────────────────────────────────

def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class _Server:
    """Thin wrapper around _DashboardServer to simplify setup/teardown."""

    def __init__(self, root: Path) -> None:
        self.port = _free_port()
        self.bc = Broadcaster()
        self.orch = Orchestrator(self.bc, root)
        handler_cls = make_handler(self.bc, self.orch)
        self.httpd = _DashboardServer(("127.0.0.1", self.port), handler_cls)
        self.httpd._stop = threading.Event()
        self._t = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def start(self) -> "_Server":
        self._t.start()
        # Give the server a short moment to bind
        deadline = time.monotonic() + 2.0
        while time.monotonic() < deadline:
            try:
                conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=0.2)
                conn.request("GET", "/")
                conn.getresponse().read()
                conn.close()
                break
            except Exception:
                time.sleep(0.05)
        return self

    def stop(self) -> None:
        self.httpd._stop.set()
        self.httpd.shutdown()
        self.httpd.server_close()
        self._t.join(timeout=5)

    def get(self, path: str, *, timeout: float = 3.0) -> tuple[int, str, bytes]:
        """Return (status, content-type, body)."""
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=timeout)
        try:
            conn.request("GET", path)
            r = conn.getresponse()
            status = r.status
            ct = r.getheader("Content-Type", "")
            body = r.read()
        finally:
            conn.close()
        return status, ct, body

    def post(self, path: str, body: bytes = b"", *, timeout: float = 3.0) -> tuple[int, str, bytes]:
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=timeout)
        try:
            conn.request("POST", path, body=body,
                         headers={"Content-Length": str(len(body))})
            r = conn.getresponse()
            status = r.status
            ct = r.getheader("Content-Type", "")
            resp_body = r.read()
        finally:
            conn.close()
        return status, ct, resp_body

    def get_headers_only(self, path: str, *, timeout: float = 3.0) -> tuple[int, dict]:
        """Request path and return (status, headers) — closes conn without reading body."""
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=timeout)
        try:
            conn.request("GET", path)
            r = conn.getresponse()
            status = r.status
            headers = {k.lower(): v for k, v in r.headers.items()}
        finally:
            conn.close()
        return status, headers


@pytest.fixture(scope="module")
def server(tmp_path_factory):
    """One server shared across all tests in this module (faster)."""
    root = tmp_path_factory.mktemp("repo")
    srv = _Server(root).start()
    yield srv
    srv.stop()


# ── GET / ─────────────────────────────────────────────────────────────────────

class TestDashboardRoot:
    def test_returns_200(self, server: _Server):
        status, _, _ = server.get("/")
        assert status == 200

    def test_content_type_html(self, server: _Server):
        _, ct, _ = server.get("/")
        assert ct.startswith("text/html")

    def test_contains_panel_overview_id(self, server: _Server):
        _, _, body = server.get("/")
        assert b"panel-overview" in body

    def test_contains_panel_findings_id(self, server: _Server):
        _, _, body = server.get("/")
        assert b"panel-findings" in body

    def test_contains_panel_blast_id(self, server: _Server):
        _, _, body = server.get("/")
        assert b"panel-blast" in body

    def test_contains_panel_history_id(self, server: _Server):
        _, _, body = server.get("/")
        assert b"panel-history" in body

    def test_doctype_present(self, server: _Server):
        _, _, body = server.get("/")
        assert b"<!DOCTYPE html>" in body.lower() or b"<!doctype html>" in body.lower()

    def test_query_string_ignored(self, server: _Server):
        """GET /?v=123 should still return 200 (query params stripped)."""
        status, _, _ = server.get("/?v=123&foo=bar")
        assert status == 200


# ── GET /api/state ────────────────────────────────────────────────────────────

class TestApiState:
    def test_returns_200(self, server: _Server):
        status, _, _ = server.get("/api/state")
        assert status == 200

    def test_content_type_json(self, server: _Server):
        _, ct, _ = server.get("/api/state")
        assert "application/json" in ct

    def test_body_is_valid_json(self, server: _Server):
        _, _, body = server.get("/api/state")
        data = json.loads(body)
        assert isinstance(data, dict)

    def test_has_panels_key(self, server: _Server):
        _, _, body = server.get("/api/state")
        data = json.loads(body)
        assert "panels" in data

    def test_has_charts_key(self, server: _Server):
        _, _, body = server.get("/api/state")
        data = json.loads(body)
        assert "charts" in data

    def test_has_graph_key(self, server: _Server):
        _, _, body = server.get("/api/state")
        data = json.loads(body)
        assert "graph" in data

    def test_has_summary_key(self, server: _Server):
        _, _, body = server.get("/api/state")
        data = json.loads(body)
        assert "summary" in data

    def test_panels_contains_expected_subkeys(self, server: _Server):
        _, _, body = server.get("/api/state")
        panels = json.loads(body)["panels"]
        for key in ("overview", "findings", "blast", "history"):
            assert key in panels, f"panels missing key: {key}"

    def test_panels_html_are_strings(self, server: _Server):
        _, _, body = server.get("/api/state")
        panels = json.loads(body)["panels"]
        for key, val in panels.items():
            assert isinstance(val, str), f"panels[{key!r}] is not a string"

    def test_summary_has_counts(self, server: _Server):
        _, _, body = server.get("/api/state")
        summary = json.loads(body)["summary"]
        for k in ("error", "warning", "info", "total"):
            assert k in summary, f"summary missing key: {k}"


# ── GET /events ───────────────────────────────────────────────────────────────

class TestSseEvents:
    def test_returns_200(self, server: _Server):
        status, _ = server.get_headers_only("/events")
        assert status == 200

    def test_content_type_event_stream(self, server: _Server):
        _, headers = server.get_headers_only("/events")
        ct = headers.get("content-type", "")
        assert "text/event-stream" in ct

    def test_cache_control_no_cache(self, server: _Server):
        _, headers = server.get_headers_only("/events")
        cc = headers.get("cache-control", "")
        assert "no-cache" in cc


# ── GET /static/* ─────────────────────────────────────────────────────────────

class TestStaticFiles:
    def test_app_js_returns_200(self, server: _Server):
        status, _, _ = server.get("/static/app.js")
        assert status == 200

    def test_app_js_content_type(self, server: _Server):
        _, ct, _ = server.get("/static/app.js")
        assert "javascript" in ct

    def test_app_css_returns_200(self, server: _Server):
        status, _, _ = server.get("/static/app.css")
        assert status == 200

    def test_d3_returns_200(self, server: _Server):
        status, _, _ = server.get("/static/d3.v7.min.js")
        assert status == 200

    def test_d3_content_type(self, server: _Server):
        _, ct, _ = server.get("/static/d3.v7.min.js")
        assert "javascript" in ct

    def test_nonexistent_static_file_404(self, server: _Server):
        status, _, _ = server.get("/static/does_not_exist_12345.js")
        assert status == 404

    def test_path_traversal_dotdot_404(self, server: _Server):
        """/../ path traversal must yield 404, not a real file."""
        status, _, _ = server.get("/static/../server.py")
        assert status == 404

    def test_path_traversal_slash_in_name_404(self, server: _Server):
        """Nested path inside /static/ must yield 404."""
        status, _, _ = server.get("/static/sub/secret.js")
        assert status == 404


# ── GET unknown path ──────────────────────────────────────────────────────────

class TestNotFound:
    def test_unknown_path_404(self, server: _Server):
        status, _, _ = server.get("/no/such/path")
        assert status == 404

    def test_unknown_path_body(self, server: _Server):
        _, _, body = server.get("/no/such/path")
        assert b"not found" in body.lower()


# ── POST /api/triage ─────────────────────────────────────────────────────────

class TestApiTriage:
    def test_returns_202(self, server: _Server):
        status, _, _ = server.post("/api/triage")
        assert status == 202

    def test_never_500(self, server: _Server):
        """POST triage with no API key must never return 500."""
        status, _, _ = server.post("/api/triage")
        assert status != 500

    def test_response_is_json(self, server: _Server):
        _, ct, _ = server.post("/api/triage")
        assert "application/json" in ct

    def test_response_body_json(self, server: _Server):
        _, _, body = server.post("/api/triage")
        data = json.loads(body)
        assert isinstance(data, dict)
        assert "status" in data

    def test_unknown_post_path_404(self, server: _Server):
        status, _, _ = server.post("/api/unknown")
        assert status == 404


# ── Rapid sequential requests (regression for thread-pool exhaustion) ─────────

class TestConcurrency:
    def test_multiple_sequential_state_requests(self, server: _Server):
        """Issue 10 sequential /api/state requests — all must return 200."""
        for _ in range(10):
            status, _, _ = server.get("/api/state")
            assert status == 200

    def test_multiple_concurrent_root_requests(self, server: _Server):
        """Fire 5 concurrent GET / requests via threads — all must succeed."""
        results: list[int] = []

        def _hit():
            try:
                status, _, _ = server.get("/")
                results.append(status)
            except Exception:
                results.append(0)

        threads = [threading.Thread(target=_hit, daemon=True) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5)

        assert all(s == 200 for s in results), f"Some requests failed: {results}"
