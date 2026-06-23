"""Tests for radar.serve.server.Broadcaster.

Covers:
- register / unregister clients
- push writes a correctly-formatted SSE frame to connected streams
- a client whose write raises is pruned and delivery continues to healthy clients
- concurrent thread safety (multi-threaded push)
"""
from __future__ import annotations

import io
import json
import threading

import pytest

from radar.serve.server import Broadcaster


# ── Helpers ───────────────────────────────────────────────────────────────────

class _BytesStream:
    """Minimal file-like capturing bytes written to it."""

    def __init__(self) -> None:
        self._buf = io.BytesIO()
        self._closed = False

    def write(self, data: bytes) -> None:
        if self._closed:
            raise BrokenPipeError("stream closed")
        self._buf.write(data)

    def flush(self) -> None:
        pass

    def getvalue(self) -> bytes:
        return self._buf.getvalue()

    def close(self) -> None:
        self._closed = True


# ── register / unregister ─────────────────────────────────────────────────────

class TestBroadcasterRegistry:
    def test_register_adds_client(self):
        bc = Broadcaster()
        stream = _BytesStream()
        bc.register(stream)
        assert len(bc._clients) == 1

    def test_register_multiple_clients(self):
        bc = Broadcaster()
        streams = [_BytesStream() for _ in range(3)]
        for s in streams:
            bc.register(s)
        assert len(bc._clients) == 3

    def test_unregister_removes_client(self):
        bc = Broadcaster()
        stream = _BytesStream()
        bc.register(stream)
        bc.unregister(stream)
        assert len(bc._clients) == 0

    def test_unregister_unknown_client_is_safe(self):
        bc = Broadcaster()
        stream = _BytesStream()
        # Unregistering a stream that was never registered must not raise
        bc.unregister(stream)
        assert len(bc._clients) == 0

    def test_register_unregister_multiple_preserves_others(self):
        bc = Broadcaster()
        s1, s2, s3 = _BytesStream(), _BytesStream(), _BytesStream()
        for s in (s1, s2, s3):
            bc.register(s)
        bc.unregister(s2)
        assert len(bc._clients) == 2
        assert s2 not in bc._clients


# ── push: correct SSE frame format ───────────────────────────────────────────

class TestBroadcasterPush:
    def test_push_writes_correct_sse_frame(self):
        bc = Broadcaster()
        stream = _BytesStream()
        bc.register(stream)
        bc.push("findings", '{"html": "<p>hi</p>"}')
        data = stream.getvalue()
        assert data == b'event: findings\ndata: {"html": "<p>hi</p>"}\n\n'

    def test_push_frame_starts_with_event_line(self):
        bc = Broadcaster()
        stream = _BytesStream()
        bc.register(stream)
        bc.push("status", '{"text":"ok","level":"ok"}')
        frame = stream.getvalue().decode("utf-8")
        assert frame.startswith("event: status\n")

    def test_push_frame_has_data_line(self):
        bc = Broadcaster()
        stream = _BytesStream()
        bc.register(stream)
        payload = json.dumps({"html": "fragment"})
        bc.push("overview", payload)
        frame = stream.getvalue().decode("utf-8")
        lines = frame.split("\n")
        assert lines[0] == "event: overview"
        assert lines[1] == f"data: {payload}"

    def test_push_frame_ends_with_double_newline(self):
        bc = Broadcaster()
        stream = _BytesStream()
        bc.register(stream)
        bc.push("blast", "{}")
        data = stream.getvalue()
        assert data.endswith(b"\n\n")

    def test_push_delivers_to_all_clients(self):
        bc = Broadcaster()
        streams = [_BytesStream() for _ in range(5)]
        for s in streams:
            bc.register(s)
        bc.push("history", '{"html":""}')
        for s in streams:
            assert b"event: history" in s.getvalue()

    def test_push_with_no_clients_is_safe(self):
        bc = Broadcaster()
        # Should not raise even with zero clients
        bc.push("status", '{"text":"ok"}')

    def test_push_multiple_events_accumulates(self):
        bc = Broadcaster()
        stream = _BytesStream()
        bc.register(stream)
        bc.push("findings", '{"html":"a"}')
        bc.push("overview", '{"html":"b"}')
        data = stream.getvalue()
        assert b"event: findings\n" in data
        assert b"event: overview\n" in data

    def test_push_frame_is_utf8_encoded(self):
        """Frame bytes must be valid UTF-8 (round-trips cleanly)."""
        bc = Broadcaster()
        stream = _BytesStream()
        bc.register(stream)
        # json.dumps escapes non-ASCII as \uXXXX by default; ensure the frame
        # is valid UTF-8 and the event name/data structure survives the round-trip.
        payload = json.dumps({"html": "café"})
        bc.push("findings", payload)
        data = stream.getvalue()
        # The raw bytes must decode cleanly as UTF-8
        text = data.decode("utf-8")
        assert "event: findings" in text
        assert "caf" in text  # the content is present (escaped as é is fine)


# ── dead client pruning ───────────────────────────────────────────────────────

class TestBroadcasterDeadClientPruning:
    def test_broken_pipe_client_is_pruned(self):
        bc = Broadcaster()
        dead = _BytesStream()
        dead.close()  # mark as broken-pipe
        healthy = _BytesStream()
        bc.register(dead)
        bc.register(healthy)

        bc.push("findings", '{"html":"x"}')

        # dead client removed, healthy client kept
        assert dead not in bc._clients
        assert healthy in bc._clients

    def test_healthy_client_receives_frame_despite_dead_client(self):
        bc = Broadcaster()
        dead = _BytesStream()
        dead.close()
        healthy = _BytesStream()
        bc.register(dead)
        bc.register(healthy)

        bc.push("overview", '{"html":"ok"}')

        # healthy received its frame
        assert b"event: overview" in healthy.getvalue()

    def test_multiple_dead_clients_all_pruned(self):
        bc = Broadcaster()
        dead1, dead2 = _BytesStream(), _BytesStream()
        dead1.close()
        dead2.close()
        healthy = _BytesStream()
        for s in (dead1, dead2, healthy):
            bc.register(s)

        bc.push("status", '{}')

        assert dead1 not in bc._clients
        assert dead2 not in bc._clients
        assert healthy in bc._clients

    def test_connection_error_triggers_prune(self):
        """Any OSError subclass prunes the client."""
        bc = Broadcaster()

        class _OsErrorStream:
            def write(self, data):
                raise ConnectionResetError("reset")
            def flush(self):
                pass

        bad = _OsErrorStream()
        good = _BytesStream()
        bc.register(bad)
        bc.register(good)
        bc.push("findings", "{}")
        assert bad not in bc._clients
        assert b"event: findings" in good.getvalue()

    def test_value_error_triggers_prune(self):
        """ValueError (e.g. write to a closed file) prunes the client."""
        bc = Broadcaster()

        class _ValueErrorStream:
            def write(self, data):
                raise ValueError("I/O on closed file")
            def flush(self):
                pass

        bad = _ValueErrorStream()
        healthy = _BytesStream()
        bc.register(bad)
        bc.register(healthy)
        bc.push("history", "{}")
        assert bad not in bc._clients
        assert b"event: history" in healthy.getvalue()


# ── thread safety ─────────────────────────────────────────────────────────────

class TestBroadcasterThreadSafety:
    def test_concurrent_push_does_not_crash(self):
        """Multiple threads pushing simultaneously should not corrupt state."""
        bc = Broadcaster()
        streams = [_BytesStream() for _ in range(10)]
        for s in streams:
            bc.register(s)

        errors: list[Exception] = []

        def _push():
            try:
                for _ in range(20):
                    bc.push("findings", '{"html":"x"}')
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=_push, daemon=True) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5)

        assert not errors, f"Unexpected errors during concurrent push: {errors}"

    def test_concurrent_register_unregister(self):
        """register/unregister from multiple threads must not crash."""
        bc = Broadcaster()
        errors: list[Exception] = []

        def _add_remove():
            try:
                for _ in range(50):
                    s = _BytesStream()
                    bc.register(s)
                    bc.unregister(s)
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=_add_remove, daemon=True) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5)

        assert not errors, f"Thread safety violation: {errors}"
