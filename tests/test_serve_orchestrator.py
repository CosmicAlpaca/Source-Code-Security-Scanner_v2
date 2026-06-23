"""Tests for radar.serve.orchestrator.Orchestrator.

Covers:
- on_change: mocked scan_file → state.findings updated, broadcaster pushed
  (findings + overview events emitted; schedule_heavy triggered)
- on_change: file outside repo root (relative path handling)
- on_change: scan returns empty → stale findings for that file cleared
- schedule_heavy: multiple rapid calls coalesce into one compute_full after
  the debounce window
- run_triage: with no OPENAI_API_KEY → pushes a status warning, never raises
- State.to_json: returns valid JSON with expected keys
"""
from __future__ import annotations

import io
import json
import os
import threading
import time
from pathlib import Path
from unittest.mock import MagicMock, patch, call

import pytest

from radar.scan.findings import Finding
from radar.serve.orchestrator import Orchestrator, State, _HEAVY_DEBOUNCE
from radar.serve.server import Broadcaster


# ── Helpers ───────────────────────────────────────────────────────────────────

class _RecordingStream:
    """Captures pushed SSE frames."""

    def __init__(self) -> None:
        self._frames: list[bytes] = []

    def write(self, data: bytes) -> None:
        self._frames.append(data)

    def flush(self) -> None:
        pass

    def events(self) -> list[str]:
        """Return the event names pushed so far."""
        out: list[str] = []
        for frame in self._frames:
            for line in frame.split(b"\n"):
                if line.startswith(b"event: "):
                    out.append(line[7:].decode("utf-8"))
        return out

    def full_text(self) -> str:
        return b"".join(self._frames).decode("utf-8")


def _make_orch(root: Path) -> tuple[Orchestrator, Broadcaster, _RecordingStream]:
    bc = Broadcaster()
    stream = _RecordingStream()
    bc.register(stream)
    orch = Orchestrator(bc, root)
    return orch, bc, stream


# ── State.to_json ─────────────────────────────────────────────────────────────

class TestStateToJson:
    def test_returns_valid_json(self, tmp_path: Path):
        state = State()
        js = state.to_json()
        data = json.loads(js)
        assert isinstance(data, dict)

    def test_has_panels_key(self, tmp_path: Path):
        state = State()
        data = json.loads(state.to_json())
        assert "panels" in data

    def test_has_charts_key(self, tmp_path: Path):
        state = State()
        data = json.loads(state.to_json())
        assert "charts" in data

    def test_has_graph_key(self, tmp_path: Path):
        state = State()
        data = json.loads(state.to_json())
        assert "graph" in data

    def test_has_summary_key(self, tmp_path: Path):
        state = State()
        data = json.loads(state.to_json())
        assert "summary" in data

    def test_panels_subkeys_present(self, tmp_path: Path):
        state = State()
        panels = json.loads(state.to_json())["panels"]
        for key in ("overview", "findings", "blast", "history"):
            assert key in panels

    def test_findings_empty_initial_state(self, tmp_path: Path):
        state = State()
        data = json.loads(state.to_json())
        assert data["summary"]["total"] == 0

    def test_with_findings(self, tmp_path: Path):
        state = State()
        state.findings = [
            Finding("ERROR", "f.py", 1, "rule", "msg"),
        ]
        data = json.loads(state.to_json())
        assert data["summary"]["error"] == 1
        assert data["summary"]["total"] == 1


# ── on_change: fast-path file update ─────────────────────────────────────────

class TestOnChange:
    def test_updates_state_findings(self, tmp_path: Path):
        orch, bc, stream = _make_orch(tmp_path)
        fake_raw = [{"severity": "ERROR", "path": "app/db.py",
                     "line": 10, "rule": "py-sql", "message": "SQLi"}]
        target_file = tmp_path / "app" / "db.py"

        with patch("radar.serve.orchestrator.scan_file", return_value=fake_raw):
            with patch.object(orch, "schedule_heavy"):
                orch.on_change(target_file)

        assert len(orch.state.findings) == 1
        assert orch.state.findings[0].severity == "ERROR"

    def test_pushes_findings_event(self, tmp_path: Path):
        orch, bc, stream = _make_orch(tmp_path)
        fake_raw = [{"severity": "WARNING", "path": "x.py",
                     "line": 5, "rule": "py-hash", "message": "weak"}]
        with patch("radar.serve.orchestrator.scan_file", return_value=fake_raw):
            with patch.object(orch, "schedule_heavy"):
                orch.on_change(tmp_path / "x.py")

        assert "findings" in stream.events()

    def test_pushes_overview_event(self, tmp_path: Path):
        orch, bc, stream = _make_orch(tmp_path)
        with patch("radar.serve.orchestrator.scan_file", return_value=[]):
            with patch.object(orch, "schedule_heavy"):
                orch.on_change(tmp_path / "y.py")

        assert "overview" in stream.events()

    def test_pushes_status_events(self, tmp_path: Path):
        orch, bc, stream = _make_orch(tmp_path)
        with patch("radar.serve.orchestrator.scan_file", return_value=[]):
            with patch.object(orch, "schedule_heavy"):
                orch.on_change(tmp_path / "z.py")

        assert "status" in stream.events()

    def test_triggers_schedule_heavy(self, tmp_path: Path):
        orch, bc, stream = _make_orch(tmp_path)
        with patch("radar.serve.orchestrator.scan_file", return_value=[]):
            with patch.object(orch, "schedule_heavy") as sh:
                orch.on_change(tmp_path / "f.py")
                assert sh.called

    def test_replaces_findings_for_changed_file(self, tmp_path: Path):
        orch, bc, stream = _make_orch(tmp_path)

        # Prime with a pre-existing finding for a different file
        existing = Finding("INFO", "other/x.py", 1, "rule", "msg")
        orch.state.findings = [existing]

        # on_change for db.py should REPLACE db.py findings only
        fake_raw = [{"severity": "ERROR", "path": "app/db.py",
                     "line": 20, "rule": "py-sql", "message": "SQLi"}]
        with patch("radar.serve.orchestrator.scan_file", return_value=fake_raw):
            with patch.object(orch, "schedule_heavy"):
                orch.on_change(tmp_path / "app" / "db.py")

        paths = {f.path for f in orch.state.findings}
        # existing finding from other/x.py should be kept
        assert "other/x.py" in paths
        # new finding for app/db.py should be present
        assert any("db.py" in p for p in paths)

    def test_clears_findings_for_fixed_file(self, tmp_path: Path):
        orch, bc, stream = _make_orch(tmp_path)
        # Pre-populate with a finding for the file we'll "fix"
        old = Finding("ERROR", "app/db.py", 10, "py-sql", "SQLi")
        orch.state.findings = [old]

        # scan returns empty (file was fixed)
        with patch("radar.serve.orchestrator.scan_file", return_value=[]):
            with patch.object(orch, "schedule_heavy"):
                orch.on_change(tmp_path / "app" / "db.py")

        # Findings for that file should be gone
        remaining = [f for f in orch.state.findings if "db.py" in f.path]
        assert remaining == []

    def test_verdict_map_cleared_on_change(self, tmp_path: Path):
        """Stale AI verdicts must be dropped when findings change."""
        orch, bc, stream = _make_orch(tmp_path)
        orch.state.verdict_map = {("old.py", 1, "rule"): {"verdict": {"exploitability": "exploitable"}}}
        with patch("radar.serve.orchestrator.scan_file", return_value=[]):
            with patch.object(orch, "schedule_heavy"):
                orch.on_change(tmp_path / "old.py")

        assert orch.state.verdict_map is None

    def test_handles_relative_path(self, tmp_path: Path):
        """on_change should not crash when given a relative path."""
        orch, bc, stream = _make_orch(tmp_path)
        with patch("radar.serve.orchestrator.scan_file", return_value=[]):
            with patch.object(orch, "schedule_heavy"):
                orch.on_change(Path("relative/path.py"))  # no error


# ── schedule_heavy: debounce coalescing ──────────────────────────────────────

class TestScheduleHeavy:
    def test_single_call_fires_compute_full(self, tmp_path: Path):
        orch, bc, _ = _make_orch(tmp_path)
        called = threading.Event()

        def fake_compute():
            called.set()

        with patch.object(orch, "compute_full", side_effect=fake_compute):
            orch.schedule_heavy()
            fired = called.wait(timeout=_HEAVY_DEBOUNCE + 1.0)

        assert fired, "compute_full was not called after schedule_heavy"

    def test_rapid_calls_coalesce_to_one(self, tmp_path: Path):
        orch, bc, _ = _make_orch(tmp_path)
        call_count = []
        finished = threading.Event()

        def fake_compute():
            call_count.append(1)
            finished.set()

        with patch.object(orch, "compute_full", side_effect=fake_compute):
            # Call schedule_heavy 5 times in rapid succession
            for _ in range(5):
                orch.schedule_heavy()
                time.sleep(0.01)  # small gap, still within debounce window

            finished.wait(timeout=_HEAVY_DEBOUNCE + 1.5)

        # All 5 rapid saves should coalesce into a single compute_full
        assert len(call_count) == 1, (
            f"Expected 1 compute_full call (debounced), got {len(call_count)}"
        )

    def test_two_bursts_separated_by_debounce_fire_twice(self, tmp_path: Path):
        orch, bc, _ = _make_orch(tmp_path)
        call_count = []

        def fake_compute():
            call_count.append(1)

        with patch.object(orch, "compute_full", side_effect=fake_compute):
            orch.schedule_heavy()
            # Wait for first to fire
            time.sleep(_HEAVY_DEBOUNCE + 0.5)
            orch.schedule_heavy()
            # Wait for second to fire
            time.sleep(_HEAVY_DEBOUNCE + 0.5)

        assert len(call_count) == 2, (
            f"Expected 2 compute_full calls (two separate bursts), got {len(call_count)}"
        )

    def test_cancels_previous_timer_on_rapid_calls(self, tmp_path: Path):
        """Intermediate timers must not fire; only the last one should."""
        orch, bc, _ = _make_orch(tmp_path)
        call_count = []
        done = threading.Event()

        def fake_compute():
            call_count.append(1)
            done.set()

        with patch.object(orch, "compute_full", side_effect=fake_compute):
            for _ in range(10):
                orch.schedule_heavy()
            done.wait(timeout=_HEAVY_DEBOUNCE + 1.0)

        assert len(call_count) == 1


# ── run_triage: offline-safe ──────────────────────────────────────────────────

class TestRunTriage:
    def test_does_not_raise_without_api_key(self, tmp_path: Path):
        """run_triage must never propagate an exception."""
        orch, bc, stream = _make_orch(tmp_path)
        env_backup = os.environ.pop("OPENAI_API_KEY", None)
        env_backup2 = os.environ.pop("RADAR_AI_API_KEY", None)
        try:
            from radar.triage import engine
            from radar.triage.llm_client import TriageError
            with patch.object(engine, "triage",
                              side_effect=TriageError("No API key")):
                # Must complete without raising
                orch.run_triage()
        finally:
            if env_backup is not None:
                os.environ["OPENAI_API_KEY"] = env_backup
            if env_backup2 is not None:
                os.environ["RADAR_AI_API_KEY"] = env_backup2

    def test_pushes_status_warning_when_no_key(self, tmp_path: Path):
        orch, bc, stream = _make_orch(tmp_path)
        from radar.triage import engine
        from radar.triage.llm_client import TriageError

        with patch.object(engine, "triage",
                          side_effect=TriageError("No API key")):
            orch.run_triage()

        text = stream.full_text()
        assert "status" in stream.events()
        assert "warn" in text or "unavailable" in text

    def test_status_level_is_warn_when_no_key(self, tmp_path: Path):
        orch, bc, stream = _make_orch(tmp_path)
        from radar.triage import engine
        from radar.triage.llm_client import TriageError

        with patch.object(engine, "triage",
                          side_effect=TriageError("No API key")):
            orch.run_triage()

        # Find the last status frame and check its level
        status_frames = [
            f.decode("utf-8") for f in stream._frames
            if b"event: status" in f
        ]
        assert status_frames, "No status event was pushed"
        last = status_frames[-1]
        payload = json.loads(last.split("data: ", 1)[1].strip())
        assert payload.get("level") == "warn"

    def test_does_not_crash_on_arbitrary_exception(self, tmp_path: Path):
        """Any exception from engine.triage must be caught, never re-raised."""
        orch, bc, stream = _make_orch(tmp_path)
        from radar.triage import engine

        with patch.object(engine, "triage",
                          side_effect=RuntimeError("unexpected boom")):
            orch.run_triage()  # must not raise

        # A status warning should have been emitted
        assert "status" in stream.events()

    def test_successful_triage_updates_findings(self, tmp_path: Path):
        orch, bc, stream = _make_orch(tmp_path)
        from radar.triage import engine
        from radar.triage import risk

        finding = Finding("ERROR", "app/x.py", 1, "rule", "msg")

        fake_result = MagicMock()
        fake_result.finding = finding
        fake_result.reach = MagicMock(status="reachable", routes=["POST /api"])
        fake_result.verdict = {"exploitability": "likely", "confidence": 0.8,
                               "reasoning": "tainted"}
        fake_result.error = None

        with patch.object(engine, "triage", return_value=([fake_result], 1)):
            with patch.object(risk, "build_risk_map", return_value={}):
                orch.run_triage()

        assert orch.state.findings == [finding]

    def test_successful_triage_pushes_status_ok(self, tmp_path: Path):
        orch, bc, stream = _make_orch(tmp_path)
        from radar.triage import engine
        from radar.triage import risk

        finding = Finding("ERROR", "app/x.py", 1, "rule", "msg")
        fake_result = MagicMock()
        fake_result.finding = finding
        fake_result.reach = MagicMock(status="reachable", routes=[])
        fake_result.verdict = {"exploitability": "unlikely", "confidence": 0.5,
                               "reasoning": "no path"}
        fake_result.error = None

        with patch.object(engine, "triage", return_value=([fake_result], 1)):
            with patch.object(risk, "build_risk_map", return_value={}):
                orch.run_triage()

        status_frames = [
            f.decode("utf-8") for f in stream._frames
            if b"event: status" in f
        ]
        last = status_frames[-1]
        payload = json.loads(last.split("data: ", 1)[1].strip())
        assert payload.get("level") == "ok"


# ── _push_status ──────────────────────────────────────────────────────────────

class TestPushStatus:
    def test_status_event_has_correct_format(self, tmp_path: Path):
        orch, bc, stream = _make_orch(tmp_path)
        orch._push_status("scanning…", "busy")
        text = stream.full_text()
        assert "event: status" in text
        assert "scanning" in text
        assert "busy" in text

    def test_status_json_has_text_level_ts(self, tmp_path: Path):
        orch, bc, stream = _make_orch(tmp_path)
        orch._push_status("idle", "ok")
        frames = [f for f in stream._frames if b"event: status" in f]
        assert frames
        data_line = frames[0].decode("utf-8").split("data: ", 1)[1].strip()
        payload = json.loads(data_line)
        assert "text" in payload
        assert "level" in payload
        assert "ts" in payload
