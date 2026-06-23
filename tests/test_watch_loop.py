"""Unit tests for radar.scan.watcher.watch_loop and scan_file.

These exercise the reusable detect-and-callback loop without invoking semgrep:
- watch_loop is callable and stops cleanly via a stop_event from another thread.
- a real file edit inside the watched dir triggers on_change with the path.
- scan_file dispatches to the native/docker scanners (patched here).
"""
from __future__ import annotations

import threading
import time
from pathlib import Path

import pytest

from radar.scan import watcher
from radar.scan.watcher import scan_file, watch_loop

pytest.importorskip("watchdog")


def test_watch_loop_stops_via_stop_event(tmp_path: Path):
    """watch_loop returns True and exits promptly when stop_event is set."""
    stop = threading.Event()
    result: dict = {}

    def run():
        result["ret"] = watch_loop(tmp_path, {".py"}, lambda p: None, stop_event=stop)

    t = threading.Thread(target=run, daemon=True)
    t.start()
    time.sleep(0.2)  # let the observer spin up
    stop.set()
    t.join(timeout=5)

    assert not t.is_alive(), "watch_loop did not stop after stop_event was set"
    assert result["ret"] is True


def test_watch_loop_fires_on_change(tmp_path: Path):
    """Editing a watched-extension file calls on_change with its path."""
    seen: list[Path] = []
    fired = threading.Event()
    stop = threading.Event()

    def on_change(path: Path) -> None:
        seen.append(path)
        fired.set()

    t = threading.Thread(
        target=watch_loop,
        args=(tmp_path, {".py"}, on_change),
        kwargs={"stop_event": stop},
        daemon=True,
    )
    t.start()
    time.sleep(0.3)  # observer ready

    target = tmp_path / "sample.py"
    target.write_text("x = 1\n", encoding="utf-8")

    got = fired.wait(timeout=5)
    stop.set()
    t.join(timeout=5)

    assert got, "on_change was not invoked for a watched-extension edit"
    assert any(p.name == "sample.py" for p in seen)


def test_watch_loop_ignores_unwatched_extension(tmp_path: Path):
    """Files whose suffix is not in extensions do not trigger on_change."""
    fired = threading.Event()
    stop = threading.Event()

    t = threading.Thread(
        target=watch_loop,
        args=(tmp_path, {".py"}, lambda p: fired.set()),
        kwargs={"stop_event": stop},
        daemon=True,
    )
    t.start()
    time.sleep(0.3)

    (tmp_path / "notes.txt").write_text("hello\n", encoding="utf-8")
    got = fired.wait(timeout=1.5)
    stop.set()
    t.join(timeout=5)

    assert not got, "on_change fired for an unwatched extension"


def test_scan_file_dispatches_native(monkeypatch, tmp_path: Path):
    """scan_file (use_docker=False) routes to _scan_file."""
    called = {}

    def fake_native(filepath, rules_dir):
        called["native"] = (filepath, rules_dir)
        return [{"rule": "r", "line": 1, "message": "m", "severity": "INFO"}]

    monkeypatch.setattr(watcher, "_scan_file", fake_native)
    out = scan_file(tmp_path / "a.py", tmp_path / "rules")
    assert out and out[0]["rule"] == "r"
    assert "native" in called


def test_scan_file_dispatches_docker(monkeypatch, tmp_path: Path):
    """scan_file (use_docker=True) routes to _docker_scan_file with repo_root."""
    called = {}

    def fake_docker(filepath, rules_dir, repo_root):
        called["docker"] = (filepath, rules_dir, repo_root)
        return []

    monkeypatch.setattr(watcher, "_docker_scan_file", fake_docker)
    scan_file(tmp_path / "a.py", tmp_path / "rules", use_docker=True, repo_root=tmp_path)
    assert called["docker"][2] == tmp_path
