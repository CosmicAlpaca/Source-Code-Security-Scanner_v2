"""`radar scan` CLI tests — Semgrep is fully mocked (no real scan)."""

import json

from click.testing import CliRunner

from radar import cli
from radar.scan.runner import ScanError

SAMPLE = {
    "results": [
        {"check_id": "rules.x", "path": "a.js", "start": {"line": 3},
         "extra": {"severity": "ERROR", "message": "bad"}},
        {"check_id": "rules.y", "path": "b.py", "start": {"line": 9},
         "extra": {"severity": "WARNING", "message": "meh"}},
    ]
}


def _patch(monkeypatch, report=SAMPLE):
    from radar.scan import runner

    monkeypatch.setattr(runner, "detect_runtime", lambda: "native")
    monkeypatch.setattr(runner, "run_semgrep", lambda *a, **k: report)


def test_scan_terminal(monkeypatch, tmp_path):
    _patch(monkeypatch)
    result = CliRunner().invoke(cli.main, ["scan", str(tmp_path)])
    assert result.exit_code == 0
    assert "2 finding(s)" in result.output


def test_scan_json(monkeypatch, tmp_path):
    _patch(monkeypatch)
    result = CliRunner().invoke(cli.main, ["scan", str(tmp_path), "--format", "json"])
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["summary"]["total"] == 2


def test_scan_sarif_passthrough(monkeypatch, tmp_path):
    sarif = {"version": "2.1.0", "runs": []}
    _patch(monkeypatch, report=sarif)
    result = CliRunner().invoke(cli.main, ["scan", str(tmp_path), "--format", "sarif"])
    assert result.exit_code == 0
    assert json.loads(result.output)["version"] == "2.1.0"


def test_scan_error_gate_exits_one(monkeypatch, tmp_path):
    _patch(monkeypatch)
    result = CliRunner().invoke(cli.main, ["scan", str(tmp_path), "--error", "--fail-on", "error"])
    assert result.exit_code == 1  # an ERROR finding is present


def test_scan_error_gate_passes_when_below_threshold(monkeypatch, tmp_path):
    only_info = {"results": [{"check_id": "r", "path": "a.js", "start": {"line": 1},
                              "extra": {"severity": "INFO", "message": "fyi"}}]}
    _patch(monkeypatch, report=only_info)
    result = CliRunner().invoke(cli.main, ["scan", str(tmp_path), "--error", "--fail-on", "error"])
    assert result.exit_code == 0


def test_scan_no_runtime_exits_two(monkeypatch, tmp_path):
    from radar.scan import runner

    def boom():
        raise ScanError("No Semgrep runtime found.")

    monkeypatch.setattr(runner, "detect_runtime", boom)
    result = CliRunner().invoke(cli.main, ["scan", str(tmp_path)])
    assert result.exit_code == 2
    assert "scan failed" in result.output
