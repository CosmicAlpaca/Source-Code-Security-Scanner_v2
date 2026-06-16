"""Tests for `radar impact --findings` overlay (findings x blast radius)."""

import json

import pytest
from click.testing import CliRunner

from radar import cli
from radar.impact.tracer import ImpactItem
from radar.report.terminal import _finding_tag


def _json(res):
    """Parse JSON from CLI output (CliRunner merges the stderr progress line)."""
    out = res.output
    return json.loads(out[out.index("{"):])


def test_finding_tag_marks_items_with_findings():
    item = ImpactItem(id="x", name="f", kind="function", file="a.php", line=3,
                      findings=[{"severity": "ERROR", "rule": "php-sql-injection"},
                                {"severity": "WARNING", "rule": "php-weak-hash"}])
    tag = _finding_tag(item)
    assert "2 findings" in tag and "php-sql-injection" in tag
    assert _finding_tag(ImpactItem(id="y", name="g", kind="function", file="b", line=1)) == ""


def _mk_repo(tmp_path):
    # vuln() at lines 2-4 contains a finding on line 3; safe() is unrelated.
    (tmp_path / "app.php").write_text(
        "<?php\nfunction vuln() {\n  $x = md5($_GET['p']);\n  return $x;\n}\n"
        "function safe() {\n  return 1;\n}\n",
        encoding="utf-8",
    )


def _mock_scan(monkeypatch, line=3):
    from radar.scan import runner
    sample = {"results": [{"check_id": "rules.php-weak-hash", "path": "app.php",
                           "start": {"line": line}, "extra": {"severity": "WARNING", "message": "md5"}}]}
    monkeypatch.setattr(runner, "detect_runtime", lambda: "native")
    monkeypatch.setattr(runner, "run_semgrep", lambda *a, **k: sample)


def test_overlay_tags_changed_function(monkeypatch, tmp_path):
    pytest.importorskip("tree_sitter_php")
    _mk_repo(tmp_path)
    _mock_scan(monkeypatch)
    res = CliRunner().invoke(cli.main, ["impact", "--path", str(tmp_path),
                                        "--function", "vuln", "--findings", "--format", "json"])
    assert res.exit_code == 0, res.output
    payload = _json(res)
    changed = payload["changed"]
    assert changed and changed[0]["findings"], "vuln() should be tagged with its finding"
    assert changed[0]["findings"][0]["rule"] == "php-weak-hash"


def test_no_findings_flag_means_no_overlay(monkeypatch, tmp_path):
    pytest.importorskip("tree_sitter_php")
    _mk_repo(tmp_path)
    _mock_scan(monkeypatch)
    res = CliRunner().invoke(cli.main, ["impact", "--path", str(tmp_path),
                                        "--function", "vuln", "--format", "json"])
    assert res.exit_code == 0
    payload = _json(res)
    assert all(not i["findings"] for i in payload["changed"] + payload["affected"])


def test_finding_outside_blast_radius_excluded(monkeypatch, tmp_path):
    pytest.importorskip("tree_sitter_php")
    _mk_repo(tmp_path)
    _mock_scan(monkeypatch, line=7)  # finding in safe(), but we trace vuln()
    res = CliRunner().invoke(cli.main, ["impact", "--path", str(tmp_path),
                                        "--function", "vuln", "--findings", "--format", "json"])
    assert res.exit_code == 0
    payload = _json(res)
    assert all(not i["findings"] for i in payload["changed"] + payload["affected"])


def test_overlay_falls_back_when_scan_unavailable(monkeypatch, tmp_path):
    pytest.importorskip("tree_sitter_php")
    _mk_repo(tmp_path)
    from radar.scan import runner

    def boom():
        raise runner.ScanError("No Semgrep runtime found.")

    monkeypatch.setattr(runner, "detect_runtime", boom)
    res = CliRunner().invoke(cli.main, ["impact", "--path", str(tmp_path),
                                        "--function", "vuln", "--findings", "--format", "json"])
    assert res.exit_code == 0  # impact still renders, overlay skipped
    assert _json(res)["changed"][0]["findings"] == []


def test_overlay_empty_scan_no_tags(monkeypatch, tmp_path):
    pytest.importorskip("tree_sitter_php")
    _mk_repo(tmp_path)
    from radar.scan import runner
    monkeypatch.setattr(runner, "detect_runtime", lambda: "native")
    monkeypatch.setattr(runner, "run_semgrep", lambda *a, **k: {"results": []})
    res = CliRunner().invoke(cli.main, ["impact", "--path", str(tmp_path),
                                        "--function", "vuln", "--findings", "--format", "json"])
    assert res.exit_code == 0
    assert all(not i["findings"] for i in _json(res)["changed"] + _json(res)["affected"])
