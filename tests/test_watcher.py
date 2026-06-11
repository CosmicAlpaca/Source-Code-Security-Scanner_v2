"""Unit tests for radar.scan.watcher — _ScanState logic (no filesystem required)."""
import pytest
from radar.scan.watcher import _ScanState


def make_finding(rule: str, line: int, message: str = "test msg", severity: str = "WARNING") -> dict:
    return {"rule": rule, "line": line, "message": message, "severity": severity}


class TestScanState:
    def test_first_scan_all_new(self):
        """All findings on first scan are NEW (nothing was there before)."""
        state = _ScanState()
        findings = [make_finding("sql-injection", 10), make_finding("eval-input", 20)]
        new_f, fixed_f = state.update("/app/foo.js", findings)
        assert len(new_f) == 2
        assert len(fixed_f) == 0

    def test_same_findings_no_diff(self):
        """Same findings on second scan → no diff."""
        state = _ScanState()
        findings = [make_finding("sql-injection", 10)]
        state.update("/app/foo.js", findings)
        new_f, fixed_f = state.update("/app/foo.js", findings)
        assert new_f == []
        assert fixed_f == []

    def test_fixed_finding_detected(self):
        """A finding that disappears is reported as FIXED."""
        state = _ScanState()
        findings = [make_finding("eval-input", 5), make_finding("sql-injection", 10)]
        state.update("/app/foo.js", findings)
        # Fix one finding
        new_f, fixed_f = state.update("/app/foo.js", [make_finding("sql-injection", 10)])
        assert new_f == []
        assert len(fixed_f) == 1
        assert fixed_f[0]["rule"] == "eval-input"
        assert fixed_f[0]["line"] == 5

    def test_new_finding_added(self):
        """A new finding introduced by an edit is reported as NEW."""
        state = _ScanState()
        state.update("/app/foo.js", [make_finding("sql-injection", 10)])
        new_f, fixed_f = state.update("/app/foo.js", [
            make_finding("sql-injection", 10),
            make_finding("xss-reflected", 25),
        ])
        assert len(new_f) == 1
        assert new_f[0]["rule"] == "xss-reflected"
        assert fixed_f == []

    def test_simultaneous_new_and_fixed(self):
        """One finding added and one fixed at the same time."""
        state = _ScanState()
        state.update("/app/foo.js", [make_finding("old-rule", 1)])
        new_f, fixed_f = state.update("/app/foo.js", [make_finding("new-rule", 99)])
        assert len(new_f) == 1 and new_f[0]["rule"] == "new-rule"
        assert len(fixed_f) == 1 and fixed_f[0]["rule"] == "old-rule"

    def test_empty_to_empty_no_diff(self):
        """Empty → empty stays clean."""
        state = _ScanState()
        new_f, fixed_f = state.update("/app/foo.js", [])
        assert new_f == []
        assert fixed_f == []
        new_f2, fixed_f2 = state.update("/app/foo.js", [])
        assert new_f2 == []
        assert fixed_f2 == []

    def test_different_files_isolated(self):
        """State for different files does not interfere."""
        state = _ScanState()
        state.update("/app/a.js", [make_finding("rule-a", 1)])
        state.update("/app/b.js", [make_finding("rule-b", 2)])
        # Update a.js only
        new_f, fixed_f = state.update("/app/a.js", [])
        assert fixed_f[0]["rule"] == "rule-a"
        # b.js state unchanged
        new_f2, fixed_f2 = state.update("/app/b.js", [make_finding("rule-b", 2)])
        assert new_f2 == [] and fixed_f2 == []

    def test_same_rule_different_line_treated_as_new(self):
        """Same rule but different line = old position fixed, new position added."""
        state = _ScanState()
        state.update("/app/foo.js", [make_finding("sql-injection", 10)])
        # Rule moved from line 10 to line 15 (e.g. code refactored)
        new_f, fixed_f = state.update("/app/foo.js", [make_finding("sql-injection", 15)])
        assert len(new_f) == 1 and new_f[0]["line"] == 15
        assert len(fixed_f) == 1 and fixed_f[0]["line"] == 10

    def test_fixed_finding_contains_filepath(self):
        """Fixed finding dict always includes filepath key."""
        state = _ScanState()
        state.update("/app/foo.py", [make_finding("hardcoded-key", 3)])
        _, fixed_f = state.update("/app/foo.py", [])
        assert fixed_f[0]["filepath"] == "/app/foo.py"

    def test_multiple_updates_accumulate_correctly(self):
        """Three consecutive scans — state accumulates correctly."""
        state = _ScanState()
        # Scan 1: two findings
        state.update("/app/foo.js", [make_finding("a", 1), make_finding("b", 2)])
        # Scan 2: fix b, add c
        state.update("/app/foo.js", [make_finding("a", 1), make_finding("c", 3)])
        # Scan 3: fix a, keep c
        new_f, fixed_f = state.update("/app/foo.js", [make_finding("c", 3)])
        assert len(new_f) == 0
        assert len(fixed_f) == 1
        assert fixed_f[0]["rule"] == "a"
