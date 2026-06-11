"""Tests for the suppression system (radar-ignore inline + .radar-ignore file)."""

import textwrap
from pathlib import Path

import pytest

from radar.scan.findings import Finding
from radar.scan.suppress import filter_findings


def _finding(path="app/routes/auth.js", line=10, rule="js-eval-user-input", sev="ERROR"):
    return Finding(severity=sev, path=path, line=line, rule=rule, message="test")


# ---------------------------------------------------------------------------
# Inline suppression
# ---------------------------------------------------------------------------

def test_inline_suppress_specific_rule(tmp_path):
    src = tmp_path / "app" / "routes" / "auth.js"
    src.parent.mkdir(parents=True)
    src.write_text("const x = eval(input);  // radar-ignore: js-eval-user-input\n")

    f = _finding(path="app/routes/auth.js", line=1, rule="js-eval-user-input")
    kept, suppressed = filter_findings([f], tmp_path)
    assert kept == []
    assert len(suppressed) == 1


def test_inline_suppress_all_rules(tmp_path):
    src = tmp_path / "app.js"
    src.write_text("const x = eval(input);  // radar-ignore\n")

    f = _finding(path="app.js", line=1, rule="js-eval-user-input")
    kept, suppressed = filter_findings([f], tmp_path)
    assert kept == []
    assert len(suppressed) == 1


def test_inline_suppress_wrong_rule_not_suppressed(tmp_path):
    src = tmp_path / "app.js"
    src.write_text("const x = eval(input);  // radar-ignore: js-sql-string-concat\n")

    f = _finding(path="app.js", line=1, rule="js-eval-user-input")
    kept, suppressed = filter_findings([f], tmp_path)
    assert len(kept) == 1
    assert suppressed == []


def test_inline_suppress_case_insensitive(tmp_path):
    src = tmp_path / "app.js"
    src.write_text("const x = eval(input);  // RADAR-IGNORE: js-eval-user-input\n")

    f = _finding(path="app.js", line=1, rule="js-eval-user-input")
    kept, suppressed = filter_findings([f], tmp_path)
    assert suppressed == [f]


# ---------------------------------------------------------------------------
# .radar-ignore file
# ---------------------------------------------------------------------------

def test_radar_ignore_file_specific(tmp_path):
    (tmp_path / ".radar-ignore").write_text("app/routes/auth.js:js-eval-user-input\n")
    f = _finding(path="app/routes/auth.js", line=5, rule="js-eval-user-input")
    kept, suppressed = filter_findings([f], tmp_path)
    assert kept == []
    assert suppressed == [f]


def test_radar_ignore_file_wildcard_rule(tmp_path):
    (tmp_path / ".radar-ignore").write_text("app/legacy/old.js:*\n")
    f = _finding(path="app/legacy/old.js", line=1, rule="js-sql-string-concat")
    kept, suppressed = filter_findings([f], tmp_path)
    assert suppressed == [f]


def test_radar_ignore_file_wildcard_path(tmp_path):
    (tmp_path / ".radar-ignore").write_text("*:js-hardcoded-jwt-secret\n")
    f1 = _finding(path="app/auth.js", line=1, rule="js-hardcoded-jwt-secret")
    f2 = _finding(path="lib/utils.js", line=2, rule="js-hardcoded-jwt-secret")
    kept, suppressed = filter_findings([f1, f2], tmp_path)
    assert kept == []
    assert len(suppressed) == 2


def test_radar_ignore_file_comments_ignored(tmp_path):
    (tmp_path / ".radar-ignore").write_text(textwrap.dedent("""\
        # this is a comment
        app/auth.js:js-eval-user-input
    """))
    f = _finding(path="app/auth.js", line=1, rule="js-eval-user-input")
    kept, suppressed = filter_findings([f], tmp_path)
    assert suppressed == [f]


def test_no_suppression_file_keeps_all(tmp_path):
    f = _finding()
    kept, suppressed = filter_findings([f], tmp_path)
    assert kept == [f]
    assert suppressed == []


def test_mixed_kept_and_suppressed(tmp_path):
    (tmp_path / ".radar-ignore").write_text("app/old.js:*\n")
    f_keep = _finding(path="app/new.js", line=1, rule="js-eval-user-input")
    f_suppress = _finding(path="app/old.js", line=5, rule="js-sql-string-concat")
    kept, suppressed = filter_findings([f_keep, f_suppress], tmp_path)
    assert kept == [f_keep]
    assert suppressed == [f_suppress]
