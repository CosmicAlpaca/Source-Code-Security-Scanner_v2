"""scan.findings + scan.report tests."""

import json
from pathlib import Path

from radar.scan import report
from radar.scan.findings import exceeds_threshold, parse, summary

FIXTURE = Path(__file__).parent / "fixtures" / "semgrep-sample.json"


def load_fixture() -> dict:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def test_parse_sorts_by_severity_then_path():
    findings = parse(load_fixture())
    assert [f.severity for f in findings] == ["ERROR", "ERROR", "WARNING"]
    # within ERROR, sorted by path: routes/auth.js before services/db.js
    assert findings[0].path == "demo/app/routes/auth.js"
    assert findings[1].path == "demo/app/services/db.js"


def test_parse_empty_report():
    assert parse({"results": []}) == []


def test_parse_unknown_severity_defaults_info():
    report_dict = {"results": [{"path": "x.py", "start": {"line": 1}, "check_id": "r", "extra": {"severity": "BOGUS"}}]}
    assert parse(report_dict)[0].severity == "INFO"


def test_summary_counts():
    s = summary(parse(load_fixture()))
    assert s == {"error": 2, "warning": 1, "info": 0, "total": 3}


def test_exceeds_threshold():
    findings = parse(load_fixture())
    assert exceeds_threshold(findings, "error") is True   # 2 errors present
    assert exceeds_threshold(findings, "warning") is True
    assert exceeds_threshold([], "info") is False


def test_to_json_stable_schema():
    payload = json.loads(report.to_json(parse(load_fixture())))
    assert payload["schema"] == 1
    assert payload["summary"]["total"] == 3
    assert len(payload["findings"]) == 3
    assert payload["findings"][0]["severity"] == "ERROR"
