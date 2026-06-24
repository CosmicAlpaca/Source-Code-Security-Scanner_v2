"""Multi-engine scan registry + aggregator + per-engine parsers.

Engines are exercised with their subprocess/runner boundary stubbed (no real
Semgrep/Bandit/Trivy/Gitleaks binaries), so the orchestration and normalization
logic runs fully offline.
"""

from pathlib import Path

from click.testing import CliRunner

from radar import cli
from radar.scan import engines
from radar.scan.engines import EngineRun, scan_all
from radar.scan.engines.base import ScanEngine, all_engines, default_engine_names
from radar.scan.findings import Finding


# ── registry ──────────────────────────────────────────────────────────────────

def test_four_engines_registered():
    names = {e.name for e in all_engines()}
    assert {"semgrep", "gitleaks", "bandit", "trivy"} <= names


def test_all_engines_default_on():
    assert set(default_engine_names()) >= {"semgrep", "gitleaks", "bandit", "trivy"}


# ── aggregator: scan_all ──────────────────────────────────────────────────────

class _FakeEngine(ScanEngine):
    def __init__(self, name, runtime, findings, default=True):
        self.name = name
        self.description = f"fake {name}"
        self.default = default
        self._runtime = runtime
        self._findings = findings

    def detect(self):
        return self._runtime

    def scan(self, target, *, rules_only=False, runtime=None, extra_config=None):
        return list(self._findings)


def _install(monkeypatch, *fakes):
    """Replace the registry with a deterministic set of fake engines."""
    reg = {f.name: f for f in fakes}
    monkeypatch.setattr(engines.base, "ENGINES", reg, raising=True)
    monkeypatch.setattr(engines, "ENGINES", reg, raising=True)


def test_scan_all_merges_sorts_and_tags(monkeypatch):
    a = _FakeEngine("eng_a", "native", [
        Finding("WARNING", "z.py", 9, "a.warn", "w"),
        Finding("ERROR", "a.py", 2, "a.err", "e"),
    ])
    b = _FakeEngine("eng_b", "docker", [Finding("ERROR", "b.py", 1, "b.err", "x")])
    _install(monkeypatch, a, b)

    items, runs = scan_all(Path("."))
    # sorted by (severity, path, line): errors before warnings
    assert [f.rule for f in items] == ["a.err", "b.err", "a.warn"]
    # every finding tagged with its engine
    assert {f.metadata["engine"] for f in items} == {"eng_a", "eng_b"}
    assert all(r.status == "ok" for r in runs)
    assert {r.name: r.count for r in runs} == {"eng_a": 2, "eng_b": 1}


def test_scan_all_skips_unavailable(monkeypatch):
    ok = _FakeEngine("ok", "native", [Finding("ERROR", "a.py", 1, "r", "m")])
    off = _FakeEngine("off", None, [Finding("ERROR", "b.py", 1, "r", "m")])
    _install(monkeypatch, ok, off)

    items, runs = scan_all(Path("."))
    assert len(items) == 1
    status = {r.name: r.status for r in runs}
    assert status == {"ok": "ok", "off": "unavailable"}


def test_scan_all_engine_error_is_recorded_not_fatal(monkeypatch):
    class _Boom(_FakeEngine):
        def scan(self, *a, **k):
            raise RuntimeError("kaboom")

    boom = _Boom("boom", "native", [])
    good = _FakeEngine("good", "native", [Finding("ERROR", "a.py", 1, "r", "m")])
    _install(monkeypatch, boom, good)

    items, runs = scan_all(Path("."))
    assert len(items) == 1  # good still ran
    status = {r.name: r.status for r in runs}
    assert status["boom"] == "error" and status["good"] == "ok"


def test_scan_all_explicit_subset(monkeypatch):
    a = _FakeEngine("a", "native", [Finding("ERROR", "a.py", 1, "r", "m")])
    b = _FakeEngine("b", "native", [Finding("ERROR", "b.py", 1, "r", "m")])
    _install(monkeypatch, a, b)

    items, runs = scan_all(Path("."), engines=["a"])
    assert [r.name for r in runs] == ["a"]
    assert len(items) == 1


def test_scan_all_dedups_within_engine(monkeypatch):
    dup = Finding("ERROR", "a.py", 1, "r", "m")
    dup2 = Finding("ERROR", "a.py", 1, "r", "m")
    a = _FakeEngine("a", "native", [dup, dup2])
    _install(monkeypatch, a)
    items, _ = scan_all(Path("."))
    assert len(items) == 1


# ── Bandit parser ─────────────────────────────────────────────────────────────

def test_bandit_parse_maps_severity_and_path(tmp_path):
    from radar.scan.engines.bandit_engine import parse_bandit

    report = {"results": [
        {"filename": str(tmp_path / "app.py"), "issue_severity": "HIGH",
         "issue_confidence": "HIGH", "issue_text": "subprocess w/ shell",
         "test_id": "B602", "line_number": 12, "issue_cwe": {"id": 78}},
        {"filename": str(tmp_path / "x.py"), "issue_severity": "LOW",
         "issue_text": "assert used", "test_id": "B101", "line_number": 3},
    ]}
    items = parse_bandit(report, tmp_path)
    assert items[0].severity == "ERROR" and items[0].rule == "bandit.B602"
    assert items[0].path == "app.py" and items[0].line == 12
    assert items[0].metadata["cwe"] == "CWE-78"
    # B602 (subprocess shell) -> A03 via the B6xx prefix, set directly on the finding
    assert items[0].metadata["owasp"] == "A03"
    assert items[1].severity == "INFO" and items[1].rule == "bandit.B101"


def test_bandit_owasp_direct_tagging():
    from radar.scan.engines.bandit_engine import _bandit_owasp
    from radar.scan.findings import owasp_tag_for

    assert _bandit_owasp("B303") == "A02"   # md5 -> crypto
    assert _bandit_owasp("B608") == "A03"   # hardcoded SQL -> injection
    assert _bandit_owasp("B506") == "A08"   # yaml.load -> deserialization
    assert _bandit_owasp("B602") == "A03"   # B6xx prefix
    assert _bandit_owasp("B101") is None    # assert_used -> unmapped (fallback)

    # end-to-end: a tagged Bandit finding classifies without needing CWE/keyword
    from radar.scan.findings import Finding
    f = Finding("WARNING", "a.py", 1, "bandit.B303", "md5", metadata={"engine": "bandit", "owasp": "A02"})
    assert owasp_tag_for(f) == ("A02", "Cryptographic Failures")


# ── Trivy parser ──────────────────────────────────────────────────────────────

def test_trivy_parse_vuln_misconfig_secret(tmp_path):
    from radar.scan.engines.trivy_engine import parse_trivy

    report = {"Results": [
        {"Target": "package-lock.json", "Vulnerabilities": [
            {"VulnerabilityID": "CVE-2021-23337", "PkgName": "lodash",
             "InstalledVersion": "4.17.20", "FixedVersion": "4.17.21",
             "Severity": "HIGH", "Title": "command injection"}]},
        {"Target": "Dockerfile", "Misconfigurations": [
            {"ID": "DS002", "Title": "root user", "Description": "runs as root",
             "Severity": "MEDIUM", "CauseMetadata": {"StartLine": 5}}]},
        {"Target": ".env", "Secrets": [
            {"RuleID": "aws-access-key", "Title": "AWS key", "StartLine": 2}]},
    ]}
    items = parse_trivy(report, tmp_path)
    by_rule = {f.rule: f for f in items}

    cve = by_rule["trivy.CVE-2021-23337"]
    assert cve.severity == "ERROR" and "lodash" in cve.message and "4.17.21" in cve.message
    assert cve.metadata["owasp"].startswith("A06")

    mis = by_rule["trivy.DS002"]
    assert mis.severity == "WARNING" and mis.line == 5

    sec = by_rule["trivy.secret.aws-access-key"]
    assert sec.severity == "ERROR" and sec.line == 2


# ── Semgrep engine uses the runner (monkeypatched) ────────────────────────────

def test_semgrep_engine_parses_runner_output(monkeypatch, tmp_path):
    from radar.scan import runner
    from radar.scan.engines.semgrep_engine import SemgrepEngine

    report = {"results": [{"check_id": "rules.x", "path": "a.js",
                           "start": {"line": 3}, "extra": {"severity": "ERROR", "message": "bad"}}]}
    monkeypatch.setattr(runner, "detect_runtime", lambda: "native")
    monkeypatch.setattr(runner, "run_semgrep", lambda *a, **k: report)

    eng = SemgrepEngine()
    assert eng.detect() == "native"
    items = eng.scan(tmp_path, runtime="native")
    assert len(items) == 1 and items[0].rule == "rules.x"


# ── Gitleaks engine detect() never auto-downloads ─────────────────────────────

def test_gitleaks_detect_is_side_effect_free(monkeypatch):
    import radar.scan.engines.gitleaks_engine as ge

    monkeypatch.setattr(ge.shutil, "which", lambda _n: None)
    monkeypatch.setattr(ge, "_vendored_exists", lambda: False)
    # No native binary, no vendored, no docker -> None, and crucially no download.
    assert ge.GitleaksEngine().detect() is None


# ── `radar engines` CLI ───────────────────────────────────────────────────────

def test_engines_command_lists_all():
    res = CliRunner().invoke(cli.main, ["engines"])
    assert res.exit_code == 0
    for name in ("semgrep", "gitleaks", "bandit", "trivy"):
        assert name in res.output


# ── `radar scan --engine` selector ────────────────────────────────────────────

def test_scan_engine_selector_runs_only_chosen(monkeypatch, tmp_path):
    from radar.scan import runner

    report = {"results": [{"check_id": "rules.x", "path": "a.js",
                           "start": {"line": 3}, "extra": {"severity": "ERROR", "message": "bad"}}]}
    monkeypatch.setattr(runner, "detect_runtime", lambda: "native")
    monkeypatch.setattr(runner, "run_semgrep", lambda *a, **k: report)

    res = CliRunner().invoke(cli.main, ["scan", str(tmp_path), "--engine", "semgrep"])
    assert res.exit_code == 0
    assert "1 finding(s)" in res.output
    assert "semgrep:1" in res.output
