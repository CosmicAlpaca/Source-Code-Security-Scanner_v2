"""Engine orchestration: floor filtering, dry-run makes no calls, verdict wiring.

Stubs the LLM and semgrep boundaries (NOT the product's real code path) so the
orchestration logic is exercised offline. The real network call is validated live.
"""

from pathlib import Path

from radar.graph.builder import build_graph
from radar.triage import engine

FIXTURE = Path(__file__).parent / "fixtures" / "express-handler-object"

REPORT = {
    "results": [
        {"check_id": "js.xss", "path": "session.js", "start": {"line": 5},
         "extra": {"severity": "ERROR", "message": "reflected xss"}},
        {"check_id": "js.info", "path": "session.js", "start": {"line": 10},
         "extra": {"severity": "INFO", "message": "fyi"}},
    ]
}


def _wire(monkeypatch, verdict=None, fail_if_called=False):
    monkeypatch.setattr(engine, "detect_runtime", lambda: "native")
    monkeypatch.setattr(engine, "run_semgrep", lambda *a, **k: REPORT)
    monkeypatch.setattr("radar.cli._load_or_build_graph", lambda root, *a, **k: build_graph(FIXTURE))
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-not-used")

    calls = {"n": 0}

    def _stub(root, finding, snippet, reach, *, force=False):
        calls["n"] += 1
        if fail_if_called:
            raise AssertionError("get_verdict must not be called")
        return (verdict or {"exploitability": "exploitable", "confidence": 0.9,
                             "reasoning": "reachable from POST /login", "reachable": True}), False

    monkeypatch.setattr(engine.llm_client, "get_verdict", _stub)
    return calls


def test_floor_filters_info(monkeypatch):
    _wire(monkeypatch)
    results, _calls = engine.triage(FIXTURE, floor="warning")
    assert len(results) == 1  # INFO dropped
    assert results[0].finding.rule == "js.xss"
    assert results[0].verdict["exploitability"] == "exploitable"
    assert results[0].reach.status == "reachable"


def test_all_overrides_floor(monkeypatch):
    _wire(monkeypatch)
    results, _calls = engine.triage(FIXTURE, floor="warning", only_all=True)
    assert len(results) == 2


def test_dry_run_makes_zero_calls(monkeypatch):
    calls = _wire(monkeypatch, fail_if_called=True)
    emitted = []
    results, n_calls = engine.triage(FIXTURE, only_all=True, dry_run=True, emit=emitted.append)
    assert calls["n"] == 0
    assert n_calls == 0
    assert len(results) == 2
    assert any("POST /login" in m for m in emitted)  # reachability shown in payload


def test_call_count_tracks_uncached(monkeypatch):
    _wire(monkeypatch)
    _results, n_calls = engine.triage(FIXTURE, only_all=True)
    assert n_calls == 2


def _wire_no_key(monkeypatch):
    """Same boundaries as _wire but with no resolvable API key."""
    monkeypatch.setattr(engine, "detect_runtime", lambda: "native")
    monkeypatch.setattr(engine, "run_semgrep", lambda *a, **k: REPORT)
    monkeypatch.setattr("radar.cli._load_or_build_graph", lambda root, *a, **k: build_graph(FIXTURE))
    monkeypatch.setattr(engine.llm_client, "resolve_key", lambda: None)
    monkeypatch.setattr(engine.llm_client, "get_verdict",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("must not call AI offline")))


def test_no_key_raises_without_allow_offline(monkeypatch):
    _wire_no_key(monkeypatch)
    try:
        engine.triage(FIXTURE, only_all=True)
        raise AssertionError("expected TriageError")
    except engine.llm_client.TriageError:
        pass


def test_allow_offline_returns_reachability_only(monkeypatch):
    _wire_no_key(monkeypatch)
    results, n_calls = engine.triage(FIXTURE, only_all=True, allow_offline=True)
    assert n_calls == 0
    assert len(results) == 2
    assert all(tf.verdict is None for tf in results)  # ranked by risk, no AI verdict
    assert any(tf.reach.status == "reachable" for tf in results)
