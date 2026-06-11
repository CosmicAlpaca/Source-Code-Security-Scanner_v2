"""Verdict cache: stable keys + cache hits that never touch the network."""

import json
from pathlib import Path

from radar.scan.findings import Finding
from radar.triage import llm_client
from radar.triage.reachability import Reach

FINDING = Finding("ERROR", "a.js", 10, "js.xss", "msg")
REACH = Reach("a.js::f", ["POST /x"], "reachable")


def test_cache_key_stable_and_snippet_sensitive():
    k1 = llm_client.cache_key("gpt-4o-mini", FINDING, "snippet A", REACH.status)
    k2 = llm_client.cache_key("gpt-4o-mini", FINDING, "snippet A", REACH.status)
    k3 = llm_client.cache_key("gpt-4o-mini", FINDING, "snippet B", REACH.status)
    assert k1 == k2
    assert k1 != k3


def test_get_verdict_uses_cache_without_network(tmp_path, monkeypatch):
    monkeypatch.setenv("RADAR_CACHE", str(tmp_path))
    monkeypatch.delenv("LOCALAPPDATA", raising=False)

    # Any network attempt must fail the test.
    def _boom(*_a, **_k):
        raise AssertionError("network call attempted on a cache hit")

    monkeypatch.setattr(llm_client, "call", _boom)

    root = Path("/repo/demo")
    snippet = "res.send(user)"
    key = llm_client.cache_key(llm_client.resolve_model(), FINDING, snippet, REACH.status)
    path = llm_client.verdict_cache_path(root, key)
    path.parent.mkdir(parents=True, exist_ok=True)
    seeded = {"exploitability": "exploitable", "confidence": 0.9, "reasoning": "x", "reachable": True}
    path.write_text(json.dumps(seeded), encoding="utf-8")

    verdict, cached = llm_client.get_verdict(root, FINDING, snippet, REACH)
    assert cached is True
    assert verdict["exploitability"] == "exploitable"


def test_missing_key_raises_actionable_error(tmp_path, monkeypatch):
    monkeypatch.setenv("RADAR_CACHE", str(tmp_path))
    monkeypatch.delenv("LOCALAPPDATA", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("RADAR_AI_API_KEY", raising=False)
    try:
        llm_client.get_verdict(Path("/repo/x"), FINDING, "fresh snippet", REACH, force=True)
        assert False, "expected TriageError"
    except llm_client.TriageError as exc:
        assert "API key" in str(exc)
