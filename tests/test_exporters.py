"""Exporter tests: JSON schema stability, Mermaid structure, HTML smoke."""

import json
from pathlib import Path

import pytest

from radar.config import load_config
from radar.graph.builder import build_graph
from radar.impact.tracer import ImpactItem, ImpactResult, trace
from radar.report.exporters import MERMAID_MAX_NODES, to_html, to_json, to_mermaid

FIXTURE = Path(__file__).parent / "fixtures" / "js-app"


@pytest.fixture(scope="module")
def result():
    graph = build_graph(FIXTURE)
    return trace(graph, ["utils/validate.js::validateUser"])


def test_json_schema_keys(result):
    payload = json.loads(to_json(result))
    assert set(payload) == {"schema", "changed", "affected", "apis", "features", "stats"}
    assert payload["schema"] == 1
    changed = payload["changed"][0]
    assert {"id", "name", "kind", "file", "line", "feature"} <= set(changed)
    affected = payload["affected"][0]
    assert {"name", "depth", "via_changed", "confidence"} <= set(affected)


def test_json_matches_pr_comment_renderer(result):
    """The CI comment script must accept exactly what `--format json` emits."""
    import importlib.util

    script = Path(__file__).parent.parent / "scripts" / "render-pr-comment.py"
    spec = importlib.util.spec_from_file_location("rpc", script)
    rpc = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(rpc)
    out = "\n".join(rpc.render_impact_section(json.loads(to_json(result))))
    assert "Impact (blast radius)" in out
    assert "validateUser" in out


def test_mermaid_structure(result):
    mermaid = to_mermaid(result)
    assert mermaid.startswith("flowchart TD")
    assert '"validateUser"' in mermaid
    assert '(["POST /login"])' in mermaid  # route shape
    assert "-->" in mermaid
    assert "style n0 fill:#f88" in mermaid  # changed node highlighted


def test_mermaid_caps_nodes():
    changed = [ImpactItem(id="c0", name="c0", kind="function", file="f.js", line=1)]
    affected = [
        ImpactItem(id=f"a{i}", name=f"a{i}", kind="function", file="f.js", line=i,
                   depth=1, via_changed="c0", parent="c0")
        for i in range(80)
    ]
    result = ImpactResult(changed, affected, [], [], {"functions_affected": 80, "apis_affected": 0,
                                                      "features_affected": 0, "approximate": 0})
    mermaid = to_mermaid(result)
    assert "nodes hidden" in mermaid
    assert mermaid.count('["a') <= MERMAID_MAX_NODES


def test_html_smoke(result):
    html = to_html(result)
    assert "<!DOCTYPE html>" in html
    assert "validateUser" in html
    assert "mermaid" in html


def test_mermaid_sanitizes_untrusted_names():
    changed = [ImpactItem(id="c", name='x"]; click n0 evil[<b>', kind="function", file="f.js", line=1)]
    result = ImpactResult(changed, [], [], [], {"functions_affected": 0, "apis_affected": 0,
                                                "features_affected": 0, "approximate": 0})
    label = to_mermaid(result).split('"')[1]  # text between the label quotes
    assert not set('"[];<>{}`') & set(label)


def test_html_escapes_untrusted_names():
    changed = [ImpactItem(id="c", name="<script>alert(1)</script>", kind="function", file="f.js", line=1)]
    result = ImpactResult(changed, [], [], [], {"functions_affected": 0, "apis_affected": 0,
                                                "features_affected": 0, "approximate": 0})
    html = to_html(result)
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html
