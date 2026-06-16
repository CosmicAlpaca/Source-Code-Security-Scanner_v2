"""External graph cache + zero-footprint impact behavior."""

import shutil
from pathlib import Path

from radar import cache, cli
from radar.cli import _load_or_build_graph

JS_FIXTURE = Path(__file__).parent / "fixtures" / "js-app"


def test_cache_root_respects_env(monkeypatch, tmp_path):
    monkeypatch.setenv("RADAR_CACHE", str(tmp_path / "c"))
    assert cache.cache_root() == tmp_path / "c"


def test_graph_cache_path_outside_repo_and_deterministic(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    p1 = cache.graph_cache_path(repo)
    p2 = cache.graph_cache_path(repo)
    assert p1 == p2
    assert p1.name == "graph.json"
    assert repo not in p1.parents  # never inside the scanned repo


def test_impact_autobuild_is_zero_footprint(monkeypatch, tmp_path):
    """Auto-build for an external repo writes to the cache, not <repo>/.radar."""
    repo = tmp_path / "ext-repo"
    shutil.copytree(JS_FIXTURE, repo)
    monkeypatch.setenv("RADAR_CACHE", str(tmp_path / "cache"))

    graph = _load_or_build_graph(repo)

    assert graph.number_of_nodes() > 0
    assert not (repo / ".radar").exists()                 # nothing dropped into the repo
    assert cache.graph_cache_path(repo).is_file()         # cached outside instead


def test_graph_override_skips_build(tmp_path):
    """--graph loads the given file and never builds/caches."""
    from radar.graph.builder import build_graph, save_graph

    out = tmp_path / "g.json"
    save_graph(build_graph(JS_FIXTURE), out)
    graph = _load_or_build_graph(tmp_path / "irrelevant", out)
    assert "routes/auth.js::login" in graph.nodes
