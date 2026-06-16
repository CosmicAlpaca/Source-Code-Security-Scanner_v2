"""External graph cache + zero-footprint impact behavior."""

import json
import os
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


def test_impact_not_found_emits_valid_machine_format(tmp_path):
    """`--function <missing>` keeps stdout pure: valid empty json/html, progress on stderr.

    Run as a real subprocess so stdout/stderr are truly separate (CliRunner merges them).
    """
    import subprocess
    import sys

    repo = tmp_path / "ext-repo"
    shutil.copytree(JS_FIXTURE, repo)
    env = {**os.environ, "RADAR_CACHE": str(tmp_path / "cache")}
    base = [sys.executable, "-m", "radar.cli", "impact", "--path", str(repo), "--function", "doesNotExist"]

    js = subprocess.run([*base, "--format", "json"], capture_output=True, text=True, env=env)
    assert js.returncode == 0
    data = json.loads(js.stdout)  # stdout is pure JSON, not "No function named ..."
    assert data["changed"] == [] and data["apis"] == []
    assert "building graph" in js.stderr  # progress went to stderr, off stdout

    html = subprocess.run([*base, "--format", "html"], capture_output=True, text=True, env=env)
    assert html.returncode == 0 and html.stdout.lstrip().startswith("<!DOCTYPE html>")

    term = subprocess.run(base, capture_output=True, text=True, env=env)  # friendly on terminal
    assert "No function named 'doesNotExist'" in term.stdout + term.stderr


def _seed_cache(repo: Path, *, version, head="deadbeef", marker="SEED::marker"):
    """Write a hand-crafted cache graph with a chosen version + head + marker node."""
    cache_path = cache.graph_cache_path(repo)
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "version": version,
        "head": head,
        "stats": {},
        "nodes": [{"id": marker, "kind": "function", "name": "marker"}],
        "edges": [],
    }
    cache_path.write_text(json.dumps(payload), encoding="utf-8")
    return cache_path


def test_stale_version_cache_is_rebuilt(monkeypatch, tmp_path):
    """A cache from an OLDER builder version is stale even if repo HEAD is unchanged."""
    from radar.graph import builder

    repo = tmp_path / "ext-repo"
    shutil.copytree(JS_FIXTURE, repo)
    monkeypatch.setenv("RADAR_CACHE", str(tmp_path / "cache"))
    monkeypatch.setattr(builder, "git_head", lambda root: "deadbeef")  # pin HEAD

    cache_path = _seed_cache(repo, version=builder.GRAPH_VERSION - 1, marker="STALE::marker")

    graph = _load_or_build_graph(repo)

    assert "STALE::marker" not in graph.nodes      # stale cache discarded
    assert graph.number_of_nodes() > 1             # real graph rebuilt from source
    reloaded = json.loads(cache_path.read_text(encoding="utf-8"))
    assert reloaded["version"] == builder.GRAPH_VERSION  # cache restamped to current


def test_fresh_version_cache_is_reused(monkeypatch, tmp_path):
    """Matching HEAD + current version → cache reused, no rebuild."""
    from radar.graph import builder

    repo = tmp_path / "ext-repo"
    shutil.copytree(JS_FIXTURE, repo)
    monkeypatch.setenv("RADAR_CACHE", str(tmp_path / "cache"))
    monkeypatch.setattr(builder, "git_head", lambda root: "deadbeef")

    _seed_cache(repo, version=builder.GRAPH_VERSION, marker="SEED::marker")

    graph = _load_or_build_graph(repo)

    assert "SEED::marker" in graph.nodes  # returned the seeded graph as-is, did not rebuild


def test_graph_override_skips_build(tmp_path):
    """--graph loads the given file and never builds/caches."""
    from radar.graph.builder import build_graph, save_graph

    out = tmp_path / "g.json"
    save_graph(build_graph(JS_FIXTURE), out)
    graph = _load_or_build_graph(tmp_path / "irrelevant", out)
    assert "routes/auth.js::login" in graph.nodes
