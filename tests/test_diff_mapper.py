"""diff_mapper tests against a temporary git repo built from the js-app fixture."""

import shutil
import subprocess
from pathlib import Path

import pytest

from radar.graph.builder import build_graph
from radar.impact.diff_mapper import changed_lines, find_function_nodes, map_to_nodes

FIXTURE = Path(__file__).parent / "fixtures" / "js-app"
GIT_ENV = [
    "-c", "user.email=test@example.com",
    "-c", "user.name=test",
    "-c", "core.autocrlf=false",
]


def git(repo: Path, *args: str) -> None:
    subprocess.run(["git", *GIT_ENV, *args], cwd=repo, check=True, capture_output=True)


@pytest.fixture()
def repo(tmp_path: Path) -> Path:
    repo = tmp_path / "app"
    shutil.copytree(FIXTURE, repo)
    git(repo, "init", "-q")
    git(repo, "add", ".")
    git(repo, "commit", "-q", "-m", "init")
    return repo


def test_changed_lines_detects_edit(repo: Path):
    target = repo / "utils" / "validate.js"
    source = target.read_text(encoding="utf-8")
    target.write_text(source.replace("!payload.username", "!payload.username || !payload.password"),
                      encoding="utf-8")
    git(repo, "commit", "-aqm", "edit")
    changes = changed_lines(repo, rev="HEAD~1")
    assert set(changes) == {"utils/validate.js"}
    assert 5 in changes["utils/validate.js"]  # line inside validateUser


def test_staged_changes(repo: Path):
    target = repo / "services" / "db.js"
    target.write_text(target.read_text(encoding="utf-8").replace("DELETE FROM", "DELETE  FROM"),
                      encoding="utf-8")
    git(repo, "add", ".")
    changes = changed_lines(repo, staged=True)
    assert set(changes) == {"services/db.js"}


def test_map_edit_to_function_node(repo: Path):
    graph = build_graph(repo)
    changed = map_to_nodes(graph, {"utils/validate.js": {5}})
    assert changed == ["utils/validate.js::validateUser"]


def test_map_nested_picks_narrowest(repo: Path):
    graph = build_graph(repo)
    # line 10 of routes/users.js is inside listUsers? route registration is top-level
    changed = map_to_nodes(graph, {"routes/users.js": {7}})
    assert changed == ["routes/users.js::listUsers"]


def test_top_level_change_falls_back_to_file(repo: Path):
    graph = build_graph(repo)
    # line 1 (require) is outside every function
    changed = map_to_nodes(graph, {"services/db.js": {23}})
    assert changed == ["services/db.js"]


def test_pure_deletion_maps_to_anchor(repo: Path):
    target = repo / "routes" / "auth.js"
    lines = target.read_text(encoding="utf-8").splitlines(keepends=True)
    del lines[8:10]  # remove two lines inside login()
    target.write_text("".join(lines), encoding="utf-8")
    git(repo, "commit", "-aqm", "delete lines")
    changes = changed_lines(repo, rev="HEAD~1")
    assert "routes/auth.js" in changes


def test_find_function_nodes_by_name_and_id(repo: Path):
    graph = build_graph(repo)
    assert find_function_nodes(graph, "validateUser") == ["utils/validate.js::validateUser"]
    assert find_function_nodes(graph, "utils/validate.js::validateUser") == [
        "utils/validate.js::validateUser"
    ]
    assert find_function_nodes(graph, "doesNotExist") == []
