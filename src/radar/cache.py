"""External graph cache so `radar impact --path <repo>` leaves no `.radar/` behind.

The auto-build path writes here (keyed by the resolved repo path) instead of into
the target repo. An explicit `radar build` still writes `<repo>/.radar/graph.json`.
"""

import hashlib
import os
from pathlib import Path


def cache_root() -> Path:
    """Base dir for cached graphs: $RADAR_CACHE → %LOCALAPPDATA% (win) → ~/.cache."""
    env = os.environ.get("RADAR_CACHE")
    if env:
        return Path(env)
    local = os.environ.get("LOCALAPPDATA")
    if local:
        return Path(local) / "radar" / "cache"
    return Path.home() / ".cache" / "radar"


def graph_cache_path(root: Path) -> Path:
    """Deterministic cache file for a repo, outside that repo.

    The hash is only a filesystem key (not a security boundary); SHA-256 is used
    so static scanners don't flag the weaker SHA-1.
    """
    key = hashlib.sha256(str(root.resolve()).encode("utf-8")).hexdigest()[:16]
    return cache_root() / key / "graph.json"
