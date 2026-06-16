"""radar.config.yml loader — feature map (glob -> name) + exclude globs.

Globs match against posix relpaths only (never resolved on the filesystem),
so config from an untrusted repo cannot escape the repo root. Matching uses
fnmatch semantics: '*' crosses '/' too — keep patterns simple.
"""

import fnmatch
from dataclasses import dataclass, field
from pathlib import Path

import yaml

CONFIG_FILENAME = "radar.config.yml"
UNMAPPED = "(unmapped)"


@dataclass
class RadarConfig:
    features: dict[str, list[str]] = field(default_factory=dict)  # name -> [globs]
    exclude: list[str] = field(default_factory=list)

    def feature_for(self, relpath: str) -> str | None:
        for name, globs in self.features.items():
            if any(fnmatch.fnmatch(relpath, g) for g in globs):
                return name
        return None

    def is_excluded(self, relpath: str) -> bool:
        return any(fnmatch.fnmatch(relpath, g) for g in self.exclude)


def load_config(root: Path) -> RadarConfig | None:
    """Load <root>/radar.config.yml; None if absent, ValueError if malformed."""
    config_path = root / CONFIG_FILENAME
    if not config_path.is_file():
        return None
    data = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise ValueError(f"{CONFIG_FILENAME}: top level must be a mapping")

    features_raw = data.get("features") or {}
    if not isinstance(features_raw, dict):
        raise ValueError(f"{CONFIG_FILENAME}: 'features' must be a mapping of name -> globs")
    features: dict[str, list[str]] = {}
    for name, globs in features_raw.items():
        if isinstance(globs, str):
            globs = [globs]
        if not isinstance(globs, list) or not all(isinstance(g, str) for g in globs):
            raise ValueError(f"{CONFIG_FILENAME}: feature '{name}' globs must be strings")
        features[str(name)] = globs

    exclude = data.get("exclude") or []
    if isinstance(exclude, str):
        exclude = [exclude]
    if not isinstance(exclude, list) or not all(isinstance(g, str) for g in exclude):
        raise ValueError(f"{CONFIG_FILENAME}: 'exclude' must be a list of glob strings")

    return RadarConfig(features=features, exclude=[str(g) for g in exclude])
