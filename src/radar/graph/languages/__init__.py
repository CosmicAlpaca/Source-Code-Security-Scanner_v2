"""Auto-discover language plugins: import every module in this package."""

import importlib
import pkgutil

from radar.graph.languages.base import EXTRACTORS, extractor_for, register  # noqa: F401

for _mod in pkgutil.iter_modules(__path__):
    if _mod.name != "base":
        importlib.import_module(f"{__name__}.{_mod.name}")
