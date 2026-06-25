"""Scan-engine plugin interface + registry.

Adding a scanner = drop one module in this package that defines a ScanEngine
subclass and calls register() at import time. The package __init__ auto-imports
every module here (pkgutil), so the aggregator never references a specific
engine — exactly mirroring the graph/languages plugin pattern.

Every engine normalizes its native output into radar's shared Finding model, so
the rest of the pipeline (risk ranking, suppression, dashboard, blast-radius
overlay) treats Semgrep, Gitleaks, Bandit and Trivy results identically.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

from radar.scan.findings import Finding


class ScanEngine(ABC):
    """One security scanner wrapped behind a uniform interface."""

    #: stable id used on the CLI and in metadata["engine"], e.g. "semgrep"
    name: str = ""
    #: one-line human description (shown by `radar engines`)
    description: str = ""
    #: run in the default set when the user passes no --engine
    default: bool = True

    @abstractmethod
    def detect(self) -> str | None:
        """Return a runtime label ('native'/'docker'/…) if the engine can run,
        else None. Must be cheap and side-effect-free — no downloads, no network,
        no writes — so it is safe to probe on every scan."""

    @abstractmethod
    def scan(
        self,
        target: Path,
        *,
        rules_only: bool = False,
        runtime: str | None = None,
        extra_config: list[str] | None = None,
    ) -> list[Finding]:
        """Run the scanner on `target` and return normalized findings.

        `runtime` is the label returned by detect() (so the engine need not probe
        twice). Engines should fail soft — return [] rather than raise — for
        recoverable problems; raise only when the run is genuinely unusable.
        """


#: name -> engine instance
ENGINES: dict[str, ScanEngine] = {}


def register(engine: ScanEngine) -> None:
    ENGINES[engine.name] = engine


def get_engine(name: str) -> ScanEngine | None:
    return ENGINES.get(name)


def all_engines() -> list[ScanEngine]:
    """Registered engines, sorted by name for deterministic output."""
    return sorted(ENGINES.values(), key=lambda e: e.name)


def default_engine_names() -> list[str]:
    """Engines that run when the user doesn't restrict with --engine."""
    return [e.name for e in all_engines() if e.default]
