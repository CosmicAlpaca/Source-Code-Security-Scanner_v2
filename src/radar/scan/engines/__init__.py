"""Auto-discover scan engines + the multi-engine aggregator (`scan_all`).

Import this package to trigger discovery of every engine module, then call
`scan_all()` to run the selected engines and get a single, merged, sorted
list[Finding] back — the one place the rest of radar gets its findings from.
"""

from __future__ import annotations

import importlib
import pkgutil
from dataclasses import dataclass
from pathlib import Path

from radar.scan.engines.base import (  # noqa: F401  (re-exported)
    ENGINES,
    ScanEngine,
    all_engines,
    default_engine_names,
    get_engine,
    register,
)
from radar.scan.findings import SEVERITY_ORDER, Finding

# Auto-import every sibling module so each engine's register() runs at import
# time. Core never names a concrete engine — drop a file in, it's discovered.
for _mod in pkgutil.iter_modules(__path__):
    if _mod.name != "base":
        importlib.import_module(f"{__name__}.{_mod.name}")


@dataclass
class EngineRun:
    """Per-engine outcome of a scan_all() run (for reporting/diagnostics)."""

    name: str
    status: str  # "ok" | "unavailable" | "error"
    runtime: str | None = None
    count: int = 0
    message: str = ""


def _dedup(findings: list[Finding]) -> list[Finding]:
    """Drop exact duplicates keyed by (engine, path, line, rule).

    Cross-engine overlap (e.g. Semgrep and Trivy both flagging a secret) is kept
    on purpose — different engines give independent signal; only identical rows
    from the same engine are collapsed.
    """
    seen: set[tuple] = set()
    out: list[Finding] = []
    for f in findings:
        key = (f.metadata.get("engine", ""), f.path, f.line, f.rule)
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out


def scan_all(
    target: Path | str,
    *,
    rules_only: bool = False,
    engines: list[str] | None = None,
    extra_config: list[str] | None = None,
    emit=None,
) -> tuple[list[Finding], list[EngineRun]]:
    """Run the selected engines and return (merged_findings, runs).

    `engines`: explicit list of engine names, or None for the default set. An
    unavailable or failing engine is recorded in `runs` and skipped — never
    fatal. The caller decides what to do when *nothing* ran (status == "ok"
    appears nowhere): `radar scan` treats that as exit-2 "scan failed".
    """
    target = Path(target)
    names = list(engines) if engines else default_engine_names()
    emit = emit or (lambda _m: None)

    runs: list[EngineRun] = []
    merged: list[Finding] = []

    for name in names:
        eng = get_engine(name)
        if eng is None:
            runs.append(EngineRun(name, "error", message="unknown engine"))
            emit(f"[yellow]⚠ unknown engine: {name}[/]")
            continue

        try:
            runtime = eng.detect()
        except Exception as exc:  # detect must be safe, but never trust it fully
            runs.append(EngineRun(name, "unavailable", message=str(exc)))
            emit(f"[dim]· {name}: skipped (not available)[/]")
            continue

        if not runtime:
            runs.append(EngineRun(name, "unavailable", message="not installed"))
            emit(f"[dim]· {name}: skipped (not available)[/]")
            continue

        emit(f"[dim]· {name} ({runtime})…[/]")
        try:
            items = eng.scan(
                target, rules_only=rules_only, runtime=runtime,
                extra_config=extra_config,
            )
        except Exception as exc:
            runs.append(EngineRun(name, "error", runtime=runtime, message=str(exc)))
            emit(f"[yellow]⚠ {name} failed: {exc}[/]")
            continue

        for f in items:
            f.metadata.setdefault("engine", name)
        merged.extend(items)
        runs.append(EngineRun(name, "ok", runtime=runtime, count=len(items)))

    merged = _dedup(merged)
    merged.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 3), f.path, f.line))
    return merged, runs


def ran_any(runs: list[EngineRun]) -> bool:
    """True if at least one engine actually executed (status 'ok')."""
    return any(r.status == "ok" for r in runs)


def runs_summary(runs: list[EngineRun]) -> str:
    """Compact one-line engine summary, e.g. 'semgrep:4 trivy:2 bandit:skipped'."""
    parts = []
    for r in runs:
        if r.status == "ok":
            parts.append(f"{r.name}:{r.count}")
        elif r.status == "unavailable":
            parts.append(f"{r.name}:skipped")
        else:
            parts.append(f"{r.name}:error")
    return "  ".join(parts)
