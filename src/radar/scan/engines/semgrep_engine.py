"""Semgrep engine — radar's primary SAST scanner (preset + 50 bundled rules).

Thin adapter over scan.runner so the existing native→module→docker discovery and
zero-footprint behaviour are reused verbatim. Calls are routed through the
`runner` module object (not bound imports) so existing monkeypatches in the test
suite keep working.
"""

from __future__ import annotations

from pathlib import Path

from radar.scan import findings as fm
from radar.scan import runner
from radar.scan.engines.base import ScanEngine, register


class SemgrepEngine(ScanEngine):
    name = "semgrep"
    description = "Semgrep SAST — preset + 50 bundled OWASP rules (30+ languages)"
    default = True

    def detect(self) -> str | None:
        # runner.detect_runtime raises ScanError when nothing is available; the
        # aggregator catches that and records the engine as unavailable.
        return runner.detect_runtime()

    def scan(self, target, *, rules_only=False, runtime=None, extra_config=None):
        report = runner.run_semgrep(
            Path(target),
            rules_only=rules_only,
            sarif=False,
            extra_config=list(extra_config or []),
            runtime=runtime,
        )
        return fm.parse(report)


register(SemgrepEngine())
