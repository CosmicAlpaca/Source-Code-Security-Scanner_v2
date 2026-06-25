"""Gitleaks engine — secret scanning (API keys, tokens, credentials).

detect() is deliberately side-effect-free: it checks for a native binary, an
already-vendored binary, or Docker, but never triggers the auto-download in
gitleaks_runner (that would mean a network call on every `radar scan`). The
download path still exists for users who want it, just not during discovery.
"""

from __future__ import annotations

import platform
import shutil
from pathlib import Path

from radar.scan import gitleaks_runner as gl
from radar.scan.engines.base import ScanEngine, register


def _vendored_exists() -> bool:
    base = Path.home() / ".radar" / "bin"
    exe = "gitleaks.exe" if platform.system() == "Windows" else "gitleaks"
    return (base / exe).is_file()


class GitleaksEngine(ScanEngine):
    name = "gitleaks"
    description = "Gitleaks — secret scanner (API keys, tokens, credentials)"
    default = True

    def detect(self) -> str | None:
        if shutil.which("gitleaks"):
            return "native"
        if _vendored_exists():
            return "vendored"
        if shutil.which("docker"):
            return "docker"
        return None

    def scan(self, target, *, rules_only=False, runtime=None, extra_config=None):
        # Pass the already-resolved runtime so run_gitleaks does not re-probe
        # (and therefore never auto-downloads here).
        return gl.run_gitleaks(Path(target), runtime=runtime)


register(GitleaksEngine())
