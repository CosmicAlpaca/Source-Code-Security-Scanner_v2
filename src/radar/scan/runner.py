"""Discover a Semgrep runtime (native binary → Docker) and run a scan.

Semgrep has no native Windows build, so we fall back to `docker run`. The scan
emits JSON/SARIF to stdout — we parse it in memory and never write into the
target repo (zero footprint). The bundled custom rules travel inside the wheel
(`radar/rules/`) so a `pip install` is self-contained.
"""

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Literal

DOCKER_IMAGE = "semgrep/semgrep:latest"
SEMGREP_PRESETS = ["p/security-audit", "p/secrets", "p/owasp-top-ten"]
RULES_DIR = Path(__file__).resolve().parent.parent / "rules"

Runtime = Literal["native", "docker"]


class ScanError(RuntimeError):
    """Semgrep failed to run (bad config, crash) — distinct from 'ran, found issues'."""


def rules_dir() -> Path:
    """Filesystem path to the bundled custom rules (works for normal + editable installs)."""
    return RULES_DIR


def detect_runtime() -> Runtime:
    """Prefer a native `semgrep`, else `docker`. Raise if neither is available."""
    if shutil.which("semgrep"):
        return "native"
    if shutil.which("docker"):
        return "docker"
    raise ScanError(
        "No Semgrep runtime found. Install Semgrep (`pipx install semgrep`) "
        "or Docker, then re-run `radar scan`."
    )


def _config_flags(config_paths: list[str]) -> list[str]:
    flags: list[str] = []
    for cfg in config_paths:
        flags += ["--config", cfg]
    return flags


def build_argv(
    target: Path,
    runtime: Runtime,
    *,
    rules_only: bool = False,
    sarif: bool = False,
    extra_config: list[str] | None = None,
) -> list[str]:
    """Construct the argv for `semgrep scan` under the given runtime."""
    out_flag = "--sarif" if sarif else "--json"
    presets = [] if rules_only else list(SEMGREP_PRESETS)
    extra = list(extra_config or [])

    if runtime == "native":
        configs = presets + [str(rules_dir())] + extra
        return ["semgrep", "scan", out_flag, "--metrics", "off", *_config_flags(configs), str(target)]

    # docker: mount target + bundled rules read-only; -w /src + target "." so semgrep
    # emits repo-relative paths (matching native), not the /src container prefix.
    configs = presets + ["/rules"] + extra
    return [
        "docker", "run", "--rm",
        "-v", f"{target.as_posix()}:/src:ro",
        "-v", f"{rules_dir().as_posix()}:/rules:ro",
        "-w", "/src",
        DOCKER_IMAGE,
        "semgrep", "scan", out_flag, "--metrics", "off", *_config_flags(configs), ".",
    ]


def run_semgrep(
    target: Path,
    *,
    rules_only: bool = False,
    sarif: bool = False,
    extra_config: list[str] | None = None,
    runtime: Runtime | None = None,
) -> dict:
    """Run Semgrep and return its parsed JSON (or SARIF) report.

    Semgrep's exit code is unreliable as a success signal (it varies with
    `--error`/severity gating across versions), so we treat *parseable JSON
    output* as success and only raise ScanError when the output is unusable.
    """
    target = target.resolve()
    runtime = runtime or detect_runtime()
    argv = build_argv(
        target, runtime, rules_only=rules_only, sarif=sarif, extra_config=extra_config
    )
    # Force UTF-8 I/O for Semgrep: Windows may default to cp932/cp1252 which breaks
    # YAML rule parsing when rule messages contain non-ASCII characters.
    semgrep_env = os.environ.copy()
    semgrep_env["PYTHONUTF8"] = "1"
    semgrep_env["PYTHONIOENCODING"] = "utf-8"
    try:
        # encoding/errors explicit: semgrep emits UTF-8, but Windows defaults to cp1252 and crashes.
        proc = subprocess.run(
            argv, capture_output=True, text=True,
            encoding="utf-8", errors="replace", env=semgrep_env,
        )
    except OSError as exc:
        raise ScanError(f"Failed to launch Semgrep ({runtime}): {exc}") from exc

    try:
        report = json.loads(proc.stdout)
    except json.JSONDecodeError:
        detail = (proc.stderr or proc.stdout or "").strip()[:1000]
        raise ScanError(
            f"Semgrep ({runtime}) produced no valid report (exit {proc.returncode}).\n{detail}"
        ) from None
    return report
