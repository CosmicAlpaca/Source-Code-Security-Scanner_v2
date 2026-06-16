"""radar watch — live security linter.

Watches source files for changes and runs an incremental Semgrep scan
on the modified file, showing NEW or FIXED findings in real-time.

Design:
- Scan scope: single changed file (fast) with --rules-only (no network)
- State: in-memory dict {filepath -> frozenset of (rule, line)}
- Output: colored diff — NEW findings flagged, FIXED findings celebrated
"""

from __future__ import annotations

import json
import os
import subprocess
import time
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    pass

# Source file extensions to watch
WATCHED_EXTENSIONS = {
    ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
    ".py", ".go", ".java",
}

# Debounce: ignore repeated events within this window (seconds)
_DEBOUNCE = 0.8


class _ScanState:
    """Tracks last-known findings per file."""

    def __init__(self) -> None:
        # filepath (str) -> frozenset of (rule_id, line)
        self._state: dict[str, frozenset[tuple[str, int]]] = {}

    def update(self, filepath: str, findings: list[dict]) -> tuple[list[dict], list[dict]]:
        """Return (new_findings, fixed_findings) compared to last scan."""
        current = frozenset((f["rule"], f["line"]) for f in findings)
        previous = self._state.get(filepath, frozenset())

        new_keys = current - previous
        fixed_keys = previous - current

        new_findings = [f for f in findings if (f["rule"], f["line"]) in new_keys]
        fixed_findings = [
            {"rule": r, "line": ln, "filepath": filepath}
            for r, ln in fixed_keys
        ]

        self._state[filepath] = current
        return new_findings, fixed_findings


def _scan_file(filepath: Path, rules_dir: Path) -> list[dict]:
    """Run semgrep on a single file, return list of {rule, line, message, severity}."""
    try:
        proc = subprocess.run(
            [
                "semgrep", "scan",
                "--json", "--metrics", "off",
                "--config", str(rules_dir),
                str(filepath),
            ],
            capture_output=True, text=True,
            encoding="utf-8", errors="replace",
            timeout=30,
        )
        report = json.loads(proc.stdout)
        results = []
        for r in report.get("results", []):
            extra = r.get("extra", {})
            results.append({
                "rule": r.get("check_id", "?").split(".")[-1],
                "line": r.get("start", {}).get("line", 0),
                "message": (extra.get("message") or "").strip()[:120],
                "severity": str(extra.get("severity", "INFO")).upper(),
            })
        return results
    except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError):
        return []


def _docker_scan_file(filepath: Path, rules_dir: Path, repo_root: Path) -> list[dict]:
    """Fallback: scan via Docker when native semgrep unavailable."""
    try:
        rel = filepath.relative_to(repo_root)
        proc = subprocess.run(
            [
                "docker", "run", "--rm",
                "-v", f"{repo_root.as_posix()}:/src:ro",
                "-v", f"{rules_dir.as_posix()}:/rules:ro",
                "-w", "/src",
                "semgrep/semgrep",
                "semgrep", "scan", "--json", "--metrics", "off",
                "--config", "/rules", str(rel),
            ],
            capture_output=True, text=True,
            encoding="utf-8", errors="replace",
            timeout=60,
        )
        report = json.loads(proc.stdout)
        results = []
        for r in report.get("results", []):
            extra = r.get("extra", {})
            results.append({
                "rule": r.get("check_id", "?").split(".")[-1],
                "line": r.get("start", {}).get("line", 0),
                "message": (extra.get("message") or "").strip()[:120],
                "severity": str(extra.get("severity", "INFO")).upper(),
            })
        return results
    except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError):
        return []


def _fmt_sev(sev: str) -> str:
    if sev == "ERROR":
        return "\033[31mERROR  \033[0m"
    if sev == "WARNING":
        return "\033[33mWARNING\033[0m"
    return "\033[36mINFO   \033[0m"


def run_watch(
    repo_root: Path,
    *,
    rules_dir: Path,
    use_docker: bool = False,
    extensions: set[str] | None = None,
) -> None:
    """Start the file watcher. Blocks until Ctrl-C."""
    try:
        from watchdog.events import FileSystemEventHandler
        from watchdog.observers import Observer
    except ImportError:
        print(
            "\033[31m[radar watch] watchdog not installed.\033[0m\n"
            "Run:  pip install 'security-radar[watch]'\n"
        )
        return

    watched_exts = extensions or WATCHED_EXTENSIONS
    state = _ScanState()
    _last_event: dict[str, float] = {}

    scanner = _docker_scan_file if use_docker else _scan_file

    class _Handler(FileSystemEventHandler):
        def on_modified(self, event):
            if event.is_directory:
                return
            path = Path(event.src_path)
            if path.suffix not in watched_exts:
                return
            # Debounce
            now = time.monotonic()
            key = str(path)
            if now - _last_event.get(key, 0) < _DEBOUNCE:
                return
            _last_event[key] = now

            rel = path.relative_to(repo_root) if path.is_absolute() else path
            print(f"\n\033[2m[{time.strftime('%H:%M:%S')}] {rel} changed — scanning…\033[0m")

            findings = scanner(path, rules_dir, repo_root) if use_docker else scanner(path, rules_dir)
            new_f, fixed_f = state.update(str(path), findings)

            if not new_f and not fixed_f:
                print(f"\033[2m  ✓ no changes in findings\033[0m")
                return

            for f in new_f:
                sev = _fmt_sev(f["severity"])
                print(f"  \033[1m⚡ NEW\033[0m  {sev} {rel}:\033[33m{f['line']}\033[0m  "
                      f"\033[36m{f['rule']}\033[0m\n        {f['message']}")

            for f in fixed_f:
                print(f"  \033[32m✓ FIXED\033[0m  {f['rule']}  line {f['line']}")

        on_created = on_modified

    observer = Observer()
    observer.schedule(_Handler(), str(repo_root), recursive=True)
    observer.start()

    print(
        f"\n\033[1m⚡ radar watch\033[0m  watching \033[36m{repo_root}\033[0m\n"
        f"   Rules: {rules_dir}\n"
        f"   Extensions: {', '.join(sorted(watched_exts))}\n"
        f"   Press \033[1mCtrl-C\033[0m to stop\n"
    )

    try:
        while True:
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("\n\033[2m[radar watch] stopped\033[0m")
        observer.stop()
    observer.join()
