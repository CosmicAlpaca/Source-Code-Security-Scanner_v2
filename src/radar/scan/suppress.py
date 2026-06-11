"""Suppression system for radar scan findings.

Two ways to suppress a finding:

1. Inline comment on the flagged line:
       x = eval(user_input)  # radar-ignore: js-eval-user-input
       x = eval(user_input)  // radar-ignore  (suppresses ALL rules on this line)

2. File-level .radar-ignore at repo root:
       # comment lines start with #
       app/legacy/old.js:js-sql-string-concat
       app/legacy/old.js:*           (suppress all rules in that file)
       *:js-hardcoded-jwt-secret     (suppress rule everywhere)
"""

from __future__ import annotations

import re
from pathlib import Path

from radar.scan.findings import Finding

# Matches both // radar-ignore (JS/TS/Go/Java) and # radar-ignore (Python/YAML)
_INLINE_RE = re.compile(r"(?://|#)\s*radar-ignore(?::\s*(\S+))?", re.IGNORECASE)
_IGNORE_FILE = ".radar-ignore"


def _load_ignore_file(repo_root: Path) -> list[tuple[str, str]]:
    ignore_path = repo_root / _IGNORE_FILE
    if not ignore_path.exists():
        return []
    entries: list[tuple[str, str]] = []
    for raw in ignore_path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(":", 1)
        if len(parts) == 2:
            file_part, rule_part = parts[0].strip(), parts[1].strip()
        else:
            file_part, rule_part = parts[0].strip(), "*"
        entries.append((file_part, rule_part))
    return entries


def _matches_glob(pattern: str, value: str) -> bool:
    if pattern == "*":
        return True
    return pattern == value


def _inline_suppressed(path: Path, line: int, rule: str) -> bool:
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        if line < 1 or line > len(lines):
            return False
        text = lines[line - 1]
        m = _INLINE_RE.search(text)
        if not m:
            return False
        suppressed_rule = m.group(1)
        return suppressed_rule is None or suppressed_rule == rule
    except OSError:
        return False


def filter_findings(
    findings: list[Finding],
    repo_root: Path,
) -> tuple[list[Finding], list[Finding]]:
    """Split findings into (kept, suppressed)."""
    ignore_entries = _load_ignore_file(repo_root)
    kept: list[Finding] = []
    suppressed: list[Finding] = []

    for f in findings:
        abs_path = (repo_root / f.path).resolve() if not Path(f.path).is_absolute() else Path(f.path)

        if _inline_suppressed(abs_path, f.line, f.rule):
            suppressed.append(f)
            continue

        rel = f.path
        short_rule = f.rule.split(".")[-1] if "." in f.rule else f.rule
        file_suppressed = any(
            _matches_glob(fp, rel) and (_matches_glob(rp, f.rule) or _matches_glob(rp, short_rule))
            for fp, rp in ignore_entries
        )
        if file_suppressed:
            suppressed.append(f)
            continue

        kept.append(f)

    return kept, suppressed
