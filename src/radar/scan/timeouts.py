"""Shared scanner timeout helpers."""

from __future__ import annotations

import os

DEFAULT_SCAN_TIMEOUT = 180


def scan_timeout(default: int = DEFAULT_SCAN_TIMEOUT) -> int:
    """Per-engine subprocess timeout in seconds.

    Override with RADAR_SCAN_TIMEOUT=<seconds> for very large repositories.
    """
    raw = os.environ.get("RADAR_SCAN_TIMEOUT", "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    return max(10, value)
