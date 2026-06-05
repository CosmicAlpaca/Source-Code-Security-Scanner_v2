#!/usr/bin/env python3
"""Render a GitHub PR comment (markdown) from a semgrep JSON report.

Usage: python render-pr-comment.py semgrep.json [impact.json] > comment.md

Stdlib only — runs on a bare GitHub Actions runner. The optional impact.json
argument (added in phase 06) appends a blast-radius section.
"""

import json
import sys

MARKER = "<!-- security-radar -->"
MAX_FINDINGS = 30
SEVERITY_ORDER = {"ERROR": 0, "WARNING": 1, "INFO": 2}
SEVERITY_EMOJI = {"ERROR": "\U0001f534", "WARNING": "\U0001f7e1", "INFO": "\U0001f535"}


def escape_cell(text: str) -> str:
    """Escape untrusted text for a markdown table cell (no HTML, pipes or code-span breakout)."""
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("|", "\\|")
        .replace("`", "'")
        .replace("\r", " ")
        .replace("\n", " ")
    )


def load_findings(report_path: str) -> list[dict]:
    with open(report_path, encoding="utf-8") as fh:
        report = json.load(fh)
    findings = []
    for result in report.get("results", []):
        severity = result.get("extra", {}).get("severity", "INFO").upper()
        findings.append(
            {
                "severity": severity if severity in SEVERITY_ORDER else "INFO",
                "path": result.get("path", "?"),
                "line": result.get("start", {}).get("line", 0),
                "rule": result.get("check_id", "?"),
                "message": result.get("extra", {}).get("message", "").strip(),
            }
        )
    findings.sort(key=lambda f: (SEVERITY_ORDER[f["severity"]], f["path"], f["line"]))
    return findings


def render_findings_section(findings: list[dict]) -> list[str]:
    lines = ["## \U0001f6e1️ Semgrep findings", ""]
    if not findings:
        lines.append("✅ No security findings.")
        return lines

    counts = {sev: sum(1 for f in findings if f["severity"] == sev) for sev in SEVERITY_ORDER}
    summary = ", ".join(f"{n} {sev.lower()}" for sev, n in counts.items() if n)
    lines.append(f"**{len(findings)} finding(s)** ({summary})")
    lines.append("")
    lines.append("| Severity | Location | Rule | Message |")
    lines.append("|---|---|---|---|")
    for f in findings[:MAX_FINDINGS]:
        emoji = SEVERITY_EMOJI[f["severity"]]
        location = escape_cell(f"{f['path']}:{f['line']}")
        rule = escape_cell(f["rule"].rsplit(".", 1)[-1])
        message = escape_cell(f["message"][:200])
        lines.append(f"| {emoji} {f['severity']} | `{location}` | `{rule}` | {message} |")
    hidden = len(findings) - MAX_FINDINGS
    if hidden > 0:
        lines.append("")
        lines.append(f"…and {hidden} more finding(s) — see the `semgrep-report` artifact.")
    return lines


def render_impact_section(impact: dict) -> list[str]:
    """Render blast-radius section from `radar impact --format json` output."""
    lines = ["", "## \U0001f4e1 Impact (blast radius)", ""]
    changed = impact.get("changed", [])
    affected = impact.get("affected", [])
    apis = impact.get("apis", [])
    features = impact.get("features", [])
    if not changed:
        lines.append("No function-level changes detected.")
        return lines
    lines.append(
        f"**{len(changed)} changed → {len(affected)} affected function(s), "
        f"{len(apis)} API(s), {len(features)} feature(s)**"
    )
    lines.append("")
    lines.append("| Changed function | Affected (depth) | APIs | Feature |")
    lines.append("|---|---|---|---|")
    by_source: dict[str, list[dict]] = {}
    for item in affected:
        by_source.setdefault(item.get("via_changed", "?"), []).append(item)
    for ch in changed[:MAX_FINDINGS]:
        name = escape_cell(ch.get("name", "?"))
        callers = [c for c in by_source.get(ch.get("id", ""), []) if c.get("kind") != "route"]
        callers_txt = escape_cell(
            ", ".join(f"{c.get('name', '?')} (d{c.get('depth', '?')})" for c in callers[:8]) or "—"
        )
        # APIs reachable from THIS change: its direct routes + affected routes traced back to it
        ch_apis = list(ch.get("routes") or [])
        ch_apis += [
            c.get("name", "?")
            for c in by_source.get(ch.get("id", ""), [])
            if c.get("kind") == "route" and c.get("name") not in ch_apis
        ]
        api_txt = escape_cell(", ".join(ch_apis[:8]) or "—")
        feature_txt = escape_cell(ch.get("feature") or "(unmapped)")
        lines.append(f"| `{name}` | {callers_txt} | {api_txt} | {feature_txt} |")
    approx = sum(1 for a in affected if a.get("confidence") == "name-only")
    if approx:
        lines.append("")
        lines.append(f"⚠️ {approx} edge(s) resolved by name only (approximate).")
    return lines


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print("usage: render-pr-comment.py semgrep.json [impact.json]", file=sys.stderr)
        return 2
    lines = [MARKER]
    lines.extend(render_findings_section(load_findings(argv[1])))
    if len(argv) > 2:
        with open(argv[2], encoding="utf-8") as fh:
            lines.extend(render_impact_section(json.load(fh)))
    print("\n".join(lines))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
