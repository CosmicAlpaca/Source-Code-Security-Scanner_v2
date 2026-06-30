"""Orchestrate triage: scan -> reachability -> LLM verdict, with caching + dry-run."""

from dataclasses import dataclass
from pathlib import Path

from radar.scan.findings import FAIL_THRESHOLD, SEVERITY_ORDER, Finding
from radar.scan.engines import scan_all
from radar.triage import llm_client
from radar.triage.prompt import build_messages, redact
from radar.triage.reachability import Reach, reachability


@dataclass
class TriagedFinding:
    finding: Finding
    reach: Reach
    verdict: dict | None = None
    cached: bool = False
    error: str | None = None


def _passes_floor(finding: Finding, floor: str) -> bool:
    return SEVERITY_ORDER[finding.severity] <= FAIL_THRESHOLD[floor]


def read_snippet(root: Path, finding: Finding, ctx: int = 6) -> str:
    """N lines of source around the finding (best-effort; empty on read error)."""
    p = Path(finding.path)
    fpath = p if p.is_absolute() else root / p
    try:
        lines = fpath.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return ""
    lo = max(finding.line - ctx - 1, 0)
    hi = min(finding.line + ctx, len(lines))
    return "\n".join(lines[lo:hi])


def triage(
    root: Path,
    *,
    rules_only: bool = False,
    extra_config: list[str] | None = None,
    floor: str = "warning",
    only_all: bool = False,
    force: bool = False,
    dry_run: bool = False,
    allow_offline: bool = False,
    emit=None,
) -> tuple[list[TriagedFinding], int]:
    """Run scan + enrich findings with AI verdicts. Returns (results, api_call_count).

    With no API key: raise TriageError unless `allow_offline` — then return findings
    enriched with reachability only (verdict=None) so the caller can still rank by
    risk score (`--min-risk`) without a key.
    """
    emit = emit or (lambda _msg: None)
    llm_client.load_dotenv(root)

    items, _runs = scan_all(
        root,
        rules_only=rules_only,
        engines=["semgrep", "gitleaks"],
        extra_config=list(extra_config or []),
    )
    
    if not only_all:
        items = [f for f in items if _passes_floor(f, floor)]

    from radar.cli import _load_or_build_graph  # reuse the zero-footprint resolver

    graph = _load_or_build_graph(root)

    # Query the model only on real runs that have a key. Without a key, run offline
    # (reachability + risk, no verdict) when allowed, else fail with a clear message.
    has_key = llm_client.resolve_key() is not None
    query_ai = not dry_run and has_key
    if not dry_run and not has_key and not allow_offline:
        raise llm_client.TriageError(
            "No API key. Set OPENAI_API_KEY (or RADAR_AI_API_KEY) in your environment "
            "or a repo-root .env file, then re-run `radar triage`."
        )

    results: list[TriagedFinding] = []
    calls = 0
    for finding in items:
        reach = reachability(graph, finding, root)
        snippet = redact(read_snippet(root, finding))
        if dry_run:
            messages = build_messages(finding, snippet, reach)
            emit(f"--- {finding.path}:{finding.line}  [{finding.rule}]  reach={reach.status} ---")
            emit(messages[1]["content"])
            results.append(TriagedFinding(finding, reach))
            continue
        if not query_ai:  # offline ranking: reachability + risk only, no AI verdict
            results.append(TriagedFinding(finding, reach))
            continue
        try:
            verdict, cached = llm_client.get_verdict(root, finding, snippet, reach, force=force)
            calls += 0 if cached else 1
            results.append(TriagedFinding(finding, reach, verdict, cached))
        except llm_client.TriageError as exc:
            results.append(TriagedFinding(finding, reach, error=str(exc)))
    return results, calls
