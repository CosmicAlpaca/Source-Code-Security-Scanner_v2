"""AI reachability-aware triage for Semgrep findings (opt-in, on-demand).

Additive layer over the deterministic scan: enriches each finding with an LLM
verdict, using the impact graph to tell the model which routes reach the code.
Never changes `radar scan` output, SARIF, or exit codes.
"""
