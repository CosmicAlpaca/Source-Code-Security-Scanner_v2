# Brainstorm Report — security-radar (Semgrep CI + Impact Graph)

> Date: 2026-06-05 | Status: Approved | Next: /ck:plan

## Problem Statement

Build NEW tool (new repo) — source code security scanner, 2 features:
1. **Security scan**: Semgrep configured in GitHub Actions (assignment keyword: "cấu hình GitHub Actions scan code sử dụng Semgrep")
2. **Dependency graph / impact tracing**: function-level — change X → which functions/APIs/features affected

Old repo (coderadar) deemed wrong direction: built custom taint engine instead of using Semgrep, no CI/CD, quality issues. New tool must NOT repeat: use Semgrep for security rules, only hand-build what has no good off-the-shelf option (call graph extraction).

## Requirements (from discovery)

- Semgrep only — no custom security scanner
- CI outputs: PR comment + SARIF → GitHub Security tab + JSON/HTML artifact
- Multi-language: Semgrep side = true multi-language (30+); call graph = JS/TS + Python first, plugin architecture for more
- Function-level call graph (not just file-level imports)
- Impact CLI local-first, then run in CI (PR comment) as phase 2
- Timeline: 1-2 weeks, done properly
- Demo target repo: TBD (suggest vulnerable app fork: dvna/NodeGoat or mini Express app)

## Evaluated Approaches — Call Graph Engine

| Option | Verdict |
|---|---|
| **A. Tree-sitter plugin extractors** | ✅ CHOSEN. Extract function defs + call sites + imports per language. Well-bounded problem (NOT taint analysis). Plugin per language ~1-2 days each |
| B. code2flow wrapper | ❌ Abandoned ~2022, no TypeScript support |
| C. SCIP indexers | ❌ Most precise but heavy, complex CI setup — old repo's failed direction |

Other decisions:
- Tool language: **Python** (team familiar, tree-sitter bindings, networkx, rich)
- Feature mapping: route auto-detect (Express/FastAPI/Flask) = "API" nodes; feature via optional `radar.config.yml` (glob → feature name). KISS
- Call resolution: name + import map (approximate, acceptable); fallback file-level edges

## Final Architecture

```
security-radar/
├── .github/workflows/security-scan.yml   # semgrep ci → SARIF + artifact + PR comment
├── rules/                                # custom semgrep rules (3-5, YAML)
├── src/radar/
│   ├── cli.py                            # radar build | radar impact
│   ├── graph/{builder,model}.py          # networkx graph
│   ├── graph/languages/{base,javascript,python}.py   # plugin interface
│   ├── impact/{diff_mapper,tracer}.py    # git diff → changed fn → reverse BFS
│   └── report/{terminal,exporters}.py    # rich / JSON / Mermaid / HTML
├── radar.config.yml                      # optional feature map
└── tests/
```

### Subsystem 1 — Semgrep CI
- Triggers: PR + push main + cron daily + workflow_dispatch
- Container `semgrep/semgrep`; configs: p/security-audit, p/secrets, p/owasp-top-ten, rules/
- SARIF via `github/codeql-action/upload-sarif` (needs `permissions: security-events: write`)
- PR comment job: Python script reads semgrep JSON → markdown table (needs `pull-requests: write`)

### Subsystem 2 — Impact Graph
- `radar build .` → parse → nodes(function/route/file) + edges(calls/imports)
- `radar impact --diff HEAD~1 | --staged | --function X` → changed lines → enclosing functions → reverse BFS → affected functions → API endpoints → features
- Export: terminal (rich), JSON, Mermaid, HTML

## Roadmap

- **Week 1**: Semgrep workflow complete; graph builder JS/TS; CLI build+impact basic
- **Week 2**: Python plugin; route/feature mapping; exports; impact-in-CI PR comment; custom rules; demo repo + script

## Risks

| Risk | Mitigation |
|---|---|
| Dynamic calls unresolvable (`obj[name]()`, callbacks) | Accept approximation; file-level fallback; label output "approximate" |
| TS syntax complexity | tree-sitter-typescript grammar; only need defs/calls, no type-check |
| PR comment permissions | default GITHUB_TOKEN + permissions block |
| Multi-language scope creep | freeze plugin interface early; only JS/TS+Python weeks 1-2 |

## Success Criteria

1. PR with SQLi → Actions flags it; finding in Security tab + PR comment
2. `radar impact --diff` returns correct affected functions/APIs/features on demo repo
3. Adding language = 1 new plugin file, zero core changes

## References

- [Semgrep + GH Code Scanning setup](https://0xdbe.github.io/GitHub-HowToEnableCodeScanningWithSemgrep/)
- [Semgrep docs: findings in GH Security dashboard](https://semgrep.dev/docs/kb/semgrep-ci/github-upload-findings-in-security-dashboard)
- [code2flow (rejected)](https://github.com/scottrogowski/code2flow)
- Old repo lessons: docs/coderadar-full.md, docs/role-assignment-coderadar.md
