# Adversarial Code Review — security-radar (initial implementation)

Date: 2026-06-06 · Reviewer: code-reviewer · Scope: all new/uncommitted code
Baseline: 73/73 pytest pass. Demo `demo/app/*.js` vulns are by-design and excluded.

Severity legend: CRITICAL / HIGH / MEDIUM / LOW.

---

## CRITICAL

None. No code-execution-of-scanned-repo path, no token leak in the write-permission job, no remote injection that yields arbitrary execution.

---

## HIGH

### H1 — PR comment markdown injection via unescaped backtick (code-span breakout)
`scripts/render-pr-comment.py:19-28` (`escape_cell`) escapes `& < > | \r \n` but **not** backtick `` ` ``. The location and rule columns wrap untrusted content in inline code spans:
- `render-pr-comment.py:67` → `` | `{location}` | `{rule}` | `` where `location = path:line` and `rule = check_id.rsplit(...)`.
- `render-pr-comment.py:103` → impact section also uses `` `{name}` `` for the changed-function name.

A semgrep `path` or `check_id`, or a graph function name, that contains a backtick breaks out of the code span. Since `<`/`>` are entity-escaped this is not a full HTML/script injection, but it allows markdown formatting injection into a PR comment posted by a job holding `pull-requests: write`. `path`/`check_id` come from semgrep on attacker-controlled PR code; function `name` comes from scanned source (`name = _text(prop)` etc. in `javascript.py`/`python.py`).

Verified:
```
escape_cell("foo` <script> | bar") -> 'foo` &lt;script&gt; \\| bar'   # backtick survives
```
Fix: add `.replace("`", "\\`")` (or wrap with a backtick count that brackets the content). The PRD §5 explicitly requires "escape markdown/rich markup khi render nội dung untrusted" — this is a spec-compliance gap, not just hardening.

### H2 — Impact PR-comment "APIs" column is not scoped to the changed function (correctness)
`scripts/render-pr-comment.py:101`: inside the per-changed-function loop, the APIs cell is built from the **global** `apis[:8]` list, identical for every row, regardless of whether that specific changed function reaches those APIs. `by_source` is computed for the "Affected" column (line 92-100) but the same scoping is not applied to APIs.

Verified with two changed functions where only `f1` reaches `POST /login`:
```
| `f1` | login (d1)  | POST /login | A |
| `f2` | —           | POST /login | B |   <-- f2 affects nothing but still lists the API
```
This directly contradicts F2.6/F2.9 ("function → API endpoint … bị ảnh hưởng") and produces misleading blast-radius output in the primary CI deliverable. Fix: derive APIs per changed-id from `callers = by_source.get(ch['id'])` (filter affected items of kind route, or roll up routes attached to affected items).

---

## MEDIUM

### M1 — Non-ASCII / quoted file paths in git diff are mis-parsed → silent missed impact
`src/radar/impact/diff_mapper.py:32-34`. With git default `core.quotepath=true`, paths with non-ASCII or special chars render as `+++ "b/src/é.js"` (C-quoted, with surrounding double-quotes). `target.removeprefix("b/")` does not strip the leading `"`, yielding `current_file = '"b/src/é.js"'`, which matches no graph node, so changes in such files are silently dropped from impact.
Verified: `'"b/src/é.js"'.removeprefix("b/") == '"b/src/é.js"'`.
Fix: pass `-c core.quotepath=false` to the `git diff` invocation (`_run_git_diff`, line 19-20) and/or strip surrounding quotes + handle the `a/`/`b/` prefixes robustly. Also paths with spaces work today only because git doesn't quote them; once quotepath triggers, spaces+unicode break together.

### M2 — `javascript.py` exceeds the <200-line NFR (234 lines)
`src/radar/graph/languages/javascript.py` is 234 lines; PRD §5 ("file code <200 dòng") and project rules cap at 200. All other source files are within budget (next largest: `python.py` 183, `resolver.py` 136). Suggest extracting the route/require/import binding helpers into a sibling module (e.g. `javascript_routes.py`) to comply. Pure standards finding — no behavior impact.

### M3 — Mermaid label injection from scanned function names (static-HTML XSS-adjacent)
`src/radar/report/exporters.py:32-33` (`_mermaid_escape`) only replaces `"` → `'`. Function/route names come from scanned source and may contain Mermaid-significant characters (`]`, `}`, `{`, `;`, `-->`, newlines). In `to_mermaid` these are emitted raw inside `n0["..."]`. In the standalone HTML (`impact.html.j2:55-61`) the `<pre class="mermaid">` block is Jinja-autoescaped at the HTML layer, but mermaid.js reads the element's decoded text and re-parses it, so a crafted name can break or inject Mermaid directives (e.g. `click` interactions in some configs). Impact is limited (requires a user to open attacker-influenced HTML locally; no server context) hence MEDIUM not HIGH. Fix: strip/replace Mermaid metacharacters and newlines, or use a quoted-id + label-via-`%%` safe form.

### M4 — `pip install .` builds attacker-controlled PR code in the `impact` job
`.github/workflows/security-scan.yml:69` runs `pip install .` on the checked-out PR head, which executes the PR's own build backend / any `setup.py`-equivalent hook. This is constrained by top-level `permissions: contents: read` and by `GITHUB_TOKEN` being read-only on fork PRs (and the write-token `pr-comment` job is gated to same-repo PRs at line 88), so it is not a token-exfil path today. Still, it executes untrusted code in CI — note for defense-in-depth (e.g. install from a pinned copy of the tool rather than the PR checkout, or run impact in a hardened/isolated job). PRD §5 "không exec code được scan" is about *scanned* code (parse-only, which holds), but build-time execution of the PR is an adjacent risk worth documenting.

---

## LOW

### L1 — `pr-comment` upsert uses `c.body.includes(marker)` without author filter
`security-scan.yml:117`: any existing comment containing the literal `<!-- security-radar -->` (e.g. a user quoting the marker, or a comment from another actor) will be matched and overwritten/updated. Low risk; filter by `c.user.type === 'Bot'` / `c.performed_via_github_app` or the bot login to be safe.

### L2 — Same-name definitions within one file silently merged
`src/radar/graph/resolver.py:41` uses `setdefault`, so two functions with the same qualified name in one file (e.g. re-assigned `exports.foo`, or shadowing nested fns) collapse to a single node id (the first). Known approximation consistent with PRD §9, but undocumented in output (no `confidence`/warning). Acceptable; note in README limitations.

### L3 — Pure-deletion anchor can map to the wrong/no function
`src/radar/impact/diff_mapper.py:40-41`: for `+c,0` hunks the anchor is line `c` (line *before* the deletion on the new side). If the deletion removed an entire function or the lines between functions, the anchor may land outside any span and fall back to the file node, or land in the preceding function. Approximation, matches design; flagged for awareness.

### L4 — `escape_cell` truncates message to 200 chars after escaping
`render-pr-comment.py:66`: `f["message"][:200]` is applied to the *raw* message before `escape_cell`? No — order is `escape_cell(f["message"][:200])`, slicing first then escaping, so an entity like `&amp;` is never split mid-entity. Correct. (Listed to confirm it was checked — no defect.)

### L5 — `_load_or_build_graph` treats missing git HEAD as never-stale path inconsistency
`src/radar/cli.py:90`: stale check is `graph.graph.get("head") and graph.graph["head"] == git_head(root)`. If the graph was built outside a git repo (`head` is `None`), this is falsy → rebuild every run (correct but mildly wasteful). If `git_head` transiently fails (returns `None`) on a valid graph, it also rebuilds. Benign; F2.10 is "Should". No fix required.

---

## Positive notes / things verified clean

- `yaml.safe_load` used in `config.py:38`; top-level type validated; no `yaml.load`. Globs matched against posix relpaths only (cannot escape root). 
- No `eval`/`exec`/`subprocess(shell=True)` over scanned content. Scanned code is only parsed by tree-sitter. `git`/`pip` subprocess calls use list-form args (no shell).
- Tree-sitter handlers consistently None-check `child_by_field_name` results before `_text` (e.g. `javascript.py:89,101,110,130,147`; `python.py:73,84,126,144,153,155`). `_string_value` guards `node is None` and type.
- Determinism: `save_graph` sorts nodes/edges and `json.dumps(..., sort_keys=True)`; resolver returns sorted nodes/edges (F2.1 deterministic ✓). Node ids use posix paths throughout (Windows normalization ✓, F2 / PRD §5).
- Tracer reverse BFS terminates on cycles (test_cycle_terminates), depth/confidence propagate correctly, same-depth dedup only upgrades name-only→resolved (verified empirically, order-stable).
- Workflow permissions are minimal and per-job: top-level `contents: read`; `semgrep` adds `security-events: write`; `pr-comment` adds `pull-requests: write` and is gated to same-repo PRs (fork PRs skip comment — F1.7 ✓). `--metrics off` set (no telemetry — F1.2 ✓). SARIF + JSON both produced (F1.3 ✓). `continue-on-error` so findings don't fail build (F1.6 ✓).
- `render-pr-comment.py` is stdlib-only (runs on bare runner), caps at 30 findings with overflow note (F1.4 ✓).
- Plugin architecture: adding a language is one self-registering module; core never references a concrete language (F2.3 ✓, Python plugin proves it).

---

## Spec-compliance summary (PRD §4-5)

| Item | Status |
|---|---|
| F1.x scan/SARIF/artifact/comment/fork-skip | Met |
| F1.4 escape untrusted markdown | **Partial — H1 (backtick)** |
| F2.1 deterministic graph.json + HEAD hash | Met |
| F2.6/F2.9 function→API attribution in comment | **Defect — H2** |
| NFR file <200 lines | **Violated — M2 (javascript.py 234)** |
| NFR Windows path normalization | Met (posix everywhere); **M1** is a diff-parsing gap for quoted unicode paths |
| NFR escape untrusted on render | terminal ✓ (rich `escape`); HTML ✓ (Jinja autoescape) except **M3 mermaid**; markdown **H1** |
| NFR no exec of scanned code | Met (parse-only); **M4** is build-time exec of PR, separate concern |

---

## Recommended fix priority
1. H1 — add backtick escaping in `escape_cell` (one line; closes the §5 markdown-escape gap).
2. H2 — scope the APIs column per changed function (correctness of the headline CI feature).
3. M1 — `git diff -c core.quotepath=false` + robust path strip.
4. M2 — split `javascript.py` under 200 lines.
5. M3 — harden mermaid label escaping.
6. M4/L1 — document/defense-in-depth.

---

**Status:** DONE_WITH_CONCERNS
**Summary:** Reviewed all 13 source modules, 5 rules, workflow, templates and tests (73/73 passing). Findings: 0 CRITICAL, 2 HIGH, 4 MEDIUM, 5 LOW.
**Concerns/Blockers:** H1 (backtick code-span breakout in PR comment) and H2 (APIs column not scoped per changed function — wrong blast-radius output) should be fixed before the GitHub end-to-end verification (task #7).
