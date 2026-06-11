# System Architecture — security-radar

> Kiến trúc kỹ thuật của bản hiện thực. Yêu cầu sản phẩm xem [PRD](./security-radar-prd.md).
> Cập nhật: 2026-06-08

## 1. Hai subsystem

security-radar gồm hai năng lực độc lập, chạy được **cả trong CI lẫn local** (sau `pip install`):

1. **Security Scan** (Semgrep) — quét lỗ hổng, không tự viết taint engine. CI: GitHub Actions. Local: `radar scan` wrap Semgrep (native → Docker fallback), dùng cùng preset + bundled rules.
2. **Impact Tracing** (Python package `radar`) — dựng call graph, trả lời "thay đổi này lan đến đâu".

Cả hai gặp nhau ở job `pr-comment` (CI): gộp findings + blast radius vào một comment PR.

**Zero footprint**: `radar scan` và `radar impact` chạy trên repo bất kỳ mà không ghi gì vào repo đó — scan parse JSON từ stdout của Semgrep; impact cache graph ra thư mục cache ngoài repo ([§5c](#5c-zero-footprint--graph-cache)).

## 2. Module map

```
.github/workflows/security-scan.yml   # 4 jobs: semgrep · rule-tests · impact · pr-comment
scripts/render-pr-comment.py          # stdlib-only: semgrep.json [+ impact.json] -> comment.md
radar.config.yml                      # feature map (glob -> feature) + exclude globs

src/radar/
├── cli.py                            # `radar build` | `radar impact` | `radar scan`
├── config.py                         # RadarConfig: feature_for / is_excluded (yaml.safe_load)
├── cache.py                          # graph_cache_path: cache ngoài repo (zero-footprint impact)
├── rules/                            # 5 custom Semgrep rules + fixtures (đóng gói trong wheel)
├── scan/
│   ├── runner.py                     # detect_runtime (native→docker) + run_semgrep (zero-footprint)
│   ├── findings.py                   # semgrep JSON -> Finding[] + summary + threshold gate
│   └── report.py                     # rich terminal table | stable JSON
├── graph/
│   ├── model.py                      # Node/Edge + FileFacts dataclasses, id helpers
│   ├── builder.py                    # walk -> extract -> resolve -> graph.json (deterministic)
│   ├── resolver.py                   # 2-pass call resolution -> nodes + edges
│   └── languages/                    # plugin registry (auto-discovery via pkgutil)
│       ├── base.py                   # LanguageExtractor ABC + EXTRACTORS registry
│       ├── javascript.py (+ javascript_imports.py)   # tree-sitter JS/TS
│       └── python.py                 # tree-sitter Python
├── impact/
│   ├── diff_mapper.py                # git diff -U0 -> changed lines -> enclosing function
│   └── tracer.py                     # reverse BFS -> ImpactResult
└── report/
    ├── terminal.py                   # rich tree
    ├── exporters.py                  # JSON / Mermaid / HTML
    └── templates/impact.html.j2      # Jinja2 (autoescape) HTML report
```

## 3. Node / Edge schema

Node id luôn dùng posix path: `"<relpath>::<name>"`.

| Kind     | id ví dụ                                  |
|----------|-------------------------------------------|
| function | `src/auth/validate.js::validateUser`      |
| route    | `src/routes/auth.js::route:POST /api/login` |
| file     | `src/auth/validate.js`                     |

- **Node**: `id, kind, name, file, start_line, end_line, language, feature`.
- **Edge**: `src, dst, kind ∈ {calls, imports, handles}, confidence ∈ {resolved, name-only}`.
- `graph.json`: sorted nodes/edges (deterministic), kèm `head` = git HEAD hash để phát hiện stale và auto-rebuild.

## 4. Data flow — `radar build`

1. **Walk** codebase (skip `node_modules`, `.git`, dotdirs, `exclude` globs).
2. **Extract** mỗi file qua plugin theo extension → `FileFacts` (defs, calls, imports, routes). Source chỉ được *parse*, không bao giờ exec.
3. **Resolve 2-pass** (`resolver.py`), thứ tự ưu tiên mỗi call site (first hit wins):
   - cùng file → `resolved`
   - import map (named import, hoặc member call trên module đã import) → `resolved`
   - global name index → `name-only` (cap `MAX_NAME_ONLY_TARGETS = 5`; vượt thì bỏ, ghi `ambiguous_skipped`)
   - dynamic call bỏ qua; fallback là file-level `imports` edge.
4. **Gán feature** theo `radar.config.yml`, ghi `graph.json` (sorted).

## 5. Data flow — `radar impact`

`--diff <rev>` | `--staged` | `--function <name>`:

1. **diff_mapper**: `git -c core.quotepath=false diff -U0` → hunk headers → changed lines (new side); pure deletion neo vào dòng kề.
2. **map_to_nodes**: dòng đổi → function bao quanh hẹp nhất; ngoài mọi function → file node (fallback).
3. **tracer (reverse BFS)**: đi ngược các edge `calls`/`handles`; với file node thêm fallback edge `imports`. Edge `name-only` trên đường lan → đánh dấu impact `approximate`. Kết quả: `ImpactResult(changed, affected, apis, features, stats)` kèm `depth` + `confidence`.
4. **report**: terminal (rich) hoặc `--format json|mermaid|html` (Mermaid cap 50 nodes).

**Graph resolution** (`_load_or_build_graph`, không ghi vào repo đích): `--graph <file>` → `<repo>/.radar/graph.json` nếu fresh (cho người dùng `radar build`) → external cache nếu fresh → build vào external cache. Fresh = HEAD khớp git HEAD hiện tại.

## 5b. Data flow — `radar scan`

`radar scan --path <repo>` (informational, mặc định không block):

1. **detect_runtime** (`scan/runner.py`): `semgrep` trên PATH → `native`; else `docker` → `docker`; else lỗi rõ (exit 2).
2. **run_semgrep**: build argv với preset (`p/security-audit` + `p/secrets` + `p/owasp-top-ten`, bỏ qua nếu `--rules-only`) + bundled `radar/rules/`. Docker mount target + rules **read-only**, `-w /src` + target `.` → path repo-relative. Semgrep ghi JSON/SARIF ra **stdout**, parse trong RAM → không chạm filesystem repo.
3. **findings.parse** → `Finding[]` sort theo (severity, path, line); `--format terminal|json|sarif`.
4. **gate**: `--error --fail-on <severity>` → exit 1 nếu có finding đạt ngưỡng; mặc định exit 0.

## 5c. Zero-footprint & graph cache

- **scan**: Semgrep emit ra stdout, không tạo file trong repo đích. Docker mount read-only.
- **impact**: auto-build ghi `graph.json` vào **cache ngoài repo** (`cache.py`): `$RADAR_CACHE` → `%LOCALAPPDATA%/radar/cache` (Windows) → `~/.cache/radar`, key = `sha1(repo_path)[:16]`. Nhờ vậy `radar impact --path <repo-khác>` không để lại `.radar/` trong repo đó.
- **build** (explicit): vẫn ghi `<repo>/.radar/graph.json` như cũ (chủ ý — index repo này), `--out` để đổi đích.

## 6. Plugin contract

Thêm ngôn ngữ = thả 1 module vào `graph/languages/` (0 dòng sửa core):

- Kế thừa `LanguageExtractor` (ABC trong `base.py`): khai báo `name`, `extensions`, hiện thực `extract(source: bytes, relpath) -> FileFacts`.
- Hiện thực `resolve_module(source, from_file, known_files) -> relpath | None` (resolver gọi để biến import specifier thành file đích).
- Gọi `register(<instance>)` ở import-time.
- `__init__.py` auto-import mọi module qua `pkgutil.iter_modules`, nên core không bao giờ tham chiếu một ngôn ngữ cụ thể.

## 7. Ranh giới bảo mật

- Chỉ parse, không exec code được scan; `yaml.safe_load`; glob match trên posix relpath (không chạm filesystem).
- Escape mọi nội dung untrusted khi render: markdown cell (escape `` ` `` → `'`, `|`, `<`/`>`), Mermaid label (whitelist), HTML (Jinja2 autoescape).
- GitHub permissions tối thiểu theo job; job `pr-comment` skip với PR từ fork.
