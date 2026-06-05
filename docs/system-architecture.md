# System Architecture — security-radar

> Kiến trúc kỹ thuật của bản hiện thực. Yêu cầu sản phẩm xem [PRD](./security-radar-prd.md).
> Cập nhật: 2026-06-06

## 1. Hai subsystem

security-radar gồm hai năng lực độc lập, gắn kết trong cùng pipeline CI:

1. **Security Scan** (Semgrep + GitHub Actions) — quét lỗ hổng, không tự viết taint engine.
2. **Impact Tracing** (Python package `radar`) — dựng call graph, trả lời "thay đổi này lan đến đâu".

Cả hai gặp nhau ở job `pr-comment`: gộp findings + blast radius vào một comment PR.

## 2. Module map

```
.github/workflows/security-scan.yml   # 4 jobs: semgrep · rule-tests · impact · pr-comment
scripts/render-pr-comment.py          # stdlib-only: semgrep.json [+ impact.json] -> comment.md
rules/                                # 5 custom Semgrep rules + fixtures (.yaml + .js/.py)
radar.config.yml                      # feature map (glob -> feature) + exclude globs

src/radar/
├── cli.py                            # `radar build` | `radar impact`
├── config.py                         # RadarConfig: feature_for / is_excluded (yaml.safe_load)
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

Graph được load từ `.radar/graph.json`; nếu thiếu hoặc HEAD lệch → tự rebuild.

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
