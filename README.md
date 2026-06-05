# security-radar

> Mỗi PR tự động biết: **code có lỗ hổng gì**, và **thay đổi này lan đến đâu**.

[![Security Scan](../../actions/workflows/security-scan.yml/badge.svg)](../../actions/workflows/security-scan.yml)

Hai subsystem gắn kết trong cùng một pipeline CI:

1. **Security Scan** — quét lỗ hổng bằng [Semgrep](https://semgrep.dev) trong GitHub Actions: rule sets chuẩn ngành (`p/security-audit`, `p/secrets`, `p/owasp-top-ten`) + 5 custom rules có test. Kết quả ở tab **Security** (SARIF), comment PR (tự update, không spam), artifact JSON.
2. **Impact Tracing** — function-level call graph (tree-sitter): `radar impact` trả lời *"sửa function này thì function/API/feature nào bị ảnh hưởng?"*

```
Changed: validateUser  demo/app/utils/validate.js:2  feature: Authentication
├── login  demo/app/routes/auth.js:9  ← POST /login  [depth 1]
└── register  demo/app/routes/auth.js:19  ← POST /register  [depth 1]
Summary: 2 functions, 2 APIs, 1 features affected
```

## Kiến trúc

```
GitHub Actions (security-scan.yml)
├─ job semgrep     → SARIF → Security tab + JSON artifact
├─ job rule-tests  → semgrep --test rules/ (5 custom rules + fixtures)
├─ job impact      → radar build + radar impact --diff base...HEAD → artifact
└─ job pr-comment  → 1 comment: findings + blast radius (upsert theo marker)

src/radar/
├── cli.py                 # radar build | radar impact
├── config.py              # radar.config.yml (feature map + exclude)
├── graph/
│   ├── model.py           # Node/Edge/FileFacts dataclasses
│   ├── builder.py         # walk files → extract → resolve → graph.json
│   ├── resolver.py        # 2-pass: same-file → import map → name-only
│   └── languages/         # plugin per language (auto-discovery)
│       ├── base.py        #   LanguageExtractor ABC + registry
│       ├── javascript.py  #   JS/TS/TSX (tree-sitter)
│       └── python.py      #   Python + Flask/FastAPI routes
├── impact/
│   ├── diff_mapper.py     # git diff -U0 → changed lines → nodes
│   └── tracer.py          # reverse BFS → blast radius + confidence
└── report/
    ├── terminal.py        # rich tree
    └── exporters.py       # JSON / Mermaid / HTML
```

## Cài đặt

```bash
pip install .          # Python ≥ 3.11
radar --help
```

## Sử dụng

```bash
radar build .                        # index → .radar/graph.json (deterministic)
radar impact --diff HEAD~1           # gì bị ảnh hưởng bởi commit cuối?
radar impact --staged                # ... bởi thay đổi đang stage?
radar impact --function validateUser # ... nếu sửa function này?
radar impact --diff HEAD~1 --format json|mermaid|html
```

Graph tự rebuild khi stale (HEAD hash lệch). Tùy chọn: `--depth N`, `--no-name-only` (bỏ edge xấp xỉ).

### Feature map (`radar.config.yml`, tùy chọn)

```yaml
features:
  Authentication: ["src/auth/**", "src/middleware/session*"]
  Payment: ["src/billing/**"]
exclude: ["**/migrations/**"]
```

## Gắn vào repo khác (<10 phút)

1. Copy `.github/workflows/security-scan.yml` (+ `scripts/render-pr-comment.py`, `rules/` nếu muốn custom rules — hoặc xóa `--config rules/` khỏi workflow).
2. Repo **public** (hoặc có GHAS) để tab Security hiển thị SARIF. Chỉ cần `GITHUB_TOKEN` mặc định — **không cần tài khoản Semgrep**.
3. (Tùy chọn) thêm `radar.config.yml` để gắn nhãn feature.

Job `impact` cần `pip install .` từ repo này — nếu chỉ muốn scan, giữ 2 job `semgrep` + `pr-comment`.

## Demo

`demo/app/` là Express app **cố ý chứa lỗ hổng** (SQLi, command injection, hardcoded JWT secret) — kịch bản từng bước: [demo/run-demo.md](demo/run-demo.md). **Không deploy demo app.**

## Giới hạn (by design)

- Call graph là **xấp xỉ**: resolve theo cùng-file → import map → khớp tên toàn cục (gắn nhãn `⚠ approx`). Dynamic call (`obj[x]()`) bị bỏ qua — fallback là edge import file-level.
- Không type-aware, không phân giải dynamic dispatch.
- Ngôn ngữ call graph: JS/TS + Python (thêm ngôn ngữ = 1 file plugin trong `graph/languages/`). Semgrep scan thì đa ngôn ngữ tự nhiên.
- CI chỉ informational — không block merge.

## Development

```bash
pip install -e ".[dev]"
pytest                                       # toàn bộ test suite
docker run --rm -v "$PWD:/src" semgrep/semgrep semgrep --test --metrics off /src/rules/
```

## Tài liệu

- [PRD](docs/security-radar-prd.md) · [Implementation plan](plans/20260605-1835-security-radar-semgrep-impact-graph/plan.md)
