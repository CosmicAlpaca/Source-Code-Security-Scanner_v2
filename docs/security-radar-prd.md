# PRD — security-radar

> **Product Requirements Document** | Phiên bản 1.0 | Ngày: 2026-06-05
> Nguồn: [Brainstorm report](../plans/reports/brainstorm-260605-security-radar-semgrep-impact-graph.md) · [Implementation plan](../plans/20260605-1835-security-radar-semgrep-impact-graph/plan.md)
> Trạng thái: **Approved** — sẵn sàng implement

---

## 1. Tổng quan

**security-radar** là công cụ bảo mật mã nguồn dành cho developer, gồm 2 năng lực dùng được ở **hai chế độ**: **CLI local zero-footprint** (sau `pip install`, quét repo bất kỳ không để lại dấu vết) **và** workflow CI **tuỳ chọn** gắn vào PR.

1. **Security Scan** — quét lỗ hổng bằng **Semgrep** theo rule sets chuẩn ngành + rule tự viết. Local: `radar scan` (native→Docker). CI (tuỳ chọn): GitHub Actions trên mỗi PR/push → tab Security (SARIF), comment PR, report artifact.
2. **Impact Tracing** — dựng **function-level dependency graph** (call graph) của codebase: khi có thay đổi code, trả lời ngay *"sửa function/API này thì những function nào, API nào, feature nào bị ảnh hưởng?"*. Local: `radar impact` (cache ngoài repo). CI: gộp blast radius vào PR comment.

**One-liner:** *Local biết ngay code có lỗ hổng gì và thay đổi lan đến đâu; gắn CI thì mỗi PR tự biết.*

> Định vị này (local-first + CI tuỳ chọn) là kết quả M7/M8 bổ sung sau v1.0; §4–§11 giữ nguyên yêu cầu chức năng. Bản gốc v1.0 mô tả CI-centric.

### Bối cảnh

Dự án tiền nhiệm (coderadar) thất bại do: tự viết taint engine thay vì dùng Semgrep (over-engineering), không có CI/CD (chỉ chạy local), chất lượng không đạt. security-radar là bản làm lại từ đầu với nguyên tắc: **dùng tool chuẩn ngành cho phần đã có lời giải (Semgrep), chỉ tự viết phần chưa có tool tốt (impact graph)**.

---

## 2. Vấn đề & Người dùng

### Vấn đề

| # | Pain point | Hậu quả |
|---|---|---|
| P1 | Lỗ hổng bảo mật (SQLi, command injection, hardcoded secret...) chỉ bị phát hiện khi review thủ công hoặc sau khi lên production | Chi phí sửa cao, rủi ro bị khai thác |
| P2 | Dev sửa một function dùng chung mà không biết bao nhiêu API/feature phụ thuộc vào nó | Regression bất ngờ, test thiếu chỗ, sợ refactor |
| P3 | Reviewer đọc PR không có ngữ cảnh "thay đổi này lan đến đâu" | Review hời hợt hoặc tốn thời gian tự lần code |

### Người dùng mục tiêu

- **Developer** trong team: nhận cảnh báo lỗi + impact ngay trong PR của mình, chạy `radar impact` local trước khi push.
- **Reviewer/Lead**: dùng PR comment (findings + blast radius) làm checklist review.
- **Repo bất kỳ trên GitHub**: workflow thiết kế dạng copy-được, gắn vào repo khác trong <10 phút.

---

## 3. Goals / Non-Goals

### Goals (phạm vi 2 tuần)

- G1: Workflow GitHub Actions scan Semgrep đa ngôn ngữ trên mọi PR/push/cron/manual — **không cần tài khoản Semgrep**, chỉ cần GITHUB_TOKEN.
- G2: Findings hiển thị ở 3 nơi: tab Security (SARIF), comment PR (bảng tóm tắt, tự update không spam), artifact JSON/HTML.
- G3: ≥4 custom Semgrep rules (JS + Python) có test fixture — chứng minh năng lực viết rule, không chỉ dùng preset.
- G4: CLI `radar build` dựng function-level call graph cho **JS/TS + Python** (kiến trúc plugin per-language).
- G5: CLI `radar impact --diff/--staged/--function` trả về danh sách function → API endpoint → feature bị ảnh hưởng, kèm độ tin cậy.
- G6: Impact chạy trong CI: PR comment gộp cả findings lẫn blast radius.
- G7: Demo end-to-end trên GitHub thật với app mẫu có lỗ hổng cài sẵn.

### Non-Goals (chủ động loại bỏ)

- ❌ Tự viết security/taint engine — Semgrep lo toàn bộ phần rule bảo mật.
- ❌ Call graph cho 30+ ngôn ngữ — chỉ JS/TS + Python trong phạm vi này; kiến trúc plugin để mở sau.
- ❌ Block merge PR theo severity — chỉ informational; chính sách block là tính năng tương lai.
- ❌ Web UI / dashboard tương tác — output là terminal, markdown, Mermaid, HTML tĩnh.
- ❌ Phân tích chính xác tuyệt đối (type-aware, dynamic dispatch) — chấp nhận xấp xỉ có nhãn confidence.
- ❌ Semgrep AppSec Platform / SaaS integration.

---

## 4. Tính năng & Yêu cầu chức năng

### F1 — Semgrep Security Scan trong GitHub Actions

| ID | Yêu cầu | Ưu tiên |
|---|---|---|
| F1.1 | Workflow trigger: `pull_request`, `push` (main), `schedule` (daily), `workflow_dispatch` | Must |
| F1.2 | Scan bằng container `semgrep/semgrep`, configs: `p/security-audit`, `p/secrets`, `p/owasp-top-ten`, `rules/` (custom); `--metrics off` | Must |
| F1.3 | Xuất đồng thời JSON (artifact) + SARIF (upload `github/codeql-action/upload-sarif` → tab Security) | Must |
| F1.4 | PR comment: bảng findings theo severity (emoji, file:line, rule id, message), marker `<!-- security-radar -->`, upsert thay vì tạo mới, cap 30 findings + link artifact | Must |
| F1.5 | Custom rules có fixture `// ruleid:` / `ok:`, CI chạy `semgrep --test rules/` | Must |
| F1.6 | Không fail build khi có findings (continue-on-error) | Must |
| F1.7 | PR từ fork: bỏ qua job comment (token read-only), scan vẫn chạy | Should |

**Custom rules tối thiểu:** `js-sql-string-concat`, `js-hardcoded-jwt-secret`, `js-child-process-user-input`, `py-subprocess-shell-true`, `py-flask-debug-true`.

### F2 — Impact Graph & Tracing

| ID | Yêu cầu | Ưu tiên |
|---|---|---|
| F2.1 | `radar build <dir>` index codebase → `.radar/graph.json` (deterministic, có metadata HEAD hash) | Must |
| F2.2 | Node types: `function` (gồm method, arrow), `route` (API endpoint), `file`. Edge types: `calls`, `imports`, `handles` (route→handler) | Must |
| F2.3 | Plugin per-language (`LanguageExtractor` ABC + registry): JS/TS (tree-sitter-javascript/typescript), Python (tree-sitter-python). Thêm ngôn ngữ = 1 file plugin, không sửa core | Must |
| F2.4 | Call resolution 2-pass: cùng file → import map → name-only (gắn nhãn `confidence`); dynamic call bỏ qua, fallback file-level import edge | Must |
| F2.5 | Route auto-detect: Express (`app/router.get/post/...`), Flask/FastAPI (decorator) | Must |
| F2.6 | `radar impact --diff <rev>` \| `--staged` \| `--function <name>`: git diff → dòng đổi → function chứa → reverse BFS → affected functions + APIs + features, kèm depth + confidence | Must |
| F2.7 | Feature mapping qua `radar.config.yml`: glob → tên feature; thiếu config → `(unmapped)`; hỗ trợ `exclude` globs | Must |
| F2.8 | Output formats: terminal (rich tree), `--format json|mermaid|html` (Mermaid cap 50 nodes) | Must |
| F2.9 | Job `impact` trong CI: diff 3-dot với base branch, kết quả gộp vào PR comment chung với F1.4 | Must |
| F2.10 | Auto-rebuild graph khi stale (HEAD hash lệch) | Should |

**Ví dụ output (terminal):**
```
Changed: validateUser()  src/auth/validate.js:12
  ├─ login()      ← POST /api/login     [depth 1]            feature: Authentication
  └─ register()   ← POST /api/register  [depth 1, ⚠ approx]  feature: Authentication
Summary: 3 functions, 2 APIs, 1 feature affected (1 approximate)
```

### F3 — Demo & Tài liệu

| ID | Yêu cầu | Ưu tiên |
|---|---|---|
| F3.1 | `demo/app/` — mini Express app có lỗ hổng cài sẵn (SQLi, command injection, hardcoded secret), call chain ≥2 tầng, cảnh báo "intentionally vulnerable" | Must |
| F3.2 | `demo/run-demo.md` — kịch bản demo từng bước trên GitHub thật | Must |
| F3.3 | README: kiến trúc, setup <10 phút, usage, giới hạn (approximate analysis) | Must |

---

## 5. Yêu cầu phi chức năng

| Loại | Yêu cầu |
|---|---|
| Hiệu năng | Workflow scan < 5 phút (repo demo); `radar build` 1000 files < 30s; `radar impact` query < 2s trên graph 5k nodes |
| Bảo mật | Không exec code được scan (chỉ parse); `yaml.safe_load`; escape markdown/rich markup khi render nội dung untrusted; permissions GitHub tối thiểu (`security-events: write`, `pull-requests: write` theo job); không telemetry |
| Tương thích | Windows + Linux (normalize path `/` trong node id); Python ≥3.11; GitHub public repo (Code Scanning free) |
| Chất lượng | pytest cho mọi module; `semgrep --test` cho rules; file code <200 dòng; không fake/mock để pass build |
| DX | Cài bằng `pip install .`; `radar --help` đầy đủ; graph.json schema ổn định, sort deterministic |

---

## 6. Kiến trúc tổng thể

```
┌──────────────── GitHub Actions (security-scan.yml) ────────────────┐
│  job semgrep ──► SARIF ──► Security tab                            │
│      │              └────► JSON artifact                           │
│  job impact ──► radar build + radar impact --diff base...HEAD      │
│      │                                                             │
│  job pr-comment ◄── gộp findings + blast radius ──► PR comment     │
└─────────────────────────────────────────────────────────────────────┘

src/radar/
├── cli.py                       # radar build | radar impact
├── graph/{model,builder}.py     # networkx DiGraph, 2-pass resolve
├── graph/languages/             # plugin: base.py + javascript.py + python.py
├── impact/{diff_mapper,tracer}.py
├── report/{terminal,exporters}.py
└── config.py                    # radar.config.yml (features, exclude)
```

**Stack:** Python (click, rich, networkx, py-tree-sitter, PyYAML, Jinja2) · Semgrep (container) · GitHub Actions.

**Quyết định kiến trúc then chốt** (chi tiết + alternatives đã loại trong [brainstorm report](../plans/reports/brainstorm-260605-security-radar-semgrep-impact-graph.md)):
- Tree-sitter tự viết extractor thay vì code2flow (bỏ hoang, không TS) hay SCIP (quá nặng, hướng cũ thất bại).
- `semgrep scan` thay vì `semgrep ci` (không phụ thuộc account/token SaaS).
- Xấp xỉ có nhãn confidence thay vì cố chính xác tuyệt đối.

---

## 7. Lộ trình & Milestones

| Milestone | Nội dung | Phase plan | Thời gian |
|---|---|---|---|
| M1 — Scan pipeline sống | Repo + workflow Semgrep, SARIF lên Security tab, artifact | [Phase 01](../plans/20260605-1835-security-radar-semgrep-impact-graph/phase-01-scaffold-and-semgrep-workflow.md) | Tuần 1 |
| M2 — PR feedback | Comment bot + 5 custom rules có test | [Phase 02](../plans/20260605-1835-security-radar-semgrep-impact-graph/phase-02-pr-comment-and-custom-rules.md) | Tuần 1 |
| M3 — Graph JS/TS | Graph core + JS extractor + `radar build` | [Phase 03](../plans/20260605-1835-security-radar-semgrep-impact-graph/phase-03-graph-core-and-js-extractor.md) | Tuần 1 |
| M4 — Impact CLI | diff → blast radius + rich output | [Phase 04](../plans/20260605-1835-security-radar-semgrep-impact-graph/phase-04-impact-cli.md) | Tuần 1-2 |
| M5 — Đa ngôn ngữ + feature | Python plugin + route detect + feature map | [Phase 05](../plans/20260605-1835-security-radar-semgrep-impact-graph/phase-05-python-plugin-and-feature-map.md) | Tuần 2 |
| M6 — Đóng gói demo | Exporters + impact-in-CI + demo app + README | [Phase 06](../plans/20260605-1835-security-radar-semgrep-impact-graph/phase-06-exporters-ci-impact-demo.md) | Tuần 2 |

---

## 8. Success Metrics (Definition of Done)

1. **Scan**: PR chứa SQLi cố ý → finding xuất hiện ở tab Security + comment PR + artifact — verify trên GitHub thật.
2. **Impact**: `radar impact --diff HEAD~1` trên demo app trả đúng danh sách function/API/feature bị ảnh hưởng (so với kỳ vọng kịch bản demo).
3. **Mở rộng**: thêm ngôn ngữ mới = 1 file plugin, 0 dòng sửa core (đã chứng minh bằng Python plugin ở M5).
4. **Chất lượng**: toàn bộ pytest + `semgrep --test rules/` xanh; workflow xanh trên GitHub.
5. **DX**: người ngoài team setup được workflow vào repo khác trong <10 phút chỉ với README.

---

## 9. Rủi ro & Giảm thiểu

| Rủi ro | Mức | Giảm thiểu |
|---|---|---|
| Call resolution sai với dynamic call (`obj[x]()`, callback, DI) | Cao | Chấp nhận xấp xỉ; fallback file-level edge; nhãn `approximate` trong mọi output; option `--no-name-only` |
| Private repo không có Code Scanning (GHAS) | Trung bình | Repo demo bắt buộc public; README ghi rõ giới hạn |
| Semgrep JSON/SARIF schema đổi theo version | Trung bình | Pin version image; fixture JSON commit kèm cho render script |
| Trùng tên function nhiều file → name-only edges nổ to | Trung bình | Cap edges + confidence label |
| PR comment vượt giới hạn 65k chars | Thấp | Cap 30 findings + link artifact |
| Windows path mismatch | Thấp | Normalize `/` toàn bộ node id (bài học repo cũ) |

---

## 10. Câu hỏi mở

- Q1: Có cần chính sách block merge theo severity threshold không? → để sau M6, làm config opt-in.
- Q2: Impact → test selection (chạy đúng test file bị ảnh hưởng)? → tính năng tương lai, ngoài phạm vi 2 tuần.
- Q3: Thêm ngôn ngữ thứ 3 nào trước (Go/Java)? → quyết sau khi M5 chứng minh plugin interface.

---

## 11. Thuật ngữ

| Thuật ngữ | Nghĩa |
|---|---|
| **SARIF** | Static Analysis Results Interchange Format — chuẩn JSON để GitHub Code Scanning hiển thị findings ở tab Security |
| **Blast radius** | Tập hợp function/API/feature bị ảnh hưởng (trực tiếp + gián tiếp) bởi một thay đổi |
| **Call graph** | Đồ thị có hướng: node = function/route/file, edge = quan hệ gọi/import/handle |
| **Confidence (resolved / name-only)** | Mức tin cậy của edge: resolve qua import map (chắc) vs khớp tên toàn cục (xấp xỉ) |
| **Feature map** | Cấu hình glob → tên feature trong `radar.config.yml` để gom function/API theo nghiệp vụ |
