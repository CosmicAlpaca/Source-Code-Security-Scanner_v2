# Nhật ký: Triển khai ban đầu Security Radar (6 phase)

**Ngày:** 2026-06-06
**Plan:** `plans/20260605-1835-security-radar-semgrep-impact-graph/`

## Bối cảnh

Thực thi toàn bộ plan 6 phase ở chế độ auto trong một session duy nhất: xây dựng Security Radar — kết hợp Semgrep (phát hiện lỗ hổng) với một call/impact graph để truy ngược tác động của thay đổi code lên các route/endpoint. Toàn bộ code triển khai cục bộ, chưa commit (user chọn review trước).

## Việc đã làm

- **Phase 01 — Scaffold:** Python package (pyproject + Click CLI). Workflow `.github/workflows/security-scan.yml`: chạy Semgrep trong container, xuất SARIF + JSON artifact, 4 trigger.
- **Phase 02 — Custom rules:** 5 rule Semgrep + fixtures (gồm 1 rule taint-mode `js-child-process-user-input`), 5/5 pass qua docker. `scripts/render-pr-comment.py` (escape markdown, cap 30, upsert theo marker). Thêm job `rule-tests` + `pr-comment`.
- **Phase 03 — Graph core:** `model.py` (dataclasses), plugin registry auto-discover qua `pkgutil`, extractor `javascript.py` dùng tree-sitter (duyệt AST thủ công thay vì query API để ổn định giữa các version), `resolver.py` 2 pass (same-file → import map gồm cả member-call qua object import → name-only cap 5), `builder.py` sinh `graph.json` deterministic + hash git HEAD. 24 test.
- **Phase 04 — Impact tracing:** `diff_mapper` (parse hunk `git diff -U0`, tìm hàm bao gần nhất, fallback file-level), `tracer` (reverse BFS, lan truyền depth + confidence, theo dõi parent), cây terminal qua rich, CLI `impact` 3 mode + tự rebuild graph khi stale. 16 test.
- **Phase 05 — Python plugin:** `python.py` (decorator route Flask/FastAPI, resolve relative import) — 1 file mới, 0 sửa core (đạt success criterion). `config.py` feature map. 20 test.
- **Phase 06 — Export & demo:** exporters (JSON khớp schema `render-pr-comment`, Mermaid cap 50 + sanitize whitelist, HTML Jinja2 autoescape), CI job `impact` (diff 3-dot), demo Express cố tình có lỗ hổng, `run-demo.md`, README.

## Quyết định kỹ thuật đáng nhớ

- **Manual AST walk thay vì tree-sitter query API:** query API thay đổi giữa các version tree-sitter, gây vỡ silent. Duyệt AST thủ công đổi lấy độ ổn định cross-version.
- **Tách module giữ <200 dòng:** `javascript.py` (234 dòng) tách phần import sang `javascript_imports.py` còn 174 dòng.
- **Name-only resolution cap 5:** pass cuối khi không resolve được theo file/import thì match theo tên nhưng giới hạn 5 edge để tránh bùng nổ edge nhiễu.
- **Member-call qua import object:** resolver hiểu được call dạng `obj.method()` khi `obj` đến từ import, không chỉ named import trực tiếp.

## Sự cố & cách xử lý

**Environment (Windows):**
- `pip.exe` / `radar.exe` bị Windows Application Control chặn → dùng `python -m`.
- Semgrep không chạy native Windows → chạy qua docker.
- rich crash trên console cp1252 → `sys.stdout.reconfigure(errors="replace")`.
- `gh` CLI không có sẵn.

**Code review (subagent) — 2 HIGH đã fix:**
- Markdown injection qua backtick trong `escape_cell` → escape backtick.
- Cột APIs sai scope → đổi sang per-changed-function.

**3 MEDIUM đã fix:** `core.quotepath=false`; tách `javascript.py`; whitelist label Mermaid.
**1 MEDIUM chấp nhận:** `pip install` PR code trong job `impact` (không có quyền write).

## Trạng thái & việc tiếp theo

- **Test:** 76/76 pytest pass.
- **Docs:** đã cập nhật `system-architecture`, `project-changelog`, `development-roadmap`; plan files đã sync.
- **Chưa commit:** chưa có gì được commit — user review trước.
- **Pending:** verify end-to-end trên GitHub (chạy thật workflow + PR comment) sau khi commit.
