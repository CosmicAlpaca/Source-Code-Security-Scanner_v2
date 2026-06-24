# Nhật ký: `radar serve` — Live Localhost Security Dashboard

**Ngày:** 2026-06-23
**Branch:** `feat/serve-dashboard`
**PR:** #23 → main (https://github.com/CosmicAlpaca/Source-Code-Security-Scanner_v2/pull/23)
**Commits:** 4 (feat / refactor / test / docs)

## Bối cảnh

Workflow cũ: chạy `radar report --html` → mở file tĩnh → chỉnh code → chạy lại → mở file mới. Session này thay thế bằng một lệnh duy nhất `radar serve` mở trình duyệt 127.0.0.1 và tự cập nhật khi user sửa code, không reload trang.

## Việc đã làm

**Phase 01 — Fragment refactor (`report.py`, `graph_viz.py`):**
- Tách `report.py` thành các hàm `render_*_fragment` trả về HTML snippet (không full page) để SSE có thể push từng panel riêng lẻ.
- Thêm `graph_viz.render_graph_fragment` tương tự; hardened XSS escaping trong `render_graph_html` standalone export.

**Phase 02 — Watcher refactor (`watcher.py`):**
- Tách `watch_loop` và `scan_file` thành hàm độc lập tái dùng được — serve orchestrator gọi cùng machinery với `radar watch`.

**Phase 03 — SSE server (`serve/server.py`, CLI):**
- `ThreadingHTTPServer` stdlib, không thêm runtime dep.
- Endpoint `/events` dùng SSE (text/event-stream); mỗi panel là một event type riêng (`findings`, `graph`, `history`, `triage`).
- CLI `radar serve [--port] [--host] [--open/--no-open]`.

**Phase 04 — Tiered orchestrator + frontend (`serve/orchestrator.py`, `serve/pipeline.py`, `shell.html`, `app.js`, `app.css`):**
- Model cập nhật theo tầng: findings + history instant mỗi lần save (incremental single-file scan), graph + blast-radius debounce ~2s (tận dụng graph cache), AI triage chỉ khi user bấm nút (không tự kích hoạt — tránh đốt API key và chi phí).
- Frontend nhận SSE, cập nhật DOM từng panel; chart.js được vendor offline (không cần CDN).

**Phase 05 — Tests + docs:**
- 128 test mới cho serve; tổng suite: **334 passed / 9 skipped / 0 failed**.
- Cập nhật `development-roadmap`, `project-changelog`, `system-architecture`, `COMMANDS.md`.

## Quyết định kỹ thuật đáng nhớ

- **SSE thay vì WebSocket:** cập nhật một chiều server→client, dùng được stdlib hoàn toàn, không thêm dep.
- **Tiered update model:** scan đơn file nhanh hơn full-scan ~10x; graph rebuild chỉ sau debounce 2s; AI triage on-demand để user kiểm soát chi phí và chạy offline được.
- **Snapshot-under-lock (fix C1 — race condition):** `push_*` helper ban đầu đọc state ngoài lock → KeyError khi watcher thread và debounce timer chạy đồng thời. Fix: snapshot toàn bộ state bên trong `with self._lock` trước khi serialize.

## Sự cố & cách xử lý

**Code review (subagent, điểm 7.5/10) — 2 merge blocker:**

- **C1 — Race condition (KeyError):** state read ngoài lock trong `push_findings` / `push_graph`. Fix: snapshot-under-lock như trên.
- **C2 — Stored XSS:** `app.js` dùng `innerHTML` để render tên file/hàm lấy từ repo được scan — nếu repo chứa tên hàm có `<script>` thì XSS thật. Fix: chuyển sang `textContent` + DOM node building cho D3 tooltip và tất cả dynamic string từ dữ liệu repo. Đây là lỗi đáng chú ý vì tool scan repo không tin cậy mà lại render string từ repo đó.

**2 warning đã fix:**
- W1: vendor chart.js (offline-safe, không phụ thuộc CDN).
- W3: tách `build_risk_map` từ `cli.py` ra `triage/risk.py` (separation of concerns).

**Playwright verification:** drop file có lỗ hổng vào repo demo → Findings badge 0→1, WARNINGS 0→1, OWASP A02 donut render live — không reload trang, chart.js offline hoạt động.

## Trạng thái & việc tiếp theo

- PR #23 mở, chưa merge.
- Không sửa trực tiếp `main`.
- Follow-up tiềm năng: throttle SSE khi nhiều file thay đổi cùng lúc (bulk save); rate-limit `/triage` endpoint để tránh spam API key.
