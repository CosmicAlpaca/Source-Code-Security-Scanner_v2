# Phase 06 — Exporters + impact-in-CI + demo repo

## Context Links

- Plan: [plan.md](plan.md) | Phụ thuộc: tất cả phase trước
- [Mermaid flowchart syntax](https://mermaid.js.org/syntax/flowchart.html) (dùng skill `mermaidjs-v11` khi viết)

## Overview

- **Priority**: P1 — phase "đóng gói để demo" | **Status**: complete-local-pending-github-verify
- Export JSON/Mermaid/HTML; job CI chạy `radar impact` trên PR và comment; demo app có lỗ hổng + script demo end-to-end.

## Key Insights

- PR diff trong CI: `git diff origin/${{ github.base_ref }}...HEAD` (3-dot, merge-base) — checkout cần `fetch-depth: 0`.
- Impact comment gộp chung comment Semgrep (1 comment 2 section, marker chung `<!-- security-radar -->`) — tránh 2 bot comment.
- HTML export: Jinja2 template đơn giản nhúng Mermaid CDN — KHÔNG build web app.
- Demo app: tự viết mini Express app (~6 file) lỗi cài sẵn (SQLi, command injection, hardcoded secret) thay vì fork dvna — kiểm soát được kịch bản demo, nhỏ gọn.

## Requirements

- FR1: `radar impact --format json|mermaid|html` (mặc định terminal)
- FR2: PR trên repo demo → 1 comment: section Semgrep findings + section Impact (functions/APIs/features affected)
- FR3: Demo script (`demo/run-demo.md` kịch bản từng bước): sửa 1 function auth → push PR → thấy cả 2 section
- NFR: README đủ để người khác setup workflow vào repo bất kỳ trong <10 phút

## Architecture

```
src/radar/report/exporters.py
  to_json(result)     # machine-readable, schema ổn định
  to_mermaid(result)  # flowchart TD: changed (đỏ) → affected → route (xanh), cap 50 nodes
  to_html(result)     # Jinja2: bảng + mermaid embed

.github/workflows/security-scan.yml
  job impact (if: pull_request):
    checkout fetch-depth 0 → pip install radar → radar build → radar impact --diff origin/$BASE...HEAD --format json
    → render section markdown → merge vào comment bot (script phase 2 mở rộng nhận 2 input)
```

## Related Code Files (repo `security-radar/`)

Create:
- `src/radar/report/exporters.py` (<200 dòng) + `templates/impact.html.j2`
- `demo/app/` — mini Express app có lỗ hổng (routes/users.js, routes/auth.js, services/db.js, utils/validate.js...)
- `demo/run-demo.md` — kịch bản demo từng bước
- `tests/test_exporters.py`

Modify:
- `.github/workflows/security-scan.yml` — job `impact`
- `scripts/render-pr-comment.py` — nhận thêm impact.json, render 2 section
- `README.md` — hướng dẫn cài đặt đầy đủ + screenshots

## Implementation Steps

1. `exporters.py` + tests (snapshot mermaid/json; html chỉ smoke test render được).
2. CLI `--format`; mermaid cap 50 nodes + note "N nodes hidden".
3. Demo app Express với 3 lỗi cố ý khớp cả preset rules lẫn custom rules phase 2; call chain ≥2 tầng để impact demo đẹp (route → controller → service → util).
4. Job `impact` trong workflow (pip install từ source `pip install .`), merge output vào render-pr-comment.
5. Chạy kịch bản demo thật trên GitHub: PR sửa `utils/validate.js` → verify comment có Semgrep findings + "2 APIs, 1 feature affected".
6. README: badges, kiến trúc, setup, usage, giới hạn (approximate analysis).
7. Cuối phase: review toàn bộ bằng code-reviewer, chạy full pytest + `semgrep --test rules/`.

## Todo List

- [x] exporters.py 3 format + tests
- [x] Demo app + radar.config.yml (feature: Authentication, Users)
- [x] Job impact trong CI + comment gộp
- [ ] Kịch bản demo chạy thật trên GitHub, chụp screenshot
- [x] README hoàn chỉnh
- [x] Full test suite xanh

## Success Criteria

- 1 PR demo cho thấy: Security tab + comment (findings + impact) + artifact — toàn bộ pipeline trong 1 màn hình demo.

## Risk Assessment

- `pip install` mỗi run chậm → cache pip (actions/cache key pyproject hash).
- Mermaid trong GitHub comment: GitHub render được ```mermaid``` block — nếu graph to bị xấu → để mermaid trong artifact HTML, comment chỉ để bảng.
- Demo app có lỗ hổng thật → README cảnh báo "intentionally vulnerable, do not deploy"; folder `demo/` exclude khỏi mọi deploy.

## Security Considerations

- Demo app không có secret thật (dùng giá trị giả rõ ràng `fake-jwt-secret-for-demo`).
- Job impact chỉ cần `contents: read` + `pull-requests: write` (qua job comment).

## Next Steps

- Mở rộng sau (ngoài scope 2 tuần): block merge theo severity threshold, thêm ngôn ngữ (Go/Java plugin), test selection (impact → chạy đúng test files), Semgrep AppSec Platform integration.
