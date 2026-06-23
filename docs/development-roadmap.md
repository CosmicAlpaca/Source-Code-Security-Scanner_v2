# Development Roadmap — security-radar

> Living document theo dõi tiến độ. Yêu cầu sản phẩm & milestone gốc xem [PRD §7](./security-radar-prd.md). Chi tiết bản phát hành xem [Changelog](./project-changelog.md).
> Cập nhật: 2026-06-23

## Trạng thái tổng quan

M1→M8 done. **M9 (radar serve — live localhost dashboard)** done — `radar serve` lệnh duy nhất mở tab browser live, findings cập nhật <1s qua SSE không reload, graph/impact debounce ~2s, triage on-demand. Post-review hardening: C1 state race (snapshot-under-lock), C2 XSS (innerHTML→textContent), W3 (build_risk_map → triage/risk.py). Full suite: 334 passed / 9 skipped / 0 failed. Toàn bộ scope yêu cầu ban đầu hoàn tất.

## Milestones

| Milestone | Nội dung | Trạng thái |
|---|---|---|
| M1 — Scan pipeline sống | Workflow Semgrep, SARIF → Security tab, artifact | ✅ Done (local) |
| M2 — PR feedback | Comment bot + 5 custom rules có test | ✅ Done (local) |
| M3 — Graph JS/TS | Graph core + JS extractor + `radar build` | ✅ Done (local) |
| M4 — Impact CLI | diff → blast radius + rich output | ✅ Done (local) |
| M5 — Đa ngôn ngữ + feature | Python plugin + route detect + feature map | ✅ Done (local) |
| M6 — Đóng gói demo | Exporters + impact-in-CI + demo app + README | ✅ Done (local) |
| M7 — Local scan tool | `radar scan` (native→docker) + bundled rules + impact zero-footprint | ✅ Done |
| M8 — Verify CI GitHub | DoD §8 trên repo public: workflow xanh, PR comment, SARIF, blast radius | ✅ Done |
| M9 — radar serve | Live localhost dashboard: SSE, fragments, orchestrator, 128 new tests, security hardening | ✅ Done |

334 pytest xanh trên máy (128 test serve mới + test cũ); CI xanh 9/9 run trên GitHub.

## Đã verify (2026-06-10, repo public)

- **Workflow xanh** — 9/9 run "completed successfully", gồm `rule-tests` với 6 custom rules.
- **PR comment bot (F1.4)** — PR #1: bảng findings theo severity + section impact render đúng.
- **SARIF → Code scanning (F1.3)** — `github-advanced-security[bot]` review comments (danh sách alert tab cần đăng nhập mới xem).
- **Blast radius engine (F2.6)** — `radar impact --function validateUser` → login/register → feature Authentication, zero-footprint. Impact-in-CI non-empty chứng minh ở local (PR #1 diff không chạm function demo nên ra rỗng — đúng logic).

## Tương lai (ngoài phạm vi 2 tuần — [PRD §10](./security-radar-prd.md))

- **Block-merge policy opt-in** — chính sách fail PR theo severity threshold, cấu hình bật/tắt (Q1).
- **Test selection** — từ impact suy ra test file bị ảnh hưởng để chạy đúng tập test (Q2).
- **Ngôn ngữ thứ 3** — Go hoặc Java, quyết sau khi plugin interface đã chứng minh ở M5 (Q3).
