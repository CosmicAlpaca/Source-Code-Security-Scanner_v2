# Development Roadmap — security-radar

> Living document theo dõi tiến độ. Yêu cầu sản phẩm & milestone gốc xem [PRD §7](./security-radar-prd.md). Chi tiết bản phát hành xem [Changelog](./project-changelog.md).
> Cập nhật: 2026-06-08

## Trạng thái tổng quan

Bản hiện thực đầu tiên hoàn tất cục bộ — M1→M6 done. **M7 (local CLI scan + zero-footprint)** done. Còn 1 bước xác minh GitHub trước khi coi là Definition of Done đầy đủ ([PRD §8](./security-radar-prd.md)).

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

"Local" = hiện thực + 103 pytest + `semgrep --test` xanh trên máy; chưa verify trên GitHub Actions thật.

## Đang làm

- **GitHub end-to-end verify** — push repo, mở PR thử, kiểm tra: workflow xanh, finding SQLi cố ý hiện ở tab Security + comment PR + artifact, `radar impact` trong CI trả đúng blast radius. Tương ứng success metrics [PRD §8](./security-radar-prd.md) #1, #2, #4, #5.

## Tương lai (ngoài phạm vi 2 tuần — [PRD §10](./security-radar-prd.md))

- **Block-merge policy opt-in** — chính sách fail PR theo severity threshold, cấu hình bật/tắt (Q1).
- **Test selection** — từ impact suy ra test file bị ảnh hưởng để chạy đúng tập test (Q2).
- **Ngôn ngữ thứ 3** — Go hoặc Java, quyết sau khi plugin interface đã chứng minh ở M5 (Q3).
