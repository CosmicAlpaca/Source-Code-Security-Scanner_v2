---
title: "security-radar — Semgrep CI + Function-level Impact Graph"
status: in-progress
created: 2026-06-05
branch: main (repo mới)
blockedBy: []
blocks: []   # supersedes: 20260604-impact-radar-phase2 (đã cancelled, nằm ở repo cũ Source-Code-Security-Scanner)
effort: 2 tuần / 6 phase
repoPath: E:\Documents\AI_Vin\security-radar
brainstorm: plans/reports/brainstorm-260605-security-radar-semgrep-impact-graph.md
---

# security-radar — Implementation Plan

Tool mới (repo mới, thay thế hướng cũ của coderadar). 2 subsystem:
1. **SCAN**: Semgrep trong GitHub Actions → SARIF (Security tab) + artifact + PR comment
2. **IMPACT**: Function-level call graph (tree-sitter, Python) → `radar impact --diff` → function/API/feature bị ảnh hưởng

> Design đã duyệt: [brainstorm report](../reports/brainstorm-260605-security-radar-semgrep-impact-graph.md)
> Plan cũ `20260604-impact-radar-phase2` (SCIP) → cancelled, superseded by plan này.

## Phases

| # | Phase | Tuần | Status | File |
|---|---|---|---|---|
| 1 | Scaffold repo + Semgrep workflow (SARIF + artifact) | 1 | 🔶 done (local) — GitHub verify pending | [phase-01](phase-01-scaffold-and-semgrep-workflow.md) |
| 2 | PR comment bot + custom Semgrep rules | 1 | 🔶 done (local) — GitHub verify pending | [phase-02](phase-02-pr-comment-and-custom-rules.md) |
| 3 | Graph core + JS/TS extractor (tree-sitter) | 1 | ✅ done | [phase-03](phase-03-graph-core-and-js-extractor.md) |
| 4 | Impact CLI: diff → blast radius + terminal output | 1-2 | ✅ done | [phase-04](phase-04-impact-cli.md) |
| 5 | Python plugin + route detect + feature map | 2 | ✅ done | [phase-05](phase-05-python-plugin-and-feature-map.md) |
| 6 | Exporters + impact-in-CI + demo repo | 2 | 🔶 done (local) — GitHub verify pending | [phase-06](phase-06-exporters-ci-impact-demo.md) |

## Dependencies giữa phases

```
phase-01 ──► phase-02 (workflow có trước, comment bot gắn vào)
phase-03 ──► phase-04 (graph có trước, impact query sau)
phase-04 ──► phase-05 ──► phase-06
phase-02 độc lập với 03-05; phase-06 cần tất cả
```

## Key decisions (từ brainstorm)

- **Semgrep only** cho security rules — KHÔNG tự viết taint engine (bài học repo cũ)
- Call graph: **tree-sitter plugin per language**, KHÔNG dùng code2flow (bỏ hoang) / SCIP (quá nặng)
- Ngôn ngữ: Semgrep = đa ngôn ngữ tự nhiên; call graph = JS/TS + Python trước, plugin mở rộng sau
- Tool viết bằng **Python** (tree-sitter, networkx, rich, click)
- Call resolution xấp xỉ (tên + import map), fallback file-level edge, label "approximate"
- Route = API node (Express/FastAPI/Flask auto-detect); feature qua `radar.config.yml` (glob → name)
- CI không block merge (chỉ comment + report + Security tab); block là option sau

## Success criteria

1. PR chứa SQLi → finding hiện ở tab Security + comment trong PR + artifact JSON/HTML
2. `radar impact --diff HEAD~1` trả đúng function/API/feature bị ảnh hưởng trên demo repo
3. Thêm ngôn ngữ mới = 1 file plugin, không sửa core
4. Tests pass (pytest), workflow xanh trên GitHub thật

## Implementation notes

Trạng thái: 6/6 phase đã implement + test local. Việc còn lại duy nhất = verify end-to-end trên GitHub thật (push, mở PR test, kiểm tra Security tab + PR comment + artifacts).

- **Repo remote**: dùng remote sẵn có `CosmicAlpaca/Source-Code-Security-Scanner_v2` (public) thay vì tạo repo mới `security-radar`.
- **Tách file giữ <200 dòng**: `resolver.py` tách riêng khỏi `builder.py`; `javascript_imports.py` tách từ `javascript.py`.
- **CallSite** có thêm field `object` để resolve member call (`obj.method()`) qua import map.
- **Code review**: 2 HIGH (markdown injection qua backtick; APIs column scope) + 3 MEDIUM đã fix. M4 (pip install code của PR trong CI) = accepted risk — job `impact` không có write permission.
- **Test**: 76 pytest pass + 5/5 semgrep `--test rules/` (qua docker).
