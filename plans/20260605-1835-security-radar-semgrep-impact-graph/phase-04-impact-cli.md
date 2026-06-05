# Phase 04 — Impact CLI: diff → blast radius + terminal output

## Context Links

- Plan: [plan.md](plan.md) | Phụ thuộc: [phase-03](phase-03-graph-core-and-js-extractor.md)
- Tham khảo (KHÔNG copy): repo cũ `src/impact/` (diff→blast radius đã làm với SCIP), `src/change_detector/git_diff_reader.py`

## Overview

- **Priority**: P0 — đây là tính năng "sửa cái này ảnh hưởng cái gì" | **Status**: pending
- `radar impact --diff <rev> | --staged | --function <name>` → function bị sửa → reverse BFS → function/API bị ảnh hưởng, output rich terminal.

## Key Insights

- `git diff -U0 <rev> -- '*.js' ...` parse hunk header `@@ -a,b +c,d @@` → (file, dòng mới thay đổi). Dùng `subprocess` gọi git (KISS, không cần gitpython).
- Map dòng → function: graph node có start_line/end_line → tìm node nhỏ nhất chứa dòng (nested function chọn trong cùng).
- File bị sửa nhưng dòng ngoài mọi function (top-level code, config) → impact = mọi file import file đó (file-level fallback).
- Reverse BFS trên edge `calls` + `handles` đảo chiều, ghi depth; mặc định không giới hạn, `--depth N` để cắt. Edge `name-only` đi qua nhưng đánh dấu để output phân biệt "chắc chắn" vs "có thể".
- Graph build từ HEAD có thể lệch với diff — chấp nhận (rebuild nhanh); CLI tự `radar build` nếu thiếu/cũ (so mtime graph.json vs git HEAD hash lưu trong graph metadata).

## Requirements

- FR1: `--diff <rev>` (mặc định HEAD~1), `--staged`, `--function <name|file::name>` đều chạy
- FR2: Output: function bị sửa → danh sách affected (function, file:line, depth, qua route nào), API endpoints tổng hợp, confidence
- FR3: Exit code: 0 luôn (phase này chỉ informational)
- NFR: query < 2s trên graph 5k nodes

## Architecture

```
src/radar/impact/
├── diff_mapper.py   # git diff/staged → [(file, line)] → changed function nodes
└── tracer.py        # reverse BFS → ImpactResult{changed:[...], affected:[{node, depth, via, confidence}], apis:[...]}

src/radar/report/terminal.py   # rich tree/table render ImpactResult
```

## Related Code Files (repo `security-radar/`)

Create:
- `src/radar/impact/__init__.py`, `diff_mapper.py` (<150), `tracer.py` (<150)
- `src/radar/report/__init__.py`, `terminal.py` (<150)
- `tests/test_diff_mapper.py` (fixture: git repo tạm bằng pytest tmp_path + git init), `tests/test_tracer.py`

Modify:
- `src/radar/cli.py` — lệnh `impact`

## Implementation Steps

1. `diff_mapper.py`: chạy git diff -U0, parse hunks → changed lines; map sang nodes qua graph (line trong [start,end], chọn node hẹp nhất); trả cả files-without-function-hit.
2. `tracer.py`: nx reverse BFS từ changed nodes qua edges calls/handles (đảo chiều) + imports cho file fallback; gom ImpactResult; suy `apis` = affected/changed nodes kind=route hoặc nối tới route qua `handles`.
3. `terminal.py`: rich Tree giống mock brainstorm:
```
Changed: validateUser()  src/auth/validate.js:12
  ├─ login()  ← POST /api/login   [depth 1]
  └─ register()  ← POST /api/register   [depth 1, name-only ⚠]
Summary: 3 functions, 2 APIs affected (1 approximate)
```
4. CLI `impact` wire 3 mode + auto-rebuild graph khi stale.
5. Tests: repo git tạm, sửa 1 function trong fixture js-app, assert affected list đúng; test top-level change fallback.

## Todo List

- [ ] diff_mapper: --diff/--staged + hunk parse + line→node
- [ ] tracer: reverse BFS + depth + confidence + API rollup
- [ ] terminal.py rich output
- [ ] CLI impact 3 mode + auto-rebuild
- [ ] Tests git-repo-tạm pass

## Success Criteria

- Trên fixture: sửa `validateUser` → ra đúng caller + route như thiết kế; `--function` mode khớp `--diff` mode.

## Risk Assessment

- Rename file/function trong diff làm node cũ biến mất → map theo graph mới (sau thay đổi), thiếu node cũ thì fallback file-level; ghi chú trong output.
- Windows path (`\` vs `/`) — normalize về `/` ở mọi node id (bài học repo cũ commit `746ae1a`).

## Security Considerations

- Không trust nội dung diff khi render (escape rich markup: `rich.markup.escape`).

## Next Steps

→ Phase 05 thêm Python plugin + feature map để output có tầng "feature".
