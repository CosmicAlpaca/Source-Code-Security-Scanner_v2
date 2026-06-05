# Phase 05 — Python plugin + route detect + feature map

## Context Links

- Plan: [plan.md](plan.md) | Phụ thuộc: [phase-03](phase-03-graph-core-and-js-extractor.md), [phase-04](phase-04-impact-cli.md)

## Overview

- **Priority**: P1 | **Status**: complete
- Chứng minh kiến trúc plugin: thêm Python extractor KHÔNG sửa core. Thêm tầng "feature" qua `radar.config.yml`.

> **Note**: Python plugin = 1 file mới `python.py` + tách helper `javascript_imports.py`, 0 thay đổi core → success criterion #3 ("thêm ngôn ngữ = 1 file plugin") đã validate.

## Key Insights

- Đây là phase validate success criterion #3 ("thêm ngôn ngữ = 1 file plugin"). Nếu phải sửa core → kiến trúc sai, dừng lại refactor base interface trước.
- Python routes: decorator `@app.get("/x")` / `@app.route("/x", methods=[...])` (FastAPI/Flask) — decorator nằm ngay trên function def → dễ hơn Express.
- Feature map KISS: YAML glob → feature name, match theo file path của node. Không magic inference.

## Requirements

- FR1: `radar build` index .py: defs (def/async def/method trong class), calls, imports (import/from-import), routes (Flask/FastAPI decorators)
- FR2: `radar.config.yml`:
```yaml
features:
  Authentication: ["src/auth/**", "src/middleware/session*"]
  Payment: ["src/billing/**"]
exclude: ["**/migrations/**"]
```
- FR3: ImpactResult + terminal output thêm cột feature; node không match glob → feature `(unmapped)`
- NFR: javascript.py và python.py không import lẫn nhau; core không import extractor cụ thể (chỉ registry)

## Architecture

```
src/radar/graph/languages/python.py   # LanguageExtractor cho .py
src/radar/config.py                   # load radar.config.yml (features, exclude) + glob match (pathlib PurePath.match / fnmatch)
builder.py: gán node.feature lúc build (sau extract, trước save)
```

## Related Code Files (repo `security-radar/`)

Create:
- `src/radar/graph/languages/python.py` (<200 dòng)
- `src/radar/config.py` (<100 dòng)
- `tests/fixtures/py-app/` — mini Flask hoặc FastAPI app 3-4 file
- `tests/test_python_extractor.py`, `tests/test_config.py`

Modify:
- `src/radar/graph/builder.py` — chỉ: đọc config exclude + gán feature (không đụng resolve logic)
- `src/radar/report/terminal.py` — thêm feature vào output

## Implementation Steps

1. `python.py` tree-sitter queries: `function_definition` (kèm class context → qualified name `Class.method`), `call` → callee, `import_statement`/`import_from_statement`, `decorated_definition` có decorator dạng route.
2. Đăng ký vào registry `{'.py': PythonExtractor}` — xác nhận core không cần sửa gì khác.
3. `config.py`: load YAML (yaml.safe_load), validate schema tay (KISS), API: `feature_for(path) -> str|None`, `is_excluded(path) -> bool`.
4. builder: áp exclude khi walk; gán feature sau khi có nodes.
5. terminal: feature trong tree + summary "N features affected".
6. Tests: py-app fixture (route decorator → handler → service call chain); mixed repo JS+Python build chung 1 graph.

## Todo List

- [x] python.py extractor + tests
- [x] Registry-only integration (đo: diff core = 0 dòng ngoài builder feature/exclude)
- [x] config.py + tests (glob edge cases, file thiếu → default)
- [x] Feature trong output impact
- [x] Mixed-language fixture test

## Success Criteria

- Repo trộn JS + Python build ra 1 graph; sửa function Python → impact ra route FastAPI + feature đúng theo config.

## Risk Assessment

- Python relative import (`from . import x`) resolve khó → map theo package path tương đối, sai thì fallback name-only (nhất quán với JS).
- `yaml.safe_load` bắt buộc (không `load`) — config từ repo untrusted.

## Security Considerations

- Glob từ config không được escape ra ngoài repo root (chỉ match relpath, không resolve filesystem).

## Next Steps

→ Phase 06: exporters + chạy impact trong CI + demo.
