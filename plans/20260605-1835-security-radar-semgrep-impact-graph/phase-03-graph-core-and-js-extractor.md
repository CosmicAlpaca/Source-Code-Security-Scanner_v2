# Phase 03 — Graph core + JS/TS extractor (tree-sitter)

## Context Links

- Plan: [plan.md](plan.md) | Brainstorm: [report](../reports/brainstorm-260605-security-radar-semgrep-impact-graph.md)
- [py-tree-sitter](https://github.com/tree-sitter/py-tree-sitter) | tree-sitter-javascript / tree-sitter-typescript grammars
- Tham khảo (KHÔNG copy): repo cũ `Source-Code-Security-Scanner/src/blast_radius/dependency.py` (import graph), `src/change_detector/function_mapper.py` (line→function)

## Overview

- **Priority**: P0 — trái tim của subsystem 2 | **Status**: pending
- Graph model + builder + plugin interface + extractor JS/TS đầu tiên. Output: `radar build .` → `.radar/graph.json`.

## Key Insights

- Bài toán well-bounded: chỉ trích xuất **defs + call sites + imports + routes**, KHÔNG taint, KHÔNG type-check.
- Resolve call 2-pass: pass 1 thu thập toàn bộ defs → index theo tên + file; pass 2 resolve call site: ưu tiên (a) cùng file, (b) qua import map, (c) name-only toàn cục (đánh dấu `confidence: name-only`, nếu trùng tên nhiều nơi → nối tất cả, label ambiguous).
- Method call `obj.method()` → resolve theo tên method (xấp xỉ chấp nhận được). Dynamic `obj[x]()` → bỏ qua, đã có file-level import edge làm fallback.
- Express route: `app.get('/path', handler)` / `router.post(...)` — handler có thể inline arrow hoặc identifier → route node nối tới function node tương ứng.

## Requirements

- FR1: `radar build <dir>` index JS/TS (gồm .js .jsx .ts .tsx, bỏ node_modules) → graph.json
- FR2: Node types: `function` (gồm method/arrow gán biến), `route`, `file`. Edge types: `calls`, `imports`, `handles` (route→function)
- FR3: Plugin interface — thêm ngôn ngữ không sửa core
- NFR: 1000 file < 30s; graph.json deterministic (sort) để diff được

## Architecture

```
src/radar/graph/
├── model.py        # dataclasses: Node(id,kind,name,file,start_line,end_line,language), Edge(src,dst,kind,confidence)
├── builder.py      # walk files → dispatch extractor theo extension → 2-pass resolve → networkx DiGraph → save/load JSON
└── languages/
    ├── base.py     # LanguageExtractor(ABC): extensions(), extract(source,path) -> FileFacts(defs, calls, imports, routes)
    └── javascript.py

Node id = "<relpath>::<qualified_name>"  (vd "src/auth/validate.js::validateUser")
File node id = "<relpath>"
```

## Related Code Files (repo `security-radar/`)

Create:
- `src/radar/graph/model.py` (<150 dòng)
- `src/radar/graph/builder.py` (<200 dòng)
- `src/radar/graph/languages/base.py` (~60 dòng)
- `src/radar/graph/languages/javascript.py` (<200 dòng; TS dùng chung logic, grammar khác)
- `src/radar/cli.py` — lệnh `build` thật
- `tests/fixtures/js-app/` — mini Express app 4-5 file (routes, services, utils, có vòng import)
- `tests/test_js_extractor.py`, `tests/test_builder.py`

## Implementation Steps

1. `model.py`: dataclasses + FileFacts (defs/calls/imports/routes thô từ 1 file) + JSON (de)serialize.
2. `base.py`: ABC + registry (`EXTRACTORS: dict[ext, LanguageExtractor]`).
3. `javascript.py` — tree-sitter queries:
   - defs: `function_declaration`, `method_definition`, `variable_declarator` với arrow/function expression, `export default function`
   - calls: `call_expression` → callee name (identifier hoặc member_expression property cuối)
   - imports: `import_statement` (named/default/namespace), `require()` → map local name → module path
   - routes: call_expression dạng `(app|router).(get|post|put|delete|patch|use)('/path', handler)`
4. `builder.py`: os.walk (skip node_modules, .git, dist, build) → extract per file → pass 2 resolve (cùng file > import map > global name index) → nx.DiGraph → `.radar/graph.json`.
5. CLI `radar build [path] [--out]` + rich summary (N functions, M edges, K routes, X unresolved).
6. Tests trên fixture: đếm đúng nodes/edges, resolve qua import đúng, route nối handler đúng, vòng import không crash.

## Todo List

- [ ] model.py + serialize round-trip test
- [ ] base.py plugin interface + registry
- [ ] javascript.py: defs/calls/imports/routes (JS + TS grammar)
- [ ] builder.py 2-pass resolve + skip dirs
- [ ] CLI build + rich summary
- [ ] Fixture js-app + tests pass

## Success Criteria

- `radar build tests/fixtures/js-app` ra graph đúng (snapshot test); thêm extractor mới chỉ cần đăng ký vào registry.

## Risk Assessment

- TS grammar khác JS (typescript + tsx là 2 grammar) → load 3 grammar, share extraction logic qua node-type chung.
- Arrow callback inline trong route không có tên → đặt tên synthetic `<route POST /login>`.
- Trùng tên function nhiều file → name-only edges nổ to → cap + confidence label, option `--no-name-only`.

## Security Considerations

- Tool đọc repo untrusted: không exec code được scan, chỉ parse. Path traversal khi ghi output: resolve + validate out path. (Bài học từ commit `2b1e498` repo cũ.)

## Next Steps

→ Phase 04 dùng graph này cho impact query.
