# Changelog — security-radar

Định dạng theo [Keep a Changelog](https://keepachangelog.com/). Yêu cầu sản phẩm xem [PRD](./security-radar-prd.md), kiến trúc xem [System Architecture](./system-architecture.md).

## [0.2.0] — 2026-06-08

Biến security-radar thành **tool local hoàn chỉnh**: scan + impact chạy trên repo bất kỳ sau `pip install`, **không để lại dấu vết** lên repo đích.

### Added

- **`radar scan`** — quét Semgrep cục bộ, không cần CI. Tự phát hiện runtime: `semgrep` native → fallback Docker (`semgrep/semgrep:latest`) → lỗi rõ nếu thiếu cả hai. Dùng cùng preset (`p/security-audit` + `p/secrets` + `p/owasp-top-ten`) + bundled rules. Options: `--rules-only` (offline, bỏ preset), `--config` (thêm config), `--format terminal|json|sarif`, `--error`/`--fail-on` (gate exit code). Zero-footprint: Semgrep emit JSON ra stdout, parse trong RAM; Docker mount target read-only, `-w /src` cho path repo-relative.
- **Module `scan/`** — `runner.py` (detect_runtime + run_semgrep), `findings.py` (normalize + summary + threshold), `report.py` (rich table + JSON).
- **`radar impact --graph <file>`** — dùng graph có sẵn, bỏ qua auto-build.

### Changed

- **Custom rules đóng gói trong wheel**: `rules/` → `src/radar/rules/` (đi theo `pip install`, truy cập qua package path). CI workflow + `radar.config.yml` trỏ path mới.
- **Impact zero-footprint**: auto-build ghi `graph.json` vào **cache ngoài repo** (`cache.py`: `$RADAR_CACHE` → `%LOCALAPPDATA%` → `~/.cache/radar`) thay vì `<repo>/.radar`. Thứ tự load: `--graph` → `<repo>/.radar` (nếu fresh, BC) → external cache → build vào cache. `radar build` vẫn ghi `.radar/` như cũ.

### Fixed

- **Windows subprocess decode**: `run_semgrep` ép `encoding="utf-8", errors="replace"` — trước đó `text=True` decode stderr Semgrep bằng cp1252 → `UnicodeDecodeError` crash reader thread.

### Tests

- 103 pytest (76 → 103, +27): `test_scan_runner` (argv native/docker, detect, parse), `test_scan_findings`, `test_scan_cli` (CliRunner mock), `test_cache` (zero-footprint integration).

## [0.1.0] — 2026-06-06

Bản hiện thực đầu tiên — hoàn tất cả 6 phase (M1–M6) cục bộ. Verify end-to-end trên GitHub thật còn pending (xem [roadmap](./development-roadmap.md)).

### Added

- **CI Security Scan** — `.github/workflows/security-scan.yml`, 4 jobs:
  - `semgrep`: scan `p/security-audit` + `p/secrets` + `p/owasp-top-ten` + `rules/`, xuất SARIF (→ tab Security) + JSON artifact, `--metrics off`, `continue-on-error`.
  - `rule-tests`: `semgrep --test rules/` trên fixtures.
  - `impact`: `radar build` + `radar impact --diff base...HEAD` → impact.json/html artifact (chỉ PR).
  - `pr-comment`: gộp findings + blast radius, upsert comment qua marker `<!-- security-radar -->`, skip PR từ fork.
- **5 custom Semgrep rules** kèm fixture `// ruleid:` / `ok:`: `js-sql-string-concat`, `js-hardcoded-jwt-secret`, `js-child-process-user-input` (taint mode), `py-subprocess-shell-true`, `py-flask-debug-true`.
- **Package `radar`** (`pip install .`): CLI `build` + `impact`; graph core (model/builder/resolver, networkx); plugin per-language (JS/TS + Python tree-sitter, auto-discovery registry); impact (diff_mapper, reverse-BFS tracer với depth + confidence); report (terminal rich + exporters JSON/Mermaid/HTML + Jinja2 template).
- **Feature map** `radar.config.yml` (glob → feature, exclude globs).
- **Demo** — Express app cố ý có lỗ hổng (`demo/app/`) + kịch bản `demo/run-demo.md`.
- **Tests** — 76 pytest tests phủ mọi module; fixtures js-app + py-app.
- `graph.json` deterministic (sorted), node id `"<relpath>::<name>"` posix-normalized, kèm git HEAD hash → auto-rebuild khi stale.

### Security (từ code review)

- **Markdown injection**: escape backtick (`` ` `` → `'`) trong cell PR comment để chặn code-span breakout (cùng `&`, `<`, `>`, `|`, newline).
- **APIs column scope**: cột APIs trong PR comment chỉ liệt kê route reachable từ *từng* changed function (direct routes + affected routes trace ngược về nó), không gộp toàn cục.
- **`core.quotepath=false`**: git diff không octal-escape path non-ASCII → map node đúng trên repo có tên file unicode.
- **Mermaid label sanitize**: whitelist ký tự cho label (escape `<`/`>` → `‹`/`›`) để tên untrusted không phá cú pháp Mermaid.
