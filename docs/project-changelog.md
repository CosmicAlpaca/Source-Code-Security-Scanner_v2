# Changelog — security-radar

Định dạng theo [Keep a Changelog](https://keepachangelog.com/). Yêu cầu sản phẩm xem [PRD](./security-radar-prd.md), kiến trúc xem [System Architecture](./system-architecture.md).

## [Unreleased] — Unified Dashboard & Premium UI

Gộp tất cả các chức năng (quét bảo mật, phân tích luồng ảnh hưởng, xu hướng lịch sử, AI triage) vào một file HTML dashboard duy nhất với giao diện Premium Tabbed UI, biểu đồ Chart.js và tính năng tìm kiếm.

### Added

- **`radar report` Unified Dashboard** — Thay thế xuất nhiều file rời rạc. Cung cấp một file HTML `*_unified_dashboard.html` duy nhất chứa Tabbed UI: Overview, Findings, Blast Radius, và History.
- **Premium Design** — Áp dụng Glassmorphism, theme tối tinh tế, các card hiển thị số liệu thống kê rủi ro (CRITICAL/HIGH/MEDIUM/LOW).
- **Interactive Charts (Chart.js)** — Doughnut chart phân bổ theo Severity và OWASP Category, Line chart theo dõi lịch sử lỗi.
- **Search & Filter Toolbar** — Nút bấm tương tác trên HTML giúp lọc nhanh theo mức độ nghiêm trọng và tìm kiếm lỗ hổng theo nội dung (text search).
- **Animated Counters** — Hiệu ứng tăng dần trên các panel đếm số liệu của bảng điều khiển.

### Changed

- **`scripts/analyze-github.py`** — Cập nhật logic để sinh ra 1 file unified dashboard duy nhất thay vì sinh ra 3 file rác như trước. Hỗ trợ hiển thị đúng đường dẫn file và tự động bật `--triage` chỉ khi có biến môi trường `OPENAI_API_KEY`.
- **`src/radar/cli.py`** — Lệnh `radar report` thêm option `--diff` để hỗ trợ tính blast radius thông qua branch diff, kết hợp thẳng vào unified pipeline. Hỗ trợ fix lỗi Encoding cho Windows (tiếng Nhật `cp932`).

## [Unreleased] — AI Risk Ranking

Biến AI triage (trước đây là 1 cột thụ động, ẩn sau API key) thành **trục tổ chức output**: một **Risk Score 0–100 luôn tính được** (deterministic, không cần key) sắp xếp lại findings; AI verdict là lớp **nâng cấp** thứ hạng, không phải cột rời.

### Added

- **`triage/risk.py`** — `risk_score(finding, reach, verdict)` = `severity × reachability × OWASP-class`, cap 0–100, band `critical/high/medium/low/noise` + `factors` minh bạch. Thuần stdlib, không cần network/key.
- **`radar report` Risk Ranking** — cột **Risk** + sort theo risk giảm dần; finding `noise`/`false_positive` gấp vào `<details>` (không xoá). Chạy được **offline** nhờ reachability từ call graph đã dựng sẵn.
- **`radar triage` gate** — `--top N` (chỉ N rủi ro nhất), `--min-risk N` (exit≠0 khi risk ≥ N, **không cần key**), `--fail-on exploitable|likely` (exit≠0 theo verdict AI, cần key). JSON thêm object `risk:{value,band,factors}` (additive).
- **Verdict enrichment** — prompt nhận thêm OWASP/CWE class; verdict thêm field `exploit_path` (1 câu mô tả đường đi). Cache version `v2` (vô hiệu entry cũ thiếu field).

### Changed

- **`scan/findings.py`** — `Finding` thêm `metadata` (giữ `extra.metadata` của Semgrep); `OWASP_MAP`/`owasp_tag` chuyển từ `scan/report.py` về đây để dùng chung (DRY) cho cả report lẫn risk scoring.

### Tests

- +24 test (`test_risk.py`, `test_triage_ranking.py`, mở rộng dashboard/prompt). Toàn bộ **217 pass**.

## [0.2.1] — 2026-06-10

Verify nửa CI trên GitHub thật (đóng [PRD §8](./security-radar-prd.md) DoD) + dọn nợ hygiene và sửa các finding tự-quét.

### Added

- **Rule `js-express-xss`** (taint mode) — `req.query/body/params` → `res.send()/write()`, XSS OWASP A03. Kèm fixture; nâng bộ custom rules **5 → 6**.

### Fixed

- **`fix(security)`** — `analyze-github.py` validate `url`/`branch`/`function` trước khi vào subprocess (chặn argument-injection vào `git clone/checkout`); `cache.py` đổi `sha1` → `sha256` cho cache key (clear semgrep `insecure-hash-algorithm`).
- **`fix(ci)`** — `security-scan.yml` đưa `github.base_ref` qua biến env thay vì interpolate thẳng trong `run:` (clear `run-shell-injection`).
- **`fix(analyze-github)`** — không ghi file impact rỗng (HTML/Mermaid) khi blast radius trống — bỏ artifact 0-byte.

### Changed

- **`chore`** — ngừng track `analysis_results/` (artifact sinh ra); `.gitignore` thêm `analysis_results/` + `.playwright-mcp/`.
- **`docs(demo)`** — sửa cú pháp `analyze-github.py --url …`; cross-link `run-demo.md` (CI/app mẫu) ↔ `run-github-demo.md` (repo ngoài).

### Verified (GitHub thật, repo public)

- Workflow xanh 9/9 run (gồm `rule-tests` với rule mới). PR comment bot bảng findings + section impact render (PR #1). SARIF → `github-advanced-security[bot]` review comments. Blast radius engine đúng ví dụ [PRD §4 F2.6](./security-radar-prd.md) (`validateUser → login/register → Authentication`) qua `radar impact`, zero-footprint.

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
