# security-radar

> Một tool. Cài 1 lần, quét **lỗ hổng bảo mật** và truy **blast radius** trên repo bất kỳ — **không để lại dấu vết** lên repo đó.

[![Security Scan](https://github.com/CosmicAlpaca/Source-Code-Security-Scanner_v2/actions/workflows/security-scan.yml/badge.svg)](https://github.com/CosmicAlpaca/Source-Code-Security-Scanner_v2/actions/workflows/security-scan.yml)

`radar` là CLI local với 2 năng lực, dùng độc lập:

1. **`radar scan`** — quét lỗ hổng bằng [Semgrep](https://semgrep.dev) (preset chuẩn ngành + 50 custom rules). Tự chạy native hoặc Docker.
2. **`radar impact`** — dựng function-level call graph trả lời *"sửa hàm này thì function / API / feature nào bị ảnh hưởng?"*

Và một **trục xuyên suốt**: mọi finding được **xếp hạng theo Risk Score** (`severity × reachability × OWASP-class`) — bug nguy hiểm nhất luôn lên đầu. Score tính được **không cần API key**; có key thì AI verdict nâng cấp thứ hạng (xem [Phần 3.5](#phần-35--radar-report-dashboard-hợp-nhất--risk-ranking)).

> 🔒 **Zero-footprint** — cả hai lệnh chạy trên repo bất kỳ mà **không tạo file nào** trong repo đó: scan đọc kết quả Semgrep qua stdout; impact lưu graph cache *ngoài* repo. Bạn cũng có thể [gắn vào GitHub Actions](#phần-4--gắn-vào-ci-github-actions) để tự động hoá theo PR.

**Ngôn ngữ:** scan = 30+ ngôn ngữ (Semgrep tự nhận diện) · impact graph = **JS/TS** (`.js .jsx .ts .tsx .mjs .cjs`) + **Python** (`.py`) + **Go** (`.go`) + **Java** (`.java`) + **PHP** (`.php`), route detect cho Express / Flask / FastAPI / net·http / gorilla·mux / Spring MVC / JAX-RS / Laravel.

---

## Phần 1 — Cài đặt

```bash
git clone https://github.com/CosmicAlpaca/Source-Code-Security-Scanner_v2.git
cd Source-Code-Security-Scanner_v2
pip install .              # Python ≥ 3.11
radar --help
```

> 💡 **Windows**: nếu `pip`/`radar` bị chặn bởi policy, dùng `python -m pip install .` và `python -m radar.cli` thay thế.

`radar scan` cần một Semgrep runtime — tool tự tìm theo thứ tự:
- **native** `semgrep` trên PATH (Linux/Mac: `pipx install semgrep`), hoặc
- **Docker** (`semgrep/semgrep`) — fallback khi không có native (Windows thường dùng cách này, chỉ cần Docker Desktop bật).

Thiếu cả hai → `radar scan` báo lỗi rõ. `radar impact` không cần Semgrep.

---

## Phần 2 — `radar scan`: quét lỗ hổng

Quét ngay trên máy, không cần CI, **không ghi gì** vào repo được quét:

```bash
radar scan .                          # quét repo hiện tại (preset + 50 custom rules)
radar scan ../other-repo              # quét repo khác
radar scan --rules-only               # offline: chỉ custom rules, bỏ preset (không cần mạng)
radar scan --format json > out.json   # máy đọc
radar scan --format sarif > out.sarif # nạp vào tab Security / công cụ khác
radar scan --error --fail-on warning  # exit≠0 khi có finding ≥ WARNING (gate local/CI)
```

Output mặc định — bảng terminal gom theo severity:

```
4 finding(s) (4 error)
🔴 ERROR  app/services/db.js:8   js-sql-string-concat    SQL query built from string concatenation…
🔴 ERROR  app/routes/auth.js:15  js-hardcoded-jwt-secret Hardcoded JWT secret in source code…
```

- **Mặc định không block** (exit 0) — chỉ informational. `--error` mới làm exit≠0; `--fail-on error|warning|info` chọn ngưỡng.
- **`--rules-only`** chạy được offline (chỉ custom rules). Mặc định có thêm preset registry (`p/security-audit`, `p/secrets`, `p/owasp-top-ten`) — cần mạng lần đầu.

### 50 custom rules đi kèm (JS 11 · Python 10 · Go 8 · Java 10 · PHP 11)

Bảng dưới liệt kê JS/Python (bộ gốc); Go/Java/PHP có bộ OWASP tương đương trong `src/radar/rules/`.

| Rule | OWASP | Bắt gì |
|---|---|---|
| `js-sql-string-concat` | A03 | SQL build bằng concat / template literal |
| `js-hardcoded-jwt-secret` | A07 | `jwt.sign/verify` với secret literal |
| `js-child-process-user-input` | A03 | `req.*` chảy vào `exec()` (taint mode) |
| `js-express-xss` | A03 | `req.*` chảy vào `res.send()/write()` — XSS (taint mode) |
| `js-ssrf-user-input` | A10 | `req.*` chảy vào `fetch`/`axios`/`http.get` — SSRF (taint mode) |
| `js-path-traversal` | A01 | `req.*` chảy vào `fs.readFile`/`writeFile` (taint mode) |
| `js-eval-user-input` | A08 | `req.*` chảy vào `eval()`/`Function()` — Code Injection (taint mode) |
| `py-subprocess-shell-true` | A03 | `subprocess` + `shell=True` + chuỗi động |
| `py-flask-debug-true` | A05 | `app.run(debug=True)` |
| `py-ssrf-user-input` | A10 | `request.args` chảy vào `requests.get`/`urllib` — SSRF (taint mode) |
| `py-path-traversal` | A01 | `request.args` chảy vào `open`/`os.path.join`/`Path` (taint mode) |
| `py-unsafe-deserialization` | A08 | `pickle.loads` (luôn flag) + `yaml.load` không dùng `SafeLoader` |
| `py-flask-hardcoded-secret` | A07 | `app.secret_key = "literal"` (pattern-not `os.environ`) |

Rules đóng gói trong package (`src/radar/rules/`) nên đi theo `pip install`. Mỗi rule có fixture test (`// ruleid:` / `ok:`); thêm rule mới = 1 cặp `.yaml` + fixture trong `src/radar/rules/`.

---

## Phần 3 — `radar impact`: blast radius

### Bước 1 — (Tùy chọn) Index codebase

```bash
radar build .
# ✓ graph saved to .radar/graph.json
#   172 functions · 6 routes · 33 files · 190 edges (84 approximate, ...)
```

`radar build` ghi graph vào `<repo>/.radar/graph.json` (index repo này một cách tường minh). **Không bắt buộc** — `radar impact` tự build vào cache ngoài repo nếu chưa có. Graph lưu git HEAD hash → tự rebuild khi code đổi.

### Bước 2 — Hỏi "thay đổi này lan đến đâu?"

```bash
radar impact --staged                 # đang sửa dở (đã git add), chưa commit
radar impact --diff HEAD~1            # ảnh hưởng của commit cuối
radar impact --diff main...HEAD       # toàn bộ branch so với main
radar impact --diff HEAD~1 --findings # đánh dấu hàm có lỗ hổng trong blast radius (cần Semgrep)
radar impact --function validateUser  # giả định: nếu sửa hàm này thì sao?
```

Output dạng cây:

```
Changed: validateUser  demo/app/utils/validate.js:2  feature: Authentication
├── login     demo/app/routes/auth.js:9   ← POST /login     [depth 1]
└── register  demo/app/routes/auth.js:19  ← POST /register  [depth 1, ⚠ approx]
Summary: 2 functions, 2 APIs, 1 features affected (1 approximate)
```

Đọc kết quả:
- **depth** — số bước lan từ hàm bị sửa (caller trực tiếp = depth 1).
- **← METHOD /path** — hàm này là handler của API endpoint đó.
- **⚠ approx** — edge resolve bằng khớp tên toàn cục (name-only), không chắc 100%. `--no-name-only` chỉ giữ kết quả chắc chắn.
- **feature** — gom theo nghiệp vụ (xem Bước 4).

### Bước 3 — Xuất report

```bash
radar impact --diff HEAD~1 --format json     # máy đọc (CI dùng cái này)
radar impact --diff HEAD~1 --format mermaid  # dán vào markdown/GitHub
radar impact --diff HEAD~1 --format html > impact.html  # report tĩnh, mở bằng browser
```

Tùy chọn khác: `--depth N` (cắt độ sâu), `--path <dir>` (chạy trên repo ngoài), `--graph <file>` (dùng graph có sẵn, bỏ qua build).

> **Zero-footprint**: `radar impact --path <repo-khác>` auto-build graph vào thư mục cache (`$RADAR_CACHE` → `%LOCALAPPDATA%/radar` → `~/.cache/radar`), **không** tạo `.radar/` trong repo đó.

### Bước 4 — (Tùy chọn) Gắn nhãn feature

Tạo `radar.config.yml` ở root repo để output có tầng "feature bị ảnh hưởng":

```yaml
features:
  Authentication: ["src/auth/**", "src/middleware/session*"]
  Payment: ["src/billing/**"]
exclude: ["**/migrations/**"]   # bỏ qua khi index
```

Không có config → mọi node là `(unmapped)`, tool vẫn chạy bình thường.

---

## Phần 3.5 — `radar report`: dashboard hợp nhất + Risk Ranking

Không muốn chạy `scan` / `impact` riêng lẻ? `radar report` gói **findings + blast radius + history trend** vào **1 file HTML duy nhất** — và **xếp hạng findings theo Risk Score**:

```bash
radar report .                 # dashboard offline: findings xếp theo risk + impact graph + history
radar report . --triage        # THÊM cột reachability + AI verdict, AI nâng cấp thứ hạng (opt-in)
radar report . --out dash.html # chọn đường dẫn output
```

- **Risk Ranking (luôn bật, không cần key):** mỗi finding có **cột Risk** = điểm `0–100` + band; bảng **sort theo risk giảm dần**; finding `noise` / `false_positive` được **gấp vào fold** (không xoá — triage ≠ censor). Cần graph để tính reachability nên `report` tự dựng call graph (đã có sẵn cho blast radius).
- **`--triage`** enrich mỗi finding bằng reachability + verdict AI (exploitability + confidence, reasoning + exploit-path qua tooltip) → AI **ghi đè** thứ hạng: `exploitable` lên `critical`, `false_positive` rớt xuống fold. Cần `OPENAI_API_KEY` (env hoặc `.env` ở repo root); thiếu key → tự động render bản offline (vẫn có Risk Ranking), không lỗi. `--floor` (mặc định `warning`) giới hạn severity được triage; `--force` bỏ cache verdict.

### Risk Score — công thức (giải thích được, không black-box)

```
base = severity_w × reach_mult × class_w           (không cần key)
  severity_w : ERROR 60 · WARNING 35 · INFO 15
  reach_mult : reachable → 1.0 + 0.1·min(routes,5) ;  unknown → 0.6
  class_w    : A03/A08 (injection/deser) 1.3 · A01/A10 1.1 · còn lại 1.0
ai (nếu có) : × {exploitable 1.0→critical · likely 0.85 · unlikely 0.5 · false_positive 0.1→noise}
band        : ≥80 critical · ≥60 high · ≥35 medium · ≥15 low · còn lại noise
```

Mỗi điểm hiện **factors** (vd `ERROR · reachable(3 routes) · A03(×1.3) · ai:exploitable`) qua tooltip cột Risk.

### Gate CI theo ranking (`radar triage`)

`radar triage` cũng xếp hạng + cho ranking "có răng" để chặn PR/CI:

```bash
radar triage . --top 5                  # chỉ in 5 finding rủi ro nhất
radar triage . --min-risk 80            # exit≠0 nếu có finding risk ≥ 80   (chạy ĐƯỢC offline)
radar triage . --fail-on exploitable    # exit≠0 nếu AI verdict = exploitable (cần OPENAI_API_KEY)
radar triage . --format json            # mỗi finding kèm object risk:{value,band,factors}
```

- **`--min-risk N`** dùng base score → **không cần key**, hợp cho CI offline.
- **`--fail-on exploitable|likely`** đọc verdict AI → **cần key**. Khi vi phạm, in finding kích hoạt gate trước khi exit.

---

## Phần 3.6 — `radar graph`: bản đồ phụ thuộc tương tác

Xuất call graph thành **1 file HTML self-contained** (D3 nhúng sẵn — mở trực tiếp bằng browser, **chạy offline, không cần server**):

```bash
radar graph .                      # mặc định: gom theo FILE — repo lớn vẫn mở mượt
radar graph . --level function     # đồ thị HÀM đầy đủ (chi tiết, nặng hơn)
radar graph . --focus security     # chỉ subgraph reachable từ route = mặt phẳng tấn công
radar graph . --max-nodes 800      # giới hạn node (giữ node bậc cao nhất; 0 = không giới hạn)
radar graph . --out graph.html     # chọn đường dẫn (mặc định <repo>/radar-graph.html)
radar graph . --graph .radar/graph.json   # dùng graph có sẵn, bỏ qua build
```

- **Mặc định mức file** để repo lớn (chục nghìn hàm) không làm đơ tab: hàm được **gom theo file** (vài chục–vài trăm node), layout được **tính sẵn rồi vẽ tĩnh** (không animate mỗi frame). `--level function` cho đồ thị hàm đầy đủ khi cần xem chi tiết.
- **`--focus security`** chỉ giữ phần đồ thị **đi tới được từ route** — đúng những gì input của attacker chạm tới. Repo không có route → cảnh báo và hiện full.
- **`--max-nodes N`** (mặc định 1500) chặn trần an toàn: vượt thì giữ node bậc cao nhất và **in rõ số node bị bỏ** (không cắt âm thầm).
- Mở rồi: **zoom / pan / kéo node / click** (highlight hàng xóm) / **search** / **legend** theo file.

> Các cờ này chỉ là **bộ lọc lúc hiển thị**, áp trên một bản sao ngay trước khi vẽ — **không** ảnh hưởng `impact` / `report` / `triage` hay cache `graph.json` (chúng luôn dùng graph hàm đầy đủ).

---

## Phần 3.7 — `radar history` & `radar watch`

```bash
radar history                      # bảng lịch sử scan + trend (↑/↓ so với lần trước)
radar history --path ../repo --limit 50
radar history --format html > history.html
radar watch .                      # live linter: scan file khi save, hiện NEW/FIXED tức thì
radar watch . --ext .rb --ext .php # theo dõi thêm phần mở rộng
```

- **`history`** đọc lại log các lần `radar scan` trước → bảng số ERROR/WARN/Total theo thời gian + dòng trend. Chưa scan lần nào → nhắc chạy `radar scan` trước.
- **`watch`** chạy nền, mỗi lần lưu file thì quét lại và chỉ in finding **mới xuất hiện / vừa được fix** — vòng lặp sửa lỗi nhanh ngay khi code.

---

## Phần 3.8 — `radar serve`: live dashboard trên localhost

Không muốn chạy lại lệnh mỗi lần sửa code? `radar serve` mở **1 tab trình duyệt tự cập nhật** — lưu file thì dashboard cập nhật ngay, không reload trang, không sinh file HTML mới.

```bash
pip install ".[watch]"        # cần watchdog để live-update; không có → static mode
radar serve .                 # mở dashboard tại 127.0.0.1:7070
radar serve . --port 8080     # đổi port
radar serve . --open          # tự mở tab trình duyệt
radar serve . --rules-only    # offline: chỉ custom rules (không cần mạng)
radar serve . --ext .rb --ext .php  # theo dõi thêm extension
```

Dashboard gồm 5 tab: **Overview** (stat cards + OWASP/severity donut charts), **Findings**, **Blast Radius**, **History**, **Graph** (D3 force-directed).

### Impact-first: tab Blast Radius (mặc định)

`radar serve` mở thẳng tab **Blast Radius** để tập trung câu hỏi *"thay đổi của tôi ảnh hưởng tới đâu"*. Chọn nguồn trace ở thanh **Trace impact of:**

| Mode | Trace gì | Cập nhật |
|---|---|---|
| **Changes (vs HEAD)** *(mặc định)* | Mọi thay đổi uncommitted (`git diff HEAD`) → function/API/feature bị ảnh hưởng | mỗi lần save (nhanh — graph cache + BFS, **không** chạy semgrep) |
| **This file** | File vừa save (kể cả file mới chưa commit) | mỗi lần save |
| **Findings** | Blast radius của top findings (hành vi cũ) | debounce |
| ô **trace a function…** | 1 hàm theo tên | khi nhấn Enter |

Node trong blast radius mang lỗ hổng được **đánh dấu overlay** (dùng kết quả scan sẵn có, không re-scan) → trả lời *"thay đổi của tôi có chạm code dính lỗ hổng không"*.

### Mô hình cập nhật

| Loại dữ liệu | Khi nào cập nhật | Lý do |
|---|---|---|
| Findings + History | **Tức thì** sau mỗi lần save | Incremental scan 1 file, nhanh |
| **Blast Radius** (mode Changes/This file) | **Tức thì** sau mỗi lần save | Graph cache + BFS trace, không chạy semgrep |
| Graph (full) | **~2 giây** sau save (debounce) | Cần rebuild full graph, dùng cache |
| AI Triage | **On-demand** (nút "Run AI triage") | Tốn tiền + cần `OPENAI_API_KEY`; không bao giờ tự chạy; cảnh báo nếu thiếu key |

- **Không cần dependency mới** cho HTTP/SSE — dùng stdlib `http.server.ThreadingHTTPServer`. D3 + Chart.js vendored vào package (offline-capable).
- **Localhost-only**: server chỉ bind `127.0.0.1`, không expose ra mạng.
- **Thiếu `[watch]` extra?** → static mode: scan 1 lần, hiển thị dashboard tĩnh (không live-update).

---

## Phần 4 — Gắn vào CI (GitHub Action)

Radar được đóng gói thành **GitHub Action** — bạn **không cần copy rules/script** vào repo, chỉ thêm **1 file workflow ~12 dòng**:

1. Tạo `.github/workflows/security.yml` trong repo (hoặc fork) của bạn — copy từ [examples/security.yml](examples/security.yml):

   ```yaml
   name: Security
   on: [pull_request, push]
   permissions:
     contents: read
     security-events: write   # SARIF lên tab Security
     pull-requests: write     # comment PR
   jobs:
     radar:
       runs-on: ubuntu-latest
       steps:
         - uses: actions/checkout@v4
           with: { fetch-depth: 0 }   # cần cho impact diff
         - uses: CosmicAlpaca/Source-Code-Security-Scanner_v2@v1
           with:
             github-token: ${{ secrets.GITHUB_TOKEN }}
   ```

2. **Repo phải public** (hoặc có GHAS) để tab Security hiển thị SARIF. Chỉ cần `GITHUB_TOKEN` mặc định — **không cần tài khoản Semgrep**.
3. Push / mở PR → action chạy. Xong. Rules đi theo action (đóng gói trong package), không phải bê `src/radar/rules/`.

Action làm trong **1 job**:

| Bước | Khi nào | Làm gì |
|---|---|---|
| scan (SARIF) | mọi event | `radar scan --format sarif` → SARIF lên tab Security |
| scan (JSON) | mọi event | findings cho comment + gate |
| impact | chỉ PR | `radar impact --diff base...HEAD` → artifact `radar-report` |
| PR comment | chỉ PR (fork khác bị bỏ qua) | 1 comment gộp findings + blast radius, tự update không spam |
| gate | khi đặt `fail-on` | exit≠0 nếu finding ≥ ngưỡng (mặc định informational) |

**Inputs** (đều có default, xem `examples/security.yml`):

| Input | Default | Ý nghĩa |
|---|---|---|
| `path` | `.` | thư mục quét |
| `github-token` | — | token cho PR comment (`secrets.GITHUB_TOKEN`) |
| `fail-on` | `''` | `error\|warning\|info` để chặn; rỗng = không block |
| `rules-only` | `false` | offline, chỉ rules bundled |
| `comment` / `sarif` | `true` | bật/tắt PR comment / upload SARIF |

> ⚠️ `fetch-depth: 0` ở bước checkout là **bắt buộc** để impact diff được với nhánh base. Findings **không block merge** trừ khi bạn đặt `fail-on`.

---

## Demo nhanh

`demo/app/` là Express app **cố ý chứa lỗ hổng** (SQLi, command injection, hardcoded secret) — ⚠️ không deploy.

```bash
radar scan demo --rules-only           # thấy 4 lỗ hổng ngay
radar impact --function validateUser   # thử blast radius không cần sửa gì
```

Kịch bản 5 phút (sửa 1 hàm → mở PR → xem findings + blast radius): [demo/run-demo.md](demo/run-demo.md).

## Mở rộng ngôn ngữ (impact graph)

Impact graph hỗ trợ **5 ngôn ngữ** out-of-the-box:

| Ngôn ngữ | Extension | Route detect |
|---|---|---|
| JavaScript / TypeScript | `.js .jsx .ts .tsx .mjs .cjs` | Express (`app.get/post/…`) |
| Python | `.py` | Flask, FastAPI |
| Go | `.go` | `net/http` (`HandleFunc`), gorilla/mux (`.Get/.Post/…`) |
| Java | `.java` | Spring MVC (`@GetMapping`, `@RequestMapping`), JAX-RS (`@GET` + `@Path`) |
| PHP | `.php` | Laravel (`Route::get/post/…`, closure + `[Ctrl::class,'m']` + `"Ctrl@method"`), plain `$_GET/$_POST` entrypoint |

Go / Java / PHP parser được cài tự động khi `pip install .` trên Python ≥ 3.11. Nếu bạn đang dùng Python cũ hơn hoặc muốn cài thủ công:
```bash
pip install tree-sitter-go tree-sitter-java tree-sitter-php
# hoặc qua extras:
pip install "security-radar[go,java,php]"
```

Các plugin **graceful degrade** — nếu parser chưa có thì tự bỏ qua, không crash, chỉ không parse file `.go`/`.java`/`.php`.

Thêm ngôn ngữ mới = thêm **1 file plugin** trong `src/radar/graph/languages/` (subclass `LanguageExtractor`), registry tự phát hiện — không sửa core. Xem `python.py` làm mẫu.

## Stack công nghệ

| Thành phần | Thư viện / Tool | Ghi chú |
|---|---|---|
| Static analysis engine | [Semgrep](https://semgrep.dev) | Dùng taint mode để trace data flow source → sink |
| Custom OWASP rules | YAML (Semgrep DSL) | 50 rules tự viết (JS·Py·Go·Java·PHP), đóng gói trong package |
| AST parser | [tree-sitter](https://tree-sitter.github.io) + bindings JS/TS/Python/Go/Java | Parse codebase thành AST, tự viết extractor cho từng ngôn ngữ |
| Call graph | [NetworkX](https://networkx.org) `DiGraph` | Lưu function calls + imports; reverse BFS để tính blast radius |
| CLI | [Click](https://click.palletsprojects.com) | 10 lệnh: `scan / build / impact / report / triage / graph / history / watch / analyze / serve` |
| Terminal output | [Rich](https://rich.readthedocs.io) | Bảng màu, tree view |
| HTML report | [Jinja2](https://jinja.palletsprojects.com) + Mermaid.js | Template `.j2`, diagram render phía client |
| Testing | pytest + Semgrep `--test` | 334 unit tests (9 skipped); rule fixtures với `// ruleid:` / `ok:` |

> Phần **scan** dùng Semgrep làm engine, mình viết rules. Phần **call graph** tự build từ đầu bằng tree-sitter (parse AST) và NetworkX (lưu graph + BFS).

## Validation thực tế

Đã chạy `radar scan --rules-only` trên [OWASP/NodeGoat](https://github.com/OWASP/NodeGoat) — ứng dụng Node.js cố ý chứa lỗ hổng:

| Kết quả | Chi tiết |
|---|---|
| **8 findings** (5 ERROR · 3 WARNING) | eval injection A08, SSRF A10, XSS A03, NoSQL injection, open redirect A01, plaintext password A07, session fixation A07, ReDoS A05 |
| **Coverage** | 5/8 lỗ hổng intentional của NodeGoat bị bắt bởi custom rules |
| **Impact graph** | Trace đúng `validateLogin → handleLoginRequest`, `searchCriteria → displayAllocations` |
| **True negatives** | `js-sql-string-concat` không false-positive trên MongoDB |

Gap còn lại (NoSQL injection, open redirect, ReDoS) nằm trong [roadmap](docs/development-roadmap.md).

## Giới hạn (by design)

- Call graph là **xấp xỉ**: same-file → import map → khớp tên toàn cục (nhãn `⚠ approx`). Dynamic call (`obj[x]()`) bỏ qua — fallback edge import file-level.
- Không type-aware, không dynamic dispatch.

## Development

```bash
pip install -e ".[dev]"
pytest                     # 334 tests (9 skipped)
```

## Tài liệu

[PRD](docs/security-radar-prd.md) · [Kiến trúc](docs/system-architecture.md) · [Changelog](docs/project-changelog.md) · [Roadmap](docs/development-roadmap.md)
