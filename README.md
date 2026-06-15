# security-radar

> Một tool. Cài 1 lần, quét **lỗ hổng bảo mật** và truy **blast radius** trên repo bất kỳ — **không để lại dấu vết** lên repo đó.

[![Security Scan](https://github.com/CosmicAlpaca/Source-Code-Security-Scanner_v2/actions/workflows/security-scan.yml/badge.svg)](https://github.com/CosmicAlpaca/Source-Code-Security-Scanner_v2/actions/workflows/security-scan.yml)

`radar` là CLI local với 2 năng lực, dùng độc lập:

1. **`radar scan`** — quét lỗ hổng bằng [Semgrep](https://semgrep.dev) (preset chuẩn ngành + 13 custom rules). Tự chạy native hoặc Docker.
2. **`radar impact`** — dựng function-level call graph trả lời *"sửa hàm này thì function / API / feature nào bị ảnh hưởng?"*

> 🔒 **Zero-footprint** — cả hai lệnh chạy trên repo bất kỳ mà **không tạo file nào** trong repo đó: scan đọc kết quả Semgrep qua stdout; impact lưu graph cache *ngoài* repo. Bạn cũng có thể [gắn vào GitHub Actions](#phần-4--gắn-vào-ci-github-actions) để tự động hoá theo PR.

**Ngôn ngữ:** scan = 30+ ngôn ngữ (Semgrep tự nhận diện) · impact graph = **JS/TS** (`.js .jsx .ts .tsx .mjs .cjs`) + **Python** (`.py`) + **Go** (`.go`) + **Java** (`.java`), route detect cho Express / Flask / FastAPI / net·http / gorilla·mux / Spring MVC / JAX-RS.

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
radar scan .                          # quét repo hiện tại (preset + 13 custom rules)
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

### 13 custom rules đi kèm

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

### `radar triage` — AI triage findings theo reachability (opt-in)

Mỗi finding Semgrep được AI đọc *cùng ngữ cảnh reachability từ impact graph* (route nào chạm tới đoạn code đó) → phân loại **khai thác được vs false-positive** và xếp ưu tiên. Đây là **lớp phụ**: không đổi output của `radar scan`, SARIF hay exit code; chỉ thêm cột verdict.

```bash
radar triage .                    # triage finding ≥ WARNING (mặc định)
radar triage . --all              # triage mọi finding kể cả INFO
radar triage . --dry-run          # IN CHÍNH XÁC payload sẽ gửi — không gọi API
radar triage . --format json      # máy đọc: mỗi finding thêm block "ai" + "reachability"
radar triage . --force            # bỏ qua cache verdict, hỏi lại model
```

```
Sev  Location            Rule    Reach           AI verdict          Why
🔴   session.js:5        xss     reachable ←1    exploitable 0.90    reachable từ POST /login, req.body tới res.send
🟡   utils.js:42         xss     unknown         unlikely 0.30       không thấy route nào tới hàm này
```

> 🔐 **Opt-in & privacy** — chỉ chạy khi bạn gõ `radar triage`. Mỗi finding gửi **snippet quanh dòng lỗi** (không gửi cả repo), đã **che secret** trước khi đi. `--dry-run` cho xem payload trước. Verdict cache *ngoài repo* nên chạy lại = cùng kết quả, **0 call thừa**.
>
> ⚠️ **Reachability là best-effort**: `reachable` chắc chắn có route untrusted tới; `unknown` **không** đồng nghĩa code chết (graph có thể miss dynamic dispatch) — AI được dặn không hạ severity chỉ vì `unknown`.
>
> **Cấu hình** (env hoặc `.env` ở gốc repo — xem `.env.example`): `OPENAI_API_KEY` (bắt buộc), `RADAR_AI_MODEL` (mặc định `gpt-4o-mini`, đổi `gpt-4o` cho độ chính xác cao hơn), `OPENAI_BASE_URL` (đổi sang Azure/proxy/Ollama OpenAI-compatible). `.env` đã được `.gitignore`.

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

## Phần 4 — Gắn vào CI (GitHub Actions)

Muốn tự động quét + comment theo PR (không bắt buộc — local đã đủ dùng):

1. **Copy 3 thứ** vào repo của bạn:
   - `.github/workflows/security-scan.yml`
   - `scripts/render-pr-comment.py` (cho job comment)
   - `src/radar/rules/` (custom rules — hoặc xóa `--config src/radar/rules/` trong workflow nếu không cần)
2. **Repo phải public** (hoặc có GHAS) để tab Security hiển thị SARIF. Chỉ cần `GITHUB_TOKEN` mặc định — **không cần tài khoản Semgrep**.
3. Push lên main → workflow chạy. Xong.

Workflow có 4 jobs:

| Job | Khi nào chạy | Làm gì |
|---|---|---|
| `semgrep` | PR, push main, cron daily, manual | Scan → SARIF lên tab Security + artifact `semgrep-report` |
| `rule-tests` | như trên | `semgrep --test src/radar/rules/` — kiểm custom rules |
| `impact` | chỉ PR | `radar build` + `radar impact --diff base...HEAD` → artifact `impact-report` |
| `pr-comment` | chỉ PR cùng repo (fork bị bỏ qua) | 1 comment gộp findings + blast radius, tự update không spam |

Findings **không block merge** — chỉ informational.

---

## Demo nhanh

`demo/app/` là Express app **cố ý chứa lỗ hổng** (SQLi, command injection, hardcoded secret) — ⚠️ không deploy.

```bash
radar scan demo --rules-only           # thấy 4 lỗ hổng ngay
radar impact --function validateUser   # thử blast radius không cần sửa gì
```

Kịch bản 5 phút (sửa 1 hàm → mở PR → xem findings + blast radius): [demo/run-demo.md](demo/run-demo.md).

## Mở rộng ngôn ngữ (impact graph)

Impact graph hỗ trợ **4 ngôn ngữ** out-of-the-box:

| Ngôn ngữ | Extension | Route detect |
|---|---|---|
| JavaScript / TypeScript | `.js .jsx .ts .tsx .mjs .cjs` | Express (`app.get/post/…`) |
| Python | `.py` | Flask, FastAPI |
| Go | `.go` | `net/http` (`HandleFunc`), gorilla/mux (`.Get/.Post/…`) |
| Java | `.java` | Spring MVC (`@GetMapping`, `@RequestMapping`), JAX-RS (`@GET` + `@Path`) |

Go và Java parser được cài tự động khi `pip install .` trên Python ≥ 3.11. Nếu bạn đang dùng Python cũ hơn hoặc muốn cài thủ công:
```bash
pip install tree-sitter-go tree-sitter-java
# hoặc qua extras:
pip install "security-radar[go,java]"
```

Cả hai plugin **graceful degrade** — nếu parser chưa có thì tự bỏ qua, không crash, chỉ không parse file `.go`/`.java`.

Thêm ngôn ngữ mới = thêm **1 file plugin** trong `src/radar/graph/languages/` (subclass `LanguageExtractor`), registry tự phát hiện — không sửa core. Xem `python.py` làm mẫu.

## Stack công nghệ

| Thành phần | Thư viện / Tool | Ghi chú |
|---|---|---|
| Static analysis engine | [Semgrep](https://semgrep.dev) | Dùng taint mode để trace data flow source → sink |
| Custom OWASP rules | YAML (Semgrep DSL) | 13 rules tự viết, đóng gói trong package |
| AST parser | [tree-sitter](https://tree-sitter.github.io) + bindings JS/TS/Python/Go/Java | Parse codebase thành AST, tự viết extractor cho từng ngôn ngữ |
| Call graph | [NetworkX](https://networkx.org) `DiGraph` | Lưu function calls + imports; reverse BFS để tính blast radius |
| CLI | [Click](https://click.palletsprojects.com) | Subcommands `radar scan / impact / build` |
| Terminal output | [Rich](https://rich.readthedocs.io) | Bảng màu, tree view |
| HTML report | [Jinja2](https://jinja.palletsprojects.com) + Mermaid.js | Template `.j2`, diagram render phía client |
| Testing | pytest + Semgrep `--test` | 103 unit tests; rule fixtures với `// ruleid:` / `ok:` |

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
pytest                     # 103 tests
```

## Tài liệu

[PRD](docs/security-radar-prd.md) · [Kiến trúc](docs/system-architecture.md) · [Changelog](docs/project-changelog.md) · [Roadmap](docs/development-roadmap.md)
