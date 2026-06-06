# security-radar

> Mỗi PR tự động biết: **code có lỗ hổng gì**, và **thay đổi này lan đến đâu**.

[![Security Scan](../../actions/workflows/security-scan.yml/badge.svg)](../../actions/workflows/security-scan.yml)

**security-radar** gồm 2 năng lực trong cùng một pipeline:

1. **Security Scan** — quét lỗ hổng bằng [Semgrep](https://semgrep.dev) trong GitHub Actions (preset chuẩn ngành + 5 custom rules). Kết quả hiện ở tab **Security**, comment PR, artifact.
2. **Impact Tracing** — CLI `radar` dựng function-level call graph: *"sửa function này thì function/API/feature nào bị ảnh hưởng?"*

**Ngôn ngữ hỗ trợ:** Semgrep scan = 30+ ngôn ngữ (tự nhận diện) · Impact graph = **JS/TS** (`.js .jsx .ts .tsx .mjs .cjs`) + **Python** (`.py`), route detect cho Express / Flask / FastAPI.

---

## Phần 1 — Tutorial CLI `radar` (local)

### Bước 0 — Cài đặt

```bash
git clone https://github.com/CosmicAlpaca/Source-Code-Security-Scanner_v2.git
cd Source-Code-Security-Scanner_v2
pip install .              # Python ≥ 3.11
radar --help
```

> 💡 **Windows**: nếu `pip`/`radar` bị chặn bởi policy, dùng `python -m pip install .` và `python -m radar.cli` thay thế.

### Bước 1 — Index codebase

Chạy trong repo bất kỳ (JS/TS/Python):

```bash
radar build .
# ✓ graph saved to .radar/graph.json
#   172 functions · 6 routes · 33 files · 190 edges (84 approximate, ...)
```

Graph là file JSON deterministic, có lưu git HEAD hash — các lệnh sau **tự rebuild** khi code đổi, bạn không cần chạy lại `build`.

### Bước 2 — Hỏi "thay đổi này lan đến đâu?"

3 chế độ, dùng tùy tình huống:

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
- **depth** — số bước lan truyền từ hàm bị sửa (caller trực tiếp = depth 1).
- **← METHOD /path** — hàm này là handler của API endpoint đó.
- **⚠ approx** — edge resolve bằng khớp tên toàn cục (name-only), không chắc chắn 100%. Thêm `--no-name-only` nếu chỉ muốn kết quả chắc chắn.
- **feature** — gom theo nghiệp vụ (xem Bước 4).

### Bước 3 — Xuất report

```bash
radar impact --diff HEAD~1 --format json     # máy đọc (CI dùng cái này)
radar impact --diff HEAD~1 --format mermaid  # dán vào markdown/GitHub
radar impact --diff HEAD~1 --format html > impact.html  # report tĩnh, mở bằng browser
```

Tùy chọn khác: `--depth N` (cắt độ sâu), `--path <dir>` (chạy từ ngoài repo).

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

## Phần 2 — Tutorial gắn Security Scan vào repo của bạn (<10 phút)

1. **Copy 3 thứ** vào repo của bạn:
   - `.github/workflows/security-scan.yml`
   - `scripts/render-pr-comment.py` (cho job comment)
   - `rules/` (custom rules — hoặc xóa `--config rules/` trong workflow nếu không cần)
2. **Repo phải public** (hoặc có GHAS) để tab Security hiển thị SARIF. Chỉ cần `GITHUB_TOKEN` mặc định — **không cần tài khoản Semgrep**.
3. Push lên main → workflow chạy. Xong.

Workflow có 4 jobs:

| Job | Khi nào chạy | Làm gì |
|---|---|---|
| `semgrep` | PR, push main, cron daily, manual | Scan → SARIF lên tab Security + artifact `semgrep-report` |
| `rule-tests` | như trên | `semgrep --test rules/` — kiểm custom rules |
| `impact` | chỉ PR | `radar build` + `radar impact --diff base...HEAD` → artifact `impact-report` |
| `pr-comment` | chỉ PR cùng repo (fork bị bỏ qua) | 1 comment gộp findings + blast radius, tự update không spam |

Findings **không block merge** — chỉ informational.

### Test scan local (không cần CI)

Semgrep không chạy native Windows — dùng Docker:

```bash
# Scan giống hệt CI
docker run --rm -v "$PWD:/src" semgrep/semgrep:latest semgrep scan \
  --config p/security-audit --config p/secrets --config p/owasp-top-ten \
  --metrics off /src

# Test custom rules với fixtures
docker run --rm -v "$PWD:/src" semgrep/semgrep:latest semgrep --test --metrics off /src/rules/
```

### 5 custom rules đi kèm

| Rule | Bắt gì |
|---|---|
| `js-sql-string-concat` | SQL build bằng concat / template literal |
| `js-hardcoded-jwt-secret` | `jwt.sign/verify` với secret literal |
| `js-child-process-user-input` | `req.*` chảy vào `exec()` (taint mode) |
| `py-subprocess-shell-true` | `subprocess` + `shell=True` + chuỗi động |
| `py-flask-debug-true` | `app.run(debug=True)` |

Mỗi rule có fixture test (`// ruleid:` / `ok:`) — thêm rule mới chỉ cần 1 cặp `.yaml` + fixture trong `rules/`.

---

## Demo nhanh

`demo/app/` là Express app **cố ý chứa lỗ hổng** (SQLi, command injection, hardcoded secret) — ⚠️ không deploy. Kịch bản 5 phút (sửa 1 hàm → mở PR → xem findings + blast radius): [demo/run-demo.md](demo/run-demo.md).

```bash
radar impact --function validateUser   # thử ngay không cần sửa gì
```

## Mở rộng ngôn ngữ

Thêm ngôn ngữ cho impact graph = thêm **1 file plugin** trong `src/radar/graph/languages/` (subclass `LanguageExtractor`), registry tự phát hiện — không sửa core. Xem `python.py` làm mẫu.

## Giới hạn (by design)

- Call graph là **xấp xỉ**: same-file → import map → khớp tên toàn cục (nhãn `⚠ approx`). Dynamic call (`obj[x]()`) bỏ qua — fallback edge import file-level.
- Không type-aware, không dynamic dispatch.

## Development

```bash
pip install -e ".[dev]"
pytest                     # 76 tests
```

## Tài liệu

[PRD](docs/security-radar-prd.md) · [Kiến trúc](docs/system-architecture.md) · [Changelog](docs/project-changelog.md) · [Roadmap](docs/development-roadmap.md)
