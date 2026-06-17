# Hướng dẫn Test & Demo `security-radar`

> ⚠️ `demo/app/` là Express app **cố ý chứa lỗ hổng** (SQLi, command injection, hardcoded JWT secret) để demo tool. **Không bao giờ deploy.**

Tài liệu này gồm 3 phần, chạy độc lập:

| Phần | Mục đích | Cần gì |
|---|---|---|
| [A. Demo local 5 phút](#a--demo-local-5-phút) | Chạy tay 8 lệnh `radar` trên app mẫu, thấy ngay kết quả | Cài tool + Semgrep |
| [B. Demo CI trên GitHub](#b--demo-ci-trên-github-pr) | Pipeline tự động: PR → comment findings + impact, SARIF lên tab Security | Repo public + workflow |
| [C. Chạy test suite](#c--chạy-test-suite) | Verify code đúng trước khi demo (220 unit test + 50 rule test) | `pip install -e ".[dev]"` |

> 📎 Muốn quét **repo GitHub ngoài bất kỳ** bằng script local (không cần PR) → xem [`run-github-demo.md`](run-github-demo.md).

---

## Chuẩn bị (1 lần)

```bash
cd Source-Code-Security-Scanner_v2
pip install .            # Python ≥ 3.11
radar --help            # phải in 8 lệnh: scan / build / impact / report / triage / graph / history / watch
```

> 💡 **Windows**: nếu `pip`/`radar` bị Application Control chặn → dùng `python -m pip install .` và `python -m radar.cli` thay cho `radar`.

`radar scan` cần Semgrep runtime (native `semgrep` trên PATH **hoặc** Docker Desktop bật). `radar impact` / `report` (không `--triage`) / `radar triage --min-risk` **không cần** Semgrep verdict AI và **không cần** API key.

---

## A — Demo local (5 phút)

Chạy lần lượt trên app mẫu. Mọi lệnh **zero-footprint**: không ghi file nào vào repo được quét (graph cache nằm ngoài repo).

### A1. Smoke test — quét lỗ hổng

```bash
radar scan demo --rules-only          # offline, chỉ custom rules — không cần mạng
```

Kỳ vọng: **4 finding** (4 ERROR) — SQLi (`js-sql-string-concat`), command injection (`js-child-process-user-input`), hardcoded secret (`js-hardcoded-jwt-secret`)…

```bash
radar scan demo --rules-only --error --fail-on warning   # gate: exit≠0 khi có finding ≥ WARNING
echo $?    # 1  (PowerShell: echo $LASTEXITCODE)
```

### A2. Blast radius — "sửa hàm này thì ảnh hưởng đâu?"

```bash
radar build demo                       # index → demo/.radar/graph.json (tùy chọn, impact tự build nếu thiếu)
radar impact --path demo --function validateUser
```

Kỳ vọng — cây lan truyền tới API:

```
Changed: validateUser  app/utils/validate.js:2
├── login     app/routes/auth.js:9   ← POST /login     [depth 1]
└── register  app/routes/auth.js:19  ← POST /register  [depth 1]
Summary: 2 functions, 2 APIs, 0 features affected
```

> 🏷️ **Nhãn feature** (`feature: Authentication`) cần `radar.config.yml` ở **root được quét**. Repo này có sẵn config ở root (map `demo/app/...`) — muốn thấy nhãn feature thì chạy từ root: `radar impact --function validateUser` (không `--path demo`).

Xuất report khác:

```bash
radar impact --path demo --function validateUser --format mermaid   # dán vào GitHub/Mermaid Live
radar impact --path demo --function validateUser --format html --out impact.html
```

### A3. ⭐ Risk Ranking — dashboard hợp nhất (flagship)

Mọi finding được **xếp hạng theo Risk Score 0–100** = `severity × reachability × OWASP-class`. Bug nguy hiểm nhất luôn lên đầu, `noise`/`false_positive` gấp vào fold (không xoá).

```bash
radar report demo --out dash.html      # dashboard offline: findings xếp theo risk + impact + history
```

Mở `dash.html` → cột **Risk** (điểm + band: critical/high/medium/low/noise), bảng **sort risk giảm dần**. Tooltip cột Risk hiện **factors** giải thích điểm (vd `ERROR · reachable(2 routes) · A03(×1.3)`) — không black-box.

**Gate CI theo ranking — chạy được offline (không cần key):**

```bash
radar triage demo --top 3                 # chỉ in 3 finding rủi ro nhất
radar triage demo --min-risk 80           # exit≠0 nếu có finding risk ≥ 80
radar triage demo --format json           # mỗi finding kèm object risk:{value,band,factors}
echo $?
```

### A4. (Tùy chọn) Nâng cấp bằng AI verdict

Cần `OPENAI_API_KEY` (env hoặc file `.env` ở root repo). Thiếu key → tự render bản offline, **không lỗi**.

```bash
radar triage demo --dry-run               # xem CHÍNH XÁC prompt sẽ gửi — không gọi API, không tốn token
export OPENAI_API_KEY=sk-...              # PowerShell: $env:OPENAI_API_KEY="sk-..."
radar report demo --triage --out dash.html   # THÊM cột reachability + AI verdict, AI ghi đè thứ hạng
radar triage demo --fail-on exploitable   # exit≠0 nếu AI verdict = exploitable
```

AI verdict **ghi đè** thứ hạng: `exploitable` → ép lên `critical`; `false_positive` → rớt xuống fold. Reasoning + exploit-path hiện qua tooltip.

---

## B — Demo CI trên GitHub (PR)

Pipeline tự động: mở PR → bot comment findings + blast radius, SARIF lên tab Security.

### Chuẩn bị (1 lần)
1. Repo đã push lên GitHub **public** (Code Scanning free) với `.github/workflows/security-scan.yml`.
2. **Settings → Code security** xác nhận *Code scanning* hiển thị (tự bật khi SARIF đầu tiên upload).

### Kịch bản

**Bước 1 — Branch + sửa function dùng chung:**

```bash
git checkout -b demo/change-validate
```

Sửa `demo/app/utils/validate.js` — siết logic `validateUser`:

```js
function validateUser(payload) {
  if (!payload || !payload.username || !payload.password) {
    return false;
  }
  return payload.username.length >= 3 && payload.password.length >= 8;
}
```

**Bước 2 — Xem blast radius local trước khi push:**

```bash
radar build .
radar impact --staged                  # đang sửa dở (đã git add)
```

**Bước 3 — Push + mở PR:**

```bash
git commit -am "demo: tighten validateUser"
git push -u origin demo/change-validate
```

Sau ~2-3 phút workflow xong:

| Nơi xem | Kỳ vọng |
|---|---|
| **PR comment** (bot) | *Findings*: SQLi, command injection, hardcoded secret + preset. *Impact*: `validateUser` → 2 functions, 2 APIs, 1 feature |
| **Tab Security → Code scanning** | Các finding SARIF từ Semgrep |
| **Actions → artifacts** | `semgrep-report` (JSON/SARIF) + `impact-report` (JSON/HTML) |

**Bước 4 — Push thêm commit:** comment bot **update comment cũ** (không spam comment mới).

> Findings **không block merge** — chỉ informational. Muốn "có răng" → dùng `radar triage --min-risk` / `--fail-on` trong job CI riêng (xem [A3](#a3--risk-ranking--dashboard-hợp-nhất-flagship)).

---

## C — Chạy test suite

Verify code đúng trước khi demo.

```bash
pip install -e ".[dev]"
pytest                                 # 220 unit test
```

Kỳ vọng: `220 passed`.

**Test custom rules** (mỗi rule có fixture `// ruleid:` / `ok:`):

```bash
# native:
semgrep --test --metrics off src/radar/rules/
# Docker (Windows):
docker run --rm -v "$PWD:/src" semgrep/semgrep semgrep --test --metrics off /src/rules/
```

Kỳ vọng: `✓ All tests passed`.

---

## Phụ lục — Đọc kết quả impact

```
Changed: validateUser  demo/app/utils/validate.js:2  feature: Authentication
├── login     demo/app/routes/auth.js:9   ← POST /login     [depth 1]
└── register  demo/app/routes/auth.js:19  ← POST /register  [depth 1, ⚠ approx]
```

- **depth** — số bước lan từ hàm bị sửa (caller trực tiếp = depth 1).
- **← METHOD /path** — hàm là handler của API endpoint đó.
- **⚠ approx** — edge resolve bằng khớp tên toàn cục (name-only), không chắc 100%. `--no-name-only` chỉ giữ kết quả chắc chắn.
- **feature** — map từ glob trong `radar.config.yml` (không có config → `(unmapped)`, tool vẫn chạy).
