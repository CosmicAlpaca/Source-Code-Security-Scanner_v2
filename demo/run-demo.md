# Demo end-to-end trên GitHub

> ⚠️ `demo/app/` là ứng dụng **cố ý chứa lỗ hổng** (SQLi, command injection, hardcoded JWT secret) để demo security-radar. **Không bao giờ deploy.**

## Chuẩn bị (1 lần)

1. Repo đã push lên GitHub (**public** — Code Scanning free) với workflow `.github/workflows/security-scan.yml`.
2. Vào **Settings → Code security** xác nhận *Code scanning* hiển thị (tự bật khi SARIF đầu tiên được upload).

## Kịch bản demo (~5 phút)

### Bước 1 — Tạo branch + sửa function dùng chung

```bash
git checkout -b demo/change-validate
```

Sửa `demo/app/utils/validate.js` — đổi logic `validateUser` (ví dụ thêm điều kiện độ dài password):

```js
function validateUser(payload) {
  if (!payload || !payload.username || !payload.password) {
    return false;
  }
  return payload.username.length >= 3 && payload.password.length >= 8;
}
```

### Bước 2 — Xem blast radius local (trước khi push)

```bash
radar build .
radar impact --staged        # hoặc --diff HEAD~1 sau khi commit
```

Kỳ vọng: `validateUser` → `login`, `register` → `POST /login`, `POST /register` — feature **Authentication**.

### Bước 3 — Push + mở PR

```bash
git commit -am "demo: tighten validateUser"
git push -u origin demo/change-validate
```

Mở PR trên GitHub. Sau ~2-3 phút workflow chạy xong:

| Nơi xem | Kỳ vọng |
|---|---|
| **PR comment** (bot) | Section *Semgrep findings*: SQLi (`js-sql-string-concat`), command injection (`js-child-process-user-input`), hardcoded secret (`js-hardcoded-jwt-secret`) + preset findings. Section *Impact*: `validateUser` → 2 functions, 2 APIs, 1 feature |
| **Tab Security → Code scanning** | Các finding SARIF từ Semgrep |
| **Actions → artifacts** | `semgrep-report` (JSON/SARIF) + `impact-report` (JSON/HTML) |

### Bước 4 — Push thêm commit

Sửa tiếp file bất kỳ rồi push — comment bot **update comment cũ** (không spam comment mới).

### Bước 5 — (Tùy chọn) Verify custom rules

```bash
docker run --rm -v "$PWD:/src" semgrep/semgrep semgrep --test --metrics off /src/rules/
```

Kỳ vọng: `5/5: ✓ All tests passed`.

## Giải thích kết quả impact

```
Changed: validateUser  demo/app/utils/validate.js:2  feature: Authentication
├── login  demo/app/routes/auth.js:9  ← POST /login  [depth 1]  feature: Authentication
│   └── POST /login  [depth 2]
└── register  demo/app/routes/auth.js:19  ← POST /register  [depth 1]  feature: Authentication
    └── POST /register  [depth 2]
```

- **depth** — số bước lan truyền từ function bị sửa.
- **⚠ approx** — edge resolve bằng khớp tên toàn cục (name-only), không chắc chắn 100%.
- **feature** — map từ glob trong `radar.config.yml`.
