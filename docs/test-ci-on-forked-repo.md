# Tutorial: Test luồng CI security-radar trên repo shiori (fork)

Hướng dẫn end-to-end để chạy thử GitHub Action của **security-radar** trên một bản
fork của [go-shiori/shiori](https://github.com/go-shiori/shiori) — chứng kiến đủ
luồng: scan → SARIF lên Security tab → blast-radius impact → PR comment tự động.

> Thay `<your-username>` bằng tài khoản GitHub của bạn ở mọi chỗ bên dưới.
> Tutorial này **không phụ thuộc** vào một fork cụ thể nào.

---

## 0. CI này làm gì?

Mỗi lần có `pull_request` hoặc `push`, Action `CosmicAlpaca/Source-Code-Security-Scanner_v2`:

| Bước | Kết quả |
|---|---|
| Semgrep scan (OWASP presets + 50 bundled rules) | findings JSON + SARIF |
| Upload SARIF | hiển thị ở tab **Security → Code scanning** |
| Trace impact trên diff của PR | blast-radius (function/API bị ảnh hưởng) |
| Render + upsert 1 comment | findings + impact ngay trong PR |
| Gate theo `fail-on` | pass/fail workflow theo severity |

---

## 1. Yêu cầu

- Một tài khoản GitHub.
- Fork **public** (cần public để tab Security/Code-scanning hoạt động miễn phí;
  repo private cần GitHub Advanced Security).
- Không cần cài `gh` CLI — làm hết bằng giao diện web.
- Không cần copy rules/scripts — **mọi thứ nằm trong Action**, bạn chỉ thêm 1 file.

---

## 2. Bước 1 — Fork shiori

1. Mở https://github.com/go-shiori/shiori
2. Bấm **Fork** (góc trên phải) → **Create fork**.
3. Bạn sẽ có `https://github.com/<your-username>/shiori`.

> Fork giữ nguyên lịch sử commit của shiori — đủ để Action diff impact theo PR.

---

## 3. Bước 2 — Thêm file workflow

Vào fork của bạn → **Add file → Create new file**.

Ở ô tên file, gõ **chính xác** (dấu `/` sẽ tự tạo thư mục lồng nhau):

```
.github/workflows/security.yml
```

Dán nội dung sau vào ô soạn thảo:

```yaml
name: Security
on: [pull_request, push]

permissions:
  contents: read
  security-events: write   # upload SARIF lên Security tab
  pull-requests: write     # post PR comment
  actions: read            # codeql-action đọc workflow run

jobs:
  radar:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0     # bắt buộc — impact cần diff với base branch
      - uses: CosmicAlpaca/Source-Code-Security-Scanner_v2@main
        with:
          github-token: ${{ secrets.GITHUB_TOKEN }}
          # Tuỳ chọn (giá trị mặc định):
          # path: "."            # thư mục cần scan
          # fail-on: ""          # "error" | "warning" | "info" để chặn; rỗng = chỉ báo cáo
          # rules-only: "false"  # "true" = offline, chỉ bundled rules
          # comment: "true"      # "false" = bỏ PR comment
          # sarif: "true"        # "false" = bỏ upload Security tab
```

> ⚠️ **Dùng `@main`, KHÔNG dùng `@v1`.** Tag `v1` đang cũ (upload-sarif@v3, thiếu
> `continue-on-error`). Nhánh `main` đã có bản vá (actions:read + upload-sarif v4
> non-fatal). Khi nào tag `v1` được refresh thì mới nên dùng `@v1`.

---

## 4. Bước 3 — Commit + tạo PR (để trigger CI)

Cuộn xuống cuối trang soạn file:

1. Chọn **"Create a new branch for this commit and start a pull request"**.
2. Đặt tên nhánh, ví dụ `ci/security`.
3. Bấm **Propose new file** → **Create pull request** → **Create pull request**.

PR vừa mở → Action `Security` chạy ngay (vì có cả trigger `push` lên nhánh mới và
`pull_request`).

---

## 5. Bước 4 — Xem kết quả

### a) Log workflow
Tab **Actions** → chọn run `Security` mới nhất → mở job `radar` → xem từng step.

### b) SARIF / findings
Tab **Security → Code scanning** → danh sách lỗ hổng Semgrep tìm được (shiori có
sẵn vài chỗ SSRF/path-handling để demo).

> Lần đầu có thể mất ~1 phút để GitHub index SARIF.

### c) PR comment
Mở lại PR → có **1 comment tự động** liệt kê findings + blast-radius. Comment này
được *upsert* (cập nhật tại chỗ) ở các lần push sau, không spam comment mới.

---

## 6. (Tuỳ chọn) Làm phần impact KHÔNG rỗng

Impact chỉ tính trên **file thay đổi trong PR**. PR ở trên chỉ thêm file workflow
nên impact có thể trống. Để thấy blast-radius thật:

1. Trong PR vừa tạo, vào **Files changed** hoặc sửa thêm 1 file mã nguồn, ví dụ
   `internal/http/handlers/api/v1/tags.go` — đổi 1 dòng bất kỳ (thêm comment).
2. Commit vào **cùng nhánh** `ci/security`.
3. Action chạy lại → comment cập nhật, phần "Functions/APIs affected" hiện ra.

---

## 7. (Tuỳ chọn) Bật gate chặn merge

Mặc định CI chỉ **báo cáo** (không fail). Muốn nó **fail khi có lỗi nặng**, sửa
trong `security.yml`:

```yaml
      - uses: CosmicAlpaca/Source-Code-Security-Scanner_v2@main
        with:
          github-token: ${{ secrets.GITHUB_TOKEN }}
          fail-on: "error"     # workflow đỏ nếu có finding severity = error
```

Sau đó vào **Settings → Branches → Add rule** để yêu cầu check `Security` pass
trước khi merge.

---

## 8. Chạy offline (không gọi Semgrep registry)

Nếu CI hay timeout do tải preset từ mạng, scan chỉ bằng rules đóng gói sẵn:

```yaml
        with:
          github-token: ${{ secrets.GITHUB_TOKEN }}
          rules-only: "true"
```

Nhanh hơn, ổn định hơn, nhưng bỏ qua các OWASP preset tải từ registry.

---

## 9. Troubleshooting

| Triệu chứng | Nguyên nhân / cách xử lý |
|---|---|
| Action không chạy | Thiếu `.github/workflows/` (đúng đường dẫn?) hoặc Actions bị tắt → Settings → Actions → Allow. |
| "Resource not accessible by integration" | Thiếu block `permissions:` (giữ nguyên 4 dòng ở trên). |
| Security tab trống | Repo private không có Advanced Security → để repo **public**, hoặc đợi GitHub index ~1 phút. |
| Không có PR comment | `pull-requests: write` bị thiếu, hoặc đang test bằng `push` chứ không phải PR. |
| Impact rỗng | PR không sửa file mã nguồn → xem **Mục 6**. Hoặc thiếu `fetch-depth: 0`. |
| SARIF upload lỗi đỏ cả job | Đang dùng `@v1` cũ → đổi sang `@main` (xem Bước 2). |

---

## 10. Lưu ý an toàn

- Workflow chỉ chạy trên **fork của bạn** — không đụng repo gốc `go-shiori/shiori`
  hay repo action `CosmicAlpaca/Source-Code-Security-Scanner_v2`.
- `secrets.GITHUB_TOKEN` là token GitHub **tự sinh cho mỗi run**, scope giới hạn
  trong repo, tự hết hạn khi job xong — **không phải** API key cá nhân của bạn.
- **Không** commit `.env`, API key, hay credential nào vào repo.
- AI triage (`radar triage`) cần `OPENAI_API_KEY` riêng và **không chạy trong CI
  này** — CI chỉ scan + impact + comment.

---

## Tham khảo

- File workflow mẫu trong repo: `examples/security.yml`
- Định nghĩa Action: `action.yml`
- Script render comment: `scripts/render-pr-comment.py`
