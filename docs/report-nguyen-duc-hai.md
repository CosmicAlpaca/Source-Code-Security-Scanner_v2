# Báo Cáo Đóng Góp Cá Nhân: Nguyễn Đức Hải

**Dự án:** Security Radar — Hệ thống Quét bảo mật và Phân tích luồng ảnh hưởng mã nguồn  
**Người thực hiện:** Nguyễn Đức Hải  
**Vai trò/Nhiệm vụ chính:** Xác định OWASP Top 10, phân tích luồng ảnh hưởng khi API Endpoint thay đổi, xây dựng công cụ phân tích động và tích hợp tất cả thành một Unified Dashboard duy nhất.

---

## 1. Tổng quan

Trong khuôn khổ dự án `security-radar`, tôi đảm nhiệm việc kết nối tính năng quét mã nguồn với tiêu chuẩn **OWASP Top 10**, xây dựng khả năng hình quan hóa "bán kính sát thương" (blast radius), đồng thời **gộp toàn bộ kết quả phân tích thành một file HTML Dashboard duy nhất** — thay vì xuất rải rác nhiều file rời.

---

## 2. Chi tiết công việc và Code Contribution

### 2.1. Phát hiện OWASP Top 10 Web Application Security Risks

- **Tích hợp Preset Semgrep:** Cấu hình bộ rule `p/owasp-top-ten` vào luồng quét tự động của `radar scan`.
- **Phát triển Custom Rules (Taint Analysis):** Viết và tinh chỉnh các Semgrep rules sử dụng cơ chế *Taint Mode* để bắt lỗi logic cụ thể thường gặp trong Node.js (Express) và Python:
  - `js-express-xss` — XSS (OWASP A03): `req.query/body/params` → `res.send()/write()`
  - `js-child-process-user-input` / `py-subprocess-shell-true` — Command Injection (OWASP A03)
  - `js-sql-string-concat` — SQL Injection qua cộng chuỗi
  - `js-hardcoded-jwt-secret` — Broken Authentication (OWASP A07)
- **Cấu hình Test:** Viết các fixture `// ruleid:` / `ok:` và thiết lập `semgrep --test` trong CI.

### 2.2. Phân tích và Vẽ bản đồ ảnh hưởng thay đổi API (Impact Mapping)

- Triển khai chức năng `radar impact` tập trung vào các **API endpoint**.
- Xuất dữ liệu chuỗi phụ thuộc thành biểu đồ trực quan **Mermaid** và HTML tương tác.
- Fix **KeyError** trong `exporters.py`: khi số lượng thay đổi vượt `MERMAID_MAX_NODES = 50`, hệ thống trước đó crash khi tô màu node bị ẩn; đã thêm guard `if changed.id in ids`.
- Bổ sung `--diff` option cho `radar report` (trong `cli.py`): cho phép unified report tự động tính blast radius từ git diff của một nhánh cụ thể.

### 2.3. Xây dựng Công cụ Demo Động — `scripts/analyze-github.py`

Script tương tác cho phép phân tích **bất kỳ repository GitHub nào** từ terminal:

| Bước | Hành động |
|------|-----------|
| Input | URL GitHub + nhánh (optional) + tên hàm (optional) |
| Clone | Clone repo hoặc tái dùng cache (`analysis_repos/`) |
| Report | Gọi `radar report` → sinh Unified Dashboard HTML |
| Output | File `analysis_results/<repo>_unified_dashboard.html` |

**Tính năng nổi bật của script:**
- **Caching thông minh:** Không clone lại nếu repo đã tồn tại — chỉ `git fetch + checkout`.
- **Tự động detect triage:** Chỉ thêm `--triage` nếu `OPENAI_API_KEY` có trong môi trường, không bắt buộc.
- **Tự động detect default branch:** Thử `origin/main`, nếu không có thì fallback sang `HEAD~1`.
- **Hỗ trợ đầy đủ 3 chế độ:** Theo hàm cụ thể (`--function`), theo nhánh diff (`--diff`), hoặc quét tổng quan (auto blast radius từ findings).

### 2.4. Gộp Report — Unified Dashboard & Premium UI (Nhiệm vụ hiện tại)

Trước đây hệ thống xuất nhiều file rời (JSON scan + HTML impact + MD Mermaid). Tôi đã **gộp lại thành một file `*_unified_dashboard.html` duy nhất** với giao diện vô cùng ấn tượng:

1. Thiết kế **Tabbed UI** hiện đại (Overview, Findings, Blast Radius, History).
2. **Premium Design**: Sử dụng Glassmorphism, dark mode tinh tế với các tone màu nổi bật theo mức độ rủi ro (CRITICAL, HIGH, MEDIUM, LOW).
3. **Biểu đồ động (Chart.js)**: Tích hợp Doughnut chart phân loại lỗi theo OWASP Category, Severity và biểu đồ đường theo dõi xu hướng lịch sử.
4. **Tương tác trực quan**: Thêm tính năng Search & Lọc kết quả ngay trên giao diện HTML, hiệu ứng đếm số (Animated Counters).
5. Bổ sung `--diff` option vào `radar report` (`cli.py`) để hỗ trợ phân tích theo branch diff.
### 2.5. Fix Cross-Platform Encoding (Bảo đảm chạy trên mọi máy)

Hệ thống ban đầu crash với lỗi `UnicodeDecodeError: 'cp932'` trên Windows tiếng Nhật. Tôi đã implement **3 lớp bảo vệ encoding**:

| Lớp | File | Cơ chế |
|-----|------|--------|
| **1. Process-level** | `scripts/analyze-github.py` | `os.environ.setdefault("PYTHONUTF8","1")` — toàn bộ subprocess con kế thừa |
| **2. CLI output** | `src/radar/cli.py` | Reconfigure `stdout`/`stderr` sang UTF-8 nếu encoding hiện tại không phải utf-8 |
| **3. Semgrep subprocess** | `src/radar/scan/runner.py` | Inject `PYTHONUTF8=1` + `PYTHONIOENCODING=utf-8` + `encoding="utf-8", errors="replace"` |

Điều này đảm bảo code chạy đúng trên **cp932 (JP), cp1252 (EU/US), cp936 (CN)** và mọi hệ thống phổ thông khác.

---

## 3. Danh sách file đã tạo/chỉnh sửa

| File | Loại thay đổi | Mô tả |
|------|---------------|-------|
| `scripts/analyze-github.py` | Viết mới + liên tục cải thiện | Script phân tích GitHub tương tác, caching, unified report |
| `src/radar/cli.py` | Chỉnh sửa | Thêm `--diff` cho `radar report`; fix encoding stdout/stderr |
| `src/radar/scan/runner.py` | Chỉnh sửa | Fix encoding Semgrep subprocess (PYTHONUTF8=1) |
| `src/radar/report/exporters.py` | Fix bug | Guard KeyError khi changed nodes > MERMAID_MAX_NODES |
| `src/radar/rules/js-express-xss.yaml` | Viết mới | Custom rule XSS taint mode cho Express.js |
| `src/radar/rules/js-child-process-user-input.yaml` | Viết mới | Custom rule Command Injection |
| `src/radar/rules/js-sql-string-concat.yaml` | Viết mới | Custom rule SQL Injection |
| `src/radar/rules/js-hardcoded-jwt-secret.yaml` | Viết mới | Custom rule hardcoded JWT secret |
| `src/radar/rules/py-subprocess-shell-true.yaml` | Viết mới | Custom rule Command Injection Python |
| `.gitignore` | Chỉnh sửa | Track `analysis_results/`, ignore `analysis_repos/` |
| `docs/report-nguyen-duc-hai.md` | Cập nhật | File báo cáo này |

---

## 4. Giá trị mang lại cho dự án chung

- **Hoàn thiện tính năng Security:** Đảm bảo độ phủ OWASP Top 10 với 5+ custom rules kiểm chứng bằng fixture và CI.
- **Trải nghiệm người dùng thống nhất:** Thay vì 3 file rời (JSON + HTML + MD), người dùng nhận **1 file dashboard HTML duy nhất** có đầy đủ: danh sách lỗ hổng, blast radius graph, lịch sử scan, và AI verdict (nếu có key).
- **Tính ổn định đa nền tảng:** Hệ thống chạy được trên mọi locale Windows/Linux/macOS nhờ các encoding guard nhiều lớp.
- **Demo linh hoạt:** Có thể trình diễn ngay với bất kỳ repo GitHub nào — `python scripts/analyze-github.py` → dán URL → nhận dashboard.

---

*Tài liệu tham khảo:*
- Custom rules: `src/radar/rules/`
- Script phân tích: `scripts/analyze-github.py`
- Kịch bản Demo: `demo/run-github-demo.md`
- Changelog chi tiết: `docs/project-changelog.md`
