# Báo Cáo Đóng Góp Cá Nhân: Nguyễn Đức Hải

**Dự án:** Security Radar - Hệ thống Quét bảo mật và Phân tích luồng ảnh hưởng mã nguồn  
**Người thực hiện:** Nguyễn Đức Hải  
**Vai trò/Nhiệm vụ chính:** Xác định OWASP Top 10 Web Application Security Risks, phân tích luồng ảnh hưởng (Impact Graph) khi API Endpoint thay đổi và xây dựng công cụ Demo động trên kho lưu trữ mã nguồn bất kỳ.

---

## 1. Tổng quan các hạng mục đã thực hiện

Trong khuôn khổ dự án `security-radar`, tôi đảm nhiệm việc kết nối tính năng quét mã nguồn với bộ tiêu chuẩn bảo mật **OWASP Top 10**, đồng thời xây dựng khả năng hình quan hóa "bán kính sát thương" (blast radius) khi một tính năng hoặc API endpoint bị thay đổi. 

Để chứng minh tính thực tiễn của công cụ, tôi đã xây dựng một script phân tích động cho phép chạy hệ thống trên bất kỳ repository GitHub mã nguồn mở phức tạp nào, thay vì chỉ giới hạn trong một ứng dụng demo có sẵn.

## 2. Chi tiết công việc và Code Contribution

### 2.1. Phát hiện OWASP Top 10 Web Application Security Risks
Để đảm bảo hệ thống có thể nhận diện chính xác các rủi ro bảo mật cốt lõi, tôi đã:
- **Tích hợp Preset Semgrep:** Cấu hình và tích hợp thành công bộ rule `p/owasp-top-ten` vào luồng quét tự động của `radar scan`.
- **Phát triển Custom Rules (Viết code trực tiếp):** Viết bổ sung và tinh chỉnh các Semgrep rules tùy chỉnh (custom rules) sử dụng cơ chế *Taint Analysis* nâng cao để bắt các lỗi logic cụ thể thường gặp trong Node.js (Express) và Python. Các rule tiêu biểu đã viết bao gồm:
  - `js-express-xss`: Phát hiện lỗ hổng Cross-Site Scripting (XSS - OWASP A03:2021) khi untrusted data truyền thẳng vào `res.send()` hoặc `res.write()`.
  - `js-child-process-user-input` / `py-subprocess-shell-true`: Phát hiện Command Injection (OWASP A03:2021).
  - `js-sql-string-concat`: Phát hiện SQL Injection qua việc cộng chuỗi.
  - `js-hardcoded-jwt-secret`: Phát hiện rủi ro về Broken Authentication (OWASP A07:2021).
- **Cấu hình Test:** Viết các file test fixture (ví dụ `js-express-xss.js`) và thiết lập CI để kiểm thử tự động đảm bảo các rule hoạt động chính xác (`semgrep --test`).

### 2.2. Phân tích và Vẽ bản đồ ảnh hưởng thay đổi API (Impact Mapping)
Một dự án đã đi vào sử dụng khi có sự thay đổi (đặc biệt là sửa đổi API endpoint) luôn tiềm ẩn rủi ro hồi quy (regression) và bảo mật dây chuyền. Tôi đã:
- Triển khai chức năng gọi lệnh `radar impact` tập trung vào các **API endpoint**.
- Chuyển đổi dữ liệu chuỗi phụ thuộc (Dependency Call Graph) thành định dạng biểu đồ trực quan **Mermaid**.
- **Kết quả đạt được:** Hệ thống tự động vẽ ra một biểu đồ cây chỉ rõ: "Khi hàm X thay đổi -> Luồng nào bị ảnh hưởng -> API Y và Tính năng Z nào chịu tác động cuối cùng". 

### 2.3. Xây dựng Công cụ Demo Động (Dynamic GitHub Analyzer)
Thay vì dùng ứng dụng cố định, tôi đã viết script `scripts/analyze-github.py` để minh họa sức mạnh thực tế của hệ thống. Công cụ này thực hiện:
- Nhận input là một URL GitHub bất kỳ (repo phức tạp).
- Clone source code, hỗ trợ switch sang một nhánh thay đổi (Branch PR) tự chọn.
- **Tiến hành Phân tích Cụ thể:**
  1. Chạy `radar scan` rà quét toàn bộ code hiện tại để tìm lỗi OWASP Top 10.
  2. Tính toán sự khác biệt (Git Diff) giữa nhánh hiện tại so với `main` hoặc đối với một hàm/API được chỉ định.
  3. Xuất ra giao diện Terminal bản đồ ảnh hưởng của phần thay đổi và cung cấp mã code Mermaid để render lên giao diện Web/Markdown.

## 3. Giá trị mang lại cho dự án chung
- Hoàn thiện tính năng lõi về mặt "Security" (Bảo mật) bằng cách đảm bảo độ bao phủ các tiêu chuẩn OWASP phổ biến nhất.
- Nâng tầm trải nghiệm người dùng (Reviewer/Developer) thông qua Impact Graph trực quan, giúp họ ngay lập tức hình dung được quy mô của một Pull Request thay vì đọc code thuần túy.
- Kịch bản Demo linh hoạt giúp dự án có thể dễ dàng trình diễn (Pitching/Showcase) cho bất kỳ đối tác hay giảng viên nào bằng cách áp dụng thẳng vào một dự án Open-Source đang nổi trên GitHub.

---
*Tài liệu tham khảo kèm theo:*
- Source code rules: `src/radar/rules/`
- Tool Demo động: `scripts/analyze-github.py`
- Kịch bản chạy Demo: `demo/run-github-demo.md`
