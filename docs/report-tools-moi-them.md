# Report: Cac Tools Moi Bo Sung Ben Canh Semgrep

Ngay lap report: 2026-06-24

## 1. Tong quan

He thong ban dau dung Semgrep lam cong cu chinh de quet SAST va chay bo custom OWASP rules. Phan moi bo sung mo rong kien truc theo huong multi-engine scanning, giup Radar khong chi phat hien loi source code ma con bao phu them secret leakage, Python-specific security issues, dependency CVE va IaC misconfiguration.

Cac tools moi duoc them:

- `Gitleaks`: quet secrets nhu API keys, tokens, credentials.
- `Bandit`: quet bao mat chuyen sau cho Python.
- `Trivy`: quet dependency vulnerabilities, IaC misconfigurations va secrets.

Tat ca tools duoc thiet ke de normalize ket qua ve chung model `Finding`, giup dashboard, risk ranking, suppression, history va triage xu ly thong nhat.

## 2. Gitleaks

Gitleaks duoc them de phat hien secrets bi commit vao source code, vi du API key, access token, cloud credential hoac private secret.

Gia tri chinh:

- Bo sung lop secret scanning chuyen dung.
- Phu hop hon Semgrep cho viec phat hien credential leakage.
- Findings duoc map ve rule dang `gitleaks.<RuleID>`.
- Severity hien duoc dua ve `ERROR`.
- Metadata OWASP gan voi `A02:2021-Cryptographic Failures`.

Code lien quan:

- `src/radar/scan/gitleaks_runner.py`
- `src/radar/scan/engines/gitleaks_engine.py`

Hien Gitleaks da duoc goi truc tiep trong cac luong:

- `radar report`
- `radar triage`
- `radar serve`

## 3. Bandit

Bandit duoc them de quet bao mat rieng cho Python. Tool nay phan tich AST Python va phat hien cac pattern nguy hiem nhu command injection, hardcoded password, unsafe deserialization, weak cryptography, Flask debug mode, insecure temp file va XML parser khong an toan.

Gia tri chinh:

- Bo sung chieu sau cho repo Python.
- Dung bo test id chuan cua Bandit, vi du `B602`, `B608`, `B506`.
- Findings duoc map ve rule dang `bandit.Bxxx`.

Severity mapping:

- Bandit `HIGH` -> Radar `ERROR`
- Bandit `MEDIUM` -> Radar `WARNING`
- Bandit `LOW` -> Radar `INFO`

Code lien quan:

- `src/radar/scan/engines/bandit_engine.py`

Bandit cung da co mapping OWASP truc tiep cho nhieu nhom nhu Injection, Deserialization, Cryptographic Failures, Auth Failures, Misconfiguration, Broken Access Control va SSRF.

## 4. Trivy

Trivy duoc them de quet cac van de ma Semgrep khong bao phu tot, dac biet la dependency CVE, vulnerable components, Dockerfile/Terraform/Kubernetes misconfiguration va embedded secrets.

Gia tri chinh:

- Bo sung SCA cho dependency vulnerabilities.
- Bo sung IaC/security misconfiguration checks.
- Co the chay qua native `trivy` hoac Docker image `aquasec/trivy:latest`.

Findings duoc normalize:

- CVE/dependency issue -> `trivy.<CVE-ID>`, OWASP A06.
- Misconfiguration -> `trivy.<MISCONFIG-ID>`, OWASP A05.
- Secret -> `trivy.secret.<RuleID>`, OWASP A02.

Severity mapping:

- `CRITICAL`/`HIGH` -> `ERROR`
- `MEDIUM` -> `WARNING`
- `LOW`/`UNKNOWN` -> `INFO`

Code lien quan:

- `src/radar/scan/engines/trivy_engine.py`

## 5. Kien truc Multi-Engine

Phan moi quan trong nhat la scan engine abstraction.

Code chinh:

- `src/radar/scan/engines/base.py`
- `src/radar/scan/engines/__init__.py`

`ScanEngine` dinh nghia interface chung:

- `detect()`: kiem tra runtime co san khong.
- `scan()`: chay scanner va tra ve `list[Finding]`.
- `name`, `description`, `default`: metadata cho registry/CLI.

Aggregator `scan_all()` co nhiem vu:

- Tu dong chay cac engine duoc chon.
- Skip engine khong kha dung thay vi lam hong toan bo scan.
- Merge findings tu nhieu engine.
- Dedup finding trung trong cung engine.
- Sort theo severity/path/line.
- Tra them status tung engine de bao cao/debug.

## 6. Trang thai hien tai

Da hoan thanh:

- Co engine abstraction va registry.
- Da implement Semgrep, Gitleaks, Bandit, Trivy engine.
- Da co aggregator `scan_all()`.
- Da normalize output Bandit/Trivy/Gitleaks ve `Finding`.
- Da co test trong `tests/test_scan_engines.py`.
- Gitleaks da duoc tich hop vao `report`, `triage`, `serve`.

Chua hoan tat:

- `radar scan` hien van goi Semgrep truc tiep, chua dung `scan_all()`.
- Chua co CLI option `radar scan --engine`.
- Chua co command `radar engines`.
- GitHub Action van chu yeu chay Semgrep.
- README/docs chua cap nhat day du theo huong multi-engine.
- SARIF output hien van gan voi Semgrep-native output, chua co SARIF exporter chung.

## 7. Rui ro va luu y

- Co the trung findings giua Semgrep, Gitleaks va Trivy secret scanner.
- Thoi gian scan se tang neu chay tat ca engines.
- Bandit/Trivy/Gitleaks khong nam trong dependencies mac dinh nen co the bi skip tren may chua cai runtime.
- Trivy Docker image dang dung `latest`, nen neu can CI on dinh nen pin version.
- Gitleaks runner co auto-download, nhung engine detect duoc thiet ke khong side-effect; can thong nhat behavior khi public ra CLI.

## 8. Khuyen nghi tiep theo

Uu tien tiep theo nen la:

1. Chuyen `radar scan` sang dung `scan_all()`.
2. Them option `--engine` de user chon engine can chay.
3. Them command `radar engines` de list trang thai runtime tung tool.
4. Chuyen `report`, `triage`, `serve` sang dung aggregator thay vi goi Semgrep + Gitleaks thu cong.
5. Cap nhat README va GitHub Action theo mo hinh multi-engine.
6. Quyet dinh SARIF la Semgrep-only hay viet exporter chung cho moi `Finding`.

## 9. Ket luan

Cac tools moi da mo rong Radar tu mot Semgrep-based scanner thanh nen tang multi-engine scanner. Gitleaks bo sung secret scanning, Bandit bo sung Python SAST, Trivy bo sung dependency/IaC/security config scanning.

Phan nen tang ky thuat da co, nhung can hoan tat tich hop CLI/CI/docs de tinh nang multi-engine that su san sang cho nguoi dung cuoi.
