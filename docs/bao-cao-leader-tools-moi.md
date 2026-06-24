# Bao cao leader: Bo sung cac tools bao mat ben canh Semgrep

Ngay bao cao: 2026-06-24

## 1. Tom tat

Trong dot phat trien vua roi, he thong Security Radar da duoc mo rong tu mo hinh chi dua tren Semgrep sang huong multi-engine security scanning. Muc tieu la tang do bao phu bao mat, giam diem mu cua Semgrep va tao nen tang de tong hop ket qua tu nhieu cong cu bao mat trong cung mot dashboard/risk ranking.

Ben canh Semgrep, da bo sung them 3 tools:

- Gitleaks: phat hien secrets nhu API key, token, credential bi commit vao source code.
- Bandit: phan tich bao mat chuyen sau cho Python.
- Trivy: quet dependency CVE, IaC misconfiguration va secrets.

Ket qua cua cac tools moi duoc chuan hoa ve cung mot format `Finding`, giup cac module hien co nhu dashboard, risk ranking, triage, history va suppression co the xu ly thong nhat.

## 2. Ly do bo sung

Semgrep hien van la engine SAST chinh cua du an, phu hop de quet source code va custom OWASP rules. Tuy nhien, neu chi dung Semgrep thi he thong con thieu mot so lop kiem tra quan trong:

- Secret leakage: can tool chuyen dung de bat API key/token/credential.
- Python-specific security: can bo rule sau hon cho Python.
- Dependency vulnerability: can quet CVE trong package/lockfile.
- IaC misconfiguration: can quet cau hinh Dockerfile, Terraform, Kubernetes.

Viec bo sung Gitleaks, Bandit va Trivy giup Radar tien gan hon den mot security scanner tong hop, khong chi la Semgrep wrapper.

## 3. Pham vi cac tools moi

### 3.1. Gitleaks

Muc dich:

- Phat hien secrets bi commit vao repository.
- Bao phu API keys, access tokens, cloud credentials va private secrets.

Gia tri:

- Giam rui ro lo credential trong source code.
- Bo sung lop secret scanning chuyen dung, tot hon viec chi dua vao custom Semgrep rules.

Trang thai:

- Da co runner va engine wrapper.
- Da tich hop vao cac luong `report`, `triage`, `serve`.
- Finding duoc map ve severity `ERROR` va OWASP `A02: Cryptographic Failures`.

### 3.2. Bandit

Muc dich:

- Phan tich bao mat rieng cho Python bang AST.
- Phat hien cac loi nhu command injection, hardcoded password, unsafe deserialization, weak cryptography, Flask debug mode va unsafe XML parser.

Gia tri:

- Tang do bao phu cho cac repo Python.
- Tan dung bo rule chuan cua Bandit thay vi tu viet lai toan bo bang Semgrep.

Trang thai:

- Da co engine wrapper.
- Da normalize ket qua ve model `Finding`.
- Da co mapping severity va OWASP category cho cac rule quan trong.

### 3.3. Trivy

Muc dich:

- Quet dependency vulnerabilities/CVE.
- Quet IaC misconfiguration.
- Quet embedded secrets.

Gia tri:

- Bo sung lop SCA, phat hien thu vien co loi bao mat.
- Bao phu OWASP A06: Vulnerable and Outdated Components.
- Mo rong Radar tu source-code scanner sang dependency/config scanner.

Trang thai:

- Da co engine wrapper.
- Da normalize ket qua CVE, misconfiguration va secret ve model `Finding`.
- Ho tro chay bang native `trivy` hoac Docker image.

## 4. Kien truc da thuc hien

Da bo sung lop multi-engine scanning trong thu muc:

- `src/radar/scan/engines/base.py`
- `src/radar/scan/engines/__init__.py`
- `src/radar/scan/engines/semgrep_engine.py`
- `src/radar/scan/engines/gitleaks_engine.py`
- `src/radar/scan/engines/bandit_engine.py`
- `src/radar/scan/engines/trivy_engine.py`

Thay doi chinh:

- Moi scanner duoc dong goi thanh mot `ScanEngine`.
- Moi engine co `detect()` de kiem tra runtime va `scan()` de tra ve findings.
- Co registry tu dong load cac engine.
- Co aggregator `scan_all()` de chay nhieu engine, merge ket qua va sap xep findings.
- Neu mot engine khong kha dung, he thong co the skip engine do thay vi lam fail toan bo scan.

Day la nen tang tot de sau nay them engine moi ma khong can thay doi lon o pipeline chinh.

## 5. Trang thai hien tai

Da hoan thanh:

- Da implement engine abstraction va registry.
- Da implement 4 engines: Semgrep, Gitleaks, Bandit, Trivy.
- Da co aggregator de chay multi-engine.
- Da chuan hoa output ve model `Finding`.
- Da co test cho engine registry, aggregator va parser.
- Gitleaks da duoc dua vao mot so flow quan trong nhu report, triage va serve.

Chua hoan tat:

- Command `radar scan` hien van dang goi Semgrep truc tiep, chua dung aggregator `scan_all()`.
- Chua co option CLI `--engine` de user chon engine can chay.
- Chua co command `radar engines` de hien thi trang thai cac engine.
- GitHub Action hien van chu yeu cai va chay Semgrep.
- README/docs chua duoc cap nhat day du theo mo hinh multi-engine.
- SARIF output hien van phu thuoc Semgrep native output, chua co SARIF exporter chung cho tat ca engine.

Ket luan trang thai: phan nen tang ky thuat da san sang, nhung can them mot vong tich hop CLI/CI/documentation de tinh nang multi-engine san sang cho user cuoi.

## 6. Loi ich ky vong

Neu hoan tat tich hop, Radar se co cac loi ich sau:

- Bao phu nhieu nhom rui ro hon: code vulnerability, secret leakage, dependency CVE, IaC misconfiguration.
- Giam phu thuoc vao mot engine duy nhat.
- Dashboard va risk ranking co them tin hieu tu nhieu nguon.
- Tien gan hon den mot security scanner tong hop co the dung trong local va CI.
- Kien truc plugin giup de mo rong them tool moi sau nay.

## 7. Rui ro va diem can quan ly

- Thoi gian scan co the tang neu mac dinh chay tat ca engines.
- Mot so tools nhu Bandit/Trivy/Gitleaks can runtime rieng, neu may user/CI chua cai thi se bi skip.
- Findings co the bi trung giua cac engine, nhat la secret scanning.
- Trivy Docker image dang dung `latest`; neu dung trong CI nen pin version de on dinh.
- Can quyet dinh SARIF se chi ho tro Semgrep hay xay exporter chung cho multi-engine.

## 8. De xuat next steps

Uu tien 1: Hoan tat CLI multi-engine

- Chuyen `radar scan` sang dung `scan_all()`.
- Them option `--engine` de chon engine.
- Them command `radar engines` de debug runtime va trang thai tools.

Uu tien 2: Dong bo cac flow hien co

- Chuyen `report`, `triage`, `serve` sang dung aggregator chung.
- Dam bao risk ranking/dashboard hien thi engine source ro rang.

Uu tien 3: Cap nhat CI va tai lieu

- Cap nhat README theo huong Radar la multi-engine scanner.
- Cap nhat GitHub Action de ho tro input `engines` hoac policy default ro rang.
- Quyet dinh cach xu ly SARIF cho multi-engine.

Uu tien 4: Kiem thu va on dinh

- Chay lai full test suite sau khi noi CLI.
- Kiem thu tren repo demo co Python dependency, secret va Dockerfile.
- Danh gia thoi gian scan khi bat tat ca engines.

## 9. Ket luan

Dot bo sung nay da dat nen mong quan trong de nang Security Radar tu Semgrep-based scanner thanh multi-engine security scanner. Gitleaks, Bandit va Trivy bo sung cac lop bao ve ma Semgrep khong bao phu het, dac biet la secrets, Python-specific issues, dependency CVE va IaC misconfiguration.

Phan core da duoc implement theo huong dung: co engine abstraction, registry, aggregator va normalized findings. Viec tiep theo can uu tien la hoan tat tich hop public-facing CLI/CI/docs de cac tools moi that su di vao workflow su dung hang ngay.
