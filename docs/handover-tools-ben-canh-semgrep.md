# Handover: bo sung tools ben canh Semgrep

Ngay ban giao: 2026-06-24

## 1. Muc tieu thay doi

Du an ban dau dung Semgrep lam engine chinh de quet SAST va custom OWASP rules. Dot thay doi nay mo rong huong scan theo mo hinh multi-engine, de Radar co the nhan tin hieu tu nhieu cong cu:

- Semgrep: SAST + custom OWASP rules hien co.
- Gitleaks: secret scanning, bat API keys/tokens/credentials.
- Bandit: Python-specific SAST, bo sung cac rule AST-based cua Python.
- Trivy: SCA dependency CVE, IaC misconfiguration va secret scanning.

Dinh huong kien truc la tat ca engine deu normalize ve cung model `Finding`, sau do cac lop phia sau nhu suppression, risk ranking, dashboard, triage va blast-radius overlay co the xu ly nhu nhau.

## 2. Cac file/chuc nang moi lien quan

### 2.1. Scan engine plugin layer

Thu muc chinh:

- `src/radar/scan/engines/base.py`
- `src/radar/scan/engines/__init__.py`
- `src/radar/scan/engines/semgrep_engine.py`
- `src/radar/scan/engines/gitleaks_engine.py`
- `src/radar/scan/engines/bandit_engine.py`
- `src/radar/scan/engines/trivy_engine.py`

`base.py` dinh nghia abstract class `ScanEngine` gom:

- `name`: id on dinh cua engine, vi du `semgrep`, `gitleaks`, `bandit`, `trivy`.
- `description`: mo ta ngan.
- `default`: engine co chay trong default set hay khong.
- `detect()`: kiem tra runtime co san khong, phai re va khong side-effect.
- `scan()`: chay scanner va tra ve `list[Finding]`.

`__init__.py` tu dong import cac module engine bang `pkgutil.iter_modules`, moi engine tu `register()` luc import. Ham quan trong:

- `all_engines()`: danh sach engine da dang ky.
- `default_engine_names()`: engine default.
- `scan_all(target, rules_only=False, engines=None, extra_config=None, emit=None)`: aggregator chay cac engine duoc chon, merge finding, dedup, sort.
- `ran_any(runs)`: check co engine nao chay thanh cong.
- `runs_summary(runs)`: summary dang `semgrep:4  trivy:2  bandit:skipped`.

Nguyen tac xu ly loi: engine unavailable/fail thi ghi vao `EngineRun`, bo qua engine do, khong lam hong toan bo scan. Caller se quyet dinh neu khong co engine nao chay duoc thi co fail hay khong.

### 2.2. Semgrep engine

File: `src/radar/scan/engines/semgrep_engine.py`

Day la adapter mong quanh code cu:

- `detect()` goi `radar.scan.runner.detect_runtime()`.
- `scan()` goi `run_semgrep(...)`, parse bang `radar.scan.findings.parse(...)`.

Semgrep van la engine SAST chinh, ho tro native, `python -m semgrep`, Docker fallback, custom rules bundled trong `src/radar/rules/`.

### 2.3. Gitleaks engine

File engine: `src/radar/scan/engines/gitleaks_engine.py`

Runner san co: `src/radar/scan/gitleaks_runner.py`

Muc dich: bat secret nhu API key, token, credential. Finding duoc gan rule dang `gitleaks.<RuleID>`, severity hien la `ERROR`, metadata OWASP `A02:2021-Cryptographic Failures`.

Luu y quan trong:

- Engine `detect()` duoc thiet ke side-effect-free: chi check native binary, vendored binary trong `~/.radar/bin`, hoac Docker. Khong auto-download.
- `gitleaks_runner.detect_runtime()` hien co kha nang auto-download Gitleaks 8.18.2 vao `~/.radar/bin`; cai nay dang duoc dung o cac luong goi runner truc tiep.
- Runner hien tao temp JSON o `target.parent`, sau do xoa file. Viec nay khong ghi vao repo target neu target la thu muc con? Neu target la root repo, temp file nam o parent cua repo, khong nam trong repo. Docker path mount parent de container ghi report.

### 2.4. Bandit engine

File: `src/radar/scan/engines/bandit_engine.py`

Muc dich: bo sung SAST rieng cho Python. Runtime:

- native `bandit` tren PATH; hoac
- `python -m bandit` neu package da cai.

Command chay: `bandit -r <target> -f json -q`.

Parser map:

- Bandit `HIGH` -> Radar `ERROR`
- `MEDIUM` -> `WARNING`
- `LOW` -> `INFO`

Rule id duoc normalize thanh `bandit.Bxxx`. Mot so Bandit test id duoc map truc tiep sang OWASP:

- Injection: B102, B307, B608-B611, B701-B703, B6xx/B7xx fallback -> A03.
- Deserialization/integrity: B301, B302, B506 -> A08.
- Crypto/cleartext/SSL: B303-B305, B311, B312, B321, B323, B324, B413, B502-B505 -> A02.
- Auth/secret: B105-B107, B501, B507 -> A07.
- Misconfig/XML: B104, B201, B313-B320, B405-B411 -> A05.
- Access/temp/file perms/tar: B103, B108, B202, B306 -> A01.
- SSRF: B310 -> A10.

### 2.5. Trivy engine

File: `src/radar/scan/engines/trivy_engine.py`

Muc dich: bo sung phan Semgrep khong bao phu tot:

- dependency CVEs/SCA
- IaC misconfiguration
- embedded secrets

Runtime:

- native `trivy`; hoac
- Docker image `aquasec/trivy:latest`.

Command native tuong duong:

```bash
trivy fs --quiet --format json --scanners vuln,misconfig,secret <target>
```

Parser map:

- Trivy `CRITICAL`/`HIGH` -> Radar `ERROR`
- `MEDIUM` -> `WARNING`
- `LOW`/`UNKNOWN` -> `INFO`

OWASP:

- Vulnerability/CVE -> A06 Vulnerable and Outdated Components.
- Misconfiguration -> A05 Security Misconfiguration.
- Secret -> A02 Cryptographic Failures.

## 3. Tinh trang tich hop hien tai

### Da co

- Multi-engine registry va aggregator da co trong `src/radar/scan/engines/`.
- 4 engine Semgrep/Gitleaks/Bandit/Trivy da register tu dong.
- Test cho registry, aggregator, parser va engine adapter nam trong `tests/test_scan_engines.py`.
- Gitleaks da duoc goi truc tiep trong cac luong:
  - `radar report` trong `src/radar/cli.py`
  - `radar triage` qua `src/radar/triage/engine.py`
  - `radar serve` qua `src/radar/serve/pipeline.py`

### Chua dong bo hoan toan

Co mot do lech can xu ly truoc khi coi multi-engine la fully integrated:

- `radar scan` trong `src/radar/cli.py` van goi Semgrep truc tiep bang `detect_runtime()` va `run_semgrep()`, chua dung `scan_all()`.
- `radar scan` hien chua co option `--engine`, trong khi `tests/test_scan_engines.py` da co test ky vong `radar scan ... --engine semgrep`.
- `radar engines` command chua thay trong `src/radar/cli.py`, trong khi test da ky vong command nay list ca 4 engine.
- `action.yml` van cai `semgrep` va chay `radar scan`; do `radar scan` chua dung aggregator nen CI Action hien van chu yeu la Semgrep.
- README va docs chinh van mo ta scan = Semgrep. Chua cap nhat theo multi-engine.
- `pyproject.toml` chua khai bao dependency/extra cho `bandit` hay `trivy`; hien chung duoc coi la external tools can cai rieng. Gitleaks co runner auto-download rieng, nhung engine detect thi khong auto-download.

Ket luan: phan engine abstraction da san sang, nhung CLI/public docs/Action chua noi het vao aggregator. Trang thai nen goi la "multi-engine layer da implement, tich hop mot phan".

## 4. Cach chay/kiem thu hien tai

### Chay Radar theo luong hien co

```bash
pip install -e ".[dev,watch]"
radar scan . --rules-only
radar report . --rules-only --out radar-dashboard.html
radar triage . --rules-only --min-risk 80
radar serve . --rules-only
```

Luu y: `scan` hien tai van Semgrep-only. `report`, `triage`, `serve` co them Gitleaks truc tiep.

### Kiem tra engine registry/parser

```bash
pytest tests/test_scan_engines.py
```

Neu test `radar engines` hoac `radar scan --engine` fail, day la do CLI chua duoc noi vao aggregator, khong phai parser/engine layer hong.

### Cai external tools de test thu cong

Semgrep:

```bash
pip install semgrep
```

Bandit:

```bash
pip install bandit
```

Trivy:

```bash
# Cai native theo OS, hoac dung Docker neu da co Docker Desktop
trivy fs --version
```

Gitleaks:

```bash
gitleaks version
```

Neu khong co Gitleaks native, cac luong goi `gitleaks_runner` truc tiep co the auto-download vao `~/.radar/bin`. Rieng `GitleaksEngine.detect()` khong auto-download de dam bao detect khong gay side-effect.

## 5. De xuat viec tiep theo

### 5.1. Noi `radar scan` vao aggregator

Trong `src/radar/cli.py`, command `scan` nen:

- them option `--engine` multiple choice hoac repeatable string.
- goi `scan_all(...)` thay cho `detect_runtime()` + `run_semgrep()` khi output la terminal/json/html.
- van can xu ly rieng `--format sarif`: SARIF hien chi Semgrep co native output. Co 2 huong:
  - Giu SARIF = Semgrep-only va ghi ro trong docs.
  - Hoac viet SARIF exporter tu `Finding` chung, phuc tap hon.
- ap dung suppression sau khi merge findings.
- record history theo merged findings.
- gate `--error/--fail-on` theo merged findings.
- in `runs_summary(runs)` de user biet engine nao chay/skip/error.

### 5.2. Them command `radar engines`

Command nay nen list:

- name
- default on/off
- detect status/runtime
- description

Muc tieu la giup user debug may minh thieu tool nao.

### 5.3. Cap nhat `report`, `triage`, `serve`

Hien 3 luong nay dang Semgrep + Gitleaks truc tiep. Nen chuyen sang `scan_all()` de Bandit/Trivy cung tham gia:

- `report`: dung merged findings cho dashboard/risk/history.
- `triage`: can can nhac AI verdict cho Trivy CVE va Bandit findings. Prompt hien dang doc code snippet quanh finding; voi dependency CVE line = 0 thi snippet rong, van can handling dep/package context trong prompt.
- `serve`: live incremental scan dang co logic scan 1 file; multi-engine cho Trivy/Gitleaks co the nang hon, nen can chon policy:
  - full-state initial: chay all engines.
  - on-save fast path: co the chi Semgrep/Gitleaks file-level, Trivy debounce/chay theo lockfile.

### 5.4. Cap nhat docs va Action

README can doi thong diep tu "scan bang Semgrep" sang "scan bang multi-engine, Semgrep la SAST chinh". Nen them bang pham vi:

- Semgrep: source code SAST/custom rules.
- Bandit: Python SAST.
- Gitleaks: secrets.
- Trivy: dependency/IaC/secrets.

`action.yml` can quyet dinh:

- Co cai them Bandit/Trivy/Gitleaks trong composite action khong.
- Neu co, can can nhac thoi gian CI va cache.
- Mac dinh co the van Semgrep-only de nhanh, them input `engines`.

### 5.5. Lam ro zero-footprint

Semgrep Docker mount target read-only. Trivy Docker cung mount target read-only. Bandit doc code va emit stdout JSON. Gitleaks runner hien dung file temp ngoai target repo roi xoa; nen document ro "khong ghi vao repo target", nhung van co temp artifact o parent directory trong thoi gian chay.

## 6. Rui ro/diem can chu y

- Duplicate signal: Semgrep, Gitleaks va Trivy secret scanner co the cung bat secret. Aggregator chi dedup exact duplicate trong cung engine, khong dedup cross-engine. Day la chu y co chu dich, nhung UI co the can group de tranh noise.
- Runtime variability: Bandit/Trivy/Gitleaks khong nam trong Python dependencies mac dinh, nen tren may moi co the bi skipped. Can hien summary ro.
- SARIF: multi-engine findings chua co SARIF exporter chung, nen Security tab trong GitHub Action van phu thuoc Semgrep SARIF.
- Trivy Docker image `latest` co tinh bat on theo thoi gian. Neu can reproducible CI, nen pin version.
- Gitleaks runner co auto-download qua network; engine detect khong auto-download. Can thong nhat hanh vi neu dua vao CLI public.
- `tests/test_scan_engines.py` hien co ky vong CLI chua duoc implement. Neu chay full test ma fail o do, day la viec can finish tiep.

## 7. Checklist ban giao nhanh

- [x] Engine interface va registry da co.
- [x] Semgrep/Gitleaks/Bandit/Trivy engines da implement.
- [x] Parser Bandit va Trivy da normalize ve `Finding`.
- [x] Aggregator `scan_all()` da merge/sort/dedup va ghi status tung engine.
- [x] Gitleaks da co trong `report`, `triage`, `serve`.
- [ ] `radar scan` chua dung `scan_all()`.
- [ ] `radar scan --engine` chua co trong CLI.
- [ ] `radar engines` chua co trong CLI.
- [ ] README/Action/docs chua cap nhat day du cho multi-engine.
- [ ] Full test can duoc chay lai sau khi noi CLI.

## 8. Goi y code path cho nguoi tiep nhan

Neu tiep tuc lam ngay, bat dau theo thu tu:

1. Mo `tests/test_scan_engines.py` de xem behavior mong muon.
2. Sua `src/radar/cli.py` command `scan` dung `scan_all()`, them `--engine`.
3. Them command `engines` vao `src/radar/cli.py`.
4. Chay `pytest tests/test_scan_engines.py tests/test_scan_cli.py`.
5. Sau khi xanh, moi cap nhat README/action/docs.

Phan kho nhat khong nam o parser nua, ma nam o policy public: SARIF se Semgrep-only hay multi-engine, va default CI co nen cai/chay tat ca engine hay khong.
