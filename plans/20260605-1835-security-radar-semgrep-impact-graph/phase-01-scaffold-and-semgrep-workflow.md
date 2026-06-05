# Phase 01 — Scaffold repo + Semgrep GitHub Actions workflow

## Context Links

- Plan: [plan.md](plan.md) | Brainstorm: [report](../reports/brainstorm-260605-security-radar-semgrep-impact-graph.md)
- [Semgrep + GH Code Scanning](https://0xdbe.github.io/GitHub-HowToEnableCodeScanningWithSemgrep/)
- [Semgrep CI docs](https://semgrep.dev/docs/semgrep-ci/sample-ci-configs#github-actions)

## Overview

- **Priority**: P0 — nền tảng cho mọi phase sau
- **Status**: pending
- Tạo repo mới `E:\Documents\AI_Vin\security-radar` (git init + GitHub repo) + workflow Semgrep chạy được thật: scan đa ngôn ngữ → SARIF lên Security tab + JSON artifact.

## Key Insights

- Semgrep image chính thức: `semgrep/semgrep` (Docker). Lệnh `semgrep scan` không cần account; `semgrep ci` cần SEMGREP_APP_TOKEN nếu connect platform — ta dùng `semgrep scan` (KISS, không phụ thuộc account).
- SARIF upload cần `permissions: security-events: write`. GitHub Code Scanning (tab Security) hoạt động trên public repo free; private repo cần GHAS → **tạo repo PUBLIC**.
- Semgrep ≥1.39 hỗ trợ `--sarif-output=` song song `--json --output=` → 1 lần scan, 2 output.
- Workflow KHÔNG fail build ở phase này (continue-on-error cho step scan exit code) — chính sách block để sau.

## Requirements

- FR1: push/PR/cron/manual đều trigger scan
- FR2: findings hiện ở tab Security (SARIF)
- FR3: JSON report là artifact tải được
- NFR: workflow < 5 phút trên repo demo; không cần secret/account ngoài GITHUB_TOKEN

## Architecture

```
.github/workflows/security-scan.yml
  job: semgrep
    container: semgrep/semgrep
    steps: checkout → semgrep scan (json + sarif) → upload-sarif → upload-artifact
```

## Related Code Files (repo mới `security-radar/`)

Create:
- `.github/workflows/security-scan.yml`
- `pyproject.toml` (package `radar`, deps: click, rich, networkx, tree_sitter, tree_sitter_javascript, tree_sitter_typescript, tree_sitter_python, pyyaml; dev: pytest)
- `src/radar/__init__.py`, `src/radar/cli.py` (skeleton click group: `build`, `impact`)
- `rules/.gitkeep`, `tests/__init__.py`, `README.md`, `.gitignore`

## Implementation Steps

1. `git init` repo mới tại `E:\Documents\AI_Vin\security-radar`, tạo GitHub repo **public** (`gh repo create security-radar --public`), push main.
2. Scaffold Python package (pyproject, src layout, cli skeleton chạy được `radar --help`).
3. Viết `security-scan.yml`:

```yaml
name: Security Scan
on:
  pull_request:
  push: { branches: [main] }
  schedule: [{ cron: "20 17 * * *" }]
  workflow_dispatch:

permissions:
  contents: read

jobs:
  semgrep:
    runs-on: ubuntu-latest
    container: { image: semgrep/semgrep }
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@v4
      - name: Semgrep scan
        run: >
          semgrep scan
          --config p/security-audit --config p/secrets --config p/owasp-top-ten
          --config rules/
          --json --output semgrep.json
          --sarif-output semgrep.sarif
          --metrics off
        continue-on-error: true
      - uses: github/codeql-action/upload-sarif@v3
        with: { sarif_file: semgrep.sarif }
        if: always()
      - uses: actions/upload-artifact@v4
        with: { name: semgrep-report, path: "semgrep.*" }
        if: always()
```

4. Commit 1 file JS có lỗi cố ý (vd `demo/vulnerable.js` với `db.query("SELECT * FROM users WHERE id=" + req.query.id)`) → mở PR test → verify finding hiện ở tab Security + artifact.
5. Xóa/giữ file demo trong folder `demo/` (giữ — dùng lại phase 6).

## Todo List

- [ ] Repo mới + GitHub public repo + push
- [ ] Python package skeleton (`radar --help` chạy)
- [ ] security-scan.yml đủ 4 trigger
- [ ] SARIF hiện trên tab Security (verify bằng PR thật)
- [ ] Artifact JSON tải được
- [ ] README mô tả 2 subsystem

## Success Criteria

- Workflow xanh trên GitHub thật; finding demo hiện ở Security tab; artifact tồn tại.

## Risk Assessment

- `rules/` rỗng làm semgrep lỗi config → để `.gitkeep` + 1 rule placeholder hợp lệ (phase 2 thay) hoặc bỏ `--config rules/` đến phase 2.
- Private repo không có Code Scanning → bắt buộc public.
- `--sarif-output` không có ở semgrep cũ → pin image tag mới (vd `semgrep/semgrep:latest` hoặc version cụ thể ≥1.60).

## Security Considerations

- `--metrics off` tránh gửi telemetry. Không commit secret; GITHUB_TOKEN mặc định đủ.
- `permissions` khai báo tối thiểu ở cả workflow-level và job-level.

## Next Steps

→ Phase 02 (PR comment + custom rules) gắn vào workflow này.
