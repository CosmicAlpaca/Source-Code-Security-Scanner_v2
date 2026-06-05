# Phase 02 — PR comment bot + custom Semgrep rules

## Context Links

- Plan: [plan.md](plan.md) | Phụ thuộc: [phase-01](phase-01-scaffold-and-semgrep-workflow.md)
- [Semgrep rule syntax](https://semgrep.dev/docs/writing-rules/rule-syntax)
- [Testing rules](https://semgrep.dev/docs/writing-rules/testing-rules)

## Overview

- **Priority**: P1 | **Status**: complete-local-pending-github-verify
- Bot comment kết quả Semgrep vào PR (bảng severity/file/line/message) + 4-5 rule tự viết chứng minh hiểu Semgrep (điểm demo quan trọng).

## Key Insights

- Comment qua `actions/github-script@v7` + GITHUB_TOKEN mặc định, cần `permissions: pull-requests: write`. PR từ fork → token read-only, comment fail → chỉ chạy comment job khi `github.event.pull_request.head.repo.full_name == github.repository`.
- Update comment cũ thay vì spam comment mới: tìm comment có marker `<!-- security-radar -->` rồi update.
- Rule test convention: `rules/x.yaml` + `rules/x.js` fixture chứa dòng `// ruleid: x` → chạy `semgrep --test rules/`.

## Requirements

- FR1: PR có findings → 1 comment dạng bảng markdown, cập nhật (không spam)
- FR2: 0 findings → comment "✅ No security findings"
- FR3: ≥4 custom rules (JS + Python để show đa ngôn ngữ) có fixture test pass
- NFR: comment job < 30s

## Architecture

```
job semgrep (phase 1) → artifact semgrep.json
job pr-comment (needs: semgrep, if: pull_request)
  → download artifact → python scripts/render-pr-comment.py semgrep.json > comment.md
  → github-script: upsert comment có marker
```

## Related Code Files (repo `security-radar/`)

Create:
- `scripts/render-pr-comment.py` — JSON → markdown table (severity emoji, file:line link, rule id, message; group theo severity; cap 30 findings + "and N more")
- `rules/js-sql-string-concat.yaml` + fixture — string concat/template vào `db.query`/`.execute`
- `rules/js-hardcoded-jwt-secret.yaml` + fixture — `jwt.sign(payload, "literal")`
- `rules/js-child-process-user-input.yaml` + fixture — `exec()` nhận biến từ `req.*`
- `rules/py-subprocess-shell-true.yaml` + fixture — `subprocess.*(..., shell=True)` với f-string/concat
- `rules/py-flask-debug-true.yaml` + fixture — `app.run(debug=True)`

Modify:
- `.github/workflows/security-scan.yml` — thêm job `pr-comment`, bật lại `--config rules/`

## Implementation Steps

1. Viết 5 rules + fixtures (mỗi fixture có cả case `ruleid:` và `ok:`); `semgrep --test rules/` pass.
2. Viết `render-pr-comment.py`: đọc semgrep JSON schema (`results[].check_id, path, start.line, end.line, extra.severity, extra.message`), render markdown, marker `<!-- security-radar -->` ở đầu.
3. Thêm job vào workflow:

```yaml
  pr-comment:
    needs: semgrep
    if: github.event_name == 'pull_request' && github.event.pull_request.head.repo.full_name == github.repository
    runs-on: ubuntu-latest
    permissions: { pull-requests: write }
    steps:
      - uses: actions/checkout@v4
      - uses: actions/download-artifact@v4
        with: { name: semgrep-report }
      - run: python scripts/render-pr-comment.py semgrep.json > comment.md
      - uses: actions/github-script@v7
        with:
          script: |
            const fs = require('fs');
            const body = fs.readFileSync('comment.md', 'utf8');
            const {data: comments} = await github.rest.issues.listComments({...context.repo, issue_number: context.issue.number});
            const prev = comments.find(c => c.body.includes('<!-- security-radar -->'));
            if (prev) await github.rest.issues.updateComment({...context.repo, comment_id: prev.id, body});
            else await github.rest.issues.createComment({...context.repo, issue_number: context.issue.number, body});
```

4. Thêm CI job `rule-tests`: `semgrep --test rules/` (chạy trong container semgrep).
5. Mở PR thật chứa lỗi khớp custom rule → verify comment + Security tab.

## Todo List

- [x] 5 custom rules + fixtures, `semgrep --test` pass
- [x] render-pr-comment.py + unit test (pytest, fixture JSON)
- [ ] Job pr-comment upsert comment (test PR thật)
- [x] Job rule-tests trong CI
- [x] Workflow bật `--config rules/`

## Success Criteria

- PR demo: comment bảng lỗi xuất hiện và được update khi push thêm commit; rule tests xanh.

## Risk Assessment

- Semgrep JSON schema đổi giữa version → pin version image; test render script bằng fixture JSON commit kèm.
- Findings quá nhiều làm comment vượt 65k chars → cap 30 + link artifact.

## Security Considerations

- Job comment chỉ `pull-requests: write`, không cấp thêm. Escape markdown từ message/path tránh injection vào comment.

## Next Steps

→ Phase 03 graph core (độc lập, có thể song song với phase này).
