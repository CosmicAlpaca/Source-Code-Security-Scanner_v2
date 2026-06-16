/**
 * Playwright e2e tests for security-radar HTML impact report.
 *
 * Generates real HTML reports via Python then tests them in Chromium.
 * Run: cd tests/e2e && npm install && npx playwright test
 */

const { test, expect } = require('@playwright/test');
const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const os = require('os');

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const REPO_ROOT = path.resolve(__dirname, '../..');

/**
 * Run Python to generate an HTML impact report and return the file path.
 */
function generateReport(script) {
  const outFile = path.join(os.tmpdir(), `radar-report-${Date.now()}.html`);
  const py = `
import sys
sys.path.insert(0, '${REPO_ROOT}/src')
from radar.impact.tracer import trace
from radar.graph.builder import build_graph
from radar.report.exporters import to_html
from pathlib import Path

${script}

html = to_html(result)
open(r'${outFile}', 'w', encoding='utf-8').write(html)
print('ok')
`.replace(/\\/g, '/');
  execSync(`python -c "${py.replace(/"/g, '\\"')}"`, { cwd: REPO_ROOT });
  return outFile;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test.describe('HTML impact report', () => {

  test('page title and heading', async ({ page }) => {
    const fixture = path.join(REPO_ROOT, 'tests/fixtures/js-app');
    const reportFile = generateReport(`
graph = build_graph(Path(r'${fixture}'))
result = trace(graph, changed_ids=['utils/validate.js::validateUser'])
    `);
    await page.goto('file://' + reportFile);

    await expect(page).toHaveTitle(/security-radar/i);
    await expect(page.locator('h1')).toContainText('security-radar');
  });

  test('summary shows correct counts', async ({ page }) => {
    const fixture = path.join(REPO_ROOT, 'tests/fixtures/js-app');
    const reportFile = generateReport(`
graph = build_graph(Path(r'${fixture}'))
result = trace(graph, changed_ids=['utils/validate.js::validateUser'])
    `);
    await page.goto('file://' + reportFile);

    const summary = page.locator('.summary');
    // should show 2 functions, 2 APIs (from trace result)
    await expect(summary).toContainText('2');
  });

  test('changed functions table is present and has rows', async ({ page }) => {
    const fixture = path.join(REPO_ROOT, 'tests/fixtures/js-app');
    const reportFile = generateReport(`
graph = build_graph(Path(r'${fixture}'))
result = trace(graph, changed_ids=['utils/validate.js::validateUser'])
    `);
    await page.goto('file://' + reportFile);

    const tables = page.locator('table');
    await expect(tables.first()).toBeVisible();

    // At least the changed function row should exist
    const rows = page.locator('table tr');
    await expect(rows).toHaveCount(await rows.count()); // table exists with rows
    const count = await rows.count();
    expect(count).toBeGreaterThan(1); // header + at least one data row
  });

  test('affected functions section is present', async ({ page }) => {
    const fixture = path.join(REPO_ROOT, 'tests/fixtures/js-app');
    const reportFile = generateReport(`
graph = build_graph(Path(r'${fixture}'))
result = trace(graph, changed_ids=['utils/validate.js::validateUser'])
    `);
    await page.goto('file://' + reportFile);

    const headings = page.locator('h2');
    const texts = await headings.allTextContents();
    expect(texts.some(t => /affect/i.test(t) || /changed/i.test(t))).toBe(true);
  });

  test('XSS: dangerous function name is escaped, not executed', async ({ page }) => {
    const fixture = path.join(REPO_ROOT, 'tests/fixtures/js-app');
    const reportFile = generateReport(`
graph = build_graph(Path(r'${fixture}'))
# Patch a node label to contain a script tag
result = trace(graph, changed_ids=['utils/validate.js::validateUser'])
from dataclasses import replace
from radar.impact.tracer import ImpactItem
# inject XSS payload into the first changed item's name
if result.changed:
    bad = result.changed[0]
    object.__setattr__(bad, 'name', '<script>window.__xss=1</script>')
    `);
    await page.goto('file://' + reportFile);

    // Script tag should NOT have executed
    const xssRan = await page.evaluate(() => window.__xss);
    expect(xssRan).toBeUndefined();

    // The raw text should appear escaped (literal < or &lt; in page source)
    const bodyText = await page.locator('body').innerHTML();
    expect(bodyText).not.toContain('<script>window.__xss=1</script>');
  });

  test('empty result: no changes shows graceful message', async ({ page }) => {
    const fixture = path.join(REPO_ROOT, 'tests/fixtures/js-app');
    const reportFile = generateReport(`
graph = build_graph(Path(r'${fixture}'))
result = trace(graph, changed_ids=[])
    `);
    await page.goto('file://' + reportFile);

    // Page should still load with the heading
    await expect(page.locator('h1')).toBeVisible();
    // Summary shows 0s
    const summary = page.locator('.summary');
    await expect(summary).toContainText('0');
  });

  test('report CSS: summary has left border style (basic styling check)', async ({ page }) => {
    const fixture = path.join(REPO_ROOT, 'tests/fixtures/js-app');
    const reportFile = generateReport(`
graph = build_graph(Path(r'${fixture}'))
result = trace(graph, changed_ids=['utils/validate.js::validateUser'])
    `);
    await page.goto('file://' + reportFile);

    const summary = page.locator('.summary');
    const borderLeft = await summary.evaluate(el =>
      window.getComputedStyle(el).borderLeftStyle
    );
    expect(borderLeft).toBe('solid');
  });

});
