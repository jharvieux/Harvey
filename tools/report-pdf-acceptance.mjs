// Browser/PDF acceptance runs in CI's bounded build step; fast HTML controls stay in Vitest.
/* global document, getComputedStyle */
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { resolve, join } from "node:path";
import { clearTimeout, setTimeout } from "node:timers";
import { fileURLToPath, pathToFileURL, URL } from "node:url";
import { chromium } from "playwright";
import { assertFindingNavigation } from "../report-template/navigation.mjs";

const root = fileURLToPath(new URL("../", import.meta.url));
const output = resolve(process.argv[2] ?? join(root, "tmp/report-pdf-acceptance"));
const fixture = join(root, "src/__fixtures__/report-navigation.json");
const doc = JSON.parse(readFileSync(fixture, "utf8"));
const python = process.env.HARVEY_PDF_PYTHON ?? "python3";
mkdirSync(output, { recursive: true });

function run(command, args, extraEnv = {}) {
  return new Promise((resolveResult, reject) => {
    const child = spawn(command, args, { cwd: root, env: { ...process.env, ...extraEnv }, stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "", stderr = "";
    child.stdout.on("data", (chunk) => { stdout += chunk; });
    child.stderr.on("data", (chunk) => { stderr += chunk; });
    const timer = setTimeout(() => child.kill("SIGKILL"), 120_000);
    child.once("error", (error) => { clearTimeout(timer); reject(error); });
    child.once("close", (status) => { clearTimeout(timer); resolveResult({ status, stdout, stderr }); });
  });
}

const rendered = await run(process.execPath, [join(root, "report-template/render.mjs"), fixture, output]);
assert.equal(rendered.status, 0, rendered.stderr);
const pdfPath = join(output, "report.pdf");
assert.match(rendered.stdout, /wrote .*report\.pdf/);
const pdf = readFileSync(pdfPath);
assert.equal(pdf.subarray(0, 5).toString(), "%PDF-");
const html = readFileSync(join(output, "report.html"), "utf8");
assertFindingNavigation(html);

// Fixture expectations are independent of the renderer's selected/link populations.
const linked = [...doc.findings.slice(0, 40), doc.findings[44], doc.findings[45], doc.findings[46]];
const expected = {
  link_count: 49,
  linked_findings: linked.map((f) => ({ id: f.id, detail: f.confidence === "N/A" ? [f.evidence] : [f.evidence, f.fix] })),
  required_text: [...doc.coverage.flatMap((r) => [r.detail, r.reason]), doc.findings[46].evidence,
    "4 more High finding(s) of this shape are not individually rendered", "+ 5 more qualifying action(s)"],
};
const expectedPath = join(output, "expected.json");
writeFileSync(expectedPath, JSON.stringify(expected, null, 2));
const inspect = (path) => run(python, [join(root, "tools/report-pdf-inspect.py"), path, expectedPath]);
const inspected = await inspect(pdfPath);
assert.equal(inspected.status, 0, inspected.stderr);
writeFileSync(join(output, "pdf-receipt.json"), inspected.stdout);

const browser = await chromium.launch();
try {
  const page = await browser.newPage();
  await page.goto(pathToFileURL(join(output, "report.html")).href);
  const links = page.locator("a.finding-link");
  assert.equal(await links.count(), 49);
  for (let i = 0; i < 49; i++) {
    const link = links.nth(i);
    const intended = await link.getAttribute("data-finding-link");
    const href = await link.getAttribute("href");
    const target = page.locator(href);
    assert.equal(await target.count(), 1);
    assert.equal(await target.getAttribute("data-finding-id"), intended);
    await link.click();
    await target.waitFor({ state: "visible" });
    const f = doc.findings.find((candidate) => candidate.id === intended);
    assert.ok((await target.innerText()).includes(f.evidence));
    if (f.confidence !== "N/A") assert.ok((await target.innerText()).includes(f.fix));
  }
  await links.first().focus();
  await page.keyboard.press("Tab");
  await page.keyboard.press("Shift+Tab");
  assert.equal(await links.first().evaluate((el) => getComputedStyle(el).outlineWidth), "3px");
  await page.keyboard.press("Enter");
  await page.waitForFunction(() => document.activeElement?.hasAttribute("data-finding-id"));

  // Dropping an actual target card must break both HTML navigation and the exported PDF.
  const brokenHtml = await page.evaluate(() => {
    document.querySelector('[data-finding-id="GROUP-44"]').remove();
    return document.documentElement.outerHTML;
  });
  assert.throws(() => assertFindingNavigation(brokenHtml), /no unique intended detail/);
  await page.locator("details.linked-findings").evaluateAll((nodes) => nodes.forEach((node) => { node.open = true; }));
  const missingRow = join(output, "control-missing-row.pdf");
  await page.pdf({ path: missingRow, format: "A4", printBackground: true });
  assert.notEqual((await inspect(missingRow)).status, 0, "Dropped detail must fail the independent consumer");
} finally {
  await browser.close();
}

const truncated = join(output, "control-truncated.pdf");
writeFileSync(truncated, pdf.subarray(0, 128));
assert.notEqual((await inspect(truncated)).status, 0, "Truncated requested PDF must fail");
const failedOutput = join(output, "control-render-failed");
mkdirSync(failedOutput, { recursive: true });
writeFileSync(join(failedOutput, "report.pdf"), pdf);
const failed = await run(process.execPath, [join(root, "report-template/render.mjs"), fixture, failedOutput],
  { PLAYWRIGHT_BROWSERS_PATH: join(output, "missing-browser") });
assert.notEqual(failed.status, 0, "A failed native PDF export must not report success");
assert.throws(() => readFileSync(join(failedOutput, "report.pdf")), /ENOENT/, "A previous PDF must not stand in for a failed export");
console.log(`PASS: native PDF, ${linked.length} destinations, 49 HTML links, keyboard navigation, cross-page PDF links and missing-row/truncated/render-failure controls. ${inspected.stdout.trim()}`);
