// Browser/PDF acceptance runs in CI's bounded build step; fast HTML controls stay in Vitest.
/* global document, getComputedStyle */
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
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

// These expected populations are acceptance evidence, independent of renderer classification.
const dispositionFixture = JSON.parse(readFileSync(join(root, "src/__fixtures__/dispositions/scenarios.json"), "utf8"));
const rendererSource = readFileSync(join(root, "report-template/render.mjs"), "utf8");
const populationMutants = [
  ["chart-only", "for (const x of f) counts[x.severity]", "for (const x of all) counts[x.severity]", "Rendered donut count mismatch"],
  ["cover-only", 'const sevCount = (s) => f.filter((x) => findingModule(x) === "M1" && x.assessment.disposition === "confirmed" && x.severity === s).length;', 'const sevCount = (s) => all.filter((x) => findingModule(x) === "M1" && x.severity === s).length;', "Rendered M1 severity panel mismatch"],
  ["action-only", "const actionAll = [...f]", "const actionAll = [...all]", "Non-actionable population entered action plan"],
];
for (const [name, before] of populationMutants) assert.equal(rendererSource.split(before).length, 2, `${name} control must mutate exactly one production expression`);
for (const [name, confirmed, pending, inventory, historical, total] of [["ATC", 8, 1312, 90, 83, 1502], ["AoP", 1, 708, 1, 0, 719]]) {
  const findings = dispositionFixture.scenarios[name].flatMap((group) => Array.from({ length: group.count }, (_, index) => ({
    ...dispositionFixture.templates[group.template], id: `${name}-${group.template}-${index}`, location: `src/${group.template}/${index}.ts`,
  })));
  const targetDir = join(output, name); mkdirSync(targetDir, { recursive: true });
  const inputPath = join(targetDir, "input.json");
  const rawPath = join(targetDir, "raw.json");
  const context = { engagementId: `${name}-current`, kind: "client-audit", target: { id: `fixture:${name}`, revision: "current" }, producerVersions: { scanner: "current" }, schemaVersion: "1", assessedScope: ["source", "schema"], scopeComplete: true };
  const current = { meta: { ...dispositionFixture.meta, client: `${name} synthetic disposition acceptance` }, findings, testQuality: dispositionFixture.testQuality, auditContext: context };
  const prior = { ...current, findings: name === "ATC" ? findings.slice(0, 8) : findings.slice(1, 56).map((f, i) => ({ ...f, id: `old-${i}`, taxonomy: `Legacy scanner: ${f.taxonomy}`, location: `legacy-layout/${i}.ts` })), auditContext: name === "ATC" ? { ...context, kind: "same-run-checkpoint", scopeComplete: false } : { ...context, engagementId: `${name}-prior`, producerVersions: { scanner: "legacy" }, assessedScope: ["source"] } };
  writeFileSync(rawPath, JSON.stringify({ ...current, findings: [...findings, ...findings.slice(confirmed, confirmed + 3)] }));
  const priorPath = join(targetDir, "prior.json"); writeFileSync(priorPath, JSON.stringify(prior));
  const compared = await run(process.execPath, ["--import", "tsx", "--input-type=module", "-e", 'import fs from "node:fs"; import { applyBaseline } from "./src/audit-diff.ts"; import { assembleEngagementDocument } from "./src/audit-report.ts"; const [rawPath, priorPath, output] = process.argv.slice(1); const raw = JSON.parse(fs.readFileSync(rawPath)); const doc = { ...assembleEngagementDocument([], { connected:false, dynamic:false, llm:false }, raw.findings, raw.meta, [], {}, raw.testQuality), auditContext: raw.auditContext }; fs.writeFileSync(output, JSON.stringify(applyBaseline(doc, JSON.parse(fs.readFileSync(priorPath)))));', rawPath, priorPath, inputPath]);
  assert.equal(compared.status, 0, compared.stderr);
  const rendered = await run(process.execPath, [join(root, "report-template/render.mjs"), inputPath, targetDir]);
  assert.equal(rendered.status, 0, rendered.stderr);
  const document = JSON.parse(readFileSync(join(targetDir, "findings.report.json"), "utf8"));
  assert.equal(document.findings.length, total);
  assert.deepEqual(document.populations.counts, { confirmed, actionable: 6, "pending-review": pending, "false-positive": 3, inventory, superseded: historical, "not-applicable": 0 });
  const linked = findings.filter((f) => f.id.includes("-confirmed-") || /-M[4-9]-/.test(f.id));
  const expected = {
    link_count: confirmed + 12,
    linked_findings: linked.map((f) => ({ id: f.id, detail: [f.evidence, f.fix] })),
    required_text: ["39.7%", "58.6%", "Pending review", "Data inventory", "False positives", ...(historical ? ["Superseded evidence", "fixture://M8/current-mutation-report", "not a prior client audit"] : ["Producer, rule or schema versions changed"])],
    populations: {
      chart_total: confirmed + 6,
      confirmed_m1_counts: { Critical: 0, High: confirmed, Medium: 0, Low: 0 },
      cover_text: [`Accounted population: ${total}`, `Confirmed defects: ${confirmed}`, `Current health findings: 6`, `Pending review: ${pending}`, `Data inventory: ${inventory}`, `Superseded evidence: ${historical}`, `Current actionable population: ${confirmed + 6}`, `Prior population ${name === "ATC" ? 8 : 55}; current population ${total}`, `Comparison: ${name === "ATC" ? "Same engagement checkpoint" : "Producer or rule changes"}`],
      forbidden_actions: ["Raw scanner candidate", "Classified sensitive table", "Historical surviving mutant", "Independently rejected candidate", "Transitive advisory"],
      required_actions: Array.from({ length: 6 }, (_, i) => `Current M${i + 4} health work`),
    },
  };
  expected.required_text.push(`Produced ${total + 3} = delivered ${total} + deduplicated 3`, "byte-identical duplicate capture(s) collapsed");
  const expectationPath = join(targetDir, "expected.json"); writeFileSync(expectationPath, JSON.stringify(expected, null, 2));
  const inspected = await run(python, [join(root, "tools/report-pdf-inspect.py"), join(targetDir, "report.pdf"), expectationPath]);
  assert.equal(inspected.status, 0, inspected.stderr);
  writeFileSync(join(targetDir, "pdf-receipt.json"), inspected.stdout);
  const controls = [];
  for (const [control, before, after, failure] of [...populationMutants, ["restored", "", "", ""]]) {
    const controlDir = join(targetDir, "population-controls", control);
    mkdirSync(controlDir, { recursive: true });
    const source = control === "restored" ? rendererSource : rendererSource.replace(before, after);
    // Only the disposable renderer copy changes; imports keep the real production
    // dependencies and the same native export path without another dependency tree.
    const executable = source.replaceAll('from "playwright"', `from ${JSON.stringify(import.meta.resolve("playwright"))}`)
      .replace(/from "(\.\/[^"]+)"/g, (_match, specifier) => `from ${JSON.stringify(pathToFileURL(join(root, "report-template", specifier)).href)}`);
    const rendererPath = join(controlDir, "render.mjs");
    writeFileSync(rendererPath, executable);
    const exported = await run(process.execPath, [rendererPath, inputPath, controlDir]);
    writeFileSync(join(controlDir, "render.log"), exported.stdout + exported.stderr);
    assert.equal(exported.status, 0, exported.stderr);
    const checked = await run(python, [join(root, "tools/report-pdf-inspect.py"), join(controlDir, "report.pdf"), expectationPath]);
    writeFileSync(join(controlDir, "inspect.log"), checked.stdout + checked.stderr);
    if (control === "restored") assert.equal(checked.status, 0, checked.stderr);
    else {
      assert.notEqual(checked.status, 0, `${name} ${control} must fail the independent PDF consumer`);
      assert.ok(checked.stderr.includes(`AssertionError: ${failure}`), checked.stderr);
    }
    controls.push({ control, sourceSha256: createHash("sha256").update(source).digest("hex"), renderExit: exported.status, inspectorExit: checked.status, expectedFailure: failure || undefined });
  }
  assert.equal(readFileSync(join(root, "report-template/render.mjs"), "utf8"), rendererSource);
  writeFileSync(join(targetDir, "population-controls.json"), JSON.stringify(controls, null, 2));
  console.log(`PASS: ${name} actual PDF populations, action exclusions, current M4–M9 actions and measured M8 scores. ${inspected.stdout.trim()}`);
}
