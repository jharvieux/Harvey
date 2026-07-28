// pnpm exec tsx src/cli/validate-render-fidelity.ts <findings.json>
//
// #1435 — run the render-seam check against a REAL engagement deliverable, not only the fixture the
// test suite carries. `src/render-fidelity.test.ts` is the standing gate (it rides inside
// `pnpm verify`, no browser needed); this is the same check pointed at whatever findings document is
// about to be rendered for a client, because the fixture proves the renderer keeps ITS rows and says
// nothing about the rows a particular engagement produced.
//
// Renders through the real `buildHtml` — the same function report-template/render.mjs writes
// report.html from, and it runs before `chromium.launch()`, so no Chromium is required here either.
//
// Exit 1 on any breach: a finding whose own words did not reach the rendered report and whose
// omission is not disclosed and counted.

import { readFileSync } from "node:fs";
import { buildHtml } from "../../report-template/render.mjs";
import { renderFidelityBreaches } from "../render-fidelity.js";
import type { FindingsDocument } from "../findings.js";

const path = process.argv[2];
if (!path) {
  console.error("usage: pnpm exec tsx src/cli/validate-render-fidelity.ts <findings.json>");
  process.exit(1);
}

const doc = JSON.parse(readFileSync(path, "utf8")) as FindingsDocument;
const breaches = renderFidelityBreaches(doc, buildHtml(doc));

console.log(`Render-seam fidelity (#1435) over ${path}: ${doc.findings.length} finding(s), ${doc.findings.filter((f) => f.confidence === "N/A").length} of them not-assessed rows.`);
if (breaches.length === 0) {
  console.log("GATE PASS — every finding's own words reach the rendered report, or its omission is disclosed with the right count.");
  process.exit(0);
}
console.error(`\nGATE FAIL — ${breaches.length} finding(s) lost content at the render seam:`);
for (const b of breaches) console.error(`  ${b.kind.toUpperCase()}  ${b.id} — ${b.detail}`);
process.exit(1);
