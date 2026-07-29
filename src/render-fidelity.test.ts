// #1435 — the gate that was missing. `notApplicableSection` now has unit tests; a unit test on one
// section does not reach the NEXT seam that drops content, which is the whole shape of this defect
// class (#1040/#1062): the producer is right, the ledger is clean, the run exits 0, and the client's
// report is wrong.
//
// So this runs the REAL path end to end — real disclosure-row producers → the real assembler
// (`assembleEngagementDocument`) → the real renderer (`buildHtml`, which is what writes report.html)
// → an assertion on the rendered HTML. `report.html` is written before `chromium.launch()`, so no
// browser is involved and this rides inside `pnpm verify`.
//
// The controls matter more than the pass. Each reproduces one way the last seam can lose content —
// including the exact defect that shipped, reconstructed verbatim — and asserts this gate goes red.

import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { buildHtml } from "../report-template/render.mjs";
import { esc } from "../report-template/sections.mjs";
import { assembleEngagementDocument } from "./audit-report.js";
import { checkUnreadSourceExtensions } from "./scan/ext-coverage.js";
import { renderFidelityBreaches } from "./render-fidelity.js";
import type { EngagementEnv, ModuleCoverage } from "./audit-coverage.js";
import type { Finding, FindingsDocument, ReportMeta } from "./findings.js";

const META: ReportMeta = {
  client: "Acme", subtitle: "Full audit", date: "2026-07-28", commit: "abc1234", auditor: "Harvey",
  confidential: true, overallHealth: 6, tenantIsolation: "Not verified", authModel: "Supabase",
  headline: "Ten-module audit", scope: "the app repo at abc1234", methodology: "M1–M10",
  outOfScope: "infrastructure",
};

const ENV: EngagementEnv = { connected: false, dynamic: false, llm: false };

// Every module accounted for, so the ledger this document carries is a real one.
const RECORDED: ModuleCoverage[] = (["M1", "M2", "M3", "M4", "M5", "M6", "M7", "M8", "M9", "M10"] as const).map((module) =>
  module === "M2"
    ? { module, status: "requires-live-run" as const, reason: "no two-tenant stack stood up for this engagement" }
    : { module, status: "ran" as const },
);

const finding = (over: Partial<Finding> & Pick<Finding, "id">): Finding => ({
  title: "Tenant-scope check missing", severity: "High", confidence: "Confirmed", category: "Security",
  taxonomy: "M1 — Tenant scope", location: "app/api/docs/route.ts:12", status: "Open",
  evidence: `evidence for ${over.id}: the query reaches the documents table with no org_id predicate`,
  impact: "cross-tenant read", fix: "add the predicate", value: 5, ease: 4, safety: 5, ...over,
});

/**
 * A real M1-EXT-00: produced by the shipping detector, not hand-written. It reports files LOADED vs
 * source-like files PRESENT, so a directory of unread extensions is enough to make it fire. Uses no
 * filesystem walk of its own — the detector does the walking.
 */
function realExtCoverageRow(): Finding {
  const dir = fileURLToPath(new URL("./scan/", import.meta.url));
  const rows = checkUnreadSourceExtensions(dir, []);
  // A zero here would make every assertion below vacuous — exactly the "a fixture the scanner never
  // read reports zero, just like one it scanned and missed" trap.
  expect(rows.length, "checkUnreadSourceExtensions produced no row — the fixture proves nothing").toBe(1);
  return rows[0] as Finding;
}

/** The document under test: the disclosure family, an Info row, and a shape above the rollup threshold. */
function deliverable(): FindingsDocument {
  const rolled = Array.from({ length: 14 }, (_, i) =>
    finding({ id: `M4-${i}`, title: "Duplicated block", severity: "Medium", taxonomy: "M4 — Duplication", category: "Quality", location: `src/dup/${i}.ts:3` }),
  );
  const findings: Finding[] = [
    finding({ id: "M1-01" }),
    // The Info row in the MAIN BODY (not N/A) — the severity most of the disclosure family carries
    // and the easiest thing in a report to compress away.
    finding({ id: "M9-INFO-01", severity: "Info", confidence: "Likely", category: "Architecture", taxonomy: "M9 — App Router boundary", evidence: "an Info row whose body text must survive the main findings list, not just its title" }),
    realExtCoverageRow(),
    ...rolled,
  ];
  // No dataMap ⇒ the assembler appends the real M10-ESCALATION-00 not-assessed row (#1049).
  return assembleEngagementDocument(RECORDED, ENV, findings, META);
}

describe("#1435 a finding's own words survive the render seam", () => {
  const doc = deliverable();
  const html = buildHtml(doc);

  it("the fixture actually exercises all three places content can be lost", () => {
    expect(doc.findings.filter((f) => f.confidence === "N/A").map((f) => f.id).sort()).toEqual(["M1-EXT-00", "M10-ESCALATION-00"]);
    expect(doc.findings.some((f) => f.severity === "Info" && f.confidence !== "N/A")).toBe(true);
    expect(html).toMatch(/not individually rendered/);
  });

  it("the real deliverable renders with no breach", () => {
    expect(renderFidelityBreaches(doc, html)).toEqual([]);
  });

  it("every not-assessed row's OWN reason reaches the HTML — its id and title are not enough", () => {
    for (const f of doc.findings.filter((x) => x.confidence === "N/A")) {
      expect(html, f.id).toContain(esc(f.evidence));
    }
  });

  it("CONTROL — THE SHIPPED DEFECT: the pre-#1433 N/A section, reconstructed verbatim", () => {
    // `${esc(x.note ?? "Not applicable in context.")}` with no `evidence` fallback. No disclosure row
    // sets `note`, so every one of them rendered as its title plus that one sentence.
    const na = doc.findings.filter((x) => x.confidence === "N/A");
    const broken = na.reduce(
      (acc, x) => acc.replace(esc(x.evidence), "Not applicable in context."),
      html,
    );
    const breaches = renderFidelityBreaches(doc, broken);
    expect(breaches.map((b) => b.id).sort()).toEqual(["M1-EXT-00", "M10-ESCALATION-00"]);
    expect(breaches.every((b) => b.kind === "reason-dropped")).toBe(true);
  });

  it("CONTROL — an Info row compressed out of the main body is caught", () => {
    const info = doc.findings.find((f) => f.id === "M9-INFO-01") as Finding;
    const breaches = renderFidelityBreaches(doc, html.replace(esc(info.evidence), ""));
    expect(breaches.map((b) => b.id)).toContain("M9-INFO-01");
  });

  it("CONTROL — a rolled-up group that drops members without listing them is caught", () => {
    const dropped = doc.findings.filter((f) => f.taxonomy === "M4 — Duplication").slice(-3);
    const broken = dropped.reduce((acc, f) => acc.replace(esc(f.evidence), "").replaceAll(esc(f.location), ""), html);
    const breaches = renderFidelityBreaches(doc, broken);
    expect(breaches.some((b) => b.kind === "undisclosed-omission")).toBe(true);
  });

  // #1407's lesson, applied here rather than repeated: proving the round-trip at the LIBRARY level
  // leaves the CLI wiring — argv parsing, the writeFileSync — unguarded, and that is the layer a
  // delivered report actually comes out of. This spawns the real renderer script and reads the file
  // it wrote. The PDF pass runs after report.html is written, so the exit code is deliberately NOT
  // asserted: on a checkout with no `playwright install chromium` the script throws there, and the
  // HTML this gate is about is already on disk.
  it("the reason survives the real CLI to report.html on disk, not only buildHtml's return value", () => {
    const out = mkdtempSync(join(tmpdir(), "harvey-render-fidelity-"));
    const findingsPath = join(out, "findings.json");
    writeFileSync(findingsPath, JSON.stringify(doc));
    spawnSync(process.execPath, [fileURLToPath(new URL("../report-template/render.mjs", import.meta.url)), findingsPath, out], { encoding: "utf8", timeout: 60_000 });
    const written = readFileSync(join(out, "report.html"), "utf8");
    rmSync(out, { recursive: true, force: true });
    expect(written).toBe(html);
    expect(renderFidelityBreaches(doc, written)).toEqual([]);
  });

  it("CONTROL — a withheld COUNT that understates what was withheld is caught", () => {
    // The renderer keeps disclosing "9 more ..." while ten are actually missing: the silent cap
    // wearing a number. Arithmetic, not a magic string, is what catches it.
    const extra = doc.findings.filter((f) => f.taxonomy === "M4 — Duplication")[0] as Finding;
    const broken = html.replace(esc(extra.evidence), "");
    const breaches = renderFidelityBreaches(doc, broken);
    expect(breaches.some((b) => b.kind === "miscounted-rollup")).toBe(true);
  });
});
