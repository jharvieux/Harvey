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
import { runAudit } from "./audit-runner.js";
import { AUDIT_RUNNERS } from "./audit-runners.js";
import { checkUnreadSourceExtensions } from "./scan/ext-coverage.js";
import { renderFidelityBreaches } from "./render-fidelity.js";
import type { RunContext } from "./audit-runner.js";
import type { EngagementEnv, ModuleCoverage } from "./audit-coverage.js";
import type { CoverageRow, Finding, FindingsDocument, ReportMeta } from "./findings.js";

const META: ReportMeta = {
  client: "Acme", subtitle: "Full audit", date: "2026-07-28", commit: "abc1234", auditor: "Harvey",
  confidential: true, overallHealth: 6, tenantIsolation: "Not verified", authModel: "Supabase",
  headline: "Ten-module audit", scope: "the app repo at abc1234", methodology: "M1–M10",
  outOfScope: "infrastructure",
};

const ENV: EngagementEnv = { connected: false, dynamic: false, llm: false };

// #1555 — the ledger is produced by the REAL ten-module orchestrator, not hand-written, for the same
// reason the N/A rows below are: a hand-typed `detail` proves the renderer copies a string I chose,
// while the thing that actually went missing was a string M1's own probe writes. The context drives
// M1 down its semantic-pass branch with no hotspot focus recorded, which is the shape #1553 made
// ordinary — `partial`, carrying BOTH the #502 warning in `detail` and the un-run tiers in `reason`.
const NOW = Date.parse("2026-07-30T12:00:00Z");
const LEDGER_CTX: RunContext = {
  targetDir: "/target",
  env: { connected: false, dynamic: false, llm: false },
  exec: (_command, argv) => ({
    ok: true,
    output: argv.join(" ").includes("quick-scan") ? "  4,778 lines of application code across 400 file(s)\n  Band: Small" : "",
    stderr: "",
  }),
  exists: () => true,
  isGitRepoRoot: () => true,
  artifactsDir: "/artifacts",
  now: NOW,
  readArtifact: (p) =>
    p.endsWith("M1.pass.json")
      ? { module: "M1", target: "/target", pass: "semantic", generatedAt: new Date(NOW - 3_600_000).toISOString() }
      : undefined,
};
const RECORDED: ModuleCoverage[] = runAudit(AUDIT_RUNNERS, LEDGER_CTX).recorded;

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

// #825 — a paid-tier finding carrying a diff that src/fix/attach.ts verified green. Its own unique
// taxonomy+severity so it never joins the rollup and always renders as an individual card, which is
// the case this invariant is scoped to.
const VERIFIED_DIFF = [
  "--- a/src/dead/consumer.ts",
  "+++ b/src/dead/consumer.ts",
  "@@ -3,5 +3,5 @@",
  "-export function wrap(x: string) { return inner(x); }",
  "+// removed: single-call wrapper (M5)",
  "",
].join("\n");

const fixedFinding = (): Finding =>
  finding({
    id: "M5-FIX-01", title: "Single-call wrapper", severity: "Low", confidence: "Confirmed",
    category: "Quality", taxonomy: "M5 — Dead code", location: "src/dead/consumer.ts:3",
    evidence: "wrap() has exactly one caller and adds no behaviour",
    fix: "inline the wrapper at its single call site",
    suggestedFix: {
      diff: VERIFIED_DIFF, verified: true,
      verification: "applies cleanly to the pinned baseline; the detector that found it (M5 — Single-call wrapper) no longer fires; your own check `npm run test` passes.",
    },
  });

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
    fixedFinding(),
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
    // #1555: the #502 warning, asserted on the file the PDF pass is rendered FROM — not on a string
    // buildHtml handed back. This is the artifact end of "accounted for is not delivered".
    expect(written).toContain(esc("no M3 hotspot focus"));
    expect(renderFidelityBreaches(doc, written)).toEqual([]);
  });

  // #825 — the seam one step past the ticket body. `attachSuggestedFix` decides paid + green + above
  // the filing floor; by the time a diff is on a Finding, the report's only job is not to lose it.
  it("a VERIFIED suggested fix reaches the rendered report, diff and verification sentence both", () => {
    expect(html).toContain(esc(VERIFIED_DIFF.replace(/\n+$/, "")));
    expect(html).toContain(esc("the detector that found it (M5 — Single-call wrapper) no longer fires"));
    expect(html).toMatch(/inert, for review/);
  });

  it("CONTROL — the shipped state before this change: the report renders the prose fix and drops the diff", () => {
    const f = doc.findings.find((x) => x.id === "M5-FIX-01") as Finding;
    const broken = html.replace(esc(VERIFIED_DIFF.replace(/\n+$/, "")), "");
    expect(broken, "the control must actually remove the diff").not.toBe(html);
    expect(broken).toContain(esc(f.fix)); // the prose survives — which is exactly why nothing noticed
    const breaches = renderFidelityBreaches(doc, broken);
    expect(breaches.map((b) => b.id)).toContain("M5-FIX-01");
    expect(breaches.find((b) => b.id === "M5-FIX-01")?.kind).toBe("fix-diff-dropped");
  });

  it("an UNVERIFIED fix is neither rendered nor demanded — the same fail-closed gate the ticket filer applies", () => {
    const unverified = { ...fixedFinding(), id: "M5-FIX-02", suggestedFix: { diff: "--- a/x\n+++ b/x\n@@ -1 +1 @@\n-a\n+b\n", verified: false } };
    const d = assembleEngagementDocument(RECORDED, ENV, [finding({ id: "M1-02" }), unverified], META);
    const h = buildHtml(d);
    expect(h).not.toContain(esc("-a\n+b"));
    expect(renderFidelityBreaches(d, h)).toEqual([]);
  });

  // ---- #1555: the coverage ledger, the one table that says what each module reached ----
  //
  // `coverageSection` rendered ONE of a row's two free-text fields, chosen by status: `detail` on a
  // `ran` row, `reason` otherwise. #1553 made M1 correctly read `partial` in a realistic engagement,
  // and the #502 "no M3 hotspot focus" warning — which lives in `detail` — stopped reaching the
  // client while staying in findings.json. Same seam as the N/A rows above, opposite direction.

  const m1 = (doc.coverage as CoverageRow[]).find((r) => r.module === "M1") as CoverageRow;

  it("the fixture's ledger really is a partial M1 row carrying the #502 warning", () => {
    // Without this the assertions below pass over a row that was never at risk.
    expect(m1.status).toBe("partial");
    expect(m1.detail).toMatch(/no M3 hotspot focus/);
    expect(m1.reason).toMatch(/out-of-orchestrator tiers/);
    expect((doc.coverage as CoverageRow[]).filter((r) => r.status === "requires-live-run" && r.reason).length).toBeGreaterThan(0);
  });

  it("a partial M1 row renders BOTH what ran and why it fell short — #502's warning included", () => {
    expect(html).toContain(esc(m1.detail as string));
    expect(html).toContain(esc(m1.reason as string));
    expect(html).toContain(esc("no M3 hotspot focus"));
  });

  it("CONTROL — the shipped branch reconstructed: a partial row rendering only its reason", () => {
    // Exactly what `r.status === "ran" ? detail : reason` produced — the reason survives, which is
    // why nothing noticed, and the detail is gone.
    const broken = html.replace(`${esc(m1.detail as string)}<br>`, "");
    expect(broken, "the control must actually remove the detail").not.toBe(html);
    expect(broken).toContain(esc(m1.reason as string));
    const breaches = renderFidelityBreaches(doc, broken);
    expect(breaches.map((b) => b.id)).toContain("M1");
    expect(breaches.find((b) => b.id === "M1")?.kind).toBe("coverage-text-dropped");
  });

  it("CONTROL — the mirror image: a not-assessed row that loses its reason is caught too", () => {
    // #1555 criterion 4 — the branch is generic, so the guard is checked on the other row type as
    // well. A `requires-live-run` row with no reason on screen is the "unstated limitation reads as
    // a clean bill of health" failure at its purest. The draft legal block re-states these reasons
    // further down the report, which is exactly why this check reads the coverage table alone: the
    // first occurrence is the table's, and removing it must still be caught.
    const live = (doc.coverage as CoverageRow[]).find((r) => r.status === "requires-live-run" && r.reason) as CoverageRow;
    const broken = html.replace(esc(live.reason as string), "");
    expect(broken, "the report still states this reason elsewhere — a whole-document check would pass").toContain(esc(live.reason as string));
    const breaches = renderFidelityBreaches(doc, broken);
    expect(breaches.map((b) => b.id)).toContain(live.module);
    expect(breaches.find((b) => b.id === live.module)?.kind).toBe("coverage-text-dropped");
  });

  // #1555 criterion 4. Under the orchestrator the population of these two shapes is ZERO —
  // src/audit-runner.ts attaches `reason` only on `partial` and `detail` only on `ran`/`partial`, so
  // `partial`.detail was the one field actually being lost. But the CALLER-supplied ledger path
  // (`buildAuditCoverage`, `rows.push({ ...entry, name })`) passes any combination straight through,
  // and the branch that dropped text was keyed on STATUS, not on which fields a row carries. So the
  // fix is field-driven and this is the check that keeps it that way.
  it("every status renders whatever free text its row carries, not the one field its status implies", () => {
    const mixed: ModuleCoverage[] = (["M1", "M2", "M3", "M4", "M5", "M6", "M7", "M8", "M9", "M10"] as const).map((module) => {
      if (module === "M3") return { module, status: "ran" as const, detail: "M3 ran the hotspot table", reason: "M3 ran but the clone was shallow, so the churn signal is thin" };
      if (module === "M2") return { module, status: "requires-live-run" as const, detail: "M2 got as far as provisioning the stack", reason: "M2 could not seed a second tenant" };
      return { module, status: "ran" as const, detail: `${module} ran` };
    });
    const d = assembleEngagementDocument(mixed, ENV, [finding({ id: "M1-03" })], META);
    expect(renderFidelityBreaches(d, buildHtml(d))).toEqual([]);
    const h = buildHtml(d);
    expect(h).toContain(esc("M3 ran but the clone was shallow"));
    expect(h).toContain(esc("M2 got as far as provisioning the stack"));
  });

  it("CONTROL — a report with no Module coverage table at all fails on every row", () => {
    const broken = html.replace(/<h2>Module coverage<\/h2>[\s\S]*?<\/table>/, "");
    expect(broken, "the control must actually remove the table").not.toBe(html);
    const breaches = renderFidelityBreaches(doc, broken).filter((b) => b.kind === "coverage-text-dropped");
    expect(breaches.map((b) => b.id).sort()).toEqual((doc.coverage as CoverageRow[]).map((r) => r.module).sort());
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
