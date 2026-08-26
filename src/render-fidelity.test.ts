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
import { conservationLedger } from "./conservation-ledger.js";
import {
  detectM1HardcodedTenantFindings,
  detectM5HardcodedDeploymentFindings,
  M1_HARDCODED_TENANT_TAXONOMY,
  M5_HARDCODED_SOURCE_COVERAGE_ID,
} from "./detectors/m5-hardcoded-deployment.js";
import { osvUnavailableFinding } from "./scan/dependencies.js";
import { truffleHogUnavailableFinding } from "./scan/secrets.js";
import { checkUnreadSourceExtensions } from "./scan/ext-coverage.js";
import { parseSemgrepFindings, semgrepUnavailableFinding } from "./scan/semgrep.js";
import { toSarif } from "./sarif.js";
import { MechanicalScanContext } from "./scan/mechanical-context.js";
import { runRegisteredDependencyDetectors } from "./scan/mechanical-dependency-registry.js";
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
  // #1556: "/target" is not a real directory, so the architecture probe is doubled like `exists` is.
  // "unknown" keeps every M1 tier applicable, which is the row shape the assertions below rely on.
  detectOrm: () => "unknown",
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
    // #1664: the incomplete-semgrep disclosure, produced by the real producer with the exit/signal-
    // naming reason runSemgrep now returns — the "not-assessed row's OWN reason reaches the HTML"
    // assertion below is what proves a crashed scan reaches the client as a named gap, not silence.
    semgrepUnavailableFinding("semgrep run did not complete (killed by signal SIGBUS)"),
    // #1752: the incomplete-osv-scanner disclosure, produced by the real producer with the
    // exit/signal-naming reason runOsvScanner now returns — same seam, same proof as SEM-00 above.
    osvUnavailableFinding("osv-scanner run did not complete (killed by signal SIGKILL)"),
    // #1754: the incomplete-trufflehog disclosure. Same seam again, and the one where a lost reason
    // costs the most — the row it replaces is a secret scan, so silence here reads as "no
    // credentials committed" rather than "the scan stopped after 116 of them".
    truffleHogUnavailableFinding("trufflehog run did not complete (killed by signal SIGKILL)"),
    fixedFinding(),
    ...rolled,
  ];
  // No dataMap ⇒ the assembler appends the real M10-ESCALATION-00 not-assessed row (#1049).
  return assembleEngagementDocument(RECORDED, ENV, findings, META);
}

describe("#1435 a finding's own words survive the render seam", () => {
  it("delivers npm range provenance and corrected scope through the real registry, assembly, JSON and N/A evidence fallback (#1774)", async () => {
    const dir = mkdtempSync(join(tmpdir(), "harvey-range-report-"));
    const pkg = { name: "range-report", dependencies: {} };
    let context: MechanicalScanContext | undefined;
    try {
      writeFileSync(join(dir, "package.json"), JSON.stringify(pkg));
      writeFileSync(join(dir, "package-lock.json"), JSON.stringify({ lockfileVersion: 3, packages: {
        "node_modules/parent": { version: "1.0.0", license: "MIT", dependencies: {
          child: "^2.0.0", remote: "https://report-user:report-password@example.invalid/pkg.tgz?token=report-token",
        }, peerDependencies: { compatible: "*" } },
      } }));
      context = new MechanicalScanContext(dir);
      const { findings } = await runRegisteredDependencyDetectors({ context, scanDir: dir, pkg, osv: { failure: "offline report fixture" }, skipNetworkChecks: true }, "supply");
      const scope = findings.find((finding) => finding.id === "SUP-SCOPE-00")!;
      expect(scope.evidence).toContain("2 admitted third-party range edges");
      const doc = assembleEngagementDocument(RECORDED, ENV, findings, META);
      const html = buildHtml(doc);
      expect(html).toContain(esc(scope.evidence));
      expect(html).not.toMatch(/tree cannot answer|range, which only a manifest carries/);
      expect(renderFidelityBreaches(doc, html)).toEqual([]);
      const filename = join(dir, "findings.json");
      writeFileSync(filename, JSON.stringify(doc));
      const serialized = readFileSync(filename, "utf8");
      for (const secret of ["report-user", "report-password", "report-token"]) {
        expect(serialized).not.toContain(secret);
        expect(html).not.toContain(secret);
      }
      const delivered = JSON.parse(serialized) as FindingsDocument;
      const artifact = delivered.findings.find((finding) => finding.id === "SUP-NON-REGISTRY-TREE")?.dependencyRangeEvidence;
      expect(artifact).toMatchObject({ examined: 2, matched: 1, edges: [{ source: "package-lock.json", ownerPath: "node_modules/parent", name: "remote", direct: false, redacted: true }] });
      expect(renderFidelityBreaches(doc, html.replace(esc(scope.evidence), "Not applicable in context."))).not.toEqual([]);
    } finally { context?.dispose(); rmSync(dir, { recursive: true, force: true }); }
  });

  const doc = deliverable();
  const html = buildHtml(doc);

  it("the fixture actually exercises all three places content can be lost", () => {
    expect(doc.findings.filter((f) => f.confidence === "N/A").map((f) => f.id).sort()).toEqual(["DEP-OSV-00", "M1-EXT-00", "M10-ESCALATION-00", "SEC-TH-00", "SEM-00"]);
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
    expect(breaches.map((b) => b.id).sort()).toEqual(["DEP-OSV-00", "M1-EXT-00", "M10-ESCALATION-00", "SEC-TH-00", "SEM-00"]);
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
    // This assertion spawns the real renderer in a child process and its wall time straddled
    // vitest's old 5s default (MEASURED 2026-07-31 on `origin/main`, no local changes: 6153ms in one
    // of three consecutive runs of the file alone). #1715 moved the whole light suite to one
    // measured 30s budget in vitest.config.ts, so this file no longer carries its own literal; the
    // spawnSync timeout above is still shorter, so a genuinely hung renderer surfaces as itself.
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

  // ---- #1556: "this tier does not apply here" has to reach the client, not just the ledger ----
  //
  // The row it replaces read `partial` forever on a Prisma/Drizzle target over a tier that could
  // never become `ran` there. The fix moves that sentence from `reason` to `detail`, which is the
  // field #1555 had just proven the report was dropping — so the produce→deliver leg is asserted
  // here rather than inferred from the ledger, on the same real orchestrator → assembler → renderer
  // path as everything else in this file.
  it("a Prisma target's N/A-by-architecture tier reaches the rendered report (#1556)", () => {
    const prismaDoc = assembleEngagementDocument(
      runAudit(AUDIT_RUNNERS, { ...LEDGER_CTX, detectOrm: () => "prisma" }).recorded,
      ENV,
      [finding({ id: "M1-03" })],
      META,
    );
    const row = (prismaDoc.coverage as CoverageRow[]).find((r) => r.module === "M1") as CoverageRow;
    // Without this the assertion below could pass over a row that never carried the sentence.
    expect(row.detail).toMatch(/Not applicable to this target's architecture/);
    const prismaHtml = buildHtml(prismaDoc);
    expect(prismaHtml).toContain(esc("connected Supabase"));
    expect(prismaHtml).toContain(esc("N/A by architecture"));
    expect(prismaHtml).toContain(esc("M1-ARCH-PRISMA"));
    expect(renderFidelityBreaches(prismaDoc, prismaHtml)).toEqual([]);
    // CONTROL: strip the sentence out of the rendered HTML and the fidelity gate must go red — the
    // disclosure is guarded by the same mechanism as every other coverage-row text, not by hope.
    const stripped = prismaHtml.replace(esc(row.detail as string), "");
    expect(stripped, "the control must actually remove the sentence").not.toBe(prismaHtml);
    expect(renderFidelityBreaches(prismaDoc, stripped).map((b) => b.id)).toContain("M1");
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

describe("#1929 hardcoded tenant/source-coverage rows survive production, assembly, and render", () => {
  const m1 = detectM1HardcodedTenantFindings([{
    path: "src/server/tenant-request.ts",
    text: `export const run = () => fetch("/api/data", { headers: { "X-Tenant-ID": "tenant_acme-prod-4821" } });`,
  }])[0]!;
  const m5 = detectM5HardcodedDeploymentFindings([], {
    productSourceInventory: [{ path: "src/service.py", text: "def run():\n    return 1\n" }],
  })[0]!;
  const produced = [m1, m5];
  const doc = assembleEngagementDocument(RECORDED, ENV, produced, META);
  const html = buildHtml(doc);

  it("uses the frozen disjoint identities and renders each real producer's client-legible evidence", () => {
    expect(m1).toMatchObject({
      id: expect.stringMatching(/^M1-HARDCODED-TENANT-/),
      taxonomy: M1_HARDCODED_TENANT_TAXONOMY,
    });
    expect(m5.id).toBe(M5_HARDCODED_SOURCE_COVERAGE_ID);
    expect(html).toContain(esc(m1.evidence));
    expect(html).toContain(esc(m5.evidence));
    expect(html).toContain(esc("authenticated/session context"));
    expect(html).toContain(esc("exact JavaScript/TypeScript selector: 0 admitted"));
    expect(renderFidelityBreaches(doc, html)).toEqual([]);
  });

  it("conserves both rows through assembly and fails when the M5 NotAssessed row is removed", () => {
    const byModule = { M1: [m1], M5: [m5] };
    expect(conservationLedger(produced, doc.findings, byModule)).toMatchObject({
      produced: 2,
      deliveredFromProduced: 2,
      unaccounted: 0,
      ok: true,
    });
    const dropped = conservationLedger(
      produced,
      doc.findings.filter((finding) => finding.id !== M5_HARDCODED_SOURCE_COVERAGE_ID),
      byModule,
    );
    expect(dropped).toMatchObject({ unaccounted: 1, ok: false });
    expect(dropped.rows).toContainEqual(expect.objectContaining({
      id: M5_HARDCODED_SOURCE_COVERAGE_ID,
      disposition: "unaccounted",
      modules: ["M5"],
    }));
  });

  it("CONTROL — dropping the M5 NotAssessed reason from HTML is a fidelity breach", () => {
    const broken = html.replace(esc(m5.evidence), "");
    expect(broken).not.toBe(html);
    expect(renderFidelityBreaches(doc, broken)).toContainEqual(expect.objectContaining({
      id: M5_HARDCODED_SOURCE_COVERAGE_ID,
      kind: "reason-dropped",
    }));
  });
});

// #1627 — the check's IDENTITY MODEL, which every fixture above happens not to exercise. `finding()`
// gives each row `evidence for ${id}: …`, so no two findings in the fixtures above share an evidence
// string and the collision below has a population of ZERO there. It is not rare in the field: a
// finding's text is a template over its SHAPE, so two permissive-RLS-policy rows on two different
// tables are byte-identical, and the same is true of the M4 duplication and M7 index families.
//
// MEASURED 2026-07-31 on a real ten-module deliverable over targets/calibration — shape
// `M1 — Multi-tenant security High`, 11 members — the checker scored 5 absent against the renderer's
// correct 6 and reported a MISCOUNTED-ROLLUP that did not exist. The renderer was right throughout.
describe("#1627 rendered-ness is decided per FINDING, not per evidence string", () => {
  // The real shape, reproduced: ONE rolled-up group in which most members carry their own text and
  // exactly one PAIR is byte-identical — a representative and a withheld row. That pair is the whole
  // defect, and a fixture where every member collides would not show it (the checker then finds no
  // absentees at all and reports nothing, which is a different failure).
  const TWIN_EVIDENCE = "the policy is `using (true)`, so every row is readable by every tenant";
  const twin = (i: number): Finding =>
    finding({
      id: `SB-RLS-POLICY-public.t${i}.t${i}_read`,
      title: "Permissive RLS policy",
      taxonomy: "M1 — Multi-tenant security",
      severity: "High",
      location: `supabase/policies/t${i}.sql:1`,
      evidence: i === 0 || i === 11 ? TWIN_EVIDENCE : `the policy on t${i} restricts to auth.uid() but not to the tenant`,
    });
  const members = Array.from({ length: 12 }, (_, i) => twin(i));
  const doc = assembleEngagementDocument(RECORDED, ENV, [...members], META);
  const html = buildHtml(doc);
  const withheldBlock = /<div class="group-rest">[\s\S]*?<\/details>/.exec(html)?.[0] ?? "";

  it("the fixture actually collides — one evidence string across a rendered row AND a withheld one", () => {
    expect(doc.findings.filter((f) => f.taxonomy === "M1 — Multi-tenant security")).toHaveLength(12);
    // 12 members, 5 rendered in full ⇒ 7 withheld. The count is the renderer's, and it is correct.
    expect(html).toContain("7 more High finding(s) of this shape are not individually rendered");
    // t0 renders a full card; t11 is withheld — and they share one evidence string, so a text search
    // over the whole document reads t11 as rendered, because t0's card carries the same words.
    expect(withheldBlock).toContain("SB-RLS-POLICY-public.t11.t11_read");
    expect(withheldBlock).not.toContain("SB-RLS-POLICY-public.t0.t0_read");
    expect(members[0]?.evidence).toBe(members[11]?.evidence);
  });

  it("scores no breach when the renderer discloses the right count", () => {
    // Pre-#1627 this reported MISCOUNTED-ROLLUP: t11 counted as rendered because t0's card carries
    // its words, so six absentees were scored against a correctly-disclosed seven.
    expect(renderFidelityBreaches(doc, html)).toEqual([]);
  });

  it("still catches a withheld count that understates what was withheld", () => {
    // The failing direction, so the line above is not vacuous. Seven ARE withheld; the report says three.
    const broken = html.replace("7 more High finding(s)", "3 more High finding(s)");
    expect(broken, "the control must actually change the disclosed count").not.toBe(html);
    const breaches = renderFidelityBreaches(doc, broken);
    expect(breaches.map((b) => b.kind)).toEqual(["miscounted-rollup"]);
    expect(breaches[0]?.detail).toContain("7 finding(s) of shape \"M1 — Multi-tenant security High\"");
    expect(breaches[0]?.detail).toContain("the report discloses 3");
  });

  it("CONTROL — the shared evidence string does not save a twin dropped from the withheld list", () => {
    // Identity by region must not become a way to LOSE a finding. t11's row is removed from the
    // <details> list; its words are still in the document, on t0's card. Nothing is attributed to
    // t11, so it is an undisclosed omission — and a text search over the whole document reports none.
    const broken = html.replace(/<div><span class="fid">SB-RLS-POLICY-public\.t11\.t11_read<\/span>[\s\S]*?<\/div>/, "");
    expect(broken, "the control must actually remove the row").not.toBe(html);
    expect(broken).toContain(esc(TWIN_EVIDENCE));
    const breaches = renderFidelityBreaches(doc, broken);
    expect(breaches.some((b) => b.kind === "undisclosed-omission" && b.id.includes("SB-RLS-POLICY-public.t11.t11_read"))).toBe(true);
  });
});

// #1730 — `reviewFlagSection` (report-template/render.mjs) used to emit a plain `<tr>` with no
// `<span class="fid">`, so `renderFidelityBreaches`'s reviewFlagOnly loop had no per-finding region
// to read and scored against the WHOLE document instead — the #1062 masking shape #1627 closed
// everywhere else a finding's own words render. Two nested-PII rows sharing a location and a
// column set covered for each other under that scoring.
describe("#1730 the nested-PII review table is scored per row, not against the whole document", () => {
  const reviewRow = (id: string): Finding =>
    finding({
      id,
      title: "JSON column may hold nested PII",
      confidence: "Review",
      taxonomy: "M10 — Nested PII review",
      category: "Data",
      location: "supabase/tables/orders.sql:1",
      reviewFlagOnly: true,
      reviewFlagColumns: ["metadata"],
      evidence: `evidence for ${id}: metadata is a JSON/JSONB column whose name suggests it may hold nested PII`,
    });
  // Twins: same location, same reviewFlagColumns — the exact collision shape #377/#459 name.
  const twinA = reviewRow("M10-PII-01");
  const twinB = reviewRow("M10-PII-02");
  const doc = assembleEngagementDocument(RECORDED, ENV, [twinA, twinB], META);
  const html = buildHtml(doc);

  it("the fixture actually collides — two review-flag rows share BOTH location and columns", () => {
    expect(twinA.location).toBe(twinB.location);
    expect(twinA.reviewFlagColumns).toEqual(twinB.reviewFlagColumns);
    expect(html.match(/supabase\/tables\/orders\.sql:1/g)?.length).toBe(2); // one per row, not deduped
  });

  it("both rows carry their own <span class=\"fid\"> marker", () => {
    expect(html).toContain('<span class="fid">M10-PII-01</span>');
    expect(html).toContain('<span class="fid">M10-PII-02</span>');
  });

  it("no breach when both rows render", () => {
    expect(renderFidelityBreaches(doc, html)).toEqual([]);
  });

  it("CONTROL — removing ONE row is caught, even though its location and columns still appear (on the surviving twin's row)", () => {
    const broken = html.replace(/<tr><td class="b"><span class="fid">M10-PII-02<\/span>[\s\S]*?<\/tr>/, "");
    expect(broken, "the control must actually remove a row").not.toBe(html);
    // The words are still IN the document (twinA's row), which is exactly why the old whole-
    // document scoring missed this — proving the fixture is a real collision, not just an absence.
    expect(broken).toContain("supabase/tables/orders.sql:1");
    expect(broken).toContain("metadata");
    const breaches = renderFidelityBreaches(doc, broken);
    expect(breaches.some((b) => b.kind === "reason-dropped" && b.id === "M10-PII-02")).toBe(true);
  });
});

// #1661 — `Finding.cwe` is a list, and until now nothing followed a SECOND entry past the parser.
// `harvey-cookie-insecure`'s `(?s)^[^;]*$` proves the cookie carries no attribute at all, which
// determines CWE-614, CWE-1004 and CWE-1275 identically, and CWE-1275's OWASP category (A01) is not
// the other two's (A05). This runs the REAL chain — the rule file's own metadata, through the real
// semgrep→Finding mapper, the real assembler, the real renderer and the real SARIF export — because
// the issue's own criterion is that the check has to read the assembled document, not the parser.
describe("#1661 every CWE a rule declares reaches the assembled deliverable", () => {
  const RULES = join(fileURLToPath(new URL("./scan/rules/semgrep/", import.meta.url)), "headers.yml");

  // Read the LIVE metadata out of headers.yml rather than restating it: a test that hard-codes the
  // three ids passes after somebody deletes two of them from the rule.
  const block = readFileSync(RULES, "utf8").split(/^ {2}- id: /m).find((b) => b.startsWith("harvey-cookie-insecure\n"))!;
  const flowList = (key: string): string[] => JSON.parse(new RegExp(String.raw`^\s+${key}:\s*(\[.*\])\s*$`, "m").exec(block)![1]!) as string[];
  const declaredCwe = flowList("cwe");
  const declaredOwasp = flowList("owasp");

  const produced = parseSemgrepFindings({
    results: [
      {
        check_id: "harvey-cookie-insecure",
        path: "app/api/login/route.ts",
        start: { line: 12 },
        extra: {
          message: "Set-Cookie is written with no Secure/HttpOnly/SameSite attributes.",
          severity: "ERROR",
          metadata: { cwe: declaredCwe, owasp: declaredOwasp, confidence: "HIGH", harveySeverity: "High" },
        },
      },
    ],
  });

  it("the rule really declares more than one CWE, so the rest of this block is not vacuous", () => {
    expect(declaredCwe.length).toBeGreaterThan(1);
    expect(declaredCwe.map((c) => c.match(/^CWE-\d+/)![0])).toEqual(["CWE-614", "CWE-1004", "CWE-1275"]);
    // The two categories are the point: reading cwe[0] alone silently dropped A01.
    expect(new Set(declaredOwasp).size).toBe(2);
  });

  it("the producer keeps every entry, not just the first", () => {
    expect(produced[0]!.cwe).toEqual(declaredCwe);
    expect(produced[0]!.owasp).toEqual(declaredOwasp);
  });

  it("all three CWEs and both OWASP categories reach the RENDERED report", () => {
    const html = buildHtml(assembleEngagementDocument(RECORDED, ENV, produced, META));
    for (const id of declaredCwe) expect(html, id).toContain(esc(id));
    for (const cat of declaredOwasp) expect(html, cat).toContain(esc(cat));
  });

  it("CONTROL — a renderer that emits only the first CWE loses two of them and one whole category", () => {
    // The pre-#1661 shape reconstructed: `cweOwaspLine` narrowed to `f.cwe[0]` / `f.owasp[0]`.
    const doc = assembleEngagementDocument(RECORDED, ENV, produced, META);
    const html = buildHtml({ ...doc, findings: doc.findings.map((f) => (f.id === produced[0]!.id ? { ...f, cwe: f.cwe?.slice(0, 1), owasp: f.owasp?.slice(0, 1) } : f)) });
    expect(html).toContain(esc(declaredCwe[0]!));
    expect(html).not.toContain(esc(declaredCwe[1]!));
    expect(html).not.toContain(esc(declaredCwe[2]!));
    expect(html).not.toContain(esc(declaredOwasp[1]!));
  });

  it("all three reach SARIF, as human strings AND as the machine external/cwe tags", () => {
    const sarif = toSarif(produced, { coverageAbsent: "#1661 fixture: this block measures CWE threading, not the ledger." }) as { runs: { tool: { driver: { rules: { properties: { tags: string[] } }[] } } }[] };
    const tags = sarif.runs[0]!.tool.driver.rules[0]!.properties.tags;
    for (const id of declaredCwe) expect(tags, id).toContain(id);
    for (const cat of declaredOwasp) expect(tags, cat).toContain(cat);
    expect(tags).toContain("external/cwe/cwe-614");
    expect(tags).toContain("external/cwe/cwe-1004");
    expect(tags).toContain("external/cwe/cwe-1275");
  });

  it("CONTROL — dropping the tail of `cwe` costs SARIF both its human strings and its machine tags", () => {
    const narrowed = produced.map((f) => ({ ...f, cwe: f.cwe?.slice(0, 1) }));
    const sarif = toSarif(narrowed, { coverageAbsent: "#1661 fixture: this block measures CWE threading, not the ledger." }) as { runs: { tool: { driver: { rules: { properties: { tags: string[] } }[] } } }[] };
    const tags = sarif.runs[0]!.tool.driver.rules[0]!.properties.tags;
    expect(tags).not.toContain("external/cwe/cwe-1004");
    expect(tags).not.toContain(declaredCwe[2]);
  });
});
