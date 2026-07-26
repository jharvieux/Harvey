import { basename } from "node:path";
import { describe, expect, it } from "vitest";
import { AUDIT_MODULES, type ModuleCoverage } from "./audit-coverage.js";
import { assembleEngagementDocument, coverageLedger, dedupeFindings } from "./audit-report.js";
import { runAudit, type RunContext } from "./audit-runner.js";
import { AUDIT_RUNNERS } from "./audit-runners.js";
import { type Finding, type ReportMeta, validateFindings } from "./findings.js";

const meta: ReportMeta = {
  client: "C", subtitle: "s", date: "2026-07-16", commit: "x", auditor: "a", confidential: true,
  overallHealth: 7, tenantIsolation: "HOLDS", authModel: "oauth", headline: "h", scope: "sc",
  methodology: "m", outOfScope: "none",
};

const finding = (id: string): Finding => ({
  id, title: "t", severity: "Low", confidence: "Confirmed", category: "c", taxonomy: "tx",
  location: "l", status: "Open", evidence: "e", impact: "i", fix: "f", value: 2, ease: 3, safety: 4,
});

const ctx = (over: Partial<RunContext> = {}): RunContext => ({
  targetDir: "/target",
  env: { connected: false, dynamic: false, llm: false },
  exec: () => ({ ok: true, output: "" }),
  exists: () => true,
  ...over,
});

describe("assembleEngagementDocument (#312)", () => {
  const recorded: ModuleCoverage[] = AUDIT_MODULES.map((m) => ({ module: m, status: "ran" as const, detail: `ran ${m}` }));
  recorded[4] = { module: "M5", status: "requires-live-run", reason: "target has no node_modules" };
  recorded[6] = { module: "M7", status: "partial", reason: "code tier only — no DB creds", detail: "detect-static" };
  const env = { connected: false, dynamic: false, llm: false };

  it("carries the derived coverage ledger alongside the findings, and validates", () => {
    const doc = assembleEngagementDocument(recorded, env, [finding("F-1")], meta);
    expect(doc.coverage).toHaveLength(AUDIT_MODULES.length);
    expect(validateFindings(doc).ok).toBe(true);
    expect(doc.coverage?.find((r) => r.module === "M5")?.reason).toMatch(/no node_modules/);
  });

  // #515: when an M3 hotspot ranking is passed, every module's findings on a hot file get tagged.
  it("enriches findings on a ranked hotspot with onHotspot/hotspotRank, and validates", () => {
    const onHot = { ...finding("F-hot"), location: "core/checkout.ts:42" };
    const offHot = { ...finding("F-cold"), location: "lib/leaf.ts:1" };
    const doc = assembleEngagementDocument(recorded, env, [onHot, offHot], meta, ["core/checkout.ts", "core/pay.ts"]);
    expect(doc.findings.find((f) => f.id === "F-hot")?.onHotspot).toBe(true);
    expect(doc.findings.find((f) => f.id === "F-hot")?.hotspotRank).toBe(1);
    expect(doc.findings.find((f) => f.id === "F-cold")?.onHotspot).toBeUndefined();
    expect(validateFindings(doc).ok).toBe(true);
  });

  it("leaves findings untagged when no hotspot ranking was captured", () => {
    const doc = assembleEngagementDocument(recorded, env, [finding("F-1")], meta);
    expect(doc.findings[0]?.onHotspot).toBeUndefined();
  });

  // crit 3: a module that never ran must not read the same as one that ran and found nothing.
  it("keeps a never-run module distinguishable from a module that ran clean", () => {
    const doc = assembleEngagementDocument(recorded, env, [], meta);
    const m4 = doc.coverage?.find((r) => r.module === "M4");
    const m5 = doc.coverage?.find((r) => r.module === "M5");
    expect(m4?.status).toBe("ran");
    expect(m4?.reason).toBeUndefined();
    expect(m5?.status).toBe("requires-live-run");
    expect(m5?.reason).toBeTruthy();
  });

  it("maps a partial's reason through to the ledger row", () => {
    expect(coverageLedger(recorded, env).find((r) => r.module === "M7")?.status).toBe("partial");
  });
});

// #682: a module marked `partial` because a sub-step was BLOCKED still contributes the findings its
// completed sub-step produced, and its coverage row carries the sub-step-blocked marker so the table
// can badge it apart from a partial/requires-live-run that produced nothing.
describe("sub-step-blocked partials keep findings and stay distinguishable (#682)", () => {
  const env682 = { connected: false, dynamic: false, llm: false };
  const recorded682 = (): ModuleCoverage[] => {
    const rows: ModuleCoverage[] = AUDIT_MODULES.map((m) => ({ module: m, status: "ran" as const, detail: `ran ${m}` }));
    rows[AUDIT_MODULES.indexOf("M8")] = { module: "M8", status: "partial", subStatus: "sub-step-blocked", detail: "test-intent tier", reason: "mutation tier blocked; the test-intent tier still ran (#682)" };
    return rows;
  };

  it("surfaces the blocked module's completed-sub-step findings in the assembled doc, and validates", () => {
    const doc = assembleEngagementDocument(recorded682(), env682, [finding("M8-53")], meta);
    expect(doc.findings.map((f) => f.id)).toContain("M8-53");
    expect(validateFindings(doc).ok).toBe(true);
  });

  it("carries subStatus onto the coverage row so the table badges it distinctly", () => {
    const row = coverageLedger(recorded682(), env682).find((r) => r.module === "M8");
    expect(row?.status).toBe("partial");
    expect(row?.subStatus).toBe("sub-step-blocked");
  });

  it("leaves an ordinary partial without a subStatus — it reads as a plain partial", () => {
    const plain = recorded682();
    plain[AUDIT_MODULES.indexOf("M8")] = { module: "M8", status: "partial", detail: "code tier", reason: "code tier only" };
    expect(coverageLedger(plain, env682).find((r) => r.module === "M8")?.subStatus).toBeUndefined();
  });
});

describe("dedupeFindings", () => {
  it("collapses byte-identical duplicates (the shared-CLI capture case) but keeps distinct findings", () => {
    const a = finding("F-1");
    expect(dedupeFindings([a, { ...a }, finding("F-2")]).map((f) => f.id)).toEqual(["F-1", "F-2"]);
  });

  it("preserves a same-id-but-different-content collision so validateFindings flags it loudly", () => {
    const kept = dedupeFindings([finding("F-1"), { ...finding("F-1"), title: "different" }]);
    expect(kept).toHaveLength(2);
    expect(validateFindings({ meta, findings: kept }).ok).toBe(false);
  });
});

// The evidence each tool prints on a clean run — #419's probes derive status from this, so a
// capturing run must feed it (an exit-0 with empty output now reads as requires-live-run, #350).
// mutation-scan (M8) is the exception: --out diverts its verdict off stdout into the object
// artifact (#420), so its stdout is empty and the probe reads the verdict from readArtifact instead.
const toolOutput = (argv: string[]): string => {
  const cmd = argv.join(" ");
  if (cmd.includes("quality-scan")) return "[]";
  if (cmd.includes("detect-static")) return "loaded 42 source files (30 product-code) from /target";
  if (cmd.includes("hotspot-scan.ts")) return "M3 hotspot table — /target (5 rows, worst first)";
  return "";
};

// #420: the bare-Finding[] emitters (M4/M5/M9) are read via readFindings; the object-artifact
// emitters (M3 = { findings }, M8 no-suite = { finding, moduleRecord }) are read via readArtifact.
const artifactFor = (p: string): unknown => {
  const m = basename(p, ".json");
  if (m === "M3") return { hotspots: [], findings: [finding("M3")] };
  if (m === "M8") return { finding: finding("M8"), moduleRecord: { status: "partial", note: "No automated test suite found — mutation scan could not run." } };
  return undefined;
};
const capturingCtx = ctx({
  exec: (_c, argv) => ({ ok: true, output: toolOutput(argv) }),
  captureDir: "/cap",
  readFindings: (p) => [finding(basename(p, ".json"))],
  readArtifact: artifactFor,
});

describe("runAudit findings capture (#312/#420)", () => {
  it("collects findings from the emitting modules (bare-array AND object-artifact) and nothing from the non-emitters", () => {
    const captured = runAudit(AUDIT_RUNNERS, capturingCtx);
    // M1/M4/M5/M9/M10 emit a bare Finding[] (M10 since #436, M1's mechanical tier since #1040);
    // M3/M8 embed findings in an object artifact (#420). M2/M7 collect nothing — their findings
    // come from a live/human pass this run cannot observe. M6's free indicator layer CAN collect
    // (#397), filtered to the `M6 — Indicator: …` taxonomy — this fixture's generic "tx" taxonomy
    // doesn't match, so it collects nothing here too, but for a different (mock-fidelity) reason.
    expect(captured.findings.map((f) => f.id).sort()).toEqual(["M1", "M10", "M3", "M4", "M5", "M8", "M9"]);
  });

  it("captures M8's zero-coverage finding out of its object artifact, as a partial (not ran)", () => {
    const { recorded, findings } = runAudit(AUDIT_RUNNERS, capturingCtx);
    expect(recorded.find((r) => r.module === "M8")?.status).toBe("partial");
    expect(findings.map((f) => f.id)).toContain("M8");
  });

  it("assembles M3/M8/M10 findings into the deliverable, keeping M1/M2 non-collection legible", () => {
    const { recorded, findings } = runAudit(AUDIT_RUNNERS, capturingCtx);
    const doc = assembleEngagementDocument(recorded, capturingCtx.env, findings, meta);
    expect(validateFindings(doc).ok).toBe(true);
    expect(doc.findings.map((f) => f.id)).toEqual(expect.arrayContaining(["M3", "M8", "M10"]));
    // Non-collection is not silence: each non-emitting module is a non-"ran" row whose reason says
    // the findings are not collected and names the source — distinguishable from "ran, found nothing".
    for (const m of ["M1", "M2"]) {
      const row = doc.coverage?.find((r) => r.module === m);
      expect(row?.status, `${m} must not read as a clean ran`).not.toBe("ran");
      expect(row?.reason, `${m} must say findings are not collected`).toMatch(/collected into this deliverable/i);
    }
    // #436: M10 left that list — its schema-tier findings ARE captured now, and its remaining
    // partial reason is the honest tier gap (rows not sampled), not a collection gap.
    const m10 = doc.coverage?.find((r) => r.module === "M10");
    expect(m10?.status).toBe("partial");
    expect(m10?.reason).toMatch(/schema tier only/);
    expect(m10?.reason).not.toMatch(/collected into this deliverable/i);
    // #397: M6 also left the non-collection group — this mocked context makes detect-static
    // report a positive file count, so the free indicator layer reads `partial` (ran, no verdict)
    // rather than requires-live-run. The mock's generic taxonomy ("tx") doesn't match the real
    // `M6 — Indicator: …` prefix, so no finding is actually collected here — that's a fixture
    // artifact, not a claim about product behavior (a real run's indicator findings DO collect).
    const m6 = doc.coverage?.find((r) => r.module === "M6");
    expect(m6?.status).toBe("partial");
    expect(m6?.reason).toMatch(/free indicator layer ran/i);
  });

  it("captures nothing when the context is not capturing — coverage-only runs are unchanged", () => {
    expect(runAudit(AUDIT_RUNNERS, ctx()).findings).toEqual([]);
  });
});

// #435: a real Stryker run's --out artifact now carries a `findings` array (denial/boundary-
// concentrated survivors, src/mutation-scan.ts's survivingMutantFindings) alongside its
// { summary, reportRows } shape — this is the "ran" branch, distinct from capturingCtx's fixture
// above which exercises M8's no-test-suite ("partial") branch.
describe("M8 captures findings from a real Stryker run (#435)", () => {
  it("reads the mutation-scan --out artifact's `findings` array and reports ran with findings", () => {
    const realRunCtx = ctx({
      exec: (_c, argv) => ({ ok: true, output: argv.includes("detect-static") ? "loaded 42 source files (30 product-code) from /target" : "" }),
      captureDir: "/cap",
      readFindings: () => [],
      readArtifact: (p) => (basename(p, ".json") === "M8" ? { summary: { overall: {} }, reportRows: [], findings: [finding("M8-DENIAL")] } : undefined),
    });
    const { recorded, findings } = runAudit(AUDIT_RUNNERS, realRunCtx);
    expect(recorded.find((r) => r.module === "M8")?.status).toBe("ran");
    expect(findings.map((f) => f.id)).toContain("M8-DENIAL");
  });
});
