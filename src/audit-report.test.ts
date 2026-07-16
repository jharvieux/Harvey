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
const toolOutput = (argv: string[]): string => {
  const cmd = argv.join(" ");
  if (cmd.includes("quality-scan")) return "[]";
  if (cmd.includes("mutation-scan")) return JSON.stringify({ summary: { overall: {} }, reportRows: [] });
  if (cmd.includes("detect-static")) return "loaded 42 source files (30 product-code) from /target";
  if (cmd.includes("hotspot-scan.ts")) return "M3 hotspot table — /target (5 rows, worst first)";
  return "";
};

describe("runAudit findings capture (#312)", () => {
  it("collects findings from the emitting modules and nothing from the non-emitters", () => {
    const captured = runAudit(AUDIT_RUNNERS, ctx({ exec: (_c, argv) => ({ ok: true, output: toolOutput(argv) }), captureDir: "/cap", readFindings: (p) => [finding(basename(p))] }));
    // M3/M4/M5/M8/M9 shell out to Finding-emitting CLIs; M1/M2/M6/M7/M10 do not capture.
    expect(captured.findings.map((f) => f.id).sort()).toEqual(["M3.json", "M4.json", "M5.json", "M8.json", "M9.json"]);
  });

  it("captures nothing when the context is not capturing — coverage-only runs are unchanged", () => {
    expect(runAudit(AUDIT_RUNNERS, ctx()).findings).toEqual([]);
  });
});
