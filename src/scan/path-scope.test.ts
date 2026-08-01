// #1689 — a detector whose scope is a directory convention reads zero files on a repo that does not
// follow it, and that zero is indistinguishable in the output from a clean scan. Both directions are
// asserted here: a detector WITH a real population must NOT emit its row, and one with an empty
// population MUST.

import { describe, expect, it } from "vitest";
import { detectBolaOwnerFindings } from "./bola-owner.js";
import { detectJobTenantScopeFindings } from "./job-tenant-scope.js";
import { PATH_SCOPED_DETECTORS, pathScopeCensus, pathScopeNotAssessedRows } from "./path-scope.js";
import type { SourceInput } from "../detectors/common.js";

const elsewhere: SourceInput = { path: "src/lib/orders.ts", text: "export const x = 1;\n" };
const pagesApi: SourceInput = { path: "pages/api/invoice.js", text: "export default function handler(req, res) { res.end(); }\n" };
const jobFile: SourceInput = { path: "src/inngest/import.ts", text: "export const run = async () => {};\n" };

describe("#1689 path-scoped detector disclosure", () => {
  it("emits one row per detector that read zero files, naming the detector and its convention", () => {
    const rows = pathScopeNotAssessedRows([elsewhere]);
    expect(rows.map((r) => r.id).sort()).toEqual(["M1-PATHSCOPE-BOLA-00", "M1-PATHSCOPE-JOB-00"]);
    expect(rows.every((r) => r.confidence === "N/A" && r.category === "Coverage")).toBe(true);
    expect(rows.find((r) => r.id === "M1-PATHSCOPE-BOLA-00")?.evidence).toContain("pages/api/**");
    expect(rows.find((r) => r.id === "M1-PATHSCOPE-JOB-00")?.evidence).toContain("workers/");
  });

  it("a detector WITH a real population does not emit its row — the other direction", () => {
    expect(pathScopeNotAssessedRows([elsewhere, pagesApi]).map((r) => r.id)).toEqual(["M1-PATHSCOPE-JOB-00"]);
    expect(pathScopeNotAssessedRows([elsewhere, jobFile]).map((r) => r.id)).toEqual(["M1-PATHSCOPE-BOLA-00"]);
    expect(pathScopeNotAssessedRows([elsewhere, pagesApi, jobFile])).toEqual([]);
  });

  it("stays silent when the target has no source files at all — M1-EXT-00 owns that case", () => {
    expect(pathScopeNotAssessedRows([])).toEqual([]);
  });

  it("the census counts the files each detector actually reads", () => {
    expect(pathScopeCensus([elsewhere, pagesApi, jobFile])).toEqual([
      expect.objectContaining({ detector: "bola-owner", filesRead: 1 }),
      expect.objectContaining({ detector: "job-tenant-scope", filesRead: 1 }),
    ]);
    expect(pathScopeCensus([elsewhere]).every((r) => r.filesRead === 0)).toBe(true);
  });

  // The row is only worth anything if `select` is the filter the DETECTOR scans with. A copy would
  // let the two drift and the row would then describe a scope nobody scans. Asserted by behaviour:
  // on a file set the census counts as in-scope the detector must be able to produce a finding, and
  // on one it counts as empty the detector must produce none of its own class.
  it("the census predicate is the detector's own scope, not a copy of it", () => {
    // The same plant bola-owner.test.ts scores its own positive on.
    const bolaPlant: SourceInput = {
      path: "pages/api/billing/invoice.js",
      text: [
        'import { admin } from "../../../lib/supabaseAdmin";',
        'import { getServerSession } from "next-auth";',
        "export default async function handler(req, res) {",
        "  const session = await getServerSession(req);",
        '  if (!session) return res.status(401).json({ error: "unauthorized" });',
        '  const { data } = await admin.from("invoices").select("*").eq("tenant_id", req.body.tenantId);',
        "  res.status(200).json({ invoice: data });",
        "}",
      ].join("\n"),
    };
    const bola = PATH_SCOPED_DETECTORS.find((d) => d.detector === "bola-owner");
    expect(bola?.select([bolaPlant]).length).toBe(1);
    expect(detectBolaOwnerFindings([bolaPlant]).length).toBeGreaterThan(0);
    expect(bola?.select([elsewhere]).length).toBe(0);
    expect(detectBolaOwnerFindings([{ ...bolaPlant, path: "src/lib/billing.js" }])).toEqual([]);

    const job = PATH_SCOPED_DETECTORS.find((d) => d.detector === "job-tenant-scope");
    expect(job?.select([jobFile]).length).toBe(1);
    expect(job?.select([elsewhere]).length).toBe(0);
    // detectJobTenantScopeFindings also carries M1-JOBPATH-00; the class rows are what must vanish
    // when the file leaves the convention.
    const classRows = (files: SourceInput[]): number => detectJobTenantScopeFindings(files).filter((f) => f.id !== "M1-JOBPATH-00").length;
    expect(classRows([{ ...jobFile, path: "src/lib/import.ts" }])).toBe(0);
  });
});
