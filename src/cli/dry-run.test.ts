// Exercise the owning generator with only the external mechanical engine replaced. Target
// snapshotting, migration classification, report/scorecard derivation, validation and publication
// are the production path; the separate live regeneration exercises the real scanner binaries.
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { generateDryRun } from "./dry-run.js";
import { validateDryRunFamily } from "../dry-run-artifacts.js";
import { runMechanicalScan } from "../scan/mechanical.js";
import type { Finding } from "../findings.js";

vi.mock("../scan/mechanical.js", () => ({ runMechanicalScan: vi.fn() }));

const finding: Finding = {
  id: "THIS-RUN", title: "Retained finding", evidence: "the scanned source", severity: "High", confidence: "Confirmed", category: "Security",
  taxonomy: "M1-TEST", location: "file.ts:1", status: "Open", impact: "tenant data", fix: "check the tenant", value: 3, ease: 3, safety: 3,
};
let root: string;
let target: string;
let out: string;
let migration: string;
beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), "harvey-dry-run-producer-"));
  target = join(root, "target");
  out = join(root, "out");
  migration = join(target, "supabase/migrations/schema.sql");
  mkdirSync(join(target, "supabase/migrations"), { recursive: true });
  writeFileSync(migration, "CREATE TABLE public.profiles (\n  id uuid PRIMARY KEY,\n  email text\n);\n");
  vi.mocked(runMechanicalScan).mockReset().mockResolvedValue([structuredClone(finding)]);
});
afterEach(() => rmSync(root, { recursive: true, force: true }));

describe("owning dry-run generator (#1957)", () => {
  it("derives the report from this invocation and uses the same retained SQL despite a changed original target", async () => {
    mkdirSync(out);
    writeFileSync(join(out, "findings.json"), "[]");
    writeFileSync(join(out, "findings-report.json"), JSON.stringify({ findings: [{ id: "STALE-REPORT" }] }));
    let retained = "";
    vi.mocked(runMechanicalScan).mockImplementation(async ({ dir }) => {
      retained = dir;
      expect(readFileSync(join(dir, "supabase/migrations/schema.sql"), "utf8")).toContain("email");
      writeFileSync(migration, "CREATE TABLE public.other (\n  id uuid PRIMARY KEY,\n  unrelated integer\n);\n");
      return [structuredClone(finding)];
    });
    await generateDryRun(target, out);
    const raw = JSON.parse(readFileSync(join(out, "findings.json"), "utf8")) as Finding[];
    const report = JSON.parse(readFileSync(join(out, "findings-report.json"), "utf8")) as { findings: Finding[] };
    expect(raw.map((f) => f.id)).toContain("THIS-RUN");
    expect(report.findings).toEqual(raw);
    expect(JSON.parse(readFileSync(join(out, "pii-data-map.json"), "utf8"))).toHaveProperty("profiles");
    expect(validateDryRunFamily(out)).toEqual({ ok: true, errors: [] });
    expect(existsSync(retained)).toBe(false);
  });

  it("leaves all previous outputs intact when the scanner throws or returns an incomplete run", async () => {
    await generateDryRun(target, out);
    const before = readFileSync(join(out, "artifact-family.json"), "utf8");
    vi.mocked(runMechanicalScan).mockRejectedValueOnce(new Error("scanner failed"));
    await expect(generateDryRun(target, out)).rejects.toThrow("scanner failed");
    vi.mocked(runMechanicalScan).mockResolvedValueOnce([{ ...finding, id: "SEM-00" }]);
    await expect(generateDryRun(target, out)).rejects.toThrow("incomplete mechanical run");
    expect(readFileSync(join(out, "artifact-family.json"), "utf8")).toBe(before);
    expect(validateDryRunFamily(out)).toEqual({ ok: true, errors: [] });
  });

  it("reproduces every committed artifact from identical inputs without timing/date churn", async () => {
    await generateDryRun(target, out);
    const before = readFileSync(join(out, "artifact-family.json"), "utf8");
    await generateDryRun(target, out);
    expect(readFileSync(join(out, "artifact-family.json"), "utf8")).toBe(before);
    expect(validateDryRunFamily(out)).toEqual({ ok: true, errors: [] });
  });
});
