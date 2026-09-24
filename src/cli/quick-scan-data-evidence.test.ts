import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import type { HealthScorecard } from "../health-scorecard.js";
import { CLI, MECHANICAL_BINARIES_PRESENT, createQuickScanTestHarness } from "./quick-scan-test-support.js";

const { dirs, run, cleanup } = createQuickScanTestHarness();
afterEach(cleanup);

describe.skipIf(!MECHANICAL_BINARIES_PRESENT)("quick-scan M10 evidence delivery (#2091)", () => {
  const tables = [
    ["accounts", "email text, first_name text"],
    ["patients", "ssn text, date_of_birth date, diagnosis text"],
    ["cards", "card_number text, cvv text"],
    ["contacts", "phone text"],
    ["members", "email text, phone text, date_of_birth date"],
    ["audit_users", "ip_address inet"],
    ["secrets", "ai_api_key text"],
  ] as const;

  it.each(["json", "text"])("delivers ordered table identities, classified-column totals, and the hidden-cap explanation (%s)", async (format) => {
    const target = mkdtempSync(join(tmpdir(), "harvey-pii-evidence-"));
    dirs.push(target);
    mkdirSync(join(target, "supabase/migrations"), { recursive: true });
    writeFileSync(join(target, "package.json"), JSON.stringify({ name: "pii-evidence", private: true }));
    writeFileSync(join(target, "index.ts"), "export const ready = true;\n");
    writeFileSync(join(target, "supabase/migrations/0001_tables.sql"), tables.map(([name, columns]) =>
      `create table public.${name} (\n  id uuid primary key,\n  ${columns.split(", ").join(",\n  ")}\n);`,
    ).join("\n\n"));
    if (format === "json") {
      const jsonOut = join(target, "quick.json");
      await run([CLI, "--dir", target, "--json", "--out", jsonOut]);
      const scorecard = (JSON.parse(readFileSync(jsonOut, "utf8")) as { scorecard: HealthScorecard }).scorecard;
      const m10 = scorecard.dimensions.find((row) => row.module === "M10")!;
      expect(m10).toMatchObject({ status: "risk-band", band: "Critical", count: 7, measure: "7 table(s) holding 13 classified PII/PHI/PCI column(s)" });
      expect(m10.evidence).toMatchObject({ totalShapes: 7, totalFindings: 13, hiddenShapes: 2, hiddenFindings: 2, capped: true });
      expect(m10.evidence?.examples.map(({ location, occurrences }) => [location, occurrences])).toEqual([
        ["patients", 3], ["cards", 2], ["secrets", 1], ["members", 3], ["accounts", 2],
      ]);

    } else {
      const rendered = (await run([CLI, "--dir", target])).stdout;
      expect(rendered).toContain("showing 5 of 7 distinct tables (13 classified columns in total)");
      expect(rendered).toContain("2 further tables (2 more classified columns) are NOT listed here");
      for (const table of ["patients", "cards", "secrets", "members", "accounts"]) expect(rendered).toMatch(new RegExp(`— ${table}  \\(\\d+ classified columns?\\)`));
      expect(rendered).not.toContain("— contacts  (");
    }
  }, 120000);

  it("shows zero table evidence for a parsed schema with no classified columns", async () => {
    const target = mkdtempSync(join(tmpdir(), "harvey-pii-zero-"));
    dirs.push(target);
    mkdirSync(join(target, "supabase/migrations"), { recursive: true });
    writeFileSync(join(target, "package.json"), JSON.stringify({ name: "pii-zero", private: true }));
    writeFileSync(join(target, "supabase/migrations/0001_tables.sql"), "create table public.logs (\n  id uuid primary key,\n  created_at timestamp\n);\n");
    const report = JSON.parse((await run([CLI, "--dir", target, "--json"])).stdout) as { scorecard: HealthScorecard };
    const m10 = report.scorecard.dimensions.find((row) => row.module === "M10")!;
    expect(m10).toMatchObject({ status: "risk-band", band: "Low", count: 0, measure: "0 table(s) holding 0 classified PII/PHI/PCI column(s)" });
    expect(m10.evidence).toMatchObject({ examples: [], totalShapes: 0, totalFindings: 0, hiddenShapes: 0, hiddenFindings: 0, capped: false });
    expect(m10.bandDerivation).toContain("0 classified column(s)");
  }, 120000);

  it("counts classified Prisma columns rather than every declared column", async () => {
    const target = mkdtempSync(join(tmpdir(), "harvey-pii-prisma-"));
    dirs.push(target);
    mkdirSync(join(target, "prisma"), { recursive: true });
    writeFileSync(join(target, "package.json"), JSON.stringify({ name: "pii-prisma", private: true }));
    writeFileSync(join(target, "prisma/schema.prisma"), "model Profile {\n  id String @id\n  email String\n  customer_ssn String\n}\n");
    const report = JSON.parse((await run([CLI, "--dir", target, "--json"])).stdout) as { scorecard: HealthScorecard };
    const m10 = report.scorecard.dimensions.find((row) => row.module === "M10")!;
    expect(m10).toMatchObject({ count: 1, measure: "1 table(s) holding 2 classified PII/PHI/PCI column(s)" });
    expect(m10.evidence).toMatchObject({ totalShapes: 1, totalFindings: 2, hiddenShapes: 0 });
    expect(m10.evidence?.examples[0]).toMatchObject({ location: "Profile", occurrences: 2 });
  }, 120000);
});
