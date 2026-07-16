// M8 test-intent calibration gate: every structurally-dead-test class ships only with a caught
// positive AND a cleared benign negative — the #61 fixture discipline (same gate shape as
// slop.test.ts). This CASES table is the Layer-1 gate for #372/#384/#386's mechanical classes;
// src/scan/calibration/m8.entries.ts is deliberately NOT extended — its module-tagged entries
// are excluded from validate-calibration.ts scoring (see that file's header), so entries there
// would gate nothing. This suite runs in `pnpm verify`.

import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { detectTestIntentFindings } from "./test-intent.js";
import type { SourceInput } from "./common.js";

const FIXTURES_ROOT = fileURLToPath(new URL("./__fixtures__/test-intent/", import.meta.url));

function loadFixtureDir(relDir: string): SourceInput[] {
  const root = join(FIXTURES_ROOT, relDir);
  const files: SourceInput[] = [];
  const walk = (dir: string) => {
    for (const entry of readdirSync(dir)) {
      const full = join(dir, entry);
      if (statSync(full).isDirectory()) walk(full);
      else if (entry.endsWith(".txt")) files.push({ path: relative(root, full).replace(/\.txt$/, "").split(sep).join("/"), text: readFileSync(full, "utf8") });
    }
  };
  walk(root);
  return files;
}

function byTaxonomy(relDir: string, taxonomy: string) {
  return detectTestIntentFindings(loadFixtureDir(relDir)).filter((f) => f.taxonomy === taxonomy);
}

interface Case {
  name: string;
  dir: string;
  taxonomy: string;
  posCount: number;
  severity: string;
  confidence: string;
}

const CASES: Case[] = [
  // #372's three named classes.
  { name: "mock of the subject under test", dir: "mock-of-subject", taxonomy: "M8 — Mock of the subject under test", posCount: 2, severity: "Medium", confidence: "Likely" },
  { name: "assertion-free test", dir: "assertion-free", taxonomy: "M8 — Assertion-free test", posCount: 2, severity: "Medium", confidence: "Likely" },
  { name: "tautological assertion", dir: "tautological", taxonomy: "M8 — Tautological assertion", posCount: 2, severity: "Medium", confidence: "Likely" },
  // The two variants #372's follow-up comment adds.
  { name: "snapshot-only test", dir: "snapshot-only", taxonomy: "M8 — Snapshot-only test", posCount: 2, severity: "Low", confidence: "Review" },
  { name: "call-count-only test", dir: "call-count-only", taxonomy: "M8 — Call-count-only test", posCount: 1, severity: "Low", confidence: "Review" },
  // #384 — provably false confidence by construction (RLS is enforced by Postgres, which a
  // mocked client never reaches). Distinct from mock-of-subject: the mocked module here is a
  // legitimately-mocked-looking dependency.
  { name: "tenant-isolation test mocks the DB client", dir: "rls-mocked-db", taxonomy: "M8 — Tenant-isolation test mocks the DB client", posCount: 3, severity: "High", confidence: "Likely" },
  // #386 layer 1 — a security/money-critical file whose covering tests never name or assert a
  // denial/boundary case. The post-Stryker layer 2 lives in src/mutation-scan.ts.
  { name: "happy-path-only tests on security-critical code", dir: "happy-path-only", taxonomy: "M8 — Happy-path-only tests on security-critical code", posCount: 2, severity: "Medium", confidence: "Review" },
];

for (const c of CASES) {
  describe(c.name, () => {
    it("catches the positive with the right count, severity, confidence, and a line-anchored location", () => {
      const hits = byTaxonomy(`${c.dir}/positive`, c.taxonomy);
      expect(hits).toHaveLength(c.posCount);
      for (const h of hits) {
        expect(h).toMatchObject({ category: "Test quality", status: "Open", severity: c.severity, confidence: c.confidence });
        expect(h.location).toMatch(/[^:]:\d+$/); // `path:line` — catches a detector that loses its line
      }
    });
    it("clears the benign negative (incl. the discrimination boundaries)", () => {
      expect(byTaxonomy(`${c.dir}/negative`, c.taxonomy)).toHaveLength(0);
    });
  });
}

// The discrimination boundaries that keep these low-FP are the load-bearing logic — lock them
// individually so a lost guard fails a named test, not just the aggregate count.
describe("discrimination boundaries (regression locks)", () => {
  it("mock-of-subject fires on the basename match AND on an invoked binding from a differently-named module", () => {
    const hits = byTaxonomy("mock-of-subject/positive", "M8 — Mock of the subject under test");
    expect(hits.map((h) => h.location.split(":")[0]).sort()).toEqual(["api.test.ts", "user-service.test.ts"]);
  });

  it("mock-of-subject stays silent on a dependency mock, a partial mock (importOriginal), and mock-config-only usage", () => {
    // negative/ has all three FP classes: mocking ./mailer.js while testing ./user-service.js,
    // vi.mock with an importOriginal factory, and vi.mocked(fn).mockReturnValue() configuration.
    expect(byTaxonomy("mock-of-subject/negative", "M8 — Mock of the subject under test")).toHaveLength(0);
  });

  it("assertion-free is cleared by expect, node:assert, a local assertion helper, and exempts it.todo", () => {
    expect(byTaxonomy("assertion-free/negative", "M8 — Assertion-free test")).toHaveLength(0);
  });

  it("a snapshot-only test is NOT also flagged assertion-free (toMatchSnapshot is an expect call)", () => {
    expect(byTaxonomy("snapshot-only/positive", "M8 — Assertion-free test")).toHaveLength(0);
  });

  it("a call-count-only test is NOT also flagged assertion-free, and toHaveBeenCalledWith clears it", () => {
    expect(byTaxonomy("call-count-only/positive", "M8 — Assertion-free test")).toHaveLength(0);
    expect(byTaxonomy("call-count-only/negative", "M8 — Call-count-only test")).toHaveLength(0);
  });

  it("tautological keys on the SAME expression on both sides — distinct identifiers and negation stay silent", () => {
    const pos = byTaxonomy("tautological/positive", "M8 — Tautological assertion");
    expect(pos.map((f) => f.location)).toEqual(["totals.test.ts:7", "totals.test.ts:12"]);
    expect(byTaxonomy("tautological/negative", "M8 — Tautological assertion")).toHaveLength(0);
  });

  it("a snapshot test that also asserts a specific value clears snapshot-only", () => {
    expect(byTaxonomy("snapshot-only/negative", "M8 — Snapshot-only test")).toHaveLength(0);
  });

  it("rls-mocked-db flags per CLAIMING test — the non-tenant test in the same mocked file stays silent", () => {
    const hits = byTaxonomy("rls-mocked-db/positive", "M8 — Tenant-isolation test mocks the DB client");
    // tenant-isolation.test.ts has two claiming tests; orders.test.ts has one claiming
    // ("enforces rls…") and one benign ("formats order totals") — 3 findings, not 4.
    expect(hits.map((h) => h.location.split(":")[0]).sort()).toEqual(["orders.test.ts", "tenant-isolation.test.ts", "tenant-isolation.test.ts"]);
  });

  it("rls-mocked-db resolves a local wrapper (@/lib/db-client → lib/db-client.ts) as a Supabase client mock", () => {
    const hits = byTaxonomy("rls-mocked-db/positive", "M8 — Tenant-isolation test mocks the DB client");
    const wrapper = hits.find((h) => h.location.startsWith("orders.test.ts"));
    expect(wrapper?.evidence).toContain("lib/db-client.ts");
  });

  it("rls-mocked-db clears a real-client tenant test, a mocked-client non-tenant test, and a non-db mock", () => {
    expect(byTaxonomy("rls-mocked-db/negative", "M8 — Tenant-isolation test mocks the DB client")).toHaveLength(0);
  });

  it("happy-path-only anchors on the SOURCE file, found via basename AND via import resolution", () => {
    const hits = byTaxonomy("happy-path-only/positive", "M8 — Happy-path-only tests on security-critical code");
    expect(hits.map((h) => h.location).sort()).toEqual(["auth.ts:1", "payment.ts:1"]);
    // the import-resolved covering test is named in the evidence
    expect(hits.find((h) => h.location.startsWith("payment"))?.evidence).toContain("billing/charge.test.ts");
  });

  it("happy-path-only is cleared by a denial NAME, by a toThrow ASSERTION, by a non-critical word (author ≠ auth), and by having no covering tests at all", () => {
    expect(byTaxonomy("happy-path-only/negative", "M8 — Happy-path-only tests on security-critical code")).toHaveLength(0);
  });
});

describe("finding shape", () => {
  it("emits sequential TESTINT-* ids", () => {
    const findings = detectTestIntentFindings(loadFixtureDir("tautological/positive"));
    expect(findings.length).toBeGreaterThan(0);
    findings.forEach((f, i) => expect(f.id).toBe(`TESTINT-${String(i + 1).padStart(2, "0")}`));
  });

  it("ignores non-test source files even when they contain test-shaped code", () => {
    const text = readFileSync(join(FIXTURES_ROOT, "assertion-free/positive/report.test.ts.txt"), "utf8");
    expect(detectTestIntentFindings([{ path: "report-helpers.ts", text }])).toHaveLength(0);
  });
});
