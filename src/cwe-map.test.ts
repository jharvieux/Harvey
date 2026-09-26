import { execFileSync } from "node:child_process";
import { describe, expect, it } from "vitest";
import { classifyTaxonomyCwe, enrichFindingsCwe } from "./cwe-map.js";
import type { Finding } from "./findings.js";
import { detectPgResponseExposureFindings } from "./scan/pg-response-exposure.js";
import { toSarif } from "./sarif.js";

function finding(over: Partial<Finding> = {}): Finding {
  return {
    id: "F-1", title: "t", severity: "High", confidence: "Confirmed", category: "c",
    taxonomy: "SQL injection", location: "a.ts:1", status: "Open", evidence: "", impact: "", fix: "",
    value: 3, ease: 3, safety: 3, ...over,
  };
}

// Every literal detector taxonomy, plus dynamic producer taxonomies emitted from finite control
// inputs below. Test files are excluded from the literal harvest — their fixtures ("t", "stripe",
// "audit dsih") are not real detector taxonomies. This is the fail-loud guard: a new detector
// taxonomy that isn't classified in cwe-map.ts (security CWE, or a deliberate no-CWE-with-reason)
// fails here.
function detectorTaxonomies(): string[] {
  const out = execFileSync(
    "grep",
    ["-rhoE", "--include=*.ts", "--exclude=*.test.ts", 'taxonomy: "[^"]+"', "src/detectors/", "src/scan/"],
    { encoding: "utf8" },
  );
  const set = new Set<string>();
  for (const line of out.split("\n")) {
    const m = line.match(/^taxonomy: "([^"]+)"$/);
    if (m) set.add(m[1]!);
  }
  for (const finding of dynamicPgResponseExposureFindings()) set.add(finding.taxonomy);
  return [...set].sort();
}

const PG_RESPONSE_EXPOSURE_KINDS = ["direct", "spread", "select-star"] as const;
const pgResponseExposureSources: Record<(typeof PG_RESPONSE_EXPOSURE_KINDS)[number], string> = {
  direct: `export function getUser(req, res) {
  res.json({ id: 1, passwordHash: "x" });
}`,
  spread: `export function getUser(req, res) {
  const user = { id: 1, refreshToken: "x" };
  res.json({ ...user });
}`,
  "select-star": `export async function getUser(req, res) {
  const { rows } = await db.query("SELECT * FROM users");
  res.json(rows[0]);
}`,
};

function dynamicPgResponseExposureFindings(): Finding[] {
  return PG_RESPONSE_EXPOSURE_KINDS.flatMap((kind) => detectPgResponseExposureFindings([
    { path: `pg-response-${kind}.ts`, text: pgResponseExposureSources[kind] },
  ]));
}

describe("#975: every detector taxonomy has a CWE decision (fail loud on an unclassified one)", () => {
  const taxonomies = detectorTaxonomies();

  it("harvested a non-trivial set of detector taxonomies", () => {
    // Guards the harvester itself: a zero/tiny count would make the coverage assertion vacuously pass.
    expect(taxonomies.length).toBeGreaterThan(100);
  });

  it.each(taxonomies)("%s is classified (cwe or explicit no-cwe-with-reason)", (taxonomy) => {
    const c = classifyTaxonomyCwe(taxonomy);
    expect(c, `taxonomy "${taxonomy}" is unclassified — add it to SECURITY (with a CWE) or NO_CWE (with a reason) in src/cwe-map.ts`).toBeDefined();
    if (c?.kind === "cwe") {
      expect(c.cwe.length).toBeGreaterThan(0);
      // #1661: every entry, not just the first — the field is a list and a second entry that was
      // never shape-checked would reach the report and SARIF unvalidated.
      for (const id of c.cwe) expect(id).toMatch(/^CWE-\d+:/);
    } else {
      expect(c?.kind).toBe("none");
      expect((c as { reason: string }).reason.length).toBeGreaterThan(0);
    }
  });
});

describe("#2227: dynamic pg response-exposure taxonomy coverage", () => {
  const findings = dynamicPgResponseExposureFindings();
  const taxonomyKind = (taxonomy: string): string | undefined => taxonomy.match(/\(pg-resjson-exposure-([^)]*)\)$/)?.[1];

  it("enumerates every finite producer kind from emitted findings", () => {
    // This deliberately invokes the production detector. A quoted-assignment grep cannot see these
    // template-built taxonomies, and skipping any producer makes this cardinality assertion fail.
    expect(findings).toHaveLength(PG_RESPONSE_EXPOSURE_KINDS.length);
    expect(findings.map((finding) => taxonomyKind(finding.taxonomy)).sort()).toEqual([...PG_RESPONSE_EXPOSURE_KINDS].sort());
  });

  it("preserves the detector's severity, review boundary, and stable IDs", () => {
    expect(findings.map(({ id, severity, precisionTier }) => ({ id: id.replace(/-\d+$/, ""), severity, precisionTier }))).toEqual([
      { id: "SEC-PG-RESJSON-pg-response-direct-ts", severity: "High", precisionTier: "review" },
      { id: "SEC-PG-RESJSON-pg-response-spread-ts", severity: "High", precisionTier: "review" },
      { id: "SEC-PG-RESJSON-pg-response-select-star-ts", severity: "Medium", precisionTier: "review" },
    ]);
  });

  it.each(findings)("classifies emitted %s taxonomy as CWE-200/A01", (finding) => {
    expect(classifyTaxonomyCwe(finding.taxonomy)).toEqual({
      kind: "cwe",
      cwe: ["CWE-200: Exposure of Sensitive Information to an Unauthorized Actor"],
      owasp: ["A01:2021 - Broken Access Control"],
    });
  });

  it("carries each emitted decision through normal enrichment into SARIF CWE tags", () => {
    const enriched = enrichFindingsCwe(findings.map((finding) => ({ ...finding })));
    expect(enriched.map((finding) => finding.cwe)).toEqual(Array.from({ length: PG_RESPONSE_EXPOSURE_KINDS.length }, () => ["CWE-200: Exposure of Sensitive Information to an Unauthorized Actor"]));
    const sarif = toSarif(enriched, { coverageAbsent: "#2227 exercises the normal CWE-to-SARIF seam." }) as {
      runs: { tool: { driver: { rules: { properties: { tags: string[] } }[] } } }[];
    };
    for (const rule of sarif.runs[0]!.tool.driver.rules) {
      expect(rule.properties.tags).toContain("external/cwe/cwe-200");
    }
  });
});

describe("#975: enrichFindingsCwe", () => {
  it("declares the CWE for a security taxonomy that lacks one", () => {
    const [f] = enrichFindingsCwe([finding({ taxonomy: "Object-level authorization gap: client-supplied owner id scopes the query" })]);
    expect(f!.cwe).toEqual(["CWE-639: Authorization Bypass Through User-Controlled Key"]);
    expect(f!.owasp).toEqual(["A01:2021 - Broken Access Control"]);
  });

  it("carries the CWE without an OWASP category when OWASP does not categorize it", () => {
    const [f] = enrichFindingsCwe([finding({ taxonomy: "Non-atomic read-modify-write race condition" })]);
    expect(f!.cwe).toEqual(["CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')"]);
    expect(f!.owasp).toBeUndefined();
  });

  it("leaves a non-security (quality) taxonomy without a CWE", () => {
    const [f] = enrichFindingsCwe([finding({ taxonomy: "M6 — Indicator: manual date formatting" })]);
    expect(f!.cwe).toBeUndefined();
  });

  it("does not overwrite a CWE the finding already carries (semgrep/OSV-sourced)", () => {
    const [f] = enrichFindingsCwe([finding({ taxonomy: "SQL injection", cwe: ["CWE-943: something else"] })]);
    expect(f!.cwe).toEqual(["CWE-943: something else"]);
  });
});
