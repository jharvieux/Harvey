import { execFileSync } from "node:child_process";
import { describe, expect, it } from "vitest";
import { classifyTaxonomyCwe, enrichFindingsCwe } from "./cwe-map.js";
import type { Finding } from "./findings.js";

function finding(over: Partial<Finding> = {}): Finding {
  return {
    id: "F-1", title: "t", severity: "High", confidence: "Confirmed", category: "c",
    taxonomy: "SQL injection", location: "a.ts:1", status: "Open", evidence: "", impact: "", fix: "",
    value: 3, ease: 3, safety: 3, ...over,
  };
}

// Every `taxonomy: "…"` literal a detector emits, harvested from the detector/scan source the same
// way `detector-census` does. Test files are excluded — their fixtures ("t", "stripe", "audit dsih")
// are not real detector taxonomies. This is the fail-loud guard: a new detector taxonomy that isn't
// classified in cwe-map.ts (security CWE, or a deliberate no-CWE-with-reason) fails here.
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
  return [...set].sort();
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
