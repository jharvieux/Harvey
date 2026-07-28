import { describe, expect, it } from "vitest";
import {
  CONDITIONAL_SCANS,
  auditConditionalScan,
  auditConditionalScans,
  discoverConditionalScans,
  parseScanPaths,
  readConditionalScan,
  type ConditionalScan,
} from "./conditional-scan.js";

// A miniature of the real shape: two sibling paths, one of which skips a check the other runs and
// discloses it in a counted row. Every negative case below is this file with one thing changed.
const SOURCE = `
async function scanHosted(ref: string): Promise<Finding[]> {
  return [...checkAlpha(ref), ...checkBeta(ref)];
}

function scopeRow(): Finding[] {
  return [{ id: "X-SCOPE-00", evidence: "Beta breadth was not read." }];
}

async function scanLocal(): Promise<Finding[]> {
  return [...scopeRow(), ...checkAlpha("local")];
}
`;

const ENTRY: ConditionalScan = {
  file: "fixture.ts",
  paths: ["scanHosted", "scanLocal"],
  disclosures: [
    { path: "scanLocal", rowId: "X-SCOPE-00", emitter: "scopeRow", omits: [{ fn: "checkBeta", namedInRow: "Beta breadth" }] },
  ],
};

describe("auditConditionalScan", () => {
  it("passes when the omitted check is declared and the row names its class", () => {
    expect(auditConditionalScan(ENTRY, SOURCE)).toEqual([]);
  });

  it("fails when a path omits a check the registry does not declare", () => {
    const source = SOURCE.replace(`...checkAlpha("local")`, `[]`);
    const [violation, ...rest] = auditConditionalScan(ENTRY, source);

    expect(rest).toEqual([]);
    expect(violation?.detail).toContain("checkAlpha, checkBeta");
    expect(violation?.detail).toContain("registry declares checkBeta");
  });

  it("fails loud when a new sibling scan path appears in the file", () => {
    const source = `${SOURCE}\nasync function scanRemote(): Promise<Finding[]> {\n  return [...checkAlpha("r")];\n}\n`;
    const [violation] = auditConditionalScan(ENTRY, source);

    expect(violation?.detail).toContain("scanHosted, scanLocal, scanRemote");
    expect(violation?.detail).toContain("must be enumerated");
  });

  it("fails when the omitting path never calls its declared emitter", () => {
    const source = SOURCE.replace("...scopeRow(), ", "");
    const [violation] = auditConditionalScan(ENTRY, source);

    expect(violation?.detail).toContain("never calls scopeRow()");
  });

  it("fails when the emitter no longer carries the declared row id", () => {
    const source = SOURCE.replace(`id: "X-SCOPE-00"`, `id: "X-SOMETHING-ELSE"`);
    const [violation] = auditConditionalScan(ENTRY, source);

    expect(violation?.detail).toContain("does not emit the declared not-assessed row id X-SCOPE-00");
  });

  // The row existing is not the point — the row SAYING WHAT WENT UNCHECKED is. A counted row that
  // names nothing discloses nothing, which is the #1330 defect wearing a row id.
  it("fails when the row exists but does not name the class it stands in for", () => {
    const source = SOURCE.replace("Beta breadth was not read.", "Some checks did not run.");
    const [violation] = auditConditionalScan(ENTRY, source);

    expect(violation?.detail).toContain(`never says "Beta breadth"`);
  });
});

// The gate's own recorded bound, held as a test so it cannot rot into folklore: the omission signal
// is the LITERAL text of a `check*(` call. A path that reaches the same check through a helper is
// reported as omitting it. This test passing means the blocker still holds; it is the falsifier
// named in src/conditional-scan.ts's REASON block, and it fails the day the gate follows calls.
describe("the recorded bound", () => {
  it("reads a check reached through a helper as an omission", () => {
    const source = `
async function scanHosted(): Promise<Finding[]> {
  return [...checkAlpha("h"), ...checkBeta("h")];
}

function betaViaHelper(): Finding[] {
  return checkBeta("local");
}

async function scanLocal(): Promise<Finding[]> {
  return [...checkAlpha("local"), ...betaViaHelper()];
}
`;
    const entry: ConditionalScan = { file: "fixture.ts", paths: ["scanHosted", "scanLocal"], disclosures: [] };

    // scanLocal DOES run checkBeta, through betaViaHelper. The gate cannot tell.
    expect(auditConditionalScan(entry, source)[0]?.detail).toContain("scanLocal omits checkBeta");
  });
});

describe("discoverConditionalScans", () => {
  it("finds every module with sibling scan paths, so the registry cannot go stale", () => {
    const found = discoverConditionalScans();

    expect(found).toContain("src/scan/supabase.ts");
    // Registering is not optional: anything discovered and unregistered fails the CLI.
    expect(found.filter((f) => !CONDITIONAL_SCANS.some((e) => e.file === f))).toEqual([]);
  });

  it("does not report a module with a single scan path", () => {
    expect(discoverConditionalScans()).not.toContain("src/scan/secrets.ts");
  });
});

describe("parseScanPaths", () => {
  it("reads a path's body up to the next top-level close brace, not into its sibling", () => {
    const paths = parseScanPaths(SOURCE);

    expect(paths.map((p) => p.name)).toEqual(["scanHosted", "scanLocal"]);
    expect(paths[0]?.body).toContain("checkBeta");
    expect(paths[1]?.body).not.toContain("checkBeta");
  });
});

describe("the registered modules", () => {
  it("every registered conditional omission is declared and disclosed in the real source", () => {
    expect(auditConditionalScans(CONDITIONAL_SCANS)).toEqual([]);
  });

  it("scanLocal really is the path that omits — the registry is not describing a file it does not read", () => {
    const supabase = CONDITIONAL_SCANS.find((e) => e.file === "src/scan/supabase.ts") as ConditionalScan;
    const bodies = new Map(parseScanPaths(readConditionalScan(supabase)).map((p) => [p.name, p.body]));

    for (const omit of supabase.disclosures.flatMap((d) => d.omits)) {
      expect(bodies.get("scanHosted")).toContain(`${omit.fn}(`);
      expect(bodies.get("scanLocal")).not.toContain(`${omit.fn}(`);
    }
  });
});
