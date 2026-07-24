import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { Finding } from "../findings.js";
import { selectGradedFindings } from "../quick-scan.js";
import { annotateCveReachability, byReachabilityThenSeverity, classifyReachability, filesImporting } from "./dep-reachability.js";
import { mechanicalFinding } from "./common.js";

function cve(pkg: string | undefined, id = "DEP-1"): Finding {
  return mechanicalFinding({
    id,
    title: `${pkg ?? "?"} vulnerable`,
    severity: "High",
    category: "Dependency CVE",
    taxonomy: "Known-vulnerable dependency",
    location: `package.json (${pkg ?? "?"})`,
    evidence: "version match",
    impact: "impact",
    fix: "upgrade",
    precisionTier: "review",
    ...(pkg ? { dependency: pkg } : {}),
  });
}

const src = (text: string) => [{ path: "a.ts", text }];

describe("import detection", () => {
  it("finds every module-specifier form that brings the package in", () => {
    for (const text of [
      `import merge from "lodash";`,
      `import "lodash";`,
      `const x = require("lodash");`,
      `await import("lodash");`,
      `export { merge } from "lodash";`,
      `import merge from "lodash/merge";`, // a subpath still imports the package
    ]) {
      expect(filesImporting(src(text), "lodash"), text).toEqual(["a.ts"]);
    }
  });

  it("does not mistake a longer package name or a mention in prose for an import", () => {
    expect(filesImporting(src(`import x from "lodash-es";`), "lodash")).toEqual([]);
    expect(filesImporting(src(`// we should drop lodash someday`), "lodash")).toEqual([]);
  });
});

// The point of #874 is ordering WITHOUT manufacturing confidence. Each status has to carry the
// limit of what it proves, or the client reads "not imported" as "cleared".
describe("classification and its stated limits", () => {
  const direct = new Set(["lodash"]);

  it("ranks an imported package first and cites where", () => {
    const r = classifyReachability("lodash", ["a.ts", "b.ts"], direct, 5);
    expect(r.status).toBe("imported");
    expect(r.files).toEqual(["a.ts", "b.ts"]);
    expect(r.justification).toContain("a.ts, b.ts");
    expect(r.justification).toContain("does not prove the vulnerable function is called");
  });

  it("de-prioritizes a declared-but-unimported package without clearing it", () => {
    const r = classifyReachability("lodash", [], direct, 5);
    expect(r.status).toBe("declared-not-imported");
    expect(r.justification).toContain("does not clear it");
  });

  it("de-prioritizes a transitive package without clearing it", () => {
    const r = classifyReachability("minimist", [], direct, 5);
    expect(r.status).toBe("transitive-only");
    expect(r.justification).toContain("does not clear it");
  });

  it("ranks an unmeasurable package ABOVE the not-imported ones — an unassessed row is not a safe one", () => {
    const notAssessed = classifyReachability("lodash", [], direct, 0);
    expect(notAssessed.status).toBe("not-assessed");
    expect(notAssessed.rank).toBeLessThan(classifyReachability("lodash", [], direct, 5).rank);
    expect(notAssessed.rank).toBeLessThan(classifyReachability("minimist", [], direct, 5).rank);
    expect(notAssessed.justification).toContain("NOT assessed");
  });

  it("orders imported before unassessed before not-imported", () => {
    const rank = (s: number, files: string[], pkg: string) => classifyReachability(pkg, files, direct, s).rank;
    expect(rank(5, ["a.ts"], "lodash")).toBeLessThan(rank(0, [], "lodash"));
    expect(rank(0, [], "lodash")).toBeLessThan(rank(5, [], "lodash"));
    expect(rank(5, [], "lodash")).toBeLessThan(rank(5, [], "minimist"));
  });
});

describe("annotating a scan's findings", () => {
  let dir: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "reach-"));
    mkdirSync(join(dir, "src"));
    writeFileSync(join(dir, "src", "app.ts"), `import axios from "axios";\n`);
    // node_modules must not count as the app importing the package.
    mkdirSync(join(dir, "node_modules", "lodash"), { recursive: true });
    writeFileSync(join(dir, "node_modules", "lodash", "index.js"), `require("minimist");\n`);
  });
  afterEach(() => rmSync(dir, { recursive: true, force: true }));

  it("marks a package the app imports as imported, and one it doesn't as not", () => {
    const { findings } = annotateCveReachability([cve("axios", "A"), cve("minimist", "B")], dir, new Set(["axios", "minimist"]));
    expect(findings.map((f) => f.reachability?.status)).toEqual(["imported", "declared-not-imported"]);
    expect(findings[0]!.reachability?.files).toEqual(["src/app.ts"]);
  });

  it("leaves non-CVE findings untouched", () => {
    const secret = mechanicalFinding({
      id: "S-1", title: "secret", severity: "Critical", category: "Secret exposure", taxonomy: "t",
      location: "a.ts:1", evidence: "e", impact: "i", fix: "f", precisionTier: "high",
    });
    const { findings } = annotateCveReachability([secret, cve("axios")], dir, new Set(["axios"]));
    expect(findings[0]!.reachability).toBeUndefined();
    expect(findings[1]!.reachability).toBeDefined();
  });

  it("counts a CVE row it cannot rank instead of letting it sink silently", () => {
    const { findings, unranked } = annotateCveReachability([cve("axios", "A"), cve(undefined, "B")], dir, new Set(["axios"]));
    expect(unranked).toBe(1);
    expect(findings[1]!.reachability).toBeUndefined();
  });
});

// The #213/#227 decision this issue must not undo.
describe("reachability never becomes a grade", () => {
  it("a reachable CVE still does not grade", () => {
    const reachable: Finding = {
      ...cve("axios"),
      precisionTier: "high",
      reachability: { status: "imported", rank: 0, justification: "imported in 3 files" },
    };
    expect(selectGradedFindings([reachable])).toEqual([]);
    expect(reachable.exploitabilityVerified).toBeUndefined();
  });
});

describe("list ordering", () => {
  it("sorts by reachability first, severity second", () => {
    const sevRank = (f: Finding) => (f.severity === "Critical" ? 0 : 1);
    const criticalUnreached: Finding = { ...cve("a", "A"), severity: "Critical", reachability: { status: "transitive-only", rank: 3, justification: "j" } };
    const highReached: Finding = { ...cve("b", "B"), severity: "High", reachability: { status: "imported", rank: 0, justification: "j" } };
    expect([criticalUnreached, highReached].sort(byReachabilityThenSeverity(sevRank)).map((f) => f.id)).toEqual(["B", "A"]);
  });
});
