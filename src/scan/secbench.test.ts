// Layer 1 for the SecBench.js recall gate (#879): runs in `pnpm verify` with no clone and no
// network. Proves the loader parses SecBench's file layout, the osv matcher scopes to the entry's
// OWN target package (not a transitive dep), and the scorer counts an installable-but-osv-clean
// entry as a MISS rather than dropping it from the denominator (the inflation trap #879 warns
// about). The real measurement (clone + npm + osv over 600 entries) is `validate-secbench.ts`,
// recorded in docs/design/secbench-recall-measurement.md — not run here.

import { describe, expect, it } from "vitest";
import type { OsvScanResult } from "./dependencies.js";
import {
  indexOsvByEntry,
  loadSecbenchCorpus,
  matchEntryOsv,
  scoreSecbench,
  type SecbenchEntry,
} from "./secbench.js";

// In-memory SecBench.js checkout: one entry per class, mirroring the real package.json shape.
const TREE: Record<string, string> = {
  "/sb/command-injection/aaptjs_1.3.1/package.json": JSON.stringify({
    id: "CVE-2020-26707",
    dependencies: { aaptjs: "1.3.1" },
    links: { source2: "https://github.com/advisories/GHSA-m7p2-ghfh-pjvx" },
    sink: "index.js:18:3",
  }),
  "/sb/prototype-pollution/lodash_4.17.10/package.json": JSON.stringify({
    id: "CVE-2019-10744",
    dependencies: { lodash: "4.17.10" },
    links: { source1: "https://github.com/advisories/GHSA-jf85-cpcp-j695" },
    sinkLocation: "lodash.js:2573:21",
  }),
  // A Snyk-only entry: no CVE id, no GHSA — models the class osv/GHSA cannot cover.
  "/sb/path-traversal/basic-static_2.0.2/package.json": JSON.stringify({
    id: "",
    dependencies: { "basic-static": "2.0.2" },
    links: { source1: "https://security.snyk.io/vuln/SNYK-JS-BASICSTATIC-1" },
  }),
  "/sb/redos/x_1.0.0/package.json": JSON.stringify({ id: "", dependencies: { x: "1.0.0" } }),
  "/sb/code-injection/y_2.0.0/package.json": JSON.stringify({ id: "CVE-2021-1", dependencies: { y: "2.0.0" } }),
};

const fakeFs = {
  existsSync: (p: string) => p in TREE || Object.keys(TREE).some((k) => k.startsWith(p + "/")),
  readFileSync: (p: string) => TREE[p]!,
  readdirSync: (p: string) => {
    const kids = new Set<string>();
    for (const k of Object.keys(TREE)) {
      if (!k.startsWith(p + "/")) continue;
      kids.add(k.slice(p.length + 1).split("/")[0]!);
    }
    return [...kids];
  },
};

describe("loadSecbenchCorpus", () => {
  const entries = loadSecbenchCorpus("/sb", fakeFs);

  it("loads one entry per class with pkg/version/advisory ids parsed", () => {
    expect(entries).toHaveLength(5);
    const aaptjs = entries.find((e) => e.slug === "aaptjs_1.3.1")!;
    expect(aaptjs.pkg).toBe("aaptjs");
    expect(aaptjs.version).toBe("1.3.1");
    expect(aaptjs.cveId).toBe("CVE-2020-26707");
    expect(aaptjs.advisoryIds).toContain("GHSA-M7P2-GHFH-PJVX");
    expect(aaptjs.advisoryIds).toContain("CVE-2020-26707");
  });

  it("records an empty CVE id as null, not a fake catch-all", () => {
    const snyk = entries.find((e) => e.slug === "basic-static_2.0.2")!;
    expect(snyk.cveId).toBeNull();
    expect(snyk.advisoryIds).toContain("SNYK-JS-BASICSTATIC-1");
  });
});

describe("matchEntryOsv", () => {
  const entries = loadSecbenchCorpus("/sb", fakeFs);
  const byKey = (k: string): SecbenchEntry => entries.find((e) => e.key === k)!;

  const osv: OsvScanResult = {
    results: [
      {
        source: { path: "/w/command-injection/aaptjs_1.3.1/package-lock.json" },
        packages: [{ package: { name: "aaptjs" }, vulnerabilities: [{ id: "GHSA-m7p2-ghfh-pjvx", aliases: ["CVE-2020-26707"] }] }],
      },
      {
        // lodash's vuln sits on a TRANSITIVE dep here, NOT lodash itself — must not count.
        source: { path: "/w/prototype-pollution/lodash_4.17.10/package-lock.json" },
        packages: [{ package: { name: "some-transitive" }, vulnerabilities: [{ id: "GHSA-zzzz-zzzz-zzzz" }] }],
      },
    ],
  };
  const index = indexOsvByEntry(osv);

  it("flags the entry when osv reports an advisory on its OWN target package", () => {
    const m = matchEntryOsv(byKey("command-injection/aaptjs_1.3.1"), index);
    expect(m.targetFlagged).toBe(true);
    expect(m.exactAdvisory).toBe(true); // GHSA/CVE alias matched the curated id
  });

  it("does NOT flag when only a transitive dep is vulnerable", () => {
    const m = matchEntryOsv(byKey("prototype-pollution/lodash_4.17.10"), index);
    expect(m.targetFlagged).toBe(false);
  });

  it("does NOT flag an entry osv never reported (clean or Snyk-only)", () => {
    const m = matchEntryOsv(byKey("path-traversal/basic-static_2.0.2"), index);
    expect(m.targetFlagged).toBe(false);
  });
});

describe("scoreSecbench denominator honesty", () => {
  const entries = loadSecbenchCorpus("/sb", fakeFs);
  const osv: OsvScanResult = {
    results: [
      {
        source: { path: "/w/command-injection/aaptjs_1.3.1/package-lock.json" },
        packages: [{ package: { name: "aaptjs" }, vulnerabilities: [{ id: "GHSA-m7p2-ghfh-pjvx", aliases: ["CVE-2020-26707"] }] }],
      },
    ],
  };
  const index = indexOsvByEntry(osv);

  it("counts an installable-but-osv-clean entry as a MISS (kept in the denominator)", () => {
    // Everything installable; only aaptjs is flagged. basic-static (Snyk-only) is a real miss.
    const installable = new Set(entries.map((e) => e.key));
    const { all } = scoreSecbench(entries, index, installable, new Set());
    expect(all.installable).toBe(5);
    expect(all.notInstallable).toBe(0);
    expect(all.scaFlagged).toBe(1); // only aaptjs
    // The 4 unflagged installable entries are MISSES, not dropped: denominator stays 5.
  });

  it("excludes a not-installable entry from the denominator and names it separately", () => {
    // basic-static's package never resolved from npm: no lockfile generated.
    const installable = new Set(entries.map((e) => e.key).filter((k) => !k.includes("basic-static")));
    const { all } = scoreSecbench(entries, index, installable, new Set());
    expect(all.installable).toBe(4);
    expect(all.notInstallable).toBe(1);
  });

  it("records semgrep source-pathway hits by entry key", () => {
    const installable = new Set(entries.map((e) => e.key));
    const { all } = scoreSecbench(entries, index, installable, new Set(["redos/x_1.0.0"]));
    expect(all.semgrepHits).toBe(1);
  });
});
