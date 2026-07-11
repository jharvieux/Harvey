// M7 code-layer calibration gate (#170): every class ships only with a caught positive AND a
// cleared benign negative, mirroring the app-router.test.ts fixture discipline (issue #61's
// rule, enforced here through `pnpm verify` since these detectors run outside runMechanicalScan).

import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { detectPerfCodeFindings, reactCompilerEnabled, type SourceInput } from "./perf-code.js";

const FIXTURES_ROOT = fileURLToPath(new URL("./__fixtures__/perf/", import.meta.url));

// Same loader as app-router.test.ts: fixtures are `<name>.txt` so tsc/knip/eslint don't
// compile them; strip the suffix to recover the logical source path.
function loadFixtureDir(relDir: string): SourceInput[] {
  const root = join(FIXTURES_ROOT, relDir);
  const files: SourceInput[] = [];
  const walk = (dir: string) => {
    for (const entry of readdirSync(dir)) {
      const full = join(dir, entry);
      if (statSync(full).isDirectory()) {
        walk(full);
      } else if (entry.endsWith(".txt")) {
        const path = relative(root, full).replace(/\.txt$/, "").split(sep).join("/");
        files.push({ path, text: readFileSync(full, "utf8") });
      }
    }
  };
  walk(root);
  return files;
}

function byTaxonomy(relDir: string, taxonomy: string) {
  return detectPerfCodeFindings(loadFixtureDir(relDir)).filter((f) => f.taxonomy === taxonomy);
}

describe("context value recreated every render", () => {
  const TAX = "M7 — Context value recreated every render";
  it("flags an inline object literal as a Provider value", () => {
    const hits = byTaxonomy("ctx-value/positive", TAX);
    expect(hits).toHaveLength(1);
    expect(hits[0]).toMatchObject({ severity: "Perf", confidence: "Likely", category: "Performance" });
    expect(hits[0]?.location).toBe("components/theme-provider.tsx:9");
  });
  it("does not flag a useMemo-stabilized value", () => {
    expect(byTaxonomy("ctx-value/negative", TAX)).toHaveLength(0);
  });
});

describe("inline literal props", () => {
  const TAX = "M7 — Inline literal prop";
  it("flags inline object/array literals passed to components, one rolled-up finding per file", () => {
    const hits = byTaxonomy("inline-prop/positive", TAX);
    expect(hits).toHaveLength(1);
    expect(hits[0]?.title).toContain("2×");
    expect(hits[0]).toMatchObject({ severity: "Low", confidence: "Review" });
  });
  it("does not flag hoisted constants or style objects on DOM elements", () => {
    expect(byTaxonomy("inline-prop/negative", TAX)).toHaveLength(0);
  });
});

describe("raw <img> instead of next/image", () => {
  const TAX = "M7 — Raw <img> instead of next/image";
  it("flags raw <img> elements, one rolled-up finding per file", () => {
    const hits = byTaxonomy("img-tag/positive", TAX);
    expect(hits).toHaveLength(1);
    expect(hits[0]?.title).toContain("2×");
    expect(hits[0]?.location).toBe("app/page.tsx:4");
  });
  it("does not flag next/image usage", () => {
    expect(byTaxonomy("img-tag/negative", TAX)).toHaveLength(0);
  });
});

describe("index as list key", () => {
  const TAX = "M7 — Index used as list key";
  it("flags key={i} bound to the map callback's index parameter", () => {
    const hits = byTaxonomy("index-key/positive", TAX);
    expect(hits).toHaveLength(1);
    expect(hits[0]?.location).toBe("components/todo-list.tsx:7");
  });
  it("does not flag a stable-id key even when the index is used elsewhere", () => {
    expect(byTaxonomy("index-key/negative", TAX)).toHaveLength(0);
  });
});

describe("sort in render body", () => {
  const TAX = "M7 — Sort in render body";
  it("flags .sort() running directly inside JSX", () => {
    const hits = byTaxonomy("sort-in-jsx/positive", TAX);
    expect(hits).toHaveLength(1);
    expect(hits[0]?.evidence).toContain("mutates the source array");
  });
  it("does not flag a useMemo-hoisted sort", () => {
    expect(byTaxonomy("sort-in-jsx/negative", TAX)).toHaveLength(0);
  });
});

describe("state sprawl", () => {
  const TAX = "M7 — State sprawl";
  it("flags a component with 8+ useState hooks", () => {
    const hits = byTaxonomy("state-sprawl/positive", TAX);
    expect(hits).toHaveLength(1);
    expect(hits[0]?.title).toContain("SettingsPanel");
    expect(hits[0]?.title).toContain("9");
  });
  it("does not flag a component with a few hooks", () => {
    expect(byTaxonomy("state-sprawl/negative", TAX)).toHaveLength(0);
  });
});

describe("await in loop (N+1)", () => {
  const TAX = "M7 — Await in loop (N+1)";
  it("flags per-item independent awaits, one rolled-up finding per file, tiered by request path", () => {
    const hits = byTaxonomy("await-in-loop/positive", TAX);
    expect(hits).toHaveLength(2);
    const onRoute = hits.find((h) => h.location.includes("app/api/enrich/route.ts"));
    const inLib = hits.find((h) => h.location.includes("lib/order-totals.ts"));
    // Request-path N+1 is user-facing latency; worker/lib N+1 is job runtime — different tiers.
    expect(onRoute).toMatchObject({ severity: "Perf", confidence: "Likely" });
    expect(inLib).toMatchObject({ severity: "Perf", confidence: "Review" });
    expect(inLib?.evidence).toContain("off the request path");
  });
  it("does not flag loop-carried dependencies or chunked-batch loops (i += BATCH_SIZE)", () => {
    expect(byTaxonomy("await-in-loop/negative", TAX)).toHaveLength(0);
  });
});

describe("unbounded select", () => {
  const TAX = "M7 — Unbounded select";
  it("flags select('*') with no limit/range on a list read", () => {
    const hits = byTaxonomy("unbounded-select/positive", TAX);
    expect(hits).toHaveLength(1);
    expect(hits[0]).toMatchObject({ severity: "Perf", confidence: "Review" });
  });
  it("does not flag paginated reads, .single() lookups, or count-only head:true queries", () => {
    expect(byTaxonomy("unbounded-select/negative", TAX)).toHaveLength(0);
  });
});

describe("whole-library import", () => {
  const TAX = "M7 — Whole-library import";
  it("flags bare lodash and moment imports", () => {
    const hits = byTaxonomy("whole-lib-import/positive", TAX);
    expect(hits).toHaveLength(2);
    expect(hits.map((h) => h.title).join(" ")).toMatch(/lodash/);
    expect(hits.map((h) => h.title).join(" ")).toMatch(/moment/);
  });
  it("does not flag subpath or named tree-shakeable imports", () => {
    expect(byTaxonomy("whole-lib-import/negative", TAX)).toHaveLength(0);
  });
});

describe("heavy import in client bundle", () => {
  const TAX = "M7 — Heavy import in client bundle";
  it("flags a static monaco-editor import in a 'use client' module", () => {
    const hits = byTaxonomy("heavy-client-import/positive", TAX);
    expect(hits).toHaveLength(1);
    expect(hits[0]?.title).toContain("monaco-editor");
  });
  it("does not flag a next/dynamic-loaded editor", () => {
    expect(byTaxonomy("heavy-client-import/negative", TAX)).toHaveLength(0);
  });
});

describe("unoptimized barrel import (Next < 13.5)", () => {
  const TAX = "M7 — Unoptimized barrel import";
  it("flags named barrel imports when the lowest Next version in the tree predates auto-optimization", () => {
    const hits = byTaxonomy("unopt-barrel/positive", TAX);
    expect(hits).toHaveLength(1);
    expect(hits[0]?.title).toContain("lucide-react");
    expect(hits[0]?.title).toContain("date-fns");
    expect(hits[0]?.title).toContain("13.4");
  });
  it("does not flag on Next ≥ 13.5 (auto-optimized)", () => {
    expect(byTaxonomy("unopt-barrel/negative", TAX)).toHaveLength(0);
  });
  it("does not flag when next.config lists the packages in optimizePackageImports", () => {
    expect(byTaxonomy("unopt-barrel/negative-config", TAX)).toHaveLength(0);
  });
});

describe("manual font stylesheet", () => {
  const TAX = "M7 — Manual font stylesheet";
  it("flags a Google Fonts <link rel=stylesheet>", () => {
    const hits = byTaxonomy("font-link/positive", TAX);
    expect(hits).toHaveLength(1);
    expect(hits[0]?.fix).toContain("next/font");
  });
  it("does not flag next/font usage", () => {
    expect(byTaxonomy("font-link/negative", TAX)).toHaveLength(0);
  });
});

describe("fetch in middleware", () => {
  const TAX = "M7 — Fetch in middleware hot path";
  it("flags a network call inside middleware.ts", () => {
    const hits = byTaxonomy("middleware-fetch/positive", TAX);
    expect(hits).toHaveLength(1);
    expect(hits[0]?.location).toContain("middleware.ts");
  });
  it("does not flag cookie-only middleware", () => {
    expect(byTaxonomy("middleware-fetch/negative", TAX)).toHaveLength(0);
  });
});

describe("blocking sync I/O in request handler", () => {
  const TAX = "M7 — Blocking sync I/O in request handler";
  it("flags readFileSync inside a route handler function", () => {
    const hits = byTaxonomy("sync-io/positive", TAX);
    expect(hits).toHaveLength(1);
    expect(hits[0]?.title).toContain("readFileSync");
  });
  it("does not flag a run-once module-scope sync read", () => {
    expect(byTaxonomy("sync-io/negative", TAX)).toHaveLength(0);
  });
});

describe("JSON deep-clone", () => {
  const TAX = "M7 — JSON deep-clone";
  it("flags JSON.parse(JSON.stringify(x))", () => {
    const hits = byTaxonomy("json-clone/positive", TAX);
    expect(hits).toHaveLength(1);
    expect(hits[0]?.fix).toContain("structuredClone");
  });
  it("does not flag structuredClone", () => {
    expect(byTaxonomy("json-clone/negative", TAX)).toHaveLength(0);
  });
});

describe("render-once contexts (emails / PDF documents)", () => {
  it("suppresses every React re-render class in email templates and @react-pdf documents", () => {
    // ATC dogfood: email clients REQUIRE raw <img>, and index keys can't cause remounts in
    // something rendered exactly once — flagging them there is crying wolf.
    const findings = detectPerfCodeFindings(loadFixtureDir("render-once/negative"));
    expect(findings).toHaveLength(0);
  });
});

describe("React Compiler gate", () => {
  it("detects reactCompiler in next.config and downgrades manual-memo classes to Info", () => {
    const files = loadFixtureDir("react-compiler-on/positive");
    expect(reactCompilerEnabled(files)).toBe(true);
    const hits = detectPerfCodeFindings(files).filter((f) => f.taxonomy === "M7 — Context value recreated every render");
    expect(hits).toHaveLength(1);
    expect(hits[0]?.severity).toBe("Info");
    expect(hits[0]?.evidence).toContain("React Compiler is enabled");
  });
  it("keeps the same shape at Perf severity when no compiler config is present", () => {
    const hits = byTaxonomy("ctx-value/positive", "M7 — Context value recreated every render");
    expect(hits[0]?.severity).toBe("Perf");
  });
});

describe("finding shape", () => {
  it("emits sequential M7C ids and Performance category on every finding", () => {
    const findings = detectPerfCodeFindings(loadFixtureDir("whole-lib-import/positive"));
    expect(findings.length).toBeGreaterThan(0);
    findings.forEach((f, i) => {
      expect(f.id).toBe(`M7C-${String(i + 1).padStart(2, "0")}`);
      expect(f.category).toBe("Performance");
      expect(f.status).toBe("Open");
    });
  });
});
