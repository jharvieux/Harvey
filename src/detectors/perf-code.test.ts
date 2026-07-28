// M7 code-layer calibration gate (#170): every class ships only with a caught positive AND a
// cleared benign negative, mirroring the app-router.test.ts fixture discipline (issue #61's
// rule, enforced here through `pnpm verify` since these detectors run outside runMechanicalScan).

import { readFileSync } from "node:fs";
import { join, relative, sep } from "node:path";
import { readEntriesSafe } from "../fs-walk.js";
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
    for (const { name: entry, path: full, isDirectory } of readEntriesSafe(dir).entries) {
      if (isDirectory) {
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

// #577: the Vite-aware tiers — the framework flag switches the client-JS detectors to their
// all-client shape and turns on the Vite-only glob / route-splitting checks.
function byTaxonomyVite(relDir: string, taxonomy: string) {
  return detectPerfCodeFindings(loadFixtureDir(relDir), "vite").filter((f) => f.taxonomy === taxonomy);
}

// #248: the micro-render classes (context value / inline literal prop / index-as-key) only emit
// when React Compiler is enabled, so their positives AND negatives run with this config appended —
// a negative that passes only because the whole class is suppressed would be vacuous.
const COMPILER_ON: SourceInput = {
  path: "next.config.mjs",
  text: "const nextConfig = { experimental: { reactCompiler: true } };\nexport default nextConfig;\n",
};

function byTaxonomyCompilerOn(relDir: string, taxonomy: string) {
  return detectPerfCodeFindings([...loadFixtureDir(relDir), COMPILER_ON]).filter((f) => f.taxonomy === taxonomy);
}

describe("context value recreated every render", () => {
  const TAX = "M7 — Context value recreated every render";
  it("flags an inline object literal as a Provider value (Info — compiler-covered) when React Compiler is on", () => {
    const hits = byTaxonomyCompilerOn("ctx-value/positive", TAX);
    expect(hits).toHaveLength(1);
    expect(hits[0]).toMatchObject({ severity: "Info", confidence: "Likely", category: "Performance" });
    expect(hits[0]?.location).toBe("components/theme-provider.tsx:9");
  });
  it("suppresses the class entirely when React Compiler is off (#248 — measured ~0% real without it)", () => {
    expect(byTaxonomy("ctx-value/positive", TAX)).toHaveLength(0);
  });
  it("does not flag a useMemo-stabilized value", () => {
    expect(byTaxonomyCompilerOn("ctx-value/negative", TAX)).toHaveLength(0);
  });
  it("does not flag a Provider whose Context isn't created in this project's own sources (a library/shadcn primitive, #230)", () => {
    expect(byTaxonomyCompilerOn("ctx-value/negative-library-context", TAX)).toHaveLength(0);
  });
});

describe("inline literal props", () => {
  const TAX = "M7 — Inline literal prop";
  it("flags inline object/array literals passed to components (Info — compiler-covered), one rolled-up finding per file, when React Compiler is on", () => {
    const hits = byTaxonomyCompilerOn("inline-prop/positive", TAX);
    expect(hits).toHaveLength(1);
    expect(hits[0]?.title).toContain("2×");
    expect(hits[0]).toMatchObject({ severity: "Info", confidence: "Review" });
  });
  it("suppresses the class entirely when React Compiler is off (#248)", () => {
    expect(byTaxonomy("inline-prop/positive", TAX)).toHaveLength(0);
  });
  it("does not flag hoisted constants or style objects on DOM elements", () => {
    expect(byTaxonomyCompilerOn("inline-prop/negative", TAX)).toHaveLength(0);
  });
  it("does not flag framer-motion animation props (animate/initial/transition) — the library diffs by value, not reference (#230)", () => {
    expect(byTaxonomyCompilerOn("inline-prop/negative-framer-motion", TAX)).toHaveLength(0);
  });
  it("does not flag an inline `style` object prop — idiomatic and near-zero cost (#230)", () => {
    expect(byTaxonomyCompilerOn("inline-prop/negative-style", TAX)).toHaveLength(0);
  });
  it("does not flag an array built entirely from live i18n t(...) calls (#230)", () => {
    expect(byTaxonomyCompilerOn("inline-prop/negative-i18n-array", TAX)).toHaveLength(0);
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
  it("does not flag a data:/blob: one-shot image (MFA QR in a dialog, an authenticated blob preview) — next/image can't optimize a URI with no remote fetch anyway (#230)", () => {
    expect(byTaxonomy("img-tag/negative-one-shot", TAX)).toHaveLength(0);
  });
});

describe("index as list key", () => {
  const TAX = "M7 — Index used as list key";
  it("flags key={i} bound to the map callback's index parameter when React Compiler is on (Low — keys aren't compiler-fixed)", () => {
    const hits = byTaxonomyCompilerOn("index-key/positive", TAX);
    expect(hits).toHaveLength(1);
    expect(hits[0]?.severity).toBe("Low");
    expect(hits[0]?.location).toBe("components/todo-list.tsx:7");
  });
  it("suppresses the class entirely when React Compiler is off (#248)", () => {
    expect(byTaxonomy("index-key/positive", TAX)).toHaveLength(0);
  });
  it("does not flag a stable-id key even when the index is used elsewhere", () => {
    expect(byTaxonomyCompilerOn("index-key/negative", TAX)).toHaveLength(0);
  });
  it("does not flag a hardcoded const array literal (Footer/FAQ/Stepper-style static list) — it never reorders/inserts/deletes (#230)", () => {
    expect(byTaxonomyCompilerOn("index-key/negative-static-list", TAX)).toHaveLength(0);
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
  it("does not flag sorting a (spread of a) hardcoded const list — a fixed handful never scales (#816)", () => {
    expect(byTaxonomy("sort-in-jsx/negative-static-list", TAX)).toHaveLength(0);
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
  it("does not flag a loop over a hardcoded/inline-literal list — bounded by source code, not data (#816)", () => {
    expect(byTaxonomy("await-in-loop/negative-static-list", TAX)).toHaveLength(0);
  });
});

describe("unbounded select", () => {
  const TAX = "M7 — Unbounded select";
  it("flags select('*') with no limit/range on a list read", () => {
    const hits = byTaxonomy("unbounded-select/positive", TAX);
    expect(hits).toHaveLength(1);
    expect(hits[0]).toMatchObject({ severity: "Perf", confidence: "Review" });
  });
  it("does not flag paginated reads, .single() lookups, count-only head:true queries, a bounded `.in('id', [...])` lookup, or an `.insert(...).select()` mutation echo (#230)", () => {
    expect(byTaxonomy("unbounded-select/negative", TAX)).toHaveLength(0);
  });
  it("does not flag a `.eq('id', …)` primary-key point lookup — but scoping filters like .eq('conversation_id') still fire (#816)", () => {
    expect(byTaxonomy("unbounded-select/negative-pk-eq", TAX)).toHaveLength(0);
    expect(byTaxonomy("unbounded-select/positive", TAX)).toHaveLength(1); // the .eq('conversation_id') list read must keep firing
  });
});

describe("client fetch in useEffect", () => {
  const TAX = "M7 — Client fetch in useEffect";
  it("flags a fetch/.then chain, an async-IIFE await fetch, and a Supabase read via an invoked local function — one rolled-up finding per file", () => {
    const hits = byTaxonomy("client-fetch-effect/positive", TAX);
    expect(hits).toHaveLength(3);
    for (const h of hits) expect(h).toMatchObject({ severity: "Perf", confidence: "Review" });
    expect(hits.find((h) => h.location.startsWith("components/orders-table.tsx"))?.evidence).toContain("fetch(\"/api/orders\")");
    expect(hits.find((h) => h.location.startsWith("components/profile-card.tsx"))?.evidence).toContain("supabase.from(\"profiles\")");
  });
  it("does not flag SWR-routed fetching, a Server Component fetch (the fix), a listener-registered fetch that only runs on a user event, or a fire-and-forget beacon", () => {
    expect(byTaxonomy("client-fetch-effect/negative", TAX)).toHaveLength(0);
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

describe("Vite mode (#577)", () => {
  it("flags a heavy static import in a no-directive module ONLY in Vite mode (every module is client)", () => {
    const TAX = "M7 — Heavy import in client bundle";
    // No `"use client"` directive → Next mode leaves it alone; Vite mode treats it as client.
    expect(byTaxonomy("heavy-client-import/positive-vite", TAX)).toHaveLength(0);
    const vite = byTaxonomyVite("heavy-client-import/positive-vite", TAX);
    expect(vite).toHaveLength(1);
    expect(vite[0]?.title).toContain("three");
    expect(vite[0]?.fix).toContain("React.lazy");
  });

  it("flags a useEffect fetch in a no-directive module only in Vite mode, with an SPA fix (no Server Component)", () => {
    const TAX = "M7 — Client fetch in useEffect";
    expect(byTaxonomy("client-fetch-effect/positive-vite", TAX)).toHaveLength(0);
    const vite = byTaxonomyVite("client-fetch-effect/positive-vite", TAX);
    expect(vite).toHaveLength(1);
    expect(vite[0]?.fix).toMatch(/useSWR|React Query/);
    expect(vite[0]?.fix).not.toContain("Server Component");
  });

  it("flags eager import.meta.glob only in Vite mode; a lazy glob is clean", () => {
    const TAX = "M7 — Eager import.meta.glob";
    expect(byTaxonomy("import-meta-glob/positive", TAX)).toHaveLength(0); // Next mode: detector off
    const vite = byTaxonomyVite("import-meta-glob/positive", TAX);
    expect(vite).toHaveLength(1);
    expect(vite[0]?.evidence).toContain("eager: true");
    expect(byTaxonomyVite("import-meta-glob/negative", TAX)).toHaveLength(0); // lazy glob is fine
  });

  it("flags statically-imported react-router route components; React.lazy routes are clean", () => {
    const TAX = "M7 — Route not code-split";
    const vite = byTaxonomyVite("route-split/positive", TAX);
    expect(vite).toHaveLength(1);
    expect(vite[0]?.title).toContain("3 route components");
    expect(vite[0]?.evidence).toContain("Home");
    expect(byTaxonomyVite("route-split/negative", TAX)).toHaveLength(0);
    expect(byTaxonomy("route-split/positive", TAX)).toHaveLength(0); // Next mode: detector off
  });

  it("branches raw-<img> and font remediation text on Vite", () => {
    // #1480: the TAXONOMY branches too, not only the title and the fix. It used to name
    // next/image unconditionally, so a React Router / Vite client read "instead of next/image"
    // in any grouping keyed on taxonomy — a label defect on all 60 of carbon's rows.
    expect(byTaxonomyVite("img-tag/positive", "M7 — Raw <img> instead of next/image")).toHaveLength(0);
    const img = byTaxonomyVite("img-tag/positive", "M7 — Raw <img> without dimensions or lazy-loading");
    expect(img).toHaveLength(1);
    expect(img[0]?.title).toContain("without dimensions");
    expect(img[0]?.fix).toContain("vite-imagetools");
    const font = byTaxonomyVite("font-link/positive", "M7 — Manual font stylesheet");
    expect(font).toHaveLength(1);
    expect(font[0]?.fix).toContain("@fontsource");
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
  it("#1203: flags pbkdf2Sync/readFileSync inside exported functions outside a recognised handler path, at Review confidence", () => {
    const hits = byTaxonomy("sync-io/positive-generic", TAX).filter((h) => h.confidence === "Review");
    expect(hits).toHaveLength(2);
    expect(hits.map((h) => h.title).join(" | ")).toContain("pbkdf2Sync");
    expect(hits.map((h) => h.title).join(" | ")).toContain("readFileSync");
    // #1344: the evidence must NAME the entry point that reaches it — the old wording disclaimed
    // that reachability was never established, which was true and was the precision bug.
    expect(hits[0]?.evidence).toContain("app/api/login/route.ts");
  });
  it("#1203: does not flag a sync read in a build/tooling script (scripts/ dir)", () => {
    expect(byTaxonomy("sync-io/negative-build-script", TAX)).toHaveLength(0);
  });
  it("#1344: stays silent on an exported-function sync call no request entry point imports, while the same-directory route control still fires", () => {
    const hits = byTaxonomy("sync-io/negative-unreachable", TAX);
    // Exactly the scope control — the CLI package's three exported sync calls contribute nothing.
    expect(hits.map((h) => h.location)).toEqual(["app/api/health/route.ts:8"]);
    expect(hits[0]?.confidence).toBe("Likely");
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
  it("does not flag a module-scope run-once clone (cold-start copy, same exemption as sync-io) (#816)", () => {
    expect(byTaxonomy("json-clone/negative-module-scope", TAX)).toHaveLength(0);
  });
});

describe("nested-loop join", () => {
  const TAX = "M7 — Nested-loop join";
  it("flags .find inside .map, .some inside for-of, and array .includes inside .filter — one rolled-up finding per file", () => {
    const hits = byTaxonomy("nested-loop-join/positive", TAX);
    expect(hits).toHaveLength(2);
    const enrich = hits.find((h) => h.location.startsWith("lib/enrich-orders.ts"));
    const allowed = hits.find((h) => h.location.startsWith("lib/filter-allowed.ts"));
    expect(enrich?.title).toContain("2×");
    expect(enrich).toMatchObject({ severity: "Perf", confidence: "Review" });
    expect(allowed?.evidence).toContain("allowedIds.includes(i.id)");
    expect(allowed?.fix).toContain("new Map");
  });
  it("does not flag the Map/Set-indexed fix, a hardcoded or SCREAMING_SNAKE config list, a per-item field scan, or String.includes", () => {
    expect(byTaxonomy("nested-loop-join/negative", TAX)).toHaveLength(0);
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
  it("suppresses the micro-render classes entirely when no compiler config is present (#248)", () => {
    expect(byTaxonomy("ctx-value/positive", "M7 — Context value recreated every render")).toHaveLength(0);
  });
  it("surfaces (never silently assumes false) a variable/env-derived reactCompiler flag, e.g. saas-lite's `reactCompiler: ENABLE_REACT_COMPILER` (#249)", () => {
    const files = loadFixtureDir("react-compiler-unresolvable/positive");
    expect(reactCompilerEnabled(files)).toBe(false); // can't prove it's on
    const hits = byTaxonomy("react-compiler-unresolvable/positive", "M7 — React Compiler flag unresolvable");
    expect(hits).toHaveLength(1);
    expect(hits[0]?.severity).toBe("Watch");
    expect(hits[0]?.evidence).toContain("ENABLE_REACT_COMPILER");
  });
  it("treats an unresolvable flag like compiler-off for the micro-render classes — suppressed, with the Watch row as the disclosure (#248)", () => {
    const unresolvableConfig = loadFixtureDir("react-compiler-unresolvable/positive").filter((f) => /next\.config/.test(f.path));
    const findings = detectPerfCodeFindings([...loadFixtureDir("ctx-value/positive"), ...unresolvableConfig]);
    expect(findings.filter((f) => f.taxonomy === "M7 — Context value recreated every render")).toHaveLength(0);
    expect(findings.filter((f) => f.taxonomy === "M7 — React Compiler flag unresolvable")).toHaveLength(1);
  });
  it("does not flag an explicit literal `reactCompiler: false`", () => {
    expect(byTaxonomy("react-compiler-unresolvable/negative", "M7 — React Compiler flag unresolvable")).toHaveLength(0);
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

  it("sets an explicit precisionTier on every finding so none mis-scores as untiered (#327)", () => {
    const findings = detectPerfCodeFindings(loadFixtureDir("whole-lib-import/positive"));
    expect(findings.length).toBeGreaterThan(0);
    expect(findings.every((f) => f.precisionTier === "review")).toBe(true);
  });
});

// #1475–#1480 — the six false-positive families #1261's FIELD triage of the pinned external
// corpus measured on 2026-07-28. The calibration rows in m7-code.entries.ts pin whether each
// class FIRES and at what band; these pin the sentences a client reads, which no corpus row can.
describe("field FP families (#1475–#1480)", () => {
  const SPRAWL = "M7 — State sprawl";

  it("#1475: the state-sprawl evidence no longer asserts a per-setter re-render on React >= 18", () => {
    const modern = byTaxonomy("state-sprawl/positive", SPRAWL);
    expect(modern).toHaveLength(1);
    // The exact sentence #1475 was filed against. React 18 collapsed N setters in one handler
    // into ONE render in 2022 — the finding named a mechanism that no longer exists.
    expect(modern[0]?.evidence).not.toContain("every setter triggers a full re-render");
    expect(modern[0]?.evidence).toContain("automatic batching");
    expect(modern[0]?.impact).not.toContain("re-renders per");
    expect(modern[0]?.severity).toBe("Info");
  });

  it("#1475: React < 18 keeps the counted render-cost claim, so the fix is not a blanket suppression", () => {
    const legacy = byTaxonomy("state-sprawl/positive-react17", SPRAWL);
    expect(legacy).toHaveLength(1);
    expect(legacy[0]?.severity).toBe("Low");
    expect(legacy[0]?.evidence).toContain("are NOT batched");
  });

  it("#1477: an SVG-only file emits nothing, and a mixed file counts only the raster hits and says so", () => {
    const svgOnly = byTaxonomy("img-tag/negative-svg", "M7 — Raw <img> instead of next/image");
    // components/hero.tsx is the scope control — one raster <img>, and the three SVGs in
    // logo-cloud.tsx contribute no row of their own.
    expect(svgOnly).toHaveLength(1);
    expect(svgOnly[0]?.location).toContain("components/hero.tsx");
  });

  it("#1477: a src bound through a prop or through state is one-shot, not just a data: literal", () => {
    const findings = byTaxonomy("img-tag/negative-indirect-oneshot", "M7 — Raw <img> instead of next/image");
    expect(findings).toHaveLength(1);
    expect(findings[0]?.location).toContain("components/gallery.tsx");
  });

  it("#1479: a server-only module gets the server claim, and its bundle sentence is withdrawn", () => {
    const server = byTaxonomy("whole-lib-import/positive-server-only", "M7 — Whole-library import");
    expect(server).toHaveLength(1);
    expect(server[0]?.impact).toContain("Server-side only");
    expect(server[0]?.impact).not.toContain("client chunk");
    expect(server[0]?.evidence).toContain("no client entry point does");
  });

  it("#1479: with no client entry to answer from, the claim is left unqualified rather than asserted", () => {
    const unknown = byTaxonomy("whole-lib-import/positive", "M7 — Whole-library import");
    expect(unknown.length).toBeGreaterThan(0);
    // The unanswerable case must not read as the server-side one, and must not silently
    // claim the client one either.
    expect(unknown[0]?.severity).toBe("Perf");
    expect(unknown[0]?.evidence).toContain("was not established");
  });
});
