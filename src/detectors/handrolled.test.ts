// M6 indicator calibration gate: every hand-rolled-shape class ships only with a caught positive
// AND a cleared benign negative (the #61 fixture discipline), PLUS the free-tier language lock —
// the operator ruling on #267 makes the hedged wording load-bearing, so the vocabulary itself is
// gated here: no finding may ever name a replacement, and every finding must be non-grading Info.

import { readFileSync } from "node:fs";
import { join, relative, sep } from "node:path";
import { readEntriesSafe } from "../fs-walk.js";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { depGatePresent, detectHandrolledFindings } from "./handrolled.js";
import type { SourceInput } from "./common.js";

const FIXTURES_ROOT = fileURLToPath(new URL("./__fixtures__/handrolled/", import.meta.url));

function loadFixtureDir(relDir: string): SourceInput[] {
  const root = join(FIXTURES_ROOT, relDir);
  const files: SourceInput[] = [];
  const walk = (dir: string) => {
    for (const { name: entry, path: full, isDirectory } of readEntriesSafe(dir).entries) {
      if (isDirectory) walk(full);
      else if (entry.endsWith(".txt")) files.push({ path: relative(root, full).replace(/\.txt$/, "").split(sep).join("/"), text: readFileSync(full, "utf8") });
    }
  };
  walk(root);
  return files;
}

function byTaxonomy(relDir: string, taxonomy: string) {
  return detectHandrolledFindings(loadFixtureDir(relDir)).filter((f) => f.taxonomy === taxonomy);
}

interface Case {
  name: string;
  dir: string;
  taxonomy: string;
  posCount: number;
}

// No "JSON round-trip clone" case: that shape is deliberately M7's (`M7 — JSON deep-clone` in
// perf-code.ts) — see handrolled.ts's header for the #278 double-count reasoning.
// The batch-2 dep-gated classes (raw-ms date math, email-shape regex) have their own suites
// below, mirroring class-merge: their negative is the gate staying shut, not a different shape.
const CASES: Case[] = [
  { name: "JSON deep-equal", dir: "json-equal", taxonomy: "M6 — Indicator: JSON deep-equal", posCount: 1 },
  { name: "query-string parsing", dir: "querystring", taxonomy: "M6 — Indicator: query-string parsing", posCount: 1 },
  { name: "cookie parsing", dir: "cookie", taxonomy: "M6 — Indicator: cookie parsing", posCount: 2 },
  { name: "random-string id", dir: "random-id", taxonomy: "M6 — Indicator: random-string id", posCount: 2 },
  // Batch 2 (#406 item 2):
  { name: "MIME-type lookup table", dir: "mime-table", taxonomy: "M6 — Indicator: MIME-type lookup table", posCount: 1 },
  { name: "currency formatting", dir: "currency", taxonomy: "M6 — Indicator: currency formatting", posCount: 2 },
  { name: "manual date formatting", dir: "format-date", taxonomy: "M6 — Indicator: manual date formatting", posCount: 1 },
  { name: "query-string building", dir: "querystring-build", taxonomy: "M6 — Indicator: query-string building", posCount: 1 },
  { name: "base64url conversion", dir: "base64url", taxonomy: "M6 — Indicator: base64url conversion", posCount: 2 },
  { name: "cookie serialization", dir: "cookie-serialize", taxonomy: "M6 — Indicator: cookie serialization", posCount: 2 },
  // Batch 3 (#542): the eight organic-AI-tier YES entries (docs/design/m6-corpus-frequency.md):
  { name: "array-unique via filter", dir: "filter-unique", taxonomy: "M6 — Indicator: array-unique via filter", posCount: 1 },
  { name: "composite timestamp-random id", dir: "composite-id", taxonomy: "M6 — Indicator: composite timestamp-random id", posCount: 1 },
  { name: "non-crypto string hash", dir: "string-hash", taxonomy: "M6 — Indicator: non-crypto string hash", posCount: 1 },
  { name: "month/day-name array", dir: "name-arrays", taxonomy: "M6 — Indicator: month/day-name array", posCount: 2 },
  { name: "JWT decode by hand", dir: "jwt-decode", taxonomy: "M6 — Indicator: JWT decode by hand", posCount: 2 },
  { name: "hand-rolled ErrorBoundary", dir: "error-boundary", taxonomy: "M6 — Indicator: hand-rolled ErrorBoundary", posCount: 1 },
  { name: "markdown-to-HTML by regex", dir: "markdown-html", taxonomy: "M6 — Indicator: markdown-to-HTML by regex", posCount: 3 },
  { name: "thousands-separator regex", dir: "thousands", taxonomy: "M6 — Indicator: thousands-separator regex", posCount: 1 },
  // Batch 4 (#628): the remaining measured-zero YES entries (non-dep-gated). The dep-gated three
  // (path-get, env JSON parse, Vite env coercion) have their own suites below.
  { name: "array flatten via reduce", dir: "flatten-reduce", taxonomy: "M6 — Indicator: array flatten via reduce", posCount: 1 },
  { name: "random-comparator shuffle", dir: "shuffle-sort", taxonomy: "M6 — Indicator: random-comparator shuffle", posCount: 1 },
  { name: "zero-pad via slice", dir: "zero-pad", taxonomy: "M6 — Indicator: zero-pad via slice", posCount: 1 },
  { name: "placeholder-template id", dir: "id-template", taxonomy: "M6 — Indicator: placeholder-template id", posCount: 1 },
  { name: "fetch timeout via Promise.race", dir: "fetch-timeout", taxonomy: "M6 — Indicator: fetch timeout via Promise.race", posCount: 1 },
  { name: "storage object URL concat", dir: "storage-url", taxonomy: "M6 — Indicator: storage object URL concat", posCount: 1 },
  { name: "clipboard via execCommand", dir: "clipboard", taxonomy: "M6 — Indicator: clipboard via execCommand", posCount: 1 },
  // Batch 5 (#814): the two classes #395 deferred, graduated via dep-gating (retry/backoff, its
  // own suite below) and cross-statement offset-mutation correlation (manual pagination, here —
  // not dep-gated, since the Supabase `.from(...).range(...)` chain shape IS the gate).
  { name: "manual pagination offset", dir: "pagination-offset", taxonomy: "M6 — Indicator: manual pagination offset", posCount: 1 },
];

for (const c of CASES) {
  describe(c.name, () => {
    it("catches the positive with the right count and a line-anchored location", () => {
      const hits = byTaxonomy(`${c.dir}/positive`, c.taxonomy);
      expect(hits).toHaveLength(c.posCount);
      for (const h of hits) {
        expect(h).toMatchObject({ category: "Maintainability", status: "Open", severity: "Info", confidence: "Review" });
        expect(h.location).toMatch(/[^:]:\d+$/);
      }
    });
    it("clears the benign negative", () => {
      expect(byTaxonomy(`${c.dir}/negative`, c.taxonomy)).toHaveLength(0);
    });
  });
}

describe("class-string merge (dep-gated)", () => {
  const TAX = "M6 — Indicator: class-string merge";
  const CLASS_MERGE_LIBS = ["clsx", "classnames", "tailwind-merge"];

  it("catches the inline-JSX and cn-helper positives when a merge library is in the tree", () => {
    const hits = byTaxonomy("class-merge/positive", TAX);
    expect(hits).toHaveLength(2);
    expect(hits.map((h) => h.location.split(":")[0]).sort()).toEqual(["button.tsx", "cn.ts"]);
  });

  it("stays silent when no merge library is in the tree — the deliberate dep-drop shape", () => {
    const files = loadFixtureDir("class-merge/negative-no-dep");
    expect(depGatePresent(files, CLASS_MERGE_LIBS)).toBe(false);
    expect(detectHandrolledFindings(files).filter((f) => f.taxonomy === TAX)).toHaveLength(0);
  });

  it("stays silent on a sentence-builder join even with the gate open — className context is required", () => {
    const files = loadFixtureDir("class-merge/negative-with-dep");
    expect(depGatePresent(files, CLASS_MERGE_LIBS)).toBe(true);
    expect(detectHandrolledFindings(files).filter((f) => f.taxonomy === TAX)).toHaveLength(0);
  });
});

describe("raw-millisecond date math (dep-gated, batch 2)", () => {
  const TAX = "M6 — Indicator: raw-millisecond date math";
  const DATE_LIBS = ["date-fns", "dayjs", "luxon", "moment"];

  it("catches the literal-product chain and the bare day constant when a date library is in the tree", () => {
    const hits = byTaxonomy("date-math/positive", TAX);
    expect(hits).toHaveLength(2);
    expect(hits.map((h) => h.location)).toEqual(["ttl.ts:1", "ttl.ts:4"]);
  });

  it("stays silent when no date library is in the tree — the deliberate dep-drop shape", () => {
    const files = loadFixtureDir("date-math/negative-no-dep");
    expect(depGatePresent(files, DATE_LIBS)).toBe(false);
    expect(detectHandrolledFindings(files).filter((f) => f.taxonomy === TAX)).toHaveLength(0);
  });
});

describe("email-shape regex (dep-gated on a schema-validation library, batch 2)", () => {
  const TAX = "M6 — Indicator: email-shape regex";

  it("catches the email-shaped regex literal when zod is in the tree", () => {
    const hits = byTaxonomy("email-regex/positive", TAX);
    expect(hits).toHaveLength(1);
    expect(hits[0]?.location).toBe("validate.ts:1");
  });

  it("stays silent when no schema-validation library is in the tree — a regex IS the standard approach there", () => {
    const files = loadFixtureDir("email-regex/negative-no-dep");
    expect(depGatePresent(files, ["zod"])).toBe(false);
    expect(detectHandrolledFindings(files).filter((f) => f.taxonomy === TAX)).toHaveLength(0);
  });
});

describe("nested-path get via split/reduce (dep-gated on a path-access helper, batch 4)", () => {
  const TAX = "M6 — Indicator: nested-path get via split/reduce";
  const PATH_LIBS = ["lodash", "lodash.get", "es-toolkit", "dlv", "get-value", "just-safe-get"];

  it("catches the split(\".\").reduce walk when a path-access helper is in the tree", () => {
    const hits = byTaxonomy("path-get/positive", TAX);
    expect(hits).toHaveLength(1);
    expect(hits[0]?.location).toBe("get.ts:2");
  });

  it("stays silent when no path-access helper is in the tree — the deliberate dep-drop shape", () => {
    const files = loadFixtureDir("path-get/negative-no-dep");
    expect(depGatePresent(files, PATH_LIBS)).toBe(false);
    expect(detectHandrolledFindings(files).filter((f) => f.taxonomy === TAX)).toHaveLength(0);
  });

  it("stays silent on a split on a different separator even with the gate open — only split(\".\") is the shape", () => {
    const files = loadFixtureDir("path-get/negative-with-dep");
    expect(depGatePresent(files, PATH_LIBS)).toBe(true);
    expect(detectHandrolledFindings(files).filter((f) => f.taxonomy === TAX)).toHaveLength(0);
  });
});

describe("env JSON parsing (dep-gated on a schema-validation library, batch 4)", () => {
  const TAX = "M6 — Indicator: env JSON parsing";

  it("catches JSON.parse of a process.env value when a schema-validation library is in the tree", () => {
    const hits = byTaxonomy("env-json/positive", TAX);
    expect(hits).toHaveLength(1);
    expect(hits[0]?.location).toBe("env.ts:1");
  });

  it("stays silent when no schema-validation library is in the tree — by-hand parsing is the norm there", () => {
    const files = loadFixtureDir("env-json/negative-no-dep");
    expect(depGatePresent(files, ["zod"])).toBe(false);
    expect(detectHandrolledFindings(files).filter((f) => f.taxonomy === TAX)).toHaveLength(0);
  });

  it("stays silent on a JSON.parse of a file (not process.env) even with the gate open", () => {
    const files = loadFixtureDir("env-json/negative-with-dep");
    expect(depGatePresent(files, ["zod"])).toBe(true);
    expect(detectHandrolledFindings(files).filter((f) => f.taxonomy === TAX)).toHaveLength(0);
  });
});

describe("Vite env coercion (dep-gated on a schema-validation library, #628)", () => {
  const TAX = "M6 — Indicator: Vite env coercion";

  it("catches the boolean/number/JSON coercions of import.meta.env when a schema-validation library is in the tree", () => {
    const hits = byTaxonomy("vite-env/positive", TAX);
    expect(hits).toHaveLength(3);
  });

  it("stays silent when no schema-validation library is in the tree — the deliberate dep-drop shape", () => {
    const files = loadFixtureDir("vite-env/negative-no-dep");
    expect(depGatePresent(files, ["zod"])).toBe(false);
    expect(detectHandrolledFindings(files).filter((f) => f.taxonomy === TAX)).toHaveLength(0);
  });

  it("stays silent on bare reads, a MODE string check, and the PROD boolean even with the gate open — only a coercion is the shape", () => {
    const files = loadFixtureDir("vite-env/negative-with-dep");
    expect(depGatePresent(files, ["zod"])).toBe(true);
    expect(detectHandrolledFindings(files).filter((f) => f.taxonomy === TAX)).toHaveLength(0);
  });
});

describe("retry/backoff loop (dep-gated, #814)", () => {
  const TAX = "M6 — Indicator: retry/backoff loop";

  it("catches a try/catch loop with a growing setTimeout-based delay when a retry library is in the tree", () => {
    const hits = byTaxonomy("retry-backoff/positive", TAX);
    expect(hits).toHaveLength(1);
    expect(hits[0]?.location).toBe("retry.ts:3");
  });

  it("stays silent when no retry library is in the tree — the deliberate dep-drop shape (#395)", () => {
    const files = loadFixtureDir("retry-backoff/negative-no-dep");
    expect(depGatePresent(files, ["p-retry", "async-retry", "promise-retry", "retry", "cockatiel", "exponential-backoff", "ts-retry-promise"])).toBe(false);
    expect(detectHandrolledFindings(files).filter((f) => f.taxonomy === TAX)).toHaveLength(0);
  });

  it("stays silent on a constant-delay retry loop even with the gate open — growth is the backoff signal", () => {
    const files = loadFixtureDir("retry-backoff/negative-with-dep");
    expect(depGatePresent(files, ["p-retry"])).toBe(true);
    expect(detectHandrolledFindings(files).filter((f) => f.taxonomy === TAX)).toHaveLength(0);
  });
});

// No "hand-rolled route guard" suite: attempted (#628) and retired (#638) — see the header comment
// in handrolled.ts and docs/design/m6-handrolled-catalogue.md for the EXCLUDED rationale.

// The generic dep-gate every future dep-gated class reuses (#406). The class-merge suite above
// covers the fixture-set path end-to-end; these lock the generic semantics directly.
describe("depGatePresent (generic dep-gate)", () => {
  const DATE_LIBS = ["date-fns", "dayjs"];

  it("opens on a named lib in dependencies or devDependencies of any package.json", () => {
    expect(depGatePresent([{ path: "package.json", text: JSON.stringify({ dependencies: { "date-fns": "^3.6.0" } }) }], DATE_LIBS)).toBe(true);
    expect(depGatePresent([{ path: "apps/web/package.json", text: JSON.stringify({ devDependencies: { dayjs: "^1.11.0" } }) }], DATE_LIBS)).toBe(true);
  });

  it("fails closed: no package.json in the set, none that parses, or no named lib", () => {
    expect(depGatePresent([{ path: "src/app.ts", text: "export {}" }], DATE_LIBS)).toBe(false);
    expect(depGatePresent([{ path: "package.json", text: "{ not json" }], DATE_LIBS)).toBe(false);
    expect(depGatePresent([{ path: "package.json", text: JSON.stringify({ dependencies: { react: "^18.3.0" } }) }], DATE_LIBS)).toBe(false);
  });
});

// WHY-comment suppression is ONE mechanism in the shared emission path (makeIndicator), so the
// fixtures deliberately span two indicator classes and both adjacency forms: a leading comment
// block above the flagged statement (JSON deep-equal) and a trailing comment on the statement's
// own line (random-string id). The narrated pair is the negative-of-the-negative: the SAME
// shapes with ordinary comments must still flag — narration is not a recorded reason.
describe("WHY-comment suppression (#406, the depdrop discipline generalized)", () => {
  it("an adjacent WHY: comment suppresses the indicator entirely — the reason is already recorded at the site", () => {
    expect(detectHandrolledFindings(loadFixtureDir("why-comment/suppressed"))).toHaveLength(0);
  });

  it("an ordinary narrating comment does NOT suppress the same shapes", () => {
    const taxonomies = detectHandrolledFindings(loadFixtureDir("why-comment/narrated"))
      .map((f) => f.taxonomy)
      .sort();
    expect(taxonomies).toEqual(["M6 — Indicator: JSON deep-equal", "M6 — Indicator: random-string id"]);
  });
});

describe("discrimination boundaries (regression locks)", () => {
  it("query-string: the flag anchors on the split(\"&\") site, and each lone split stays silent", () => {
    const pos = byTaxonomy("querystring/positive", "M6 — Indicator: query-string parsing");
    expect(pos[0]?.location).toBe("parse.ts:3");
    // negative has BOTH a lone split("&") and a lone split("=") in separate scopes.
    expect(byTaxonomy("querystring/negative", "M6 — Indicator: query-string parsing")).toHaveLength(0);
  });

  it("cookie: reads of document.cookie and cookie-named header strings flag; writes and non-cookie splits don't", () => {
    const pos = byTaxonomy("cookie/positive", "M6 — Indicator: cookie parsing");
    expect(pos.map((f) => f.location)).toEqual(["cookies.ts:2", "cookies.ts:12"]);
    expect(byTaxonomy("cookie/negative", "M6 — Indicator: cookie parsing")).toHaveLength(0);
  });

  it("random-id: only Math.random().toString(radix>10) flags — numeric formatting never does", () => {
    expect(byTaxonomy("random-id/positive", "M6 — Indicator: random-string id")).toHaveLength(2);
    expect(byTaxonomy("random-id/negative", "M6 — Indicator: random-string id")).toHaveLength(0);
  });

  it("query-string building and parsing are mirror classes that never fire on each other's shapes", () => {
    expect(byTaxonomy("querystring-build/positive", "M6 — Indicator: query-string parsing")).toHaveLength(0);
    expect(byTaxonomy("querystring/positive", "M6 — Indicator: query-string building")).toHaveLength(0);
  });

  it("cookie serialization vs parsing: builds are serialization's, probes of an existing cookie string are parsing's", () => {
    // The serialize positive builds cookie strings — the parse class stays silent on it.
    expect(byTaxonomy("cookie-serialize/positive", "M6 — Indicator: cookie parsing")).toHaveLength(0);
    // The serialize negative PARSES a Set-Cookie string: the parse class owns it (one finding),
    // serialization stays silent — no double-fire on one shape.
    expect(byTaxonomy("cookie-serialize/negative", "M6 — Indicator: cookie parsing")).toHaveLength(1);
    // And the complement: the parse class's write-negative (document.cookie = "…; path=/") IS
    // serialization — the two classes split reads/writes between them, deliberately.
    expect(byTaxonomy("cookie/negative", "M6 — Indicator: cookie serialization")).toHaveLength(1);
  });

  it("date math: constants inside a flagged product chain never emit a second finding", () => {
    // ttl.ts:1 is `24 * 60 * 60 * 1000` — one finding for the chain, none for its factors.
    const hits = byTaxonomy("date-math/positive", "M6 — Indicator: raw-millisecond date math");
    expect(hits.filter((h) => h.location === "ttl.ts:1")).toHaveLength(1);
  });
});

// The operator ruling's language discipline, as a gate: free-tier indicators must hedge and must
// never name the replacement — naming it IS the paid-tier judgment. If a future edit adds
// "replace with structuredClone()" to any field, this fails.
describe("free-tier language lock (#267 operator ruling)", () => {
  const allPositiveFindings = [
    ...detectHandrolledFindings(loadFixtureDir("json-equal/positive")),
    ...detectHandrolledFindings(loadFixtureDir("querystring/positive")),
    ...detectHandrolledFindings(loadFixtureDir("cookie/positive")),
    ...detectHandrolledFindings(loadFixtureDir("random-id/positive")),
    ...detectHandrolledFindings(loadFixtureDir("class-merge/positive")),
    // Batch 2 (#406 item 2):
    ...detectHandrolledFindings(loadFixtureDir("date-math/positive")),
    ...detectHandrolledFindings(loadFixtureDir("mime-table/positive")),
    ...detectHandrolledFindings(loadFixtureDir("currency/positive")),
    ...detectHandrolledFindings(loadFixtureDir("email-regex/positive")),
    ...detectHandrolledFindings(loadFixtureDir("format-date/positive")),
    ...detectHandrolledFindings(loadFixtureDir("querystring-build/positive")),
    ...detectHandrolledFindings(loadFixtureDir("base64url/positive")),
    ...detectHandrolledFindings(loadFixtureDir("cookie-serialize/positive")),
    // Batch 3 (#542):
    ...detectHandrolledFindings(loadFixtureDir("filter-unique/positive")),
    ...detectHandrolledFindings(loadFixtureDir("composite-id/positive")),
    ...detectHandrolledFindings(loadFixtureDir("string-hash/positive")),
    ...detectHandrolledFindings(loadFixtureDir("name-arrays/positive")),
    ...detectHandrolledFindings(loadFixtureDir("jwt-decode/positive")),
    ...detectHandrolledFindings(loadFixtureDir("error-boundary/positive")),
    ...detectHandrolledFindings(loadFixtureDir("markdown-html/positive")),
    ...detectHandrolledFindings(loadFixtureDir("thousands/positive")),
    // Batch 4 (#628):
    ...detectHandrolledFindings(loadFixtureDir("flatten-reduce/positive")),
    ...detectHandrolledFindings(loadFixtureDir("shuffle-sort/positive")),
    ...detectHandrolledFindings(loadFixtureDir("zero-pad/positive")),
    ...detectHandrolledFindings(loadFixtureDir("id-template/positive")),
    ...detectHandrolledFindings(loadFixtureDir("fetch-timeout/positive")),
    ...detectHandrolledFindings(loadFixtureDir("storage-url/positive")),
    ...detectHandrolledFindings(loadFixtureDir("clipboard/positive")),
    ...detectHandrolledFindings(loadFixtureDir("path-get/positive")),
    ...detectHandrolledFindings(loadFixtureDir("env-json/positive")),
    ...detectHandrolledFindings(loadFixtureDir("vite-env/positive")),
  ];
  const REPLACEMENT_NAMES =
    /structuredClone|isDeepStrictEqual|fast-deep-equal|deep-equal|URLSearchParams|useSearchParams|next\/headers|cookies\(\)|cookie-parse|randomUUID|getRandomValues|nanoid|\buuid\b|clsx|tailwind-merge|\bclassnames\b|lodash|date-fns|dayjs|luxon|\bmoment\b|\bIntl\b|toLocale(?:Date|Time)?String|DateTimeFormat|NumberFormat|\bmime\b|\bzod\b|\bjose\b|padStart|base64url|fromBase64|should be replaced/i;

  it("produced findings to lock (the corpus is not empty)", () => {
    expect(allPositiveFindings.length).toBeGreaterThanOrEqual(8);
  });

  it("every finding is a hedged, non-grading Info indicator", () => {
    for (const f of allPositiveFindings) {
      expect(f.severity).toBe("Info");
      expect(f.confidence).toBe("Review");
      expect(f.taxonomy).toMatch(/^M6 — Indicator: /);
      expect(f.title).toContain("may be worth investigating");
      expect(f.title).toContain("Looks hand-rolled");
    }
  });

  it("no field ever names a replacement library or primitive", () => {
    for (const f of allPositiveFindings) {
      for (const field of [f.title, f.evidence, f.impact, f.fix]) {
        expect(field).not.toMatch(REPLACEMENT_NAMES);
      }
    }
  });
});
