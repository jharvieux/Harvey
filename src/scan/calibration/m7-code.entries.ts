// M7 code-tier heuristic corpus (#823) — the labeled answer key for detectPerfCodeFindings
// (src/detectors/perf-code.ts), scored by src/scan/heuristic-precision.ts. Every class the
// detector ships is listed with its caught positive AND its cleared benign negative(s); the
// negative rows encode the field FP shapes the ATC dogfood + 6-repo triage catalogued
// (docs/m7-performance.md §2a, #230/#248), so a guard regression shows up as a measured
// precision drop, not a silent noise return. Dirs are relative to src/detectors/__fixtures__/
// — the same fixture pairs perf-code.test.ts asserts per class; this corpus aggregates them
// into the per-module precision/recall number the per-class tests never produced.
//
// The compilerOn/framework axes mirror how each class actually runs: the micro-render classes
// (#248) only emit with React Compiler on, and the Vite-only classes (#577) only with the vite
// framework flag — a positive scored under a config where its class is suppressed by design
// would be a false recall miss.

import type { HeuristicEntry } from "./types.js";

const M7 = "M7" as const;

export const m7CodeEntries: HeuristicEntry[] = [
  // --- POSITIVES (planted perf defects — the class must fire) ---
  { module: M7, id: "M7CODE-P-CTX-VALUE", kind: "positive", cls: "Context value recreated every render", taxonomy: "M7 — Context value recreated every render", dir: "perf/ctx-value/positive", compilerOn: true, note: "Inline object literal as a locally-created Provider value; Info under React Compiler (#248)." },
  { module: M7, id: "M7CODE-P-INLINE-PROP", kind: "positive", cls: "Inline literal prop", taxonomy: "M7 — Inline literal prop", dir: "perf/inline-prop/positive", compilerOn: true, note: "Object/array literal props on components, rolled up per file; Info under React Compiler (#248)." },
  { module: M7, id: "M7CODE-P-IMG-TAG", kind: "positive", cls: "Raw <img> instead of next/image", taxonomy: "M7 — Raw <img> instead of next/image", dir: "perf/img-tag/positive", note: "Raw <img> elements with no optimization/lazy-load, rolled up per file." },
  { module: M7, id: "M7CODE-P-INDEX-KEY", kind: "positive", cls: "Index used as list key", taxonomy: "M7 — Index used as list key", dir: "perf/index-key/positive", compilerOn: true, note: "key={i} bound to the map callback's index parameter (compiler-on only, #248)." },
  { module: M7, id: "M7CODE-P-SORT-IN-JSX", kind: "positive", cls: "Sort in render body", taxonomy: "M7 — Sort in render body", dir: "perf/sort-in-jsx/positive", note: ".sort() running directly inside JSX on a props-derived list." },
  { module: M7, id: "M7CODE-P-STATE-SPRAWL", kind: "positive", cls: "State sprawl", taxonomy: "M7 — State sprawl", dir: "perf/state-sprawl/positive", note: "9 useState hooks in one component (threshold 8)." },
  { module: M7, id: "M7CODE-P-AWAIT-IN-LOOP", kind: "positive", cls: "Await in loop (N+1)", taxonomy: "M7 — Await in loop (N+1)", dir: "perf/await-in-loop/positive", note: "Per-item independent awaits on and off the request path (two files, tiered differently)." },
  { module: M7, id: "M7CODE-P-UNBOUNDED-SELECT", kind: "positive", cls: "Unbounded select", taxonomy: "M7 — Unbounded select", dir: "perf/unbounded-select/positive", note: "select('*') list read with no limit/range — the one class the 6-repo triage kept whole (#230)." },
  { module: M7, id: "M7CODE-P-CLIENT-FETCH", kind: "positive", cls: "Client fetch in useEffect", taxonomy: "M7 — Client fetch in useEffect", dir: "perf/client-fetch-effect/positive", note: "Mount-path data reads in 'use client' components (#383) — three shapes across three files." },
  { module: M7, id: "M7CODE-P-CLIENT-FETCH-VITE", kind: "positive", cls: "Client fetch in useEffect (Vite)", taxonomy: "M7 — Client fetch in useEffect", dir: "perf/client-fetch-effect/positive-vite", framework: "vite", note: "No-directive module on a Vite SPA — every module is client (#577)." },
  { module: M7, id: "M7CODE-P-WHOLE-LIB", kind: "positive", cls: "Whole-library import", taxonomy: "M7 — Whole-library import", dir: "perf/whole-lib-import/positive", note: "Bare lodash + moment imports (CJS — any import form ships the whole package)." },
  { module: M7, id: "M7CODE-P-HEAVY-CLIENT", kind: "positive", cls: "Heavy import in client bundle", taxonomy: "M7 — Heavy import in client bundle", dir: "perf/heavy-client-import/positive", note: "Static monaco-editor import in a 'use client' module." },
  { module: M7, id: "M7CODE-P-HEAVY-CLIENT-VITE", kind: "positive", cls: "Heavy import in client bundle (Vite)", taxonomy: "M7 — Heavy import in client bundle", dir: "perf/heavy-client-import/positive-vite", framework: "vite", note: "Static three import in a no-directive Vite module (#577)." },
  { module: M7, id: "M7CODE-P-UNOPT-BARREL", kind: "positive", cls: "Unoptimized barrel import", taxonomy: "M7 — Unoptimized barrel import", dir: "perf/unopt-barrel/positive", note: "Named barrel imports on Next 13.4 — below the 13.5 auto-optimization floor." },
  { module: M7, id: "M7CODE-P-FONT-LINK", kind: "positive", cls: "Manual font stylesheet", taxonomy: "M7 — Manual font stylesheet", dir: "perf/font-link/positive", note: "Google Fonts <link rel=stylesheet> instead of next/font." },
  { module: M7, id: "M7CODE-P-EAGER-GLOB", kind: "positive", cls: "Eager import.meta.glob", taxonomy: "M7 — Eager import.meta.glob", dir: "perf/import-meta-glob/positive", framework: "vite", note: "{ eager: true } glob inlines every matched module into the entry chunk (Vite-only class)." },
  { module: M7, id: "M7CODE-P-ROUTE-SPLIT", kind: "positive", cls: "Route not code-split", taxonomy: "M7 — Route not code-split", dir: "perf/route-split/positive", framework: "vite", note: "react-router route components statically imported instead of React.lazy (Vite-only class)." },
  { module: M7, id: "M7CODE-P-MIDDLEWARE-FETCH", kind: "positive", cls: "Fetch in middleware hot path", taxonomy: "M7 — Fetch in middleware hot path", dir: "perf/middleware-fetch/positive", note: "fetch() inside middleware.ts — a network hop on every matched request." },
  { module: M7, id: "M7CODE-P-SYNC-IO", kind: "positive", cls: "Blocking sync I/O in request handler", taxonomy: "M7 — Blocking sync I/O in request handler", dir: "perf/sync-io/positive", note: "readFileSync inside a route-handler function body." },
  { module: M7, id: "M7CODE-P-JSON-CLONE", kind: "positive", cls: "JSON deep-clone", taxonomy: "M7 — JSON deep-clone", dir: "perf/json-clone/positive", note: "JSON.parse(JSON.stringify(x)) on a request path." },
  { module: M7, id: "M7CODE-P-NESTED-LOOP", kind: "positive", cls: "Nested-loop join", taxonomy: "M7 — Nested-loop join", dir: "perf/nested-loop-join/positive", note: "Per-item linear scan over a loop-invariant second collection — O(n·m) (#385)." },
  { module: M7, id: "M7CODE-P-COMPILER-FLAG", kind: "positive", cls: "React Compiler flag unresolvable", taxonomy: "M7 — React Compiler flag unresolvable", dir: "perf/react-compiler-unresolvable/positive", note: "reactCompiler read from a variable — surfaced as a Watch disclosure, never silently assumed off (#249)." },

  // --- NEGATIVES (benign lookalikes — the class must stay silent) ---
  { module: M7, id: "M7CODE-N-CTX-VALUE", kind: "negative", cls: "useMemo-stabilized context value", taxonomy: "M7 — Context value recreated every render", dir: "perf/ctx-value/negative", compilerOn: true, note: "Provider value memoized with useMemo." },
  { module: M7, id: "M7CODE-N-CTX-LIBRARY", kind: "negative", cls: "Library-owned context Provider", taxonomy: "M7 — Context value recreated every render", dir: "perf/ctx-value/negative-library-context", compilerOn: true, note: "A shadcn/library Provider the app doesn't own the memoization of (#230 dogfood FP)." },
  { module: M7, id: "M7CODE-N-INLINE-PROP", kind: "negative", cls: "Hoisted constants / DOM style props", taxonomy: "M7 — Inline literal prop", dir: "perf/inline-prop/negative", compilerOn: true, note: "Hoisted literals and style objects on DOM elements." },
  { module: M7, id: "M7CODE-N-FRAMER", kind: "negative", cls: "framer-motion animation props", taxonomy: "M7 — Inline literal prop", dir: "perf/inline-prop/negative-framer-motion", compilerOn: true, note: "animate/initial/transition are value-diffed by the library — no memoization win (#230)." },
  { module: M7, id: "M7CODE-N-STYLE-PROP", kind: "negative", cls: "Inline style object prop", taxonomy: "M7 — Inline literal prop", dir: "perf/inline-prop/negative-style", compilerOn: true, note: "Inline style objects are idiomatic and near-zero cost (#230)." },
  { module: M7, id: "M7CODE-N-I18N-ARRAY", kind: "negative", cls: "i18n t(...)-built array", taxonomy: "M7 — Inline literal prop", dir: "perf/inline-prop/negative-i18n-array", compilerOn: true, note: "An array of live translation lookups has nothing stable to hoist (#230)." },
  { module: M7, id: "M7CODE-N-IMG-TAG", kind: "negative", cls: "next/image usage", taxonomy: "M7 — Raw <img> instead of next/image", dir: "perf/img-tag/negative", note: "next/image already in use." },
  { module: M7, id: "M7CODE-N-IMG-ONE-SHOT", kind: "negative", cls: "data:/blob: one-shot image", taxonomy: "M7 — Raw <img> instead of next/image", dir: "perf/img-tag/negative-one-shot", note: "MFA QR / blob preview next/image can't optimize anyway (#230)." },
  { module: M7, id: "M7CODE-N-INDEX-KEY", kind: "negative", cls: "Stable-id key", taxonomy: "M7 — Index used as list key", dir: "perf/index-key/negative", compilerOn: true, note: "key on the item's own id even though the index is used elsewhere." },
  { module: M7, id: "M7CODE-N-INDEX-STATIC", kind: "negative", cls: "Index key on a hardcoded static list", taxonomy: "M7 — Index used as list key", dir: "perf/index-key/negative-static-list", compilerOn: true, note: "Footer/FAQ-style const list never reorders/inserts/deletes (#230)." },
  { module: M7, id: "M7CODE-N-SORT-MEMO", kind: "negative", cls: "useMemo-hoisted sort", taxonomy: "M7 — Sort in render body", dir: "perf/sort-in-jsx/negative", note: "Sort hoisted into useMemo — the fix shape." },
  { module: M7, id: "M7CODE-N-STATE-SPRAWL", kind: "negative", cls: "Few useState hooks", taxonomy: "M7 — State sprawl", dir: "perf/state-sprawl/negative", note: "A component below the sprawl threshold." },
  { module: M7, id: "M7CODE-N-AWAIT-LOOP", kind: "negative", cls: "Loop-carried / chunked-batch awaits", taxonomy: "M7 — Await in loop (N+1)", dir: "perf/await-in-loop/negative", note: "cursor-carried pagination and i += BATCH_SIZE chunking — the fix for N+1, not the bug." },
  { module: M7, id: "M7CODE-N-BOUNDED-SELECT", kind: "negative", cls: "Bounded reads", taxonomy: "M7 — Unbounded select", dir: "perf/unbounded-select/negative", note: "Paginated, .single(), count-only head:true, .in('id', [...]), and insert-echo reads (#230)." },
  { module: M7, id: "M7CODE-N-CLIENT-FETCH", kind: "negative", cls: "SWR / server / event-driven fetches", taxonomy: "M7 — Client fetch in useEffect", dir: "perf/client-fetch-effect/negative", note: "SWR-routed, Server Component fetch, listener-registered fetch, fire-and-forget beacon." },
  { module: M7, id: "M7CODE-N-WHOLE-LIB", kind: "negative", cls: "Tree-shakeable imports", taxonomy: "M7 — Whole-library import", dir: "perf/whole-lib-import/negative", note: "Subpath and named tree-shakeable imports." },
  { module: M7, id: "M7CODE-N-HEAVY-CLIENT", kind: "negative", cls: "next/dynamic-loaded heavy lib", taxonomy: "M7 — Heavy import in client bundle", dir: "perf/heavy-client-import/negative", note: "The editor loads behind next/dynamic — already code-split." },
  { module: M7, id: "M7CODE-N-BARREL-MODERN", kind: "negative", cls: "Barrel import on modern Next", taxonomy: "M7 — Unoptimized barrel import", dir: "perf/unopt-barrel/negative", note: "Next ≥ 13.5 auto-optimizes the default barrel list." },
  { module: M7, id: "M7CODE-N-BARREL-CONFIG", kind: "negative", cls: "Barrel listed in optimizePackageImports", taxonomy: "M7 — Unoptimized barrel import", dir: "perf/unopt-barrel/negative-config", note: "The project's next.config opts the package in explicitly." },
  { module: M7, id: "M7CODE-N-FONT-LINK", kind: "negative", cls: "next/font usage", taxonomy: "M7 — Manual font stylesheet", dir: "perf/font-link/negative", note: "next/font/google already in use." },
  { module: M7, id: "M7CODE-N-LAZY-GLOB", kind: "negative", cls: "Lazy import.meta.glob", taxonomy: "M7 — Eager import.meta.glob", dir: "perf/import-meta-glob/negative", framework: "vite", note: "The default lazy glob returns dynamic-import functions — already code-split." },
  { module: M7, id: "M7CODE-N-ROUTE-SPLIT", kind: "negative", cls: "React.lazy routes", taxonomy: "M7 — Route not code-split", dir: "perf/route-split/negative", framework: "vite", note: "Route components loaded via React.lazy behind Suspense." },
  { module: M7, id: "M7CODE-N-MIDDLEWARE", kind: "negative", cls: "Cookie-only middleware", taxonomy: "M7 — Fetch in middleware hot path", dir: "perf/middleware-fetch/negative", note: "Middleware that only reads/sets cookies — no network hop." },
  { module: M7, id: "M7CODE-N-SYNC-IO", kind: "negative", cls: "Module-scope run-once sync read", taxonomy: "M7 — Blocking sync I/O in request handler", dir: "perf/sync-io/negative", note: "A cold-start readFileSync at module scope — accepted pattern." },
  { module: M7, id: "M7CODE-N-JSON-CLONE", kind: "negative", cls: "structuredClone usage", taxonomy: "M7 — JSON deep-clone", dir: "perf/json-clone/negative", note: "structuredClone — the fix shape." },
  { module: M7, id: "M7CODE-N-NESTED-LOOP", kind: "negative", cls: "Indexed join / static lists / string scans", taxonomy: "M7 — Nested-loop join", dir: "perf/nested-loop-join/negative", note: "Map-indexed fix, hardcoded + SCREAMING_SNAKE lists, per-item field scans, String.includes (#385 guards)." },
  { module: M7, id: "M7CODE-N-RENDER-ONCE", kind: "negative", cls: "Render-once email/PDF templates", dir: "perf/render-once/negative", note: "Email/PDF templates render exactly once — EVERY M7 class must stay silent here (no taxonomy = any finding is a false fire)." },
  { module: M7, id: "M7CODE-N-COMPILER-FALSE", kind: "negative", cls: "Literal reactCompiler: false", taxonomy: "M7 — React Compiler flag unresolvable", dir: "perf/react-compiler-unresolvable/negative", note: "An explicit literal false is resolvable — no disclosure row." },
];
