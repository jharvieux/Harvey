// M6 indicator corpus (#1371, operator ruling 2026-07-28). Until this file M6 had ZERO calibration
// entries and rendered as a `0` census row standing on a disclosed parity exemption (#1314). The
// ruling: M6's MECHANICAL tier — src/detectors/handrolled.ts, a deterministic TS/AST pass that
// either fires on a planted shape or does not — gets CorpusEntry rows like every other module's
// detectors. The VERDICT tier (is this a genuine reinvention, and what replaces it) stays a
// reviewer's judgment, is measured by no corpus, and is untouched by this file.
//
// The #265 ruling that had been cited to keep M6 out of calibration.ts was about not folding an
// LLM-judge AGREEMENT RATE into a precision claim. That reasoning does not reach an AST pass.
//
// SCORED, NOT MERELY COUNTED — the #1428 trap. Entries that sit in CORPUS and are scored by nothing
// inflate the per-module census with coverage that does not exist (#1299 shipped three such rows;
// a verifier gutted all three detectors and the gate still exited 0). These rows are scored by
// src/scan/m6-indicator-corpus.ts, wired into BOTH `pnpm verify` (m6-indicator-corpus.test.ts,
// binary-free) and the live gate (cli/validate-calibration.ts). MEASURED 2026-07-28: gutting
// detectHandrolledFindings turns both red.
//
// LOCATION IS THE FIXTURE PATH. Every row's `location` is `m6-corpus/<dir>/<sub>`, and the scorer
// loads src/detectors/__fixtures__/handrolled/<dir>/<sub> and prefixes every source path with it.
// So the answer key stays bound to the fixtures the detector's own suite uses, and no new file
// lands in targets/calibration (which would ripple through knip / jscpd / the dry-run artifact).
//
// BUCKETED BY RUNNING THE DETECTOR, never by inspection — every taxonomy and every reviewTierHits
// row below came out of a run over the committed fixtures on 2026-07-28, which is how the two
// cross-class hits were found (the cookie fixtures are mirror images by design: the parse class's
// benign negative WRITES a cookie, and the serialization class's benign negative PARSES one).
//
// EXHAUSTIVENESS is not asserted here. m6-indicator-corpus.ts re-derives the class list from the
// `taxonomy:` literals in handrolled.ts — the same instrument `pnpm detector-census` uses — and
// fails loud if a class has no positive row, so a 34th detector arrives with a fixture pair or red.

import type { CorpusEntry } from "./types.js";

const TAX_PREFIX = "M6 — Indicator: ";

interface M6Negative {
  // Fixture subdirectory: "negative" for the ordinary boundary twin; the dep-gated classes name
  // their two boundaries explicitly (gate shut vs. gate open on a shape that must still not fire).
  sub: string;
  note: string;
  reviewTierHits?: readonly string[];
}

interface M6Class {
  dir: string;
  // The class name exactly as it follows "M6 — Indicator: " in the emitted taxonomy.
  cls: string;
  posNote: string;
  negatives: M6Negative[];
}

const ORDINARY = "negative";

const M6_CLASSES: M6Class[] = [
  { dir: "json-equal", cls: "JSON deep-equal", posNote: "JSON.stringify(a) === JSON.stringify(b) — deep-equal in disguise.", negatives: [{ sub: ORDINARY, note: "a fresh serialization compared against a STORED snapshot string is legitimate change detection, not a deep-equal." }] },
  { dir: "querystring", cls: "query-string parsing", posNote: "split(\"&\") + split(\"=\") assembling params by hand.", negatives: [{ sub: ORDINARY, note: "split(\"&\") with no companion split(\"=\") in scope is an ampersand-delimited list, not a query string." }] },
  { dir: "cookie", cls: "cookie parsing", posNote: "document.cookie split apart into pairs by hand (2 sites).", negatives: [{ sub: ORDINARY, note: "writing document.cookie is not parsing it, and split(\";\") on a non-cookie receiver is a delimited list.", reviewTierHits: [`${TAX_PREFIX}cookie serialization`] }] },
  { dir: "random-id", cls: "random-string id", posNote: "Math.random().toString(36).slice(...) id building (2 sites).", negatives: [{ sub: ORDINARY, note: "toString with a radix on a real number is formatting; a bare Math.random() is jitter. Neither builds an id." }] },
  { dir: "mime-table", cls: "MIME-type lookup table", posNote: "a hand-maintained extension→content-type map.", negatives: [{ sub: ORDINARY, note: "a single content-type constant and a one-value header object are configuration; the class needs several extension rows." }] },
  { dir: "currency", cls: "currency formatting", posNote: "a currency symbol concatenated with toFixed(2) (2 sites).", negatives: [{ sub: ORDINARY, note: "toFixed as plain numeric display precision with no adjacent currency symbol is number formatting, not money." }] },
  { dir: "format-date", cls: "manual date formatting", posNote: "getFullYear/getMonth/getDate concatenated into one date string.", negatives: [{ sub: ORDINARY, note: "the same calendar getters used as SEPARATE values — comparisons and standalone reads, never concatenated." }] },
  { dir: "querystring-build", cls: "query-string building", posNote: "a map producing k=v strings joined with \"&\".", negatives: [{ sub: ORDINARY, note: "join(\"&\") over plain values is an ampersand-delimited list; only k=v-shaped members read as query-string building." }] },
  { dir: "base64url", cls: "base64url conversion", posNote: "the +/- and /_ alphabet swap around btoa/atob (2 sites).", negatives: [{ sub: ORDINARY, note: "replaces that look like alphabet swaps but are form decoding / slug display, plus a real swap pair with no base64 context." }] },
  { dir: "cookie-serialize", cls: "cookie serialization", posNote: "a Set-Cookie string assembled from attribute literals by hand (2 sites).", negatives: [{ sub: ORDINARY, note: "a cookie string that is PARSED, not built — the attribute literal is a probe argument and the split belongs to the parse class.", reviewTierHits: [`${TAX_PREFIX}cookie parsing`] }] },
  { dir: "filter-unique", cls: "array-unique via filter", posNote: "filter((v, i, a) => a.indexOf(v) === i) de-duplication.", negatives: [{ sub: ORDINARY, note: "a two-arg predicate and a three-arg callback that never compares indexOf back to the index." }] },
  { dir: "composite-id", cls: "composite timestamp-random id", posNote: "Date.now() concatenated with a random suffix.", negatives: [{ sub: ORDINARY, note: "a bare timestamp id and a standalone random number — neither expression combines both." }] },
  { dir: "string-hash", cls: "non-crypto string hash", posNote: "the charCodeAt + shift/multiply accumulate loop.", negatives: [{ sub: ORDINARY, note: "charCodeAt without the accumulate, and a `* 31` in a different scope with no charCodeAt — the co-occurrence guard holds." }] },
  { dir: "name-arrays", cls: "month/day-name array", posNote: "hand-written month and weekday name arrays (2 sites).", negatives: [{ sub: ORDINARY, note: "ordinary string arrays: statuses, and a list containing one month name — below the >= 3 threshold." }] },
  { dir: "jwt-decode", cls: "JWT decode by hand", posNote: "split(\".\") → base64 decode → JSON.parse, including the two-statement one-hop shape (#1087) (2 sites).", negatives: [{ sub: ORDINARY, note: "each step in isolation — a file-extension split, a plain JSON.parse, a bare atob — the three-step chain never occurs (the #1087 one-hop negative)." }] },
  { dir: "error-boundary", cls: "hand-rolled ErrorBoundary", posNote: "a class component carrying the error-boundary lifecycle members.", negatives: [{ sub: ORDINARY, note: "an ordinary class component with no error-boundary lifecycle members." }] },
  { dir: "markdown-html", cls: "markdown-to-HTML by regex", posNote: "regex replaces emitting HTML tags from markdown (3 sites).", negatives: [{ sub: ORDINARY, note: "replaces that produce entities and a slug — no HTML tags emitted, so not the conversion shape." }] },
  { dir: "thousands", cls: "thousands-separator regex", posNote: "the (\\d{3})+(?!\\d) grouping fragment.", negatives: [{ sub: ORDINARY, note: "a digits check and a slug cleaner — neither carries the grouping fragment." }] },
  { dir: "flatten-reduce", cls: "array flatten via reduce", posNote: "reduce((a, b) => a.concat(b), []) flattening.", negatives: [{ sub: ORDINARY, note: "a sum reducer, a non-empty seed, and a static Buffer.concat — none is the concat-flatten idiom." }] },
  { dir: "shuffle-sort", cls: "random-comparator shuffle", posNote: "sort(() => Math.random() - 0.5), the biased shuffle.", negatives: [{ sub: ORDINARY, note: "ordinary comparators, neither using randomness." }] },
  { dir: "zero-pad", cls: "zero-pad via slice", posNote: "(\"00\" + n).slice(-2) padding.", negatives: [{ sub: ORDINARY, note: "a non-zero prefix and a positive slice — neither is the zero-pad idiom." }] },
  { dir: "id-template", cls: "placeholder-template id", posNote: "the 8-4-4-4-12 template with 'x' placeholders replaced one by one.", negatives: [{ sub: ORDINARY, note: "real hex id literals match the 8-4-4-4-12 shape but carry no 'x' placeholders." }] },
  { dir: "fetch-timeout", cls: "fetch timeout via Promise.race", posNote: "Promise.race of a fetch against a setTimeout rejection.", negatives: [{ sub: ORDINARY, note: "a race without a fetch+timer pair, and Promise.all of two fetches — neither is the timeout idiom." }] },
  { dir: "storage-url", cls: "storage object URL concat", posNote: "a storage object URL built by string interpolation.", negatives: [{ sub: ORDINARY, note: "a complete URL constant (no interpolation) and an unrelated interpolated URL that never touches the storage path." }] },
  { dir: "clipboard", cls: "clipboard via execCommand", posNote: "document.execCommand(\"copy\") instead of the clipboard API.", negatives: [{ sub: ORDINARY, note: "execCommand for rich-text editing — a different argument, so it stays silent." }] },
  { dir: "pagination-offset", cls: "manual pagination offset", posNote: "a loop mutating the offset across .range(...) calls (#814's cross-statement correlation).", negatives: [{ sub: ORDINARY, note: "correct single-page .range() use, and a retry loop re-issuing the SAME range — the bound never changes, so it is retry, not pagination." }] },
  // Dep-gated classes (#406's generic depGatePresent). Their FIRST negative is the gate staying
  // SHUT — hand-rolling with no library installed is the deliberate dep-drop choice, not a
  // reinvention — so it scores the gate, not a different code shape. Where a second negative
  // exists it is the harder boundary: gate OPEN, near-miss shape, must still stay silent.
  { dir: "class-merge", cls: "class-string merge", posNote: "an inline-JSX className join and a cn() helper, with clsx already in the tree (2 sites).", negatives: [{ sub: "negative-no-dep", note: "the same helper shape with NO merge library in the tree — the deliberate depdrop choice. Scores the gate staying shut." }, { sub: "negative-with-dep", note: "gate OPEN (clsx present) but the join builds a sentence, not a class string — no className context, so it must stay silent." }] },
  { dir: "date-math", cls: "raw-millisecond date math", posNote: "a literal-product ms chain and a bare day constant, with a date library in the tree (2 sites).", negatives: [{ sub: "negative-no-dep", note: "the SAME shapes with no date library in the tree — the depdrop choice; the gate stays shut." }] },
  { dir: "email-regex", cls: "email-shape regex", posNote: "an email-shaped regex literal with zod already in the tree.", negatives: [{ sub: "negative-no-dep", note: "the SAME regex with no schema-validation library installed — with nothing to express the rule in, a regex IS the standard approach." }] },
  { dir: "env-json", cls: "env JSON parsing", posNote: "JSON.parse over a process.env value, with a schema library in the tree.", negatives: [{ sub: "negative-no-dep", note: "the SAME by-hand env parse with no schema library installed — the ordinary approach there; the gate stays shut." }, { sub: "negative-with-dep", note: "gate OPEN, but JSON.parse of a FILE — only a process.env source is the env-parsing shape." }] },
  { dir: "path-get", cls: "nested-path get via split/reduce", posNote: "split(\".\").reduce(...) dynamic path access, with a path helper in the tree.", negatives: [{ sub: "negative-no-dep", note: "the SAME walk with no path-access helper installed — hand-rolling it is the ordinary approach; the gate stays shut." }, { sub: "negative-with-dep", note: "gate OPEN, but a split on a different separator feeding a reduce — only a dotted property path is the reinvention shape." }] },
  { dir: "retry-backoff", cls: "retry/backoff loop", posNote: "a retry loop with growing delay, with a retry library already in the tree (#814).", negatives: [{ sub: "negative-no-dep", note: "the same loop with no retry library in the tree — the depdrop choice; the gate stays shut." }, { sub: "negative-with-dep", note: "gate OPEN, but the loop retries at a CONSTANT delay — growth is the signal, so a flat retry must not flag." }] },
  { dir: "vite-env", cls: "Vite env coercion", posNote: "by-hand coercions of import.meta.env values, with a schema library in the tree (3 sites).", negatives: [{ sub: "negative-no-dep", note: "the SAME coercions with no schema library installed — the ordinary approach there; the gate stays shut." }, { sub: "negative-with-dep", note: "gate OPEN, but bare reads are the CORRECT way to read Vite env, and a MODE check / the built-in PROD boolean are not coercions." }] },
];

function positiveId(dir: string): string {
  return `M6-P-${dir.toUpperCase()}`;
}

const classRows: CorpusEntry[] = M6_CLASSES.flatMap((c) => [
  {
    module: "M6",
    id: positiveId(c.dir),
    kind: "positive" as const,
    cls: c.cls,
    location: `m6-corpus/${c.dir}/positive`,
    // Taxonomy vocabulary, and deliberately NOT a substring of the entry's own location in either
    // spelling (#1355): the location carries no space and no colon. A key that self-matched would
    // accept any finding on the fixture, including a sibling class's — which the cookie pair proves
    // is not hypothetical here.
    match: [`Indicator: ${c.cls}`],
    expectedTier: "review" as const,
    // Non-grading by construction (#267's free/paid split). Asserted here as well as in
    // handrolled.test.ts so a class that quietly started grading fails the shared matrix too.
    expectedSeverity: "Info" as const,
    note: `${c.dir}/positive: ${c.posNote} Detected by detectHandrolledFindings; taxonomy "${TAX_PREFIX}${c.cls}".`,
  },
  ...c.negatives.map((n) => ({
    module: "M6",
    id: `M6-N-${c.dir.toUpperCase()}${n.sub === ORDINARY ? "" : `-${n.sub.replace(/^negative-/, "").toUpperCase()}`}`,
    kind: "negative" as const,
    cls: c.cls,
    location: `m6-corpus/${c.dir}/${n.sub}`,
    // No `match` on a negative, by #1355: the row already means "any indicator firing here is a
    // false positive", and a key would only narrow that.
    ...(n.reviewTierHits ? { reviewTierHits: n.reviewTierHits } : {}),
    note: `${c.dir}/${n.sub}: ${n.note}${n.reviewTierHits ? ` MEASURED cross-class hit recorded in reviewTierHits: the two cookie fixtures are deliberate mirror images (see each fixture's own comment), so ${n.reviewTierHits.join(", ")} firing here is a CORRECT detection of the sibling class, not noise from the class under test.` : ""}`,
  })),
]);

// The shared emission path's own pair (#406's WHY suppression). Not a 34th indicator class — it is
// makeIndicator's suppression branch, which every class routes through, so a regression there
// silences all 33 at once and no per-class row would notice. The two fixtures are the same shapes
// with and without the `WHY:` marker, which locks it in both directions: make isWhySuppressed
// always-true and the positive misses; always-false and the negative false-fires.
const whyCommentRows: CorpusEntry[] = [
  {
    module: "M6",
    id: "M6-P-WHY-NARRATED",
    kind: "positive",
    cls: "WHY-comment suppression: an un-narrated shape still fires",
    location: "m6-corpus/why-comment/narrated",
    match: ["Indicator: JSON deep-equal"],
    expectedTier: "review",
    expectedSeverity: "Info",
    note: "why-comment/narrated: hand-rolled shapes carrying comments WITHOUT the `WHY:` marker. MEASURED to emit JSON deep-equal + random-string id; keyed to the first so the row scores one class rather than any finding on the fixture.",
  },
  {
    module: "M6",
    id: "M6-N-WHY-SUPPRESSED",
    kind: "negative",
    cls: "WHY-comment suppression: a narrated shape stays silent",
    location: "m6-corpus/why-comment/suppressed",
    note: "why-comment/suppressed: the SAME shapes with an adjacent `WHY:` comment recording the deliberate reason. Suppressed shapes emit nothing — the in-code comment is the audit record (handrolled.ts's header). Any indicator here means the suppression branch stopped working.",
  },
];

export const m6HandrolledEntries: CorpusEntry[] = [...classRows, ...whyCommentRows];
