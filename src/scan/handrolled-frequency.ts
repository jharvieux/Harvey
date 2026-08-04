// Per-shape frequency signatures for the M6 hand-rolled catalogue (#406 item 1).
//
// Each entry mirrors a numbered row of docs/design/m6-handrolled-catalogue.md (the YES and MAYBE
// verdicts) and states the EXACT signature `pnpm handrolled-frequency` counts on the 6-repo
// external corpus. These are SHAPE-PRESENCE counts by the stated signature — NOT detector
// precision, NOT recall, NOT findings (#265: no precision number of any kind for M6). Their only
// job is to order detector batch 2 by measured frequency instead of judgment.
//
// A shape whose presence cannot be counted honestly by a statable signature lives in
// UNMEASURED_SHAPES with the reason — it is never given a junk regex. The 5 SHIPPED classes are
// counted by the real detector (detectHandrolledFindings), not re-approximated here.
//
// handrolled-frequency.test.ts asserts every signature matches its own canonical example: a
// signature that cannot match its own example would report an honest-looking zero, which is
// exactly the junk count this file must not emit.

import type { SourceInput } from "../detectors/common.js";
import { EXTERNAL_CORPUS, type Provenance } from "./external-corpus.js";
import type { CommitCensus } from "./genai-admission.js";

// #413: AI-authored repos measured for M6 hand-rolled-frequency. The M6 frequency question — "do
// the catalogue's 17 measured-zero YES shapes fire on genuinely AI-generated code?" — needs only
// the source tree, so this stayed a lightweight clone-and-count list even after #1524 gave three
// of these four (cravab, flori-web, effective) a full ExternalTarget entry in external-corpus.ts
// too: the two measurements are independent questions (shape frequency vs. drift baseline) over
// the SAME pinned tree, so a slug legitimately lives in both lists — handrolled-frequency.test.ts's
// "never duplicate a slug" check was relaxed to "if a slug is in both, the pin must agree" once
// that overlap became intentional rather than a bookkeeping accident. `teardown` remains
// frequency-only per #1524's own scoping: it already serves as a live M1/M2 ground-truth target
// (the vandyand/saas-security-teardown measurements, verified in #1325) rather than needing a
// source-tier drift baseline — a fourth full ExternalTarget entry for it is untracked, separate
// follow-up work, not part of #1524.
//
// Source is NEVER vendored (same posture as external-corpus.ts): clone-on-demand only, so AGPL /
// no-license repos are usable for internal scanning as long as their source isn't copied into
// this repo. Pins verified to fetch + carry the expected shape (App Router + supabase/migrations)
// on 2026-07-18.
interface FrequencyTarget {
  slug: string;
  repo: string;
  commit: string;
  license: string;
  provenance: Provenance;
  provenanceNote: string;
  capturedHistory?: {
    snapshotRepo: string;
    snapshotCommit: string;
    originalRepo: string;
    originalCommit: string;
    measuredAt: string;
    sourceRun: number;
    census: CommitCensus;
  };
  // #413: intentionally-vulnerable / teaching repos are CURATED, not organic AI output — their
  // shape mix is authored to demonstrate bugs, so they must not dominate the organic-AI signal.
  // Measured and reported, but bucketed separately from the ai-generated/ai-assisted aggregate.
  curated?: boolean;
}

export const AI_FREQUENCY_CORPUS: FrequencyTarget[] = [
  {
    slug: "cravab",
    repo: "stoimera/Cravab",
    commit: "f0b355fe5e082b9f67bacf3593393e763f50acea",
    license: "AGPL-3.0",
    provenance: "ai-generated",
    provenanceNote: "#413: .cursor/rules mandating tenant_id isolation + AI-slop README; strong stack fit (tenant_id everywhere, RLS, migrations, App Router). AGPL — scan-only, never vendor.",
  },
  {
    slug: "flori-web",
    repo: "jharvieux/harvey-corpus-flori-web",
    commit: "908eaff6fcf598c0fe1043faaaecb6a4083c90d5",
    license: "none (all rights reserved)",
    provenance: "ai-generated",
    provenanceNote: "#413/#1832: original flori-ai-kr/web@bead044 had Co-Authored-By: Claude on ~40 commits + CLAUDE.md + .claude/; many RLS migrations, user-scoped tenancy. Upstream became inaccessible, so the private recovery mirror pins a synthetic root commit whose tree is byte-identical (tree 062ad8ac) without claiming the shallow cache recovered unavailable ancestry. No license — clone-and-scan only, never vendor.",
    capturedHistory: {
      snapshotRepo: "jharvieux/harvey-corpus-flori-web",
      snapshotCommit: "908eaff6fcf598c0fe1043faaaecb6a4083c90d5",
      originalRepo: "flori-ai-kr/web",
      originalCommit: "bead044955f069525edac4134696d0a8f1a3071b",
      measuredAt: "2026-07-31",
      sourceRun: 30658181195,
      census: { commits: 145, productCommits: 127, trailerAdmitted: 128, proseOnlyAdmitted: 5, admittedProduct: 119, unadmittedProduct: 8 },
    },
  },
  {
    slug: "effective",
    repo: "jharvieux/harvey-corpus-effective",
    commit: "6c86752d118e262fa15e8c46d3f4d38f9b53b5ce",
    license: "MIT",
    provenance: "ai-assisted",
    provenanceNote: "#413/#1832: original joshcoolman/effective@5274467 had CLAUDE.md + Co-Authored-By: Claude, but higher-skill Effect TS and a thin schema. After upstream became inaccessible, the MIT-licensed recovery mirror pinned a synthetic root whose tree is byte-identical (tree 0307f493) without claiming unavailable ancestry. Reported per-repo so its large tree cannot silently dominate the aggregate.",
    capturedHistory: {
      snapshotRepo: "jharvieux/harvey-corpus-effective",
      snapshotCommit: "6c86752d118e262fa15e8c46d3f4d38f9b53b5ce",
      originalRepo: "joshcoolman/effective",
      originalCommit: "52744674ef83306bc58ecfc607aa840092137132",
      measuredAt: "2026-07-31",
      sourceRun: 30658181195,
      census: { commits: 16, productCommits: 10, trailerAdmitted: 14, proseOnlyAdmitted: 0, admittedProduct: 9, unadmittedProduct: 1 },
    },
  },
  {
    slug: "teardown",
    repo: "vandyand/saas-security-teardown",
    commit: "1ef96ab83f9a4b13109a1945ef936c1e83648865",
    license: "none (all rights reserved)",
    provenance: "ai-generated",
    provenanceNote: "#413: README 'vibe-coded… let an AI scaffold' + Co-Authored-By: Claude Opus 4.8. CURATED — intentionally-vulnerable (8 planted cross-tenant leaks), so its shape mix is authored, not organic; bucketed separately.",
    curated: true,
  },
];

export type FrequencyTier = Provenance | "curated";

interface FrequencyCorpusTarget {
  slug: string;
  repo: string;
  commit: string;
  provenance: Provenance;
  tier: FrequencyTier;
  capturedHistory?: FrequencyTarget["capturedHistory"];
}

// #1524: three AI_FREQUENCY_CORPUS slugs (cravab, flori-web, effective) also gained a full
// EXTERNAL_CORPUS entry for the unrelated drift-baseline measurement, so the two lists can
// legitimately share a slug now (handrolled-frequency.test.ts's "pins must agree" check).
// Concatenating the two lists undeduped would make a shared slug contribute TWICE to a
// per-provenance-tier aggregate while a same-tier repo present in only one list contributes once
// — a non-proportional double-count. EXTERNAL_CORPUS wins a shared slug: none of its entries are
// `curated` teaching repos, so its provenance is the correct tier, and it is the corpus this
// measurement already treats as canonical everywhere else.
export function buildFrequencyTargets(): FrequencyCorpusTarget[] {
  const externalSlugs = new Set(EXTERNAL_CORPUS.map((t) => t.slug));
  const frequencyBySlug = new Map(AI_FREQUENCY_CORPUS.map((t) => [t.slug, t]));
  return [
    ...EXTERNAL_CORPUS.map((t) => ({
      slug: t.slug,
      repo: t.repo,
      commit: t.commit,
      provenance: t.provenance,
      tier: t.provenance as FrequencyTier,
      capturedHistory: frequencyBySlug.get(t.slug)?.capturedHistory,
    })),
    ...AI_FREQUENCY_CORPUS.filter((t) => !externalSlugs.has(t.slug)).map((t) => ({
      slug: t.slug,
      repo: t.repo,
      commit: t.commit,
      provenance: t.provenance,
      tier: (t.curated ? "curated" : t.provenance) as FrequencyTier,
      capturedHistory: t.capturedHistory,
    })),
  ];
}

interface MeasuredShape {
  /** Row number in docs/design/m6-handrolled-catalogue.md. */
  entry: number;
  verdict: "YES" | "MAYBE";
  name: string;
  /** Human-readable statement of what is counted — quoted verbatim in the frequency doc. */
  signature: string;
  /** "matches" counts signature occurrences; "files" counts files where the signature holds. */
  unit: "matches" | "files";
  /** Canonical positive snippet the test asserts the signature counts (>= 1). */
  example: string;
  /** Path the example is evaluated under, for path-scoped signatures. */
  examplePath?: string;
  count: (file: SourceInput) => number;
}

interface UnmeasuredShape {
  entry: number;
  verdict: "YES" | "MAYBE";
  name: string;
  reason: string;
}

/** The 5 shipped classes: measured by running detectHandrolledFindings itself. */
export const SHIPPED_SHAPES: { entry: number; name: string; taxonomy: string }[] = [
  { entry: 2, name: "JSON deep-equal", taxonomy: "M6 — Indicator: JSON deep-equal" },
  { entry: 21, name: "Math.random().toString(radix>10) id", taxonomy: "M6 — Indicator: random-string id" },
  { entry: 36, name: "query-string parsing via splits", taxonomy: "M6 — Indicator: query-string parsing" },
  { entry: 51, name: "cookie parsing by hand", taxonomy: "M6 — Indicator: cookie parsing" },
  { entry: 57, name: "class-string merge (dep-gated)", taxonomy: "M6 — Indicator: class-string merge" },
];

const countMatches = (re: RegExp) => (f: SourceInput): number => f.text.match(re)?.length ?? 0;
// Regexes passed here must NOT carry /g — .test() on a /g regex is stateful across calls.
const filePresence = (...res: RegExp[]) => (f: SourceInput): number => (res.every((re) => re.test(f.text)) ? 1 : 0);

// WHY: the signature/example strings below deliberately contain the raw shapes they count
// (cookie-attribute literals, currency templates, …) — they are descriptions for the frequency
// tool, not hand-rolled implementations, so the M6 indicators are suppressed on this statement.
export const MEASURED_SHAPES: MeasuredShape[] = [
  {
    entry: 3,
    verdict: "YES",
    name: "unique via filter + indexOf self-compare",
    signature: ".filter((v, i, a) => a.indexOf(v) === i) — three-arg callback comparing indexOf to the index",
    unit: "matches",
    example: "const uniq = arr.filter((v, i, a) => a.indexOf(v) === i);",
    count: countMatches(/\.filter\(\s*\(?\s*(\w+)\s*,\s*(\w+)\s*,\s*(\w+)\s*\)?\s*=>\s*\3\.indexOf\(\s*\1\s*\)\s*[!=]==?\s*\2/g),
  },
  {
    entry: 4,
    verdict: "YES",
    name: "flatten via reduce + concat with [] seed",
    signature: ".reduce((a, b) => a.concat(b), []) — bare-concat body with empty-array seed",
    unit: "matches",
    example: "const flat = nested.reduce((acc, cur) => acc.concat(cur), []);",
    count: countMatches(/\.reduce\(\s*\(\s*(\w+)\s*,\s*(\w+)\s*\)\s*=>\s*\1\.concat\(\s*\2\s*\)\s*,\s*\[\s*\]\s*\)/g),
  },
  {
    entry: 5,
    verdict: "MAYBE",
    name: "group-by via reduce pushing into acc[key]",
    signature: ".reduce( whose arrow body pushes into an element access on the accumulator, within one line",
    unit: "matches",
    example: "items.reduce((acc, x) => { (acc[x.kind] ||= []).push(x); return acc; }, {})",
    count: countMatches(/\.reduce\(\s*\(\s*(\w+)\s*,\s*\w+\s*\)\s*=>\s*\{?\s*\(?\s*\1\[[^\]\n]+\]\s*(?:\|\|=\s*\[\]\s*\)?|\?\?=\s*\[\]\s*\)?)?\s*[^\n]{0,40}\.push\(/g),
  },
  {
    entry: 6,
    verdict: "MAYBE",
    name: "chunk/window via slice(i, i + n)",
    signature: ".slice(x, x + y) — same identifier as start and as base of the end offset",
    unit: "matches",
    example: "chunks.push(items.slice(i, i + size));",
    count: countMatches(/\.slice\(\s*(\w+)\s*,\s*\1\s*\+\s*\w+\s*\)/g),
  },
  {
    entry: 11,
    verdict: "YES",
    name: "shuffle via sort(() => Math.random() - 0.5)",
    signature: ".sort(() => Math.random() - 0.5) — the biased-shuffle idiom, exact",
    unit: "matches",
    example: "const shuffled = arr.sort(() => Math.random() - 0.5);",
    count: countMatches(/\.sort\(\s*\(\s*\)\s*=>\s*Math\.random\(\)\s*-\s*0?\.5\s*\)/g),
  },
  {
    entry: 12,
    verdict: "MAYBE",
    name: "min/max via reduce comparison",
    signature: ".reduce((a, b) => …) whose body is a comparison ternary over a/b or Math.min/max(a, b)",
    unit: "matches",
    example: "const max = nums.reduce((a, b) => (a > b ? a : b));",
    count: countMatches(
      /\.reduce\(\s*\(\s*(\w+)\s*,\s*(\w+)\s*\)\s*=>\s*\(?\s*(?:(?:\1|\2)\s*[<>]=?\s*(?:\1|\2)\s*\?\s*(?:\1|\2)\s*:\s*(?:\1|\2)|Math\.(?:min|max)\(\s*\1\s*,\s*\2\s*\))/g,
    ),
  },
  {
    entry: 13,
    verdict: "YES",
    name: 'zero-padding via ("0" + n).slice(-2)',
    signature: '("0" + expr).slice(-N) — string-concat pad then negative slice',
    unit: "matches",
    example: 'const mm = ("0" + minutes).slice(-2);',
    count: countMatches(/\(\s*["'`]0["'`]\s*\+\s*[^()\n]{1,40}\)\s*\.slice\(\s*-\s*\d/g),
  },
  {
    entry: 15,
    verdict: "MAYBE",
    name: "case-converter regex chains",
    signature: "a regex literal containing ([a-z])([A-Z]) or ([a-z0-9])([A-Z]) — the camel/kebab boundary split",
    unit: "matches",
    example: 'const kebab = s.replace(/([a-z])([A-Z])/g, "$1-$2");',
    count: countMatches(/\(\[a-z\]\)\(\[A-Z\]\)|\(\[a-z0-9\]\)\(\[A-Z\]\)/g),
  },
  {
    entry: 16,
    verdict: "YES",
    name: 'path-get via split(".").reduce(…)',
    signature: '.split(".").reduce( — chained, exact',
    unit: "matches",
    example: 'const v = "a.b.c".split(".").reduce((o, k) => o?.[k], obj);',
    count: countMatches(/\.split\(\s*["'`]\.["'`]\s*\)\s*\.reduce\(/g),
  },
  {
    entry: 18,
    verdict: "MAYBE",
    name: "HTML-entity escaping replace chain",
    signature: '.replace( with an entity literal ("&amp;", "&lt;", "&gt;", "&quot;", "&#39;") in the same call',
    unit: "matches",
    example: 'const safe = s.replace(/&/g, "&amp;").replace(/</g, "&lt;");',
    count: countMatches(/\.replace\([^)\n]{0,60}["'`]&(?:amp|lt|gt|quot|#0?39);["'`]/g),
  },
  {
    entry: 22,
    verdict: "MAYBE",
    name: "char-loop id builder (random index into charset)",
    signature: "charAt( or [ indexing with Math.floor(Math.random() * X.length)",
    unit: "matches",
    example: "id += chars.charAt(Math.floor(Math.random() * chars.length));",
    count: countMatches(/(?:charAt\(|\[)\s*Math\.floor\(\s*Math\.random\(\)\s*\*\s*[\w.$]+\.length\s*\)/g),
  },
  {
    entry: 23,
    verdict: "YES",
    name: "UUID-v4 template-string snippet",
    signature: 'the literal "xxxxxxxx-xxxx-4xxx" anywhere — byte-exact fragment of the copy-pasted template',
    unit: "matches",
    example: "const id = 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, patch);",
    count: countMatches(/xxxxxxxx-xxxx-4xxx/g),
  },
  {
    entry: 24,
    verdict: "YES",
    name: "composite Date.now() + Math.random() ids",
    signature: "Date.now() and Math.random() on the same line within 60 chars of each other (either order)",
    unit: "matches",
    example: "const key = `${Date.now()}-${Math.random().toString(36).slice(2)}`;",
    count: countMatches(/Date\.now\(\)[^\n]{0,60}Math\.random\(\)|Math\.random\(\)[^\n]{0,60}Date\.now\(\)/g),
  },
  {
    entry: 27,
    verdict: "YES",
    name: "non-crypto string-hash loop (djb2/FNV/java-31)",
    signature: "file contains charCodeAt( AND a << 5 or * 31 accumulate",
    unit: "files",
    example: "let h = 0; for (let i = 0; i < s.length; i++) h = (h << 5) - h + s.charCodeAt(i);",
    count: filePresence(/charCodeAt\(/, /<<\s*5\b|\*\s*31\b/),
  },
  {
    entry: 28,
    verdict: "YES",
    name: "date math on raw ms constants",
    signature: "86400000, 3600000, 24 * 60 * 60 * 1000, 1000 * 60 * 60 (* 24), or 60 * 60 * 1000 (dep-gate NOT applied — raw shape presence)",
    unit: "matches",
    example: "const DAY_MS = 24 * 60 * 60 * 1000;",
    count: countMatches(/\b86400000\b|\b3600000\b|24\s*\*\s*60\s*\*\s*60\s*\*\s*1000|1000\s*\*\s*60\s*\*\s*60(?:\s*\*\s*24)?|60\s*\*\s*60\s*\*\s*1000/g),
  },
  {
    entry: 29,
    verdict: "YES",
    name: "formatDate via getFullYear/getMonth/getDate concat",
    signature: "file contains getFullYear() AND getMonth() AND getDate()",
    unit: "files",
    example: "const s = `${d.getFullYear()}-${d.getMonth() + 1}-${d.getDate()}`;",
    count: filePresence(/getFullYear\(\)/, /getMonth\(\)/, /getDate\(\)/),
  },
  {
    entry: 30,
    verdict: "YES",
    name: "month/day-name literal arrays",
    signature: 'adjacent literals "January","February" | "Jan","Feb" | "Sunday","Monday" | "Sun","Mon"',
    unit: "matches",
    example: 'const MONTHS = ["January", "February", "March"];',
    count: countMatches(/["'`]January["'`]\s*,\s*["'`]February["'`]|["'`]Jan["'`]\s*,\s*["'`]Feb["'`]|["'`]Sunday["'`]\s*,\s*["'`]Monday["'`]|["'`]Sun["'`]\s*,\s*["'`]Mon["'`]/g),
  },
  {
    entry: 31,
    verdict: "MAYBE",
    name: 'relative "time ago" if-ladder',
    signature: 'file contains >= 2 "<unit>(s) ago" string fragments (second/minute/hour/day/week/month/year)',
    unit: "files",
    example: "if (m < 60) return `${m} minutes ago`; return `${h} hours ago`;",
    count: (f) => ((f.text.match(/\b(?:second|minute|hour|day|week|month|year)s?\s+ago\b/g)?.length ?? 0) >= 2 ? 1 : 0),
  },
  {
    entry: 34,
    verdict: "MAYBE",
    name: "duration formatting via /3600 and %60",
    signature: "file contains % 60 AND the literal 3600",
    unit: "files",
    example: "const h = Math.floor(sec / 3600); const m = Math.floor(sec / 60) % 60;",
    count: filePresence(/%\s*60\b/, /\b3600\b/),
  },
  {
    entry: 35,
    verdict: "MAYBE",
    name: "leap-year modulo chain",
    signature: "% 400 — the third rung of the %4/%100/%400 ladder, near-unique to leap-year logic",
    unit: "matches",
    example: "const leap = (y % 4 === 0 && y % 100 !== 0) || y % 400 === 0;",
    count: countMatches(/%\s*400\b/g),
  },
  {
    entry: 37,
    verdict: "YES",
    name: 'query-string building via .join("&")',
    signature: '.join("&") — joining anything on "&" is the qs-assembly shape',
    unit: "matches",
    example: 'const qs = pairs.map(([k, v]) => `${k}=${v}`).join("&");',
    count: countMatches(/\.join\(\s*["'`]&["'`]\s*\)/g),
  },
  {
    entry: 39,
    verdict: "MAYBE",
    name: "path joining slash-de-dup replace",
    signature: String.raw`.replace(/\/+/g, "/") or .replace(/\/\/+/g, "/")`,
    unit: "matches",
    example: String.raw`const clean = url.replace(/\/+/g, "/");`,
    count: countMatches(/\.replace\(\s*\/(?:\\\/)+\+\/g?\s*,\s*["'`]\/["'`]\s*\)/g),
  },
  {
    entry: 40,
    verdict: "MAYBE",
    name: "slugify one-liner",
    signature: '.replace(/[^…0-9…]…/g?, "-") — negated char class containing 0-9, replaced with "-"',
    unit: "matches",
    example: 'const slug = title.toLowerCase().replace(/[^a-z0-9]+/g, "-");',
    count: countMatches(/\.replace\(\s*\/\[\^[^\]\n]*0-9[^\]\n]*\][^/\n]{0,20}\/[gi]{0,2}\s*,\s*["'`]-["'`]\s*\)/g),
  },
  {
    entry: 41,
    verdict: "YES",
    name: "MIME-type lookup table",
    signature: 'file contains >= 2 "<ext>": "<type>/<subtype>" object rows (image/application/text/video/audio/font)',
    unit: "files",
    example: 'const MIME = { ".png": "image/png", ".jpg": "image/jpeg" };',
    count: (f) => ((f.text.match(/["'][\w.+-]+["']\s*:\s*["'](?:image|application|text|video|audio|font)\/[\w.+-]+["']/g)?.length ?? 0) >= 2 ? 1 : 0),
  },
  {
    entry: 42,
    verdict: "YES",
    name: "base64url conversion replace chain",
    signature: String.raw`.replace(/\+/g, "-") — the +→- half of the base64→base64url dance`,
    unit: "matches",
    example: String.raw`const b64url = btoa(bin).replace(/\+/g, "-").replace(/\//g, "_");`,
    count: countMatches(/\.replace\(\s*\/\\\+\/g\s*,\s*["'`]-["'`]\s*\)/g),
  },
  {
    entry: 43,
    verdict: "MAYBE",
    name: "hex encode/decode loop",
    signature: "file contains .toString(16) AND padStart(2 or slice(-2)",
    unit: "files",
    example: 'const hex = bytes.map((b) => b.toString(16).padStart(2, "0")).join("");',
    count: filePresence(/\.toString\(\s*16\s*\)/, /padStart\(\s*2\s*|slice\(\s*-2\s*\)/),
  },
  {
    entry: 44,
    verdict: "YES",
    name: "fetch timeout via Promise.race",
    signature: "Promise.race([ … fetch( within the first 200 chars of the array",
    unit: "matches",
    example: "const res = await Promise.race([fetch(url), timeoutPromise]);",
    count: countMatches(/Promise\.race\(\s*\[[^\]]{0,200}fetch\(/g),
  },
  {
    entry: 47,
    verdict: "MAYBE",
    name: "polling via setInterval + fetch",
    signature: "setInterval( with a fetch( within the following 200 chars (proximity, not scope — stated looseness)",
    unit: "matches",
    example: 'setInterval(() => { void fetch("/api/poll"); }, 5000);',
    count: countMatches(/setInterval\([\s\S]{0,200}?fetch\(/g),
  },
  {
    entry: 52,
    verdict: "YES",
    name: "cookie serialization by hand",
    signature: 'file contains a cookie-attribute literal: "; Path=", "; Max-Age=", "; Expires=", "; SameSite=", "; HttpOnly" or "; Secure"',
    unit: "files",
    example: "document.cookie = `${name}=${value}; Path=/; Max-Age=${maxAge}; HttpOnly`;",
    count: filePresence(/; ?(?:Path|Max-Age|Expires|SameSite)=|; ?(?:HttpOnly|Secure)\b/),
  },
  {
    entry: 53,
    verdict: "YES",
    name: "JWT payload decode by hand",
    signature: '.split(".")[1] in a file that also mentions atob( or base64',
    unit: "matches",
    example: 'const claims = JSON.parse(atob(token.split(".")[1]));',
    count: (f) => (/atob\(|base64/.test(f.text) ? (f.text.match(/\.split\(\s*["'`]\.["'`]\s*\)\s*\[\s*1\s*\]/g)?.length ?? 0) : 0),
  },
  {
    entry: 58,
    verdict: "MAYBE",
    name: "hand-rolled useDebounce hook",
    signature: "a function/const DEFINITION named useDebounce (imports don't match)",
    unit: "matches",
    example: "export function useDebounce<T>(value: T, ms: number): T { return value; }",
    count: countMatches(/(?:function|const)\s+useDebounce\b/g),
  },
  {
    entry: 59,
    verdict: "MAYBE",
    name: "utility-hook family definitions",
    signature: "a function/const DEFINITION named useLocalStorage/usePrevious/useInterval/useWindowSize/useMediaQuery/useOnClickOutside/useIntersectionObserver/useEventListener/useToggle",
    unit: "matches",
    example: "export function useLocalStorage(key: string) { return key; }",
    count: countMatches(/(?:function|const)\s+use(?:LocalStorage|Previous|Interval|WindowSize|MediaQuery|OnClickOutside|IntersectionObserver|EventListener|Toggle)\b/g),
  },
  {
    entry: 61,
    verdict: "YES",
    name: "hand-rolled ErrorBoundary class",
    signature: "file contains componentDidCatch or getDerivedStateFromError",
    unit: "files",
    example: "class ErrorBoundary extends React.Component { componentDidCatch(err: Error) { console.error(err); } }",
    count: filePresence(/componentDidCatch|getDerivedStateFromError/),
  },
  {
    entry: 65,
    verdict: "MAYBE",
    name: "manual <title>/<meta> JSX in app/ files",
    signature: "<title> or <meta … in a .tsx/.jsx file under an app/ directory",
    unit: "matches",
    example: 'return (<><title>Dashboard</title><meta name="description" content="x" /></>);',
    examplePath: "app/dashboard/page.tsx",
    count: (f) => (/(^|\/)app\/.+\.[tj]sx$/.test(f.path) ? (f.text.match(/<title>|<meta\s/g)?.length ?? 0) : 0),
  },
  {
    entry: 66,
    verdict: "MAYBE",
    name: "window.location.href = navigation",
    signature: "window.location.href = (assignment, not comparison)",
    unit: "matches",
    example: 'window.location.href = "/login";',
    count: countMatches(/window\.location\.href\s*=[^=]/g),
  },
  {
    entry: 67,
    verdict: "MAYBE",
    name: "middleware pathname.startsWith ladder",
    signature: "a middleware.ts/js file containing >= 2 pathname.startsWith( calls",
    unit: "files",
    example: 'if (pathname.startsWith("/admin")) { return; } else if (pathname.startsWith("/api")) { return; }',
    examplePath: "middleware.ts",
    count: (f) => (/(^|\/)middleware\.[tj]s$/.test(f.path) && (f.text.match(/pathname\.startsWith\(/g)?.length ?? 0) >= 2 ? 1 : 0),
  },
  {
    entry: 68,
    verdict: "YES",
    name: "JSON.parse(process.env.X)",
    signature: "JSON.parse( directly on a process.env dot-member (bracket access not counted)",
    unit: "matches",
    example: "const flags = JSON.parse(process.env.FEATURE_FLAGS ?? '{}');",
    count: countMatches(/JSON\.parse\(\s*process\.env\.\w+/g),
  },
  {
    entry: 69,
    verdict: "MAYBE",
    name: "hand-rolled sitemap/robots string building",
    signature: "<urlset, <loc>, or User-agent: literals in source",
    unit: "matches",
    example: 'return `User-agent: *\nDisallow: /admin`;',
    count: countMatches(/<urlset\b|<loc>|User-agent:/g),
  },
  {
    entry: 72,
    verdict: "MAYBE",
    name: "Pages Router idioms inside app/",
    signature: 'an import from "next/document" or "next/app" in a file under an app/ directory',
    unit: "matches",
    example: 'import { Html } from "next/document";',
    examplePath: "app/layout.tsx",
    count: (f) => (/(^|\/)app\//.test(f.path) ? (f.text.match(/from\s+["'`]next\/(?:document|app)["'`]/g)?.length ?? 0) : 0),
  },
  {
    entry: 76,
    verdict: "YES",
    name: "Supabase storage public-URL concat",
    signature: 'the literal "/storage/v1/object/public/"',
    unit: "matches",
    example: "const url = `${supabaseUrl}/storage/v1/object/public/${bucket}/${path}`;",
    count: countMatches(/\/storage\/v1\/object\/public\//g),
  },
  {
    entry: 81,
    verdict: "YES",
    name: "email-shape validation regex",
    signature: ']+@ — a character class quantified into an @, the spine of every email regex (dep-gate NOT applied — raw shape presence)',
    unit: "matches",
    example: String.raw`const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;`,
    count: countMatches(/\]\+@/g),
  },
  {
    entry: 83,
    verdict: "MAYBE",
    name: "URL-shape validation regex",
    signature: "^https?: inside a regex-looking literal",
    unit: "matches",
    example: String.raw`const URL_RE = /^https?:\/\/[^\s]+$/;`,
    count: countMatches(/\^https\?:/g),
  },
  {
    entry: 88,
    verdict: "YES",
    name: "currency via symbol + toFixed concat",
    signature: '`$${…toFixed(` template or "$"/"€"/"£" string + …toFixed( concat',
    unit: "matches",
    example: "const price = `$${(cents / 100).toFixed(2)}`;",
    count: countMatches(/\$\$\{[^}\n]{0,60}\.toFixed\(|["'`][$€£]["'`]\s*\+[^\n;]{0,60}\.toFixed\(/g),
  },
  {
    entry: 89,
    verdict: "YES",
    name: "thousands-separator lookahead regex",
    signature: String.raw`the byte-exact fragment (\d{3})+(?!\d) — the famous Stack Overflow regex`,
    unit: "matches",
    example: String.raw`const pretty = n.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ",");`,
    count: countMatches(/\(\\d\{3\}\)\+\(\?!\\d\)/g),
  },
  {
    entry: 90,
    verdict: "MAYBE",
    name: "byte-size KB/MB/GB ladder",
    signature: 'file contains the literal 1024 AND a "KB"/"MB"/"GB"/"TB" string',
    unit: "files",
    example: 'const units = ["KB", "MB", "GB"]; let n = bytes / 1024;',
    count: filePresence(/\b1024\b/, /["'`][KMGT]B["'`]/),
  },
  {
    entry: 95,
    verdict: "YES",
    name: "clipboard via document.execCommand('copy')",
    signature: 'execCommand("copy") — the deprecated-API call, exact',
    unit: "matches",
    example: 'document.execCommand("copy");',
    count: countMatches(/execCommand\(\s*["'`]copy["'`]\s*\)/g),
  },
  {
    entry: 98,
    verdict: "YES",
    name: "markdown→HTML via regex replaces",
    signature: ".replace( producing a <strong>/<em>/<h1..6>/<blockquote> tag within 80 chars",
    unit: "matches",
    example: 'const html = md.replace(/\\*\\*(.+?)\\*\\*/g, "<strong>$1</strong>");',
    count: countMatches(/\.replace\([^\n]{0,80}<\/?(?:strong|em|h[1-6]|blockquote)>/g),
  },
  {
    entry: 99,
    verdict: "MAYBE",
    name: "CSV assembly via join(,) + join(\\n)",
    signature: 'file contains both .join(",") and .join("\\n")',
    unit: "files",
    example: 'const csv = rows.map((r) => r.join(",")).join("\\n");',
    count: filePresence(/\.join\(\s*["'`],["'`]\s*\)/, /\.join\(\s*["'`]\\n["'`]\s*\)/),
  },
  {
    entry: 100,
    verdict: "MAYBE",
    name: "regex-based HTML/XML tag stripping/parsing",
    signature: String.raw`the strip-tags regex fragment <[^>]*> or <[^>]+>`,
    unit: "matches",
    example: String.raw`const text = s.replace(/<[^>]*>/g, "");`,
    count: countMatches(/<\[\^>\]\*>|<\[\^>\]\+>/g),
  },
  {
    entry: 101,
    verdict: "MAYBE",
    name: "hand-rolled semver/version compare",
    signature: '.split(".").map(Number) — the version-parse idiom',
    unit: "matches",
    example: 'const parts = version.split(".").map(Number);',
    count: countMatches(/\.split\(\s*["'`]\.["'`]\s*\)\s*\.map\(\s*Number\s*\)/g),
  },
];

// Shapes that CANNOT be counted honestly by a statable regex/light-AST signature. Listed, never
// approximated — an unmeasured shape with a reason beats a junk count (the coverage-guard
// discipline applied to measurement).
export const UNMEASURED_SHAPES: UnmeasuredShape[] = [
  {
    entry: 19,
    verdict: "MAYBE",
    name: "hand-rolled event emitter",
    reason: "recognising an on/off/emit method set + listener collection is class-shape AST work; any regex either matches nothing or matches every pub/sub-ish class.",
  },
  {
    entry: 32,
    verdict: "MAYBE",
    name: "manual ISO-date parsing",
    reason: 'the catalogue\'s own blocker stands for measurement too: splitting date-shaped strings is diffuse and "the crisp subset needs definition" — there is no signature to count yet.',
  },
  {
    entry: 73,
    verdict: "MAYBE",
    name: "Supabase pagination reinvention (offset math + .slice())",
    reason: "cross-statement by definition (#395's recorded deferral): the shape is a query chain PLUS nearby offset math — no single-site signature exists.",
  },
  {
    entry: 74,
    verdict: "MAYBE",
    name: "fetch-all then .data.length as a count",
    reason: "the countable token (.data.length) is ubiquitous and benign; the shape is the ABSENCE of count options on the originating query, which is cross-statement.",
  },
  {
    entry: 75,
    verdict: "MAYBE",
    name: "select-then-branch insert/update (upsert reinvention)",
    reason: "cross-statement correlation between a select, a branch, and two write calls — same blocker as 73.",
  },
  {
    entry: 82,
    verdict: "MAYBE",
    name: "phone-number validation regex",
    reason: "phone regexes are too diverse for one stated signature (the catalogue's own reason); any umbrella regex would count arbitrary digit-group patterns.",
  },
  {
    entry: 92,
    verdict: "MAYBE",
    name: 'list joining with "a, b and c" logic',
    reason: "weak signature per the catalogue — a regex would mostly count ordinary joins and ternaries.",
  },
  {
    entry: 96,
    verdict: "MAYBE",
    name: "smooth-scroll rAF stepper loops",
    reason: "requestAnimationFrame + scroll co-occurrence is indistinguishable from legitimate animation code without loop-shape AST analysis.",
  },
  // REASON: entry 102 has no countable signature — the shape is module-scope state plus a TTL comparison somewhere else, so a regex either matches nothing or matches every legitimate cache; it needs the AST scope analysis handrolled.ts does, not a frequency regex
  // KIND: empirical
  // PROVENANCE: MEASURED 2026-07-25 (ran the falsifier below; it exits 1)
  // FALSIFIER: test -f src/detectors/handrolled.ts || exit 127; grep -q "module-level Map cache" src/detectors/handrolled.ts
  // TOUCHES: src/detectors/handrolled.ts
  {
    entry: 102,
    verdict: "MAYBE",
    name: "module-level Map cache with Date.now() TTL",
    reason: "the shape is module-scope state plus a TTL comparison somewhere else — regex cannot scope module level, and Map-in-closure alone is every legitimate cache.",
  },
];
