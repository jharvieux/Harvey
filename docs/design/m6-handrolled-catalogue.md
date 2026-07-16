# M6 hand-rolled-primitive catalogue (#267 Phase 1)

The catalogue of patterns AI coding assistants predictably hand-roll in Next.js/Supabase/TypeScript
codebases, each with: the shape, the standard replacement, a **free-indicator verdict**, and the
reason. This is the Phase-1 deliverable of #267, written 2026-07-16 after the mechanical subset
shipped (PR #395).

**Authority chain:** the operator ruling on #267 (2026-07-15) split M6 — *free tier lists
mechanically-recognisable hand-rolled shapes as non-grading indicators, hedged ("looks hand-rolled;
may be worth investigating"), never naming a replacement; paid tier triages and names the
replacement.* This catalogue is internal/paid-brief material, so it DOES name replacements — a
detector built from it must not. The vocabulary lock in `src/detectors/handrolled.test.ts` enforces
that mechanically.

## How to read the verdicts

| Verdict | Meaning |
|---|---|
| **SHIPPED** | A detector exists (`src/detectors/handrolled.ts`, PR #395), fixture-gated. |
| **BOUNDARY** | The shape is already another module's class (M1/M4/M5/M7/M9). Cross-reference it; never emit an M6 twin — the #278 double-count discipline. |
| **YES** | Graduates as a free-indicator candidate: the shape is a syntactic fact a detector can state hedged. Ships only with a paired positive+negative fixture (#61) and the vocabulary-lock test extended. |
| **MAYBE** | Plausibly mechanical but needs something first: cross-statement correlation, a dependency gate, a boundary check against another module, or shape work whose FP surface is unknown. Deferred, not rejected. |
| **NO** | Stays LLM-tier (the paid `simplify-scan` packet). Either the shape is not syntactically recognisable, or even a hedged listing would read as the tool not understanding the codebase. |
| **EXCLUDED** | Not a reinvention at all: no standard replacement exists, or the "hand-rolled" form is the idiomatic form. Recorded so the question isn't re-litigated. |

Under the operator ruling, the graduation bar for **free indicators** is relaxed — the negative case
does not need to be mechanically distinguishable, because the indicator asserts only that a shape is
present. The bar that still binds everywhere: the *paid* tier's named replacement needs the
judgment pass, and an indicator must not be so commonly justified that hedged listing reads as
tone-deaf (that is what demotes several entries below to NO/EXCLUDED despite crisp shapes).

**Honesty note on ranking:** per-pattern frequency below is engineering judgment about AI-generated
code, NOT a measured number — no frequency was counted on the 6-repo external corpus or any other
target. Measuring real per-pattern frequency (a grep/AST count across the corpus clones) is listed
as follow-up work at the end; until then no entry may be cited as "common" in client-facing or
capability-claiming text.

**Dep-gate** below means the detector fires only when the named library (or category of library) is
already in the target's dependency tree — otherwise hand-rolling is the deliberate dep-drop shape
(`targets/calibration/simplify/depdrop.ts`), not a reinvention indicator. The gate is the generic
`depGatePresent(files, libNames)` (`src/detectors/handrolled.ts`, PR #409 — fails closed with no
package.json); the shipped class-merge detector is its first consumer.

---

## A. Core language & stdlib (arrays, objects, strings)

| # | Shape | Standard replacement | Verdict | Reason / negative class |
|---|---|---|---|---|
| 1 | `JSON.parse(JSON.stringify(x))` deep clone | `structuredClone()` | **BOUNDARY → M7** | `perf-code.ts` `detectJsonDeepClone` (`M7 — JSON deep-clone`) fires on the same node; measured double-fire in #395 dogfood. |
| 2 | `JSON.stringify(a) === JSON.stringify(b)` deep equal | `util.isDeepStrictEqual` / a deep-equal dep | **SHIPPED** | `M6 — Indicator: JSON deep-equal`. |
| 3 | Unique via `arr.filter((v,i,a) => a.indexOf(v) === i)` | `[...new Set(arr)]` | **YES** | Exact three-argument-callback idiom; no justified-negative class identified. |
| 4 | Flatten via `arr.reduce((a,b) => a.concat(b), [])` | `arr.flat()` | **YES** | Exact idiom. Negative: a genuine custom accumulator that happens to concat — the detector needs the empty-array seed + bare-concat body, which excludes it. |
| 5 | Group-by via reduce pushing into `acc[key]` | `Object.groupBy` / `Map.groupBy` | **MAYBE** | Shape is real (corpus fixture `group.ts` plants it for the LLM eval) but accumulator-shape analysis is a step up from call-matching; replacement is ES2024 so the version question itself is paid-triage material. |
| 6 | Chunk via `for` loop + `slice(i, i+n)` | `lodash.chunk` etc. — **dep-gate** | **MAYBE** | No stdlib replacement, so needs the dep-gate; loop+slice correlation not yet built. |
| 7 | Recursive hand-rolled deep merge | `deepmerge` / `es-toolkit` — dep-gate | **NO** | A recursive object-walking function has too many legitimate non-merge instances; recognising "this recursion IS a merge" is judgment. |
| 8 | Hand-rolled pick/omit helpers | `Object.fromEntries(Object.entries().filter())` | **NO** | The "standard" is itself hand-assembled; no crisp line between helper and reinvention. |
| 9 | `arr[arr.length - 1]` | `arr.at(-1)` | **EXCLUDED** | Idiomatic, universal, zero maintenance cost. Flagging it is the tone failure §5 warns about. |
| 10 | Manual for-push range building | `Array.from({length: n}, (_, i) => i)` | **EXCLUDED** | Both forms idiomatic; AI generally writes this fine. |
| 11 | Shuffle via `sort(() => Math.random() - 0.5)` | Fisher–Yates / a lib | **YES** | Exact idiom, and also a correctness smell (biased shuffle) — the indicator stays descriptive; the bias claim is paid triage. |
| 12 | Min/max via reduce comparison ladder | `Math.min(...arr)` | **MAYBE** | Crisp-ish shape, low value; the spread form has its own large-array limits, which is exactly the nuance that belongs to paid triage, not an indicator. |
| 13 | Zero-padding via `("0" + n).slice(-2)` | `String.prototype.padStart` | **YES** | Exact idiom. |
| 14 | Capitalize helper `s[0].toUpperCase() + s.slice(1)` | — none exists | **EXCLUDED** | No stdlib replacement; not a reinvention. |
| 15 | Case converters (camel/kebab/title regex chains) | `change-case` / lodash — dep-gate | **MAYBE** | Regex-chain family; needs the dep-gate and shape work per converter. |
| 16 | Path-get via `"a.b.c".split(".").reduce(...)` | optional chaining / `lodash.get` — dep-gate | **YES** | Exact split-reduce idiom. |
| 17 | Hand-rolled once/memoize wrappers | `lodash.memoize` / React `cache()` | **NO** | A Map-in-closure cache is also every legitimate cache; distinguishing needs judgment. |
| 18 | HTML-entity escaping via replace chain (`&amp;`, `&lt;`…) | framework escaping (React JSX auto-escapes) | **MAYBE** | Boundary settled (#406): M1's taint rules own the sink-feeding case — `harvey-dangerously-set-inner-html` (base.yml) plus `harvey-dom-innerhtml`/`-stored` (xss.yml) — and their sanitizer lists (`DOMPurify.sanitize`/`sanitizeHtml`/`sanitize`) don't include a hand-rolled helper, so M1 still fires *through* one; an M6 indicator on the helper *definition* can't double-count. No M1 rule or b4 entry covers the replace chain itself (verified by grep 2026-07-16). Remaining blocker: non-DOM outputs (email/XML assembly) hand-escape legitimately — FP/tone surface. |
| 19 | Hand-rolled event emitter (listener array + on/emit) | `EventTarget` / `node:events` | **MAYBE** | Class-shape recognition (on/off/emit methods + listener collection) is doable but untested for FP surface. |
| 20 | Sleep helper `new Promise(r => setTimeout(r, ms))` | `node:timers/promises` (server only) | **EXCLUDED** | One line, justified everywhere client-side (browser has no stdlib form), enormous volume. The tone/volume failure case in miniature. |

## B. IDs & randomness

| # | Shape | Standard replacement | Verdict | Reason / negative class |
|---|---|---|---|---|
| 21 | `Math.random().toString(36)` chain ids | `crypto.randomUUID()` | **SHIPPED** | `M6 — Indicator: random-string id` (radix > 10 required, so numeric formatting never flags). |
| 22 | Char-loop id builder (charset string + `Math.random()` index loop) | `crypto.randomUUID()` / nanoid | **MAYBE** | Corpus fixture `id.ts` plants it for the LLM eval; a mechanical twin needs loop-shape correlation (random index into a charset accumulating a string). |
| 23 | The `'xxxxxxxx-xxxx-4xxx…'.replace(/[xy]/g, …)` UUID-v4 template snippet | `crypto.randomUUID()` | **YES** | The template literal is unmistakable — the most copy-pasted id snippet on the internet. |
| 24 | Composite `${Date.now()}-${Math.random()}` ids | `crypto.randomUUID()` | **YES** | Template combining both calls is exact; either call alone is NOT flagged (see 25). |
| 25 | Timestamp-only ids (`Date.now().toString()`) | — | **EXCLUDED** | Usually a legitimate timestamp, not an id; indistinguishable without intent. |
| 26 | Hand-rolled nanoid-alike over `crypto.getRandomValues` | nanoid | **NO** | The code already uses the right primitive; whether a lib is warranted is judgment. |
| 27 | Non-crypto string-hash loops (djb2/FNV: `hash << 5` + `charCodeAt` accumulate) | `crypto.subtle.digest` / a hash dep | **YES + M1 check** | Shift-accumulate loop is crisp. If the input is a password/secret it is M1's weak-crypto class (b6/b11) — the detector must yield to M1 on those inputs, indicator otherwise. |

## C. Dates & times

| # | Shape | Standard replacement | Verdict | Reason / negative class |
|---|---|---|---|---|
| 28 | Date math on raw ms constants (`86400000`, `24*60*60*1000`) | `date-fns`/`dayjs` — **dep-gate** | **YES (dep-gated)** | The literals are exact; gate mirrors class-merge. Negative: a codebase with no date lib hand-rolling ONE offset is the dep-drop shape — the gate handles it. |
| 29 | formatDate via `getFullYear()`/`getMonth()+1`/`getDate()` concat | `Intl.DateTimeFormat` / `toLocaleDateString` | **YES** | Co-occurrence of the getters in one template/concat is crisp; Intl is universal (no dep-gate needed). |
| 30 | Month/day-name literal arrays (`["January", …]`) | `Intl.DateTimeFormat` with `month: "long"` | **YES** | The literal array is exact. |
| 31 | Relative "time ago" if-ladder (diff < 60 → "minutes ago"…) | `Intl.RelativeTimeFormat` | **MAYBE** | Needs a string-literal + division-ladder heuristic; FP surface unknown. |
| 32 | Manual ISO-date parsing via `split("-")`/regex | `Date` / (eventually) Temporal | **MAYBE** | Splitting date-shaped strings is diffuse; the crisp subset needs definition. |
| 33 | Timezone-offset arithmetic (`getTimezoneOffset() * 60000` …) | `date-fns-tz` etc. | **NO** | Sometimes genuinely required (UTC normalization); shape alone can't tell. |
| 34 | Duration formatting (H:MM:SS via `/3600` `%60` chains) | `Intl.DurationFormat` | **MAYBE** | Replacement is very new — version-gating makes even the hedged indicator awkward today. |
| 35 | Leap-year rules re-derived (`%4`/`%100`/`%400` chain) | `new Date(y, m+1, 0).getDate()` | **MAYBE** | The modulo chain is exact but rare; low value. |

## D. URLs, query strings, paths

| # | Shape | Standard replacement | Verdict | Reason / negative class |
|---|---|---|---|---|
| 36 | Query-string parsing via `split("&")` + `split("=")` | `URLSearchParams` / `useSearchParams()` | **SHIPPED** | `M6 — Indicator: query-string parsing`. |
| 37 | Query-string **building** via `map(k => \`${k}=${v}\`).join("&")` | `URLSearchParams` | **YES** | Mirror of the shipped parse class; join("&") over key=value templates is exact. |
| 38 | URL part extraction via regex/split | `new URL()` | **NO** | Too many legitimate string operations on url-named variables; the crisp subset doesn't exist. |
| 39 | Path joining via `"/"` concat + de-dup replace | `node:path` / `URL` | **MAYBE** | The slash-de-dup replace (`/\/+/g`) is crisp-ish; plain concat is not. |
| 40 | Slugify (`toLowerCase().replace(/[^a-z0-9]+/g, "-")`) | `slugify` — dep-gate (no stdlib) | **MAYBE** | Regex is near-exact but the one-liner is often a deliberate dep-drop; needs the gate plus tone thought. |
| 41 | MIME-type lookup tables (`".png": "image/png"`, …) | `mime` dep | **YES** | The literal table is unmistakable; descriptive even without the dep in tree. |
| 42 | base64url conversion via `btoa` + `replace(/\+/g, "-")` chains | `Buffer` `"base64url"` / `Uint8Array.fromBase64` | **YES** | The replace chain over `+/=` is exact. |
| 43 | Hex encode/decode loops | `Buffer` `"hex"` / `Uint8Array.toHex` | **MAYBE** | Loop-shape work; lower frequency. |

## E. HTTP & fetch

| # | Shape | Standard replacement | Verdict | Reason / negative class |
|---|---|---|---|---|
| 44 | fetch timeout via `Promise.race([fetch, timer])` | `AbortSignal.timeout(ms)` | **YES** | Race of a fetch call with a setTimeout promise is exact; no justified-negative identified (the race leaks the request — AbortSignal doesn't — but that claim is paid triage). |
| 45 | Hand-rolled retry/backoff loop | `p-retry` etc. | **NO** | Ruled in #395: the benign case is exactly `depdrop.ts` — judgment-bearing. The catalogued decision stands. |
| 46 | JSON fetch wrapper (fetch + ok-check + `.json()`) | — | **EXCLUDED** | Every codebase legitimately has one; not a reinvention. |
| 47 | Polling via `setInterval` + fetch | SWR/React Query `refreshInterval` — dep-gate | **MAYBE** | Boundary settled (#406, probed): `detectClientFetchEffect` does NOT fire on a fetch inside a setInterval callback (callbacks handed to other calls aren't mount-path in `mountDataReads`); it fires on the fetch-immediately-then-poll variant only via the immediate call. Interval polling is outside M7's net. Remaining blockers: the dep-gate, plus suppressing the M6 indicator when M7 already flagged the same effect (the combined shape double-fires otherwise). |
| 48 | HTTP status→message literal tables | — | **EXCLUDED** | Harmless constants; no meaningful maintenance cost. |
| 49 | Hand-rolled API-error class hierarchies | — | **NO** | Over-abstraction judgment (the existing `manager.ts` corpus territory). |
| 50 | Manual AbortController-on-unmount wiring | SWR/React Query — dep-gate | **NO** | The manual code is *correct*; whether a lib is warranted is judgment. |

## F. Cookies, headers, auth glue

| # | Shape | Standard replacement | Verdict | Reason / negative class |
|---|---|---|---|---|
| 51 | Cookie parsing (`document.cookie` splits, cookie-header splits) | `next/headers` `cookies()` / a cookie dep | **SHIPPED** | `M6 — Indicator: cookie parsing` (writes stay silent). |
| 52 | Cookie **serialization** (building `"k=v; Path=/; Max-Age=…"`) | `cookies().set()` / a cookie dep | **YES** | The attribute literals (`; Path=`, `; Max-Age=`, `; HttpOnly`) are exact; mirror of the shipped parse class. |
| 53 | JWT payload decode by hand (`token.split(".")[1]` + atob/Buffer + `JSON.parse`) | `jose` / `supabase.auth.getUser()` | **YES + M1 check** | The three-step chain is exact and rampant in AI Supabase glue (judgment, unmeasured). When decoded claims gate authz without verification it is M1's territory (#221's trusting-client-input family; b11 JWT-verify) — the M6 indicator notes only the hand-rolled decode. Supabase-token receivers are the same detector with more specific evidence text. |
| 54 | Bearer extraction (`authorization.split(" ")[1]`) | — | **EXCLUDED** | One line, no stdlib replacement. |
| 55 | Hand-rolled Supabase session/Set-Cookie glue | `@supabase/ssr` | **NO** | Recorded non-candidate in the Phase-1 shortlist: `framework-adapter.ts` (a protected corpus negative) IS this shape — dep-presence is necessary but not sufficient. |
| 56 | Basic-auth encode (`btoa(\`${u}:${p}\`)`) | — | **EXCLUDED** | That IS the standard way. |

## G. React client patterns

| # | Shape | Standard replacement | Verdict | Reason / negative class |
|---|---|---|---|---|
| 57 | Hand-rolled class-string merge in className context | `clsx`/`tailwind-merge` — **dep-gate** | **SHIPPED** | `M6 — Indicator: class-string merge`; the dep-gate is the reference pattern. |
| 58 | Hand-rolled `useDebounce` hook | `use-debounce`/`usehooks-ts` — dep-gate | **MAYBE** | Hook-name + setTimeout body is crisp; a WHY-comment suppression (mechanically checkable: adjacent comment matching `/why:/i`) would buy the tone latitude the ruling asks for. Same open question as the `debounce.ts` corpus fixture, which stays LLM-judged today. |
| 59 | The utility-hook family (`useLocalStorage`, `usePrevious`, `useInterval`, `useWindowSize`, `useMediaQuery`, `useOnClickOutside`, `useIntersectionObserver`…) | `usehooks-ts` etc. — dep-gate | **MAYBE** | Name-keyed detection over the family is one detector, but the volume risk is the ruling's own risk #2 in miniature — do not build before the rollup rule exists. |
| 60 | Fetch-in-useEffect + loading/error state triple | SWR/React Query | **BOUNDARY → M7** | `detectClientFetchEffect` shipped 2026-07-16 under M7. Cross-reference; no M6 twin. |
| 61 | Hand-rolled ErrorBoundary class | `react-error-boundary` / Next.js `error.tsx` | **YES** | `class … extends Component` + `componentDidCatch` is exact. Negative: a deliberately customized boundary — the hedged indicator stays honest on it. |
| 62 | Context+Provider+hook boilerplate for simple state | `zustand`/`jotai` — dep-gate | **NO** | Whether context is "too much" is the judgment M6's paid tier exists for. |
| 63 | Manual form state (useState per field + handlers) | `react-hook-form` — dep-gate | **NO** | Diffuse; same. |
| 64 | isMounted-ref / mounted-flag patterns | — | **NO** | Usually a symptom of a different problem; needs a human read. |

## H. Next.js-specific

| # | Shape | Standard replacement | Verdict | Reason / negative class |
|---|---|---|---|---|
| 65 | Manual `<title>`/`<meta>` JSX in App Router pages | Metadata API (`export const metadata`) | **MAYBE** | Boundary settled (#406, probed): no M9 detector reacts to `<title>`/`<meta>` JSX — app-router.ts has no metadata check at all — so the shape stays M6's (a framework-primitive reinvention, not boundary/rendering). Blockers: `<svg><title>` is a legitimate a11y idiom, and React 19 natively hoists document metadata from components, so the negative class needs shape work before even a hedged indicator. |
| 66 | `window.location.href =` navigation in components | `next/navigation` `router.push` | **MAYBE** | Sometimes deliberately a full reload; hedged indicator tolerable but tone risk is real. |
| 67 | Middleware `pathname.startsWith` ladder | `config.matcher` | **MAYBE** | Boundary settled (#406): `P-MW-MATCHER-EXCLUDES-API` (b15-nextjs-authz.entries.ts) is a corpus entry only — expectedTier review, and no mechanical rule matches it (verified by grep: no rule id, no matcher/startsWith rule in semgrep or mechanical.ts). The security half stays semantic-tier M1; there is no mechanical M1 twin for an M6 ladder indicator to double-count. Remaining blocker: `config.matcher` only accepts static values, so body ladders are often the deliberate/necessary form — tone/FP surface. |
| 68 | `JSON.parse(process.env.X)` env handling | a zod env schema — dep-gate | **YES** | The nested-call shape on a `process.env` member is exact (same detection style as the shipped deep-equal). Scattered `if (!process.env.X) throw` asserting stays EXCLUDED — that's normal code. |
| 69 | Hand-rolled sitemap/robots string building | metadata routes (`sitemap.ts`/`robots.ts`) | **MAYBE** | XML-literal building in an app dir file is crisp-ish; frequency judgment says low. |
| 70 | `<img>` where `next/image` fits | `next/image` | **BOUNDARY → M7/ESLint** | Already ESLint-adjudicated in the M7 calibration work; don't re-emit. |
| 71 | Hand-rolled loading flags where `loading.tsx`/Suspense exists | `loading.tsx` / Suspense | **NO** | Whether the flag duplicates a boundary the route already has needs route-tree judgment. |
| 72 | Pages Router idioms pasted into `app/` (`_app`/`_document` patterns) | App Router conventions | **MAYBE** | Boundary settled (#406): M9's #231 piece is `isPagesRouterOnly` (app-router.ts) — it only *suppresses* App-Router checks on Pages-only projects; nothing in M9 detects Pages idioms inside `app/` (verified). No overlap. Remaining blocker: `_app`/`_document` idioms are a family, not one signature — per-idiom shape definition needed. |

## I. Supabase-specific

| # | Shape | Standard replacement | Verdict | Reason / negative class |
|---|---|---|---|---|
| 73 | Pagination reinvention (offset math + client-side `.slice()`) | `.range(from, to)` | **MAYBE (deferred)** | #395's recorded deferral: needs cross-statement correlation between the query chain and the nearby manual offset math. |
| 74 | Fetch-all then `.data.length` as a count | `count: "exact", head: true` | **BOUNDARY → M7** | Probed (#406): `detectUnboundedSelect` fires on the fetch-all `select('*')` variant, and `isCountOnlySelect` already keeps the `head:true` fix silent — the class is M7's (needless row fetch is a perf harm in every variant); an M6 indicator would be a twin. The residual gap — column-projected `select('id')` + `.length` (probed: silent) — is an M7 net extension, not an M6 class. |
| 75 | select-then-branch insert/update on the same table | `.upsert()` | **MAYBE** | Cross-statement, like 73. Note the CAS/zero-row-update anti-pattern (D-091 #7) is the *correctness* neighbor — paid triage should read both. |
| 76 | Storage public-URL concat (literals containing `/storage/v1/object/public/`) | `getPublicUrl()` | **YES** | The path literal is exact and Supabase-specific — directly on-brand for the wedge. |
| 77 | Hand-rolled realtime reconnection/backoff | supabase-js built-in retry | **NO** | Retry family (see 45). |
| 78 | Hand-written row interfaces duplicating generated types | `supabase gen types` | **NO** | Whether an interface duplicates the schema is not syntactically decidable from one file. |
| 79 | App-side `.eq("tenant_id", …)` atop a service-role client | RLS / tenant-scoped client | **BOUNDARY → M1** | Anti-pattern #5 (app-layer scope without DB enforcement) — security posture, not maintainability. |
| 80 | Hand-rolled auth middleware session refresh | `@supabase/ssr` middleware helper | **NO** | Same family as 55; the corpus's protected negative is this shape. |

## J. Validation & parsing

| # | Shape | Standard replacement | Verdict | Reason / negative class |
|---|---|---|---|---|
| 81 | Email regex where zod is in the tree | `z.string().email()` — **dep-gate on zod** | **YES (dep-gated)** | An email-shaped regex literal is exact; without zod in tree, a regex IS the standard approach → gate handles it. |
| 82 | Phone-number regex | zod/libphonenumber — dep-gate | **MAYBE** | Family of 81 with a weaker signature (phone regexes are diverse). |
| 83 | URL-shape validation regex | `new URL()` in try/catch | **MAYBE** | Crisp-ish; note the repo's own G2 anti-pattern says `z.string().url()` is NOT the safe replacement — which replacement to name is exactly why this stays paid-triage material. |
| 84 | Type guards re-implementing zod schemas already in tree | `z.infer` + `safeParse` | **NO** | Needs semantic comparison of guard vs schema. |
| 85 | `safeJsonParse` try/catch helpers | — | **EXCLUDED** | Normal code. |
| 86 | Password-strength rule sets | — | **BOUNDARY → M1** | Auth policy is security's. |
| 87 | Hand-rolled sanitizer regexes (strip `<script>` etc.) | DOMPurify | **BOUNDARY → M1** | XSS defense (b4) — a wrong "may be worth investigating" here would understate a vulnerability. |

## K. Formatting & i18n

| # | Shape | Standard replacement | Verdict | Reason / negative class |
|---|---|---|---|---|
| 88 | Currency via `"$" + (x/100).toFixed(2)` concat | `Intl.NumberFormat` | **YES** | `toFixed` concatenated with a currency-symbol literal is exact. The float-money adjacency is a correctness note for paid triage, not the indicator. |
| 89 | Thousands separator via `\B(?=(\d{3})+(?!\d))` regex | `toLocaleString()` | **YES** | The famous Stack Overflow regex, byte-exact. |
| 90 | Byte-size KB/MB/GB ladder (`/1024` chains) | `Intl.NumberFormat` units / a filesize dep | **MAYBE** | Ladder shape crisp-ish; frequency judgment says moderate. |
| 91 | Pluralization ternaries (`n === 1 ? "item" : "items"`) | `Intl.PluralRules` | **EXCLUDED** | A one-off ternary is fine code — flagging it is tone-deaf. (A hand-rolled pluralize *engine* would be NO/LLM-tier: recognising "engine" is judgment.) |
| 92 | List joining with "a, b and c" logic | `Intl.ListFormat` | **MAYBE** | Low frequency; weak signature. |
| 93 | Translations object + `t()` lookup | `next-intl`/`i18next` — dep-gate | **NO** | i18n architecture is a judgment call. |
| 94 | Numeric rounding via `Math.round(x * 100) / 100` | — | **EXCLUDED** | For *numeric* (not display) rounding there is no better stdlib form; often deliberate. |

## L. Browser/platform APIs & misc

| # | Shape | Standard replacement | Verdict | Reason / negative class |
|---|---|---|---|---|
| 95 | Clipboard via `document.execCommand("copy")` + hidden textarea | `navigator.clipboard.writeText` | **YES** | Deprecated-API call is exact; the textarea dance is unmistakable. |
| 96 | Smooth-scroll animation loops (rAF steppers) | `scrollIntoView({behavior: "smooth"})` / CSS | **MAYBE** | Loop-shape work; moderate frequency. |
| 97 | File download via `createElement("a")` + `.click()` | — | **EXCLUDED** | That IS the standard idiom. |
| 98 | Markdown→HTML via regex replaces | `react-markdown` etc. — dep-gate | **YES + M1 check** | Regexes emitting `<strong>`/`<em>` into strings are crisp; if the result feeds `dangerouslySetInnerHTML` the XSS half is M1's. |
| 99 | CSV assembly via `map` + `join(",")` + `join("\n")` | a csv dep | **MAYBE** | Same two-join-in-one-scope style as the shipped query-string class; quoting bugs make it worth eventual graduation. |
| 100 | Regex-based HTML/XML parsing | `DOMParser` | **MAYBE** | Tag-shaped regex literals are crisp-ish; FP surface unknown. |
| 101 | Hand-rolled semver compare (`split(".")` + numeric compare) | `semver` dep | **MAYBE** | Needs version-named-variable heuristics. |
| 102 | Module-level Map cache with `Date.now()` TTL | React `cache()` / `unstable_cache` / Redis | **MAYBE** | Boundary settled (#406): no Harvey detector covers either variant — nothing in src/detectors/ matches setInterval/TTL/limiter shapes, handrolled.ts has no Map-cache class, and anti-pattern #19's `check:rate-limit-store` guard is ATC's repo script, absent from Harvey's package.json (all verified by grep). The limiter-named variant is M1's if ever built; the cache variant stays M6. Remaining blocker: entry 17's problem in module-level form — a TTL Map is also every legitimate cache; the limiter-vs-cache naming split needs shape work. |
| 103 | Custom console.log level-ladder logger | `pino` etc. — dep-gate | **NO** | Logger architecture is judgment; small wrappers are often deliberate. |
| 104 | Hand-rolled feature flags (env-var ladder) | a flags provider | **NO** | Architecture judgment. |
| 105 | Sequential awaits in a loop where parallel is safe | `Promise.all` | **BOUNDARY → M7** | Perf territory (nested-loop/waterfall family, #385); not an M6 reinvention. |
| 106 | Copy-pasted Tailwind class strings across components | extraction/composition | **BOUNDARY → M4** | Duplication is jscpd's (plus the #360 diverged-clone pass). |

---

## The tally — the honest number the issue asked for

106 patterns catalogued. **Of the 106, 76 do NOT currently graduate to a free mechanical
indicator.** That is the finding, and per the issue's own framing it is a successful outcome, not a
failed one.

| Verdict | Count | Entries |
|---|---|---|
| SHIPPED (PR #395) | 5 | 2, 21, 36, 51, 57 |
| YES — graduation candidates | 25 | 3, 4, 11, 13, 16, 23, 24, 27, 28, 29, 30, 37, 41, 42, 44, 52, 53, 61, 68, 76, 81, 88, 89, 95, 98 |
| MAYBE — deferred, with the specific blocker named | 33 | 5, 6, 12, 15, 18, 19, 22, 31, 32, 34, 35, 39, 40, 43, 47, 58, 59, 65, 66, 67, 69, 72, 73, 75, 82, 83, 90, 92, 96, 99, 100, 101, 102 |
| NO — stays LLM-tier (paid packet) | 21 | 7, 8, 17, 26, 33, 38, 45, 49, 50, 55, 62, 63, 64, 71, 77, 78, 80, 84, 93, 103, 104 |
| BOUNDARY — another module's class | 9 | 1 (M7), 60 (M7), 70 (M7/ESLint), 74 (M7), 79 (M1), 86 (M1), 87 (M1), 105 (M7), 106 (M4) |
| EXCLUDED — not a reinvention / tone | 13 | 9, 10, 14, 20, 25, 46, 48, 54, 56, 85, 91, 94, 97 |

(Counting note: the 7 rows that carried an unresolved "+ M1/M7/M9 check" — 18, 47, 65, 67, 72,
74, 102 — were settled 2026-07-16 in the #406 boundary pass: 74 moved to BOUNDARY → M7 (probed);
the other six stayed MAYBE with the boundary verified absent and the remaining blocker named in
their reason cells. Entries 27, 53, and 98 carry a "+ M1 check" of a different kind — a *runtime
yield condition* on the eventual detector's inputs, not an unresolved ownership question — and
are tallied under YES unchanged. Exact arithmetic: 5 SHIPPED + 25 YES = 31 on the graduation
track; 33 MAYBE + 21 NO + 9 BOUNDARY + 13 EXCLUDED = 76 not currently graduating. 31 + 76 = 106.)

**Reading the split honestly:**

- The 25 YES entries are *candidates*, not detectors. Every one still owes a paired
  positive+negative fixture (#61), an extension of the vocabulary-lock test, and a dogfood run
  before it ships — the #395 batch is the template. None of this catalogue's verdicts is a
  precision claim; per #265's constraint, **no precision number of any kind is claimed for any
  tier of M6**, including the shipped classes.
- The 33 MAYBEs are deferred for three named reasons: cross-statement correlation (73/75),
  dep-gates not yet generalized (6/15/40/47/58/59/82), or unknown FP/tone surface on a
  loop/heuristic shape (the rest — including 18/65/67/72/102, whose module boundaries were
  settled in the #406 pass, leaving the FP/shape blocker as the only thing standing). Each is
  re-openable by resolving its named blocker — they are not soft rejections.
- The 21 NOs are the locked decision working as intended: over-abstraction, premature generality,
  "is this too much?" — asserted judgments, paid-tier, per `spec-72` preamble item 2 as amended by
  the operator ruling.
- The 13 EXCLUDED entries are recorded precisely so a future sweep doesn't "discover" them: they
  fail on tone or on the absence of any real replacement, and flagging them is the
  "tool doesn't understand our codebase" failure `m6-simplification-eval.md` §5 warns about.

## The M5/M6 boundary question (raised in the issue comments) — Phase-1 answer

`src/detectors/slop.ts` ships 11 mechanical detectors under **M5**; this catalogue adds M6
indicator classes one file over. The line this catalogue draws, and which the entries above obey:

- **M5 = code that should not exist** (dead, narrating, stub-shaped, redundant).
- **M6 = code that re-implements something that already exists** (stdlib, framework, or a dep
  already in the tree).

`detectSingleCallWrapper` sits on the line but falls M5-side: a single-call wrapper is *structure
without function* (delete/inline), not a reinvention of a platform primitive. No slop.ts class
re-files under M6, and no entry above duplicates a slop.ts class — the #278 double-count stays
unwound.

## Follow-up work this catalogue creates (tracked, not silent)

1. **Measure real frequency** — grep/AST-count the YES and MAYBE shapes across the 6-repo external
   corpus so the next detector batch is ordered by measured frequency instead of judgment. Until
   then, no "common"/"rampant" claim from this doc may appear in client-facing text.
2. **Next detector batch** — the YES column, in corpus-measured order, fixtures first. The
   per-library dep-gate the entries need is DONE (PR #409: `depGatePresent`, fails closed) — the
   dep-gated entries are unblocked on that front.
3. **The boundary checks** — SETTLED 2026-07-16 (#406): 74 → BOUNDARY → M7 (`detectUnboundedSelect`
   fires on the fetch-all variant, probed); 18/47/65/67/72/102 verified non-overlapping — each
   stays MAYBE with the evidence and the remaining blocker recorded in its reason cell. One
   residual cross-module note: the column-projected `select('id')` + `.length` count shape is
   outside M7's current net (probed silent) — an M7 net extension, if wanted, not M6 work.
4. **WHY-comment suppression** (from 58) — DONE 2026-07-16 (PR #409): implemented once, centrally,
   in the shared emission path (`makeIndicator`), so it applies to every current and future
   indicator class. Adjacency = a `/why:/i` comment leading the flagged node's enclosing statement
   or trailing on its line; narration without the marker never suppresses (fixture-locked). Known
   literalism: a WHY comment above the enclosing *function* does not suppress a shape inside the
   body — extend deliberately if real targets show that placement dominates.
