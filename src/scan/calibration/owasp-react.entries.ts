// OWASP React Security Cheat Sheet as an INDEPENDENT coverage corpus (#1192). Third of three;
// the rationale for scoring against a checklist we did not author is in owasp-multitenant.entries.ts
// and is not repeated here.
//
// PINNED SOURCE: cheatsheets_draft/React_Security_Cheat_Sheet.md at commit
// 4332c39c799d5d0ac835082ebf88c4a0a2e31cb3 — the head of OWASP/CheatSheetSeries PR #2196, which is
// STILL OPEN and NOT MERGED. There is no merged React cheat sheet to pin instead.
//
// THE PIN IS REPRODUCIBLE, which is the condition #1192 set for building this at all. The commit is
// on a fork branch (anuragnedunuri/CheatSheetSeries), but GitHub keeps a PR's head commit reachable
// from the BASE repository, so the pinned revision resolves against OWASP/CheatSheetSeries itself
// and survives the fork being deleted or the branch being force-pushed:
//   curl -sf https://api.github.com/repos/OWASP/CheatSheetSeries/commits/4332c39c799d5d0ac835082ebf88c4a0a2e31cb3
// Verified reachable 2026-07-27. Do NOT re-point this at the branch; re-pin deliberately.
//
// CONTENT WILL CHANGE BEFORE MERGE, and some of it will be cut. Maintainer review on #2196 asks for
// significant reduction and for the sheet to be "more React focused". Two consequences #1192 told us
// to accept up front: entries below may be built against paragraphs that never ship (which is fine —
// a real defect we miss is a real gap regardless of whether OWASP keeps the paragraph describing it),
// and the pinned revision must be reconciled against the merged sheet afterwards. That reconciliation
// is tracked in #1241, not left implicit.
//
// AND #1241 IS WIRED TO AN ALARM RATHER THAN A LABEL. It was first parked by labelling the issue
// `deferred`, which makes future sweeps skip it at fetch time — so the merge upstream would have
// waited for a human to happen to check GitHub. That is this repo's own silent-omission shape
// relocated to the issue tracker: nothing notices when an external blocker clears. The mechanism that
// does notice is the #1033 recorded reason below, because `.github/workflows/reasons-drift.yml` runs
// `pnpm validate-reasons --revalidate` daily and fails loud on any falsifier that now exits 0. The
// block has to live HERE and not in the issue: that job deliberately never executes a falsifier found
// in an issue body, which is attacker-writable input.
//
// The falsifier is written so a BROKEN LOOKUP cannot masquerade as "still blocked". `gh api` exits
// non-zero on an auth failure, a network failure or a missing binary, and under the contract a
// non-zero exit means the blocker holds — so the command traps that case and exits 127, which the
// gate reports as UNVERIFIABLE and fails on. A daily run that could not read upstream therefore goes
// red rather than green, at the cost of a transient network blip filing a tracking issue; that trade
// is the one #1072 was written to force. Reading a third-party repo with the workflow's `github.token`
// is proven, not assumed — owasp-ack-watch.yml does exactly that against this same upstream repo.
//
// REASON: the reconciliation #1241 owes cannot be done — OWASP/CheatSheetSeries PR #2196 is still open, so there is no merged React sheet to diff the pinned revision against, no merged commit to re-pin to, and no way to tell which entries here were built on paragraphs review cut
// KIND: empirical
// PROVENANCE: MEASURED 2026-07-27 — `gh api repos/OWASP/CheatSheetSeries/pulls/2196 --jq .merged` returns `false`, and the falsifier below exits 1. Exercised in all four directions: 1 on this open PR, 0 with the number swapped for merged #2305, 127 with no credential, 127 with the API unreachable.
// FALSIFIER: m=$(gh api repos/OWASP/CheatSheetSeries/pulls/2196 --jq .merged) || exit 127; [ "$m" = true ]
// TOUCHES: src/scan/calibration/owasp-react.entries.ts
//
// HOW THE BUCKETS WERE ASSIGNED — MEASURED, NOT INSPECTED (2026-07-27,
// `pnpm exec tsx src/cli/quick-scan.ts --dir targets/calibration --findings-out …`, 493 findings):
// every fixture was planted first and the scanner run second.
//
// A MEASUREMENT TRAP THIS CORPUS FELL INTO FIRST, recorded because it silently manufactures gaps.
// The scan reads a GIT-TRACKED SCRATCH COPY of the target, not the working tree. An unstaged fixture
// is therefore invisible to the scanner and reports ZERO findings — indistinguishable, in the output,
// from a fixture that was scanned and missed. The first run here recorded six gaps that way. That is
// why scope-control-innerhtml.tsx exists and is scored as a POSITIVE below: it plants a class Harvey
// is already known to catch, in this same directory, so a run in which the six gaps are real is
// distinguishable from a run in which the directory was never read. Without it the six "measured
// gaps" would be an unfalsifiable claim. `git add` the fixtures before believing a zero.
//
// ALREADY COVERED — accounted for, deliberately NOT re-planted (duplicating them would inflate an
// apparent coverage number without testing anything). Cross-referenced rather than copied:
//   "Avoid Unsafe HTML Injection with dangerouslySetInnerHTML" -> b4-xss (P-XSS-STORED-DSIH,
//     P-DSIH-PROP, and P-XSS-LOCAL-SANITIZE for the no-op-sanitizer bypass).
//   "Validate URLs Before Rendering" (the javascript: scheme JSX escaping does not cover)
//     -> b4-xss (P-XSS-HREF-JS, P-XSS-SETATTR, P-XSS-DANGEROUS-URL).
//   "Avoid Direct DOM Manipulation" (.innerHTML/.insertAdjacentHTML on a ref) -> b4-xss
//     (P-DOM-XSS-INNERHTML) — and re-proved in this directory by the scope control below.
//   "Avoid Dynamic Code Execution" (eval/new Function) -> b3-injection.
//   "Store Authentication Tokens in httpOnly Cookies" -> b12 (P-TOKEN-IN-WEBSTORAGE).
//   "Do Not Expose Secrets Through Environment Variables" (VITE_/NEXT_PUBLIC_ prefixes) -> base
//     (P-NEXTPUBLIC-SECRET) + b13-supa (P-VITE-SERVICE-ROLE-CLIENT, with N-VITE-ANON-CLIENT proving
//     an intentionally-public key is not flagged).
//   "Do Not Rely on UI-Only Route Protection" / "Do Not Enforce Authorization Through UI Role Checks"
//     -> b15 (P-CLIENT-RENDER-AUTHZ) + b14 (P-CLIENT-AUTHZ-STORAGE).
//   "Sanitize User Input Used in HTTP Response Headers" (response splitting) -> b12
//     (P-CRLF-HEADER-INJ, P-CRLF-MULTIHOP).
//   "Authorize Inside Server Actions" -> b7 (P-SERVER-ACTION-NOAUTH) + m9-checks (Server Action
//     missing authorization) + m9-authz (the client-supplied owner id / IDOR half).
//   "Do Not Rely on Middleware as the Sole Authorization Boundary" -> b15 (P-MW-SOLE-AUTHZ,
//     P-MW-MATCHER-EXCLUDES-API).
//   "Dependency and Supply Chain Security" -> b2-deps + b10-deps.
// TWELVE of the sheet's nineteen recommendations land here. That is the good-news half of this
// measurement and it is why the gap list below is six rows rather than nineteen.
//
// WHAT THE SIX GAPS BECAME (2026-07-27, #1237/#1238/#1239/#1240 — one sweep, four issues). Five of
// the six now have a detector and are scored as ordinary positives; ONE (PROP-OVERSHARE) is still an
// open gap, and it is the one that was recorded rather than filed because it needs per-app knowledge
// of which fields are sensitive. The five are worth reading as a group, because only ONE of them was
// the thing the corpus appeared to say it was:
//   SSR-SANITIZER  — a genuine new class. Silent BECAUSE of a correct suppression: every
//                    dangerouslySetInnerHTML rule excludes an import-bound sanitize() wrap, so
//                    DOMPurify in a Server Component read as protection. New AST pass (#1239).
//   RSC-SSRF       — a FACET of a covered class. The fix belonged in the shared request-source
//                    block, not in the SSRF rule: all 21 server-side taint rules were blind to the
//                    Server Component's `{ params }` props, not just this one (#1240).
//   URL-SECRET     — the SAME facet shape again. harvey-secret-in-url-param already scored the
//                    class and was anchored on outbound HTTP; #1237 added the navigation sinks.
//   RSC-BOUNDARY   — the issue's premise was FALSE. detectServerClientLeak has scored this class
//                    since #848; what was missing is that it recognised a raw row only through a
//                    Supabase/Drizzle `.from().select()` chain (#1238). Now scored under M9.
//   PROP-SPREAD    — a genuine new rule (harvey-jsx-prop-spread-injection, #1237).
// Three of five were FACETS of things Harvey already did, and no capability claim we could have
// written would have exposed them — "we detect SSRF" was true and missed the RSC page. That is the
// argument for a third-party answer key stated as a result rather than as a hope.
//
// THE ARITHMETIC, so nothing hides in it. The pinned sheet has 19 actionable items (18 `###`
// subsections plus the Dependency and Supply Chain section). 12 are covered above, 6 are the
// measured gaps below, and 1 — JSON State Serialization — is out-of-universe: 12 + 6 + 1 = 19, and
// every item is in exactly one bucket. The out-of-universe list below carries SEVEN entries rather
// than one because six of them are sub-recommendations inside a covered or gapped subsection, not
// items of their own; they are listed so a reader can see they were considered and why they are not
// scoreable, but they do not add to the 19.
//
// OUT-OF-UNIVERSE (recorded, not dropped — no static source signal, or not a distinct defect):
//   "JSON State Serialization" — this revision only cross-references a subsection ("Avoid JSON
//     Injection in Server-Side Rendered State", said to be in the XSS Prevention section) THAT DOES
//     NOT EXIST IN THE PINNED FILE. A dangling reference to content cut in review, so there is no
//     recommendation here to score. It is also the __NEXT_DATA__/initial-state item #1192 flagged as
//     overlapping our own Next.js sheet proposal (OWASP/CheatSheetSeries#2308 item 4) — when that
//     corpus is built, the entry belongs THERE, once, not duplicated across both.
//   "Show a confirmation prompt before following an external URL" — a UX control; a valid https URL
//     can still be a spoofing site, which is the sheet's own point, and no static rule can score it.
//   "Import the server-only package in modules containing sensitive server logic" — a remediation
//     technique for the server/client boundary gap below, not a separate defect.
//   "Use a Backend for Frontend (BFF) pattern" — architecture guidance, the remedy for the token
//     storage item already covered above.
//   "Hold sensitive values in state only as long as necessary and release them immediately after
//     use" — a value-lifetime property with no static signal.
//   "Avoid blocklists because new dangerous props may be introduced" — guidance on how to write the
//     allowlist in the prop-spread item, not an independently detectable shape.
//   "Component encapsulation and Shadow DOM do not stop extensions reading the DOM" — a factual
//     caveat, not a recommendation.
// Seven items.

import type { CorpusEntry } from "./types.js";

export const owaspReactEntries: CorpusEntry[] = [
  // ---------------------------------------------------------------------------------------------
  // SCOPE CONTROL — the row that makes the six gaps below falsifiable.
  // ---------------------------------------------------------------------------------------------
  {
    id: "P-OWASP-REACT-SCOPE-CONTROL",
    kind: "positive",
    cls: "Known-caught DOM XSS planted in the React corpus directory, to prove the directory is scanned",
    location: "src/owasp-react/scope-control-innerhtml.tsx",
    match: ["dom-innerhtml"],
    expectedTier: "high",
    note: "NOT a sheet recommendation — it is this corpus's own instrument check, and it exists because the first measurement run here produced zero findings for a directory the scanner had never read (unstaged fixtures are absent from the git-tracked scratch copy the scan actually walks). Duplicates P-DOM-XSS-INNERHTML's shape (router.query.q into ref.current.innerHTML) inside src/owasp-react/ so that 'six gaps' and 'the directory was skipped' cannot produce the same output. MEASURED 2026-07-27: harvey-dom-innerhtml fires here at high tier. If this row ever goes quiet, every gap row below is unproven and must be re-measured before it is believed.",
  },

  // ---------------------------------------------------------------------------------------------
  // MEASURED GAPS — planted, scanned, nothing fired. Each names its tracking issue.
  // ---------------------------------------------------------------------------------------------
  {
    id: "P-OWASP-REACT-PROP-SPREAD",
    kind: "positive",
    cls: "Untrusted object spread into a component, letting the caller inject arbitrary props",
    location: "src/owasp-react/prop-spread-injection.tsx",
    match: ["jsx-prop-spread"],
    expectedTier: "review",
    expectedSeverity: "High",
    note: "Sheet, XSS Prevention: 'Avoid Prop Injection via the Spread Operator'. `<Field {...userInput} />` where userInput is parsed from a query parameter lets the attacker supply dangerouslySetInnerHTML itself — an XSS sink reached without the source ever naming one, which is why every dangerouslySetInnerHTML rule stayed dark on it. CLOSED by #1237 (harvey-jsx-prop-spread-injection, xss.yml); MEASURED 2026-07-27, caught at review tier. Review and not free-count on purpose: the rule is only shippable because of its sanitizer, and a heuristic sanitizer is not a ~100%-precision boundary. The match keyword is the RULE id fragment, not the file's — `prop-spread-injection` appears in the fixture's own path and would self-match. N-OWASP-REACT-PROP-ALLOWLIST in the same file is the negative and stays silent.",
  },
  {
    id: "P-OWASP-REACT-RSC-BOUNDARY",
    kind: "positive",
    cls: "Server Component passes a whole database row as a prop to a Client Component",
    module: "M9",
    location: "src/owasp-react/rsc-boundary-full-object.tsx",
    match: ["Server→client data leak"],
    expectedTier: "review",
    note: "Sheet, SSR Security: 'Shape Data Explicitly at the Server/Client Boundary' — the sheet calls this the most critical architectural concern in SSR. CORRECTION TO THE RECORD (#1238, 2026-07-27): #1238 was filed saying 'nothing scores the server-to-client component boundary'. That was FALSE — detectServerClientLeak has scored exactly this class since #848 (M9C-LEAK-POS, live in validate-source-recall). What was real is narrower and was still worth closing: the check recognised a raw row ONLY through a Supabase/Drizzle `.from().select()` chain, so the repo/DAO and Prisma model reads every non-Supabase app uses were invisible, and the fixture ALSO had no Client Component to import (the boundary was not expressible). #1238 widened the row-read shape and planted client-profile.tsx. MEASURED 2026-07-27: caught at review tier. Scored under M9, where the detector lives — calibration.test.ts's '#1238 OWASP React RSC boundary' block, since runMechanicalScan is not that detector's pipeline.",
  },
  {
    id: "P-OWASP-REACT-SSR-SANITIZER",
    kind: "positive",
    cls: "Browser-only sanitizer (DOMPurify) called in a server-rendered component",
    location: "src/owasp-react/ssr-browser-sanitizer.tsx",
    match: ["browser-only sanitizer"],
    expectedTier: "high",
    expectedSeverity: "High",
    note: "Sheet, SSR Security: 'Use a Server-Compatible Sanitization Library for SSR HTML' — DOMPurify needs a browser DOM and cannot sanitize in Node. CLOSED by #1239 (src/scan/ssr-sanitizer.ts); MEASURED 2026-07-27, caught at high tier. The gap's cause is recorded because it recurs: every dangerouslySetInnerHTML rule EXCLUDES an import-bound sanitize() wrap (N-XSS-IMPORT-SANITIZE pins that exclusion deliberately), so a DOMPurify call in a Server Component was read as protection by exactly the rules that would otherwise fire — the semgrep layer is structurally blind to it, which is why the check is its own AST pass rather than another sanitizer exclusion. #1066's no-op-sanitizer lesson through a different mechanism: there the sanitizer was locally defined and fake, here it is a genuine library running where it cannot work. The sanitize-html form in the same fixture is the negative and stays silent.",
  },
  {
    id: "P-OWASP-REACT-RSC-SSRF",
    kind: "positive",
    cls: "Route param interpolated into a server-side fetch URL inside a Server Component page",
    location: "src/owasp-react/rsc-fetch-unvalidated.tsx",
    match: ["ssrf"],
    expectedTier: "review",
    expectedSeverity: "Medium",
    note: "Sheet, SSR Security: 'Validate User Input Before Server-Side Fetch Calls'. A FACET GAP, not a class gap, and that is what made it worth chasing: Harvey already caught this class — P-SSRF-APPROUTER scores App Router searchParams reaching a cross-file fetch wrapper — but every rule was anchored on request ACCESSORS (`req.query`, `searchParams.get`), and the sheet's own example is an async Server Component page taking `{ params }` as a destructured prop. CLOSED by #1240, which fixed it where it actually lived: the canonical `x-request-source` block (base/injection/headers .yml), so ALL 21 server-side taint rules gained the shape, not just SSRF. MEASURED 2026-07-27, caught at review tier. ProductPageValidated in the same fixture stays silent — #1240 also gave harvey-ssrf-fetch a validator-guard sanitizer, since without it the rule fired on the remedy the sheet recommends.",
  },
  {
    id: "P-OWASP-REACT-URL-SECRET",
    kind: "positive",
    cls: "Password-reset token placed in a client-side navigation URL",
    location: "src/owasp-react/sensitive-data-in-url.tsx",
    match: ["secret-in-url-param"],
    expectedTier: "review",
    expectedSeverity: "Medium",
    note: "Sheet, Sensitive Data Exposure: 'Keep Sensitive Data Out of URLs'. `navigate(`/reset?token=${passwordResetToken}`)` writes the token to browser history, to the Referer header of every subsequent third-party request, and to any proxy or analytics log on the path. CLOSED by #1237, and NOT with a new rule: harvey-secret-in-url-param already scored this class and was simply anchored on OUTBOUND HTTP sinks (fetch/axios), so #1237 added the client-side navigation sinks to it — the second facet gap of the same shape as #1240's, found in the same corpus. MEASURED 2026-07-27, caught at review tier, which is where this honestly belongs: deciding a query-parameter NAME carries a secret is a naming heuristic. The allowlist stays narrow and deliberately omits `session` and `code` — a conference `?session=` and an OAuth `?code=` are routine. The useResetRedirectSafe form in the same fixture stays silent.",
  },
  {
    id: "P-OWASP-REACT-PROP-OVERSHARE",
    kind: "positive",
    cls: "Whole account object passed as a prop to a component that needs two fields of it",
    location: "src/owasp-react/oversharing-props.tsx",
    match: ["sensitive fields in props"],
    expectedTier: "none",
    gapKind: "measured-gap",
    note: "Sheet, Sensitive Data Exposure: 'Minimize Sensitive Data in Component State and Props'. The SSN and session token reach React's Fiber tree, which session-recording scripts and browser extensions read, even though neither is rendered. MEASURED 2026-07-27: zero findings. RECORDED, NOT FILED, and the weakest candidate in this corpus: scoring it needs to know which fields of an app's own types are sensitive, which is a per-app judgment rather than a syntactic shape — a plausible LLM/semantic-tier question and a poor mechanical rule. Kept here so the recommendation is accounted for either way, rather than dropped for being hard.",
  },

  // ---------------------------------------------------------------------------------------------
  // NEGATIVES — the sheet's correct forms. Must stay silent.
  // ---------------------------------------------------------------------------------------------
  {
    id: "N-OWASP-REACT-PROP-ALLOWLIST",
    kind: "negative",
    cls: "Untrusted props filtered against an allowlist before the spread",
    location: "src/owasp-react/prop-spread-allowlisted.tsx",
    note: "ProfileFormAllowlisted filters the parsed object through ALLOWED_PROPS before spreading — the sheet's own remedy, and the form harvey-jsx-prop-spread-injection has to clear to be shippable at all. #1237 moved it out of the positive's file: while it shared that location the positive's own finding satisfied this row's relevance and it could only score 'review-tier hit, triaged out', which reads as though the safe form was flagged. Confirmed FULLY silent 2026-07-27 against the shipped rule. Its companion guard is the no-op-filter probe recorded in the rule's own header: `Object.entries(x).filter(() => true)` must still FIRE, or the sanitizer is #1066 again.",
  },
  {
    id: "P-OWASP-REACT-PROP-LITERAL-RESPREAD",
    kind: "positive",
    cls: "Untrusted object spread back into an object literal before the JSX spread",
    location: "src/owasp-react/prop-spread-literal-respread.tsx",
    match: ["prop-spread-injection"],
    expectedTier: "review",
    expectedSeverity: "High",
    note: "#1237/#1344: the ADVERSARIAL half of the literal-pick exclusion. `{...{ placeholder: \"Name\", ...raw }}` is an object literal, so the structural exclusion added for prop-spread-literal-pick.tsx would clear it — except the literal spreads the untrusted object straight back in, so every name in `raw`, dangerouslySetInnerHTML included, still reaches the component. Planted so the exclusion is falsifiable in the one way it is spoofable, rather than trusted because it sounds structural (#989/#1066). MEASURED 2026-07-27: fires with the exclusion in place.",
  },
  {
    id: "N-OWASP-REACT-PROP-LITERAL-PICK",
    kind: "negative",
    cls: "JSX spread of an object literal whose prop names are source literals",
    location: "src/owasp-react/prop-spread-literal-pick.tsx",
    note: "#1237/#1344: harvey-jsx-prop-spread-injection fired High on `{...{ placeholder: raw.placeholder, disabled: raw.disabled }}` — MEASURED 2026-07-27. The rule's own message says the weakness is that \"the caller chooses which props the component receives\"; here the prop NAMES are literals in the source, so no name can be injected and the sink does not exist (a tainted value reaching `placeholder` is a different question and not XSS). The existing negative prop-spread-allowlisted.tsx could not catch this: it uses the single `Object.fromEntries(...filter(...includes))` spelling the rule lists as a sanitizer, so \"the planted negative stays silent\" was satisfiable by matching one literal spelling — the #1191 lesson one level up. NOT fixed by a widened sanitizer, which would have traded precision for silently-cleared bugs; fixed structurally, with P-OWASP-REACT-PROP-LITERAL-RESPREAD as the adversarial control. The loop-copy allowlist spelling (`for (const k of ALLOWED) safe[k] = raw[k]`) was the residual left open here; it is CLOSED by the #1237(a) rows below, again with adversarial positives rather than a bare widening.",
  },
  // #1237(a) — the residual the literal-pick fix left open: the OWASP sheet's remedy written
  // IMPERATIVELY. MEASURED 2026-07-31, `for (const k of ALLOWED_PROPS) if (k in raw) safe[k] =
  // raw[k]` fired at High, so the rule was reporting a correct fix. Cleared by a sanitizer arm whose
  // whole guard is that $ALLOW must be a bare identifier — the key must come from somewhere other
  // than the untrusted object. The two positives below are the shapes that spoof a looser version of
  // that arm; drop the identifier constraint and both go silent, which is the #989/#1066 trade.
  {
    id: "N-OWASP-REACT-PROP-LOOP-ALLOWLIST",
    kind: "negative",
    cls: "Untrusted props copied key-by-key from a named allowlist before the spread",
    location: "src/owasp-react/prop-spread-loop-allowlist.tsx",
    note: "#1237(a): `for (const k of ALLOWED_PROPS) if (k in raw) safe[k] = raw[k]` — the same remedy prop-spread-allowlisted.tsx expresses functionally. MEASURED 2026-07-31 before the fix: harvey-jsx-prop-spread-injection fired High here, so the rule flagged a correct fix, and the existing negative could not catch that because it matched the ONE spelling the sanitizer list named (the #1191 lesson, one level up, for the second time in this rule). Its adversarial siblings are prop-spread-loop-own-keys.tsx and prop-spread-loop-tainted-list.tsx — one file each, so no row can satisfy another's relevance check.",
  },
  {
    id: "P-OWASP-REACT-PROP-LOOP-OWN-KEYS",
    kind: "positive",
    cls: "Key-by-key copy iterating the untrusted object's OWN keys, then spread",
    location: "src/owasp-react/prop-spread-loop-own-keys.tsx",
    match: ["prop-spread-injection"],
    expectedTier: "review",
    expectedSeverity: "High",
    note: "#1237(a) adversarial control: `for (const k of Object.keys(raw)) safe[k] = raw[k]` is a for-of copy that looks exactly like the negative above, and every prop name is still the caller's choice — dangerouslySetInnerHTML reaches the component. It must keep firing, which is what makes the sanitizer's identifier constraint falsifiable rather than merely plausible. MEASURED 2026-07-31: fires with the arm in place, goes silent without the constraint.",
  },
  {
    id: "P-OWASP-REACT-PROP-LOOP-ATTACKER-ALLOWLIST",
    kind: "positive",
    cls: "Key-by-key copy whose allowlist comes out of the untrusted object",
    location: "src/owasp-react/prop-spread-loop-tainted-list.tsx",
    match: ["prop-spread-injection"],
    expectedTier: "review",
    expectedSeverity: "High",
    note: "#1237(a) adversarial control: `for (const k of raw.fields) safe[k] = raw[k]` — structurally identical to the safe form apart from where the key list originates, which is exactly the difference the sanitizer has to read. MEASURED 2026-07-31: a first attempt that excluded only `Object.keys(...)` cleared this one silently; constraining $ALLOW to a bare identifier is what brings it back. Its own bound is stated in the rule message and measured: the same allowlist laundered through a local const (`const allowed = raw.fields; for (const k of allowed) ...`) is NOT reported — the one-hop indirection the .has/.includes arm has always had.",
  },
  {
    id: "N-RSC-PARAM-PLAIN-PARAMETER",
    kind: "negative",
    cls: "A plain function parameter named `params` / `searchParams` in server-internal code",
    location: "src/lib/job-runner.ts",
    reviewTierHits: ["src.scan.rules.semgrep.harvey-lib-command-injection", "src.scan.rules.semgrep.harvey-lib-path-traversal"],
    note: "#1344: the FP twin of P-OWASP-REACT-RSC-SSRF, and the row that makes #1240's source falsifiable. That source matches `params.<field>` by NAME because semgrep OSS cannot match the destructured object parameter an RSC page really receives; its only guard excluded a name bound by ASSIGNMENT, and a function parameter is never assigned. MEASURED 2026-07-27 on this file against its own twin with the parameter renamed to `opts`: 6 findings vs 3 — a name-dependent delta of 3 on a scheduler job runner with no request anywhere near it, including `harvey-command-injection` at Critical / precisionTier \"high\", which is GRADED and therefore drops a repo's free-tier letter. The two recorded review-tier rows are the pre-existing `harvey-lib-*` family, which flags exported-function parameters as library entry points BY DESIGN (see NARROW_BY_DESIGN in shared-sources.test.ts) — they fire identically on the renamed twin, so they are name-INdependent and are not this defect. Fixed by excluding a plain-identifier parameter binding; the discriminator is sound precisely because the real RSC shape is destructured and therefore unmatchable. This row fails if that exclusion is ever widened away, and P-OWASP-REACT-RSC-SSRF fails if it is widened too far.",
  },
  {
    id: "N-OWASP-REACT-SHAPED-BOUNDARY",
    kind: "negative",
    cls: "Server Component passes only the two fields the Client Component renders",
    module: "M9",
    location: "src/owasp-react/rsc-boundary-shaped.tsx",
    note: "UserProfileShaped passes name and avatarUrl individually instead of the row — the same query and the same Client Component, so the ONLY difference is the projection. #1238 moved it out of the positive's file: while the positive produced nothing this row could not fail, and once the positive fires a negative sharing its location is satisfied by the positive's own finding and can only be scored trivially. Confirmed silent 2026-07-27 against the widened row-read shape, which is exactly what it now guards.",
  },
];
