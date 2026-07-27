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
    match: ["prop injection"],
    expectedTier: "none",
    gapKind: "measured-gap",
    note: "Sheet, XSS Prevention: 'Avoid Prop Injection via the Spread Operator'. `<Field {...userInput} />` where userInput is parsed from a query parameter lets the attacker supply dangerouslySetInnerHTML itself — an XSS sink reached without the source ever naming one, which is why every dangerouslySetInnerHTML rule we have stays dark. MEASURED 2026-07-27: zero findings. Mechanically tractable and high-precision: a JSX spread whose operand traces to a request source, with the allowlist-filtered form (also in this fixture, and which must stay silent) as the negative. Tracked in #1237.",
  },
  {
    id: "P-OWASP-REACT-RSC-BOUNDARY",
    kind: "positive",
    cls: "Server Component passes a whole database row as a prop to a Client Component",
    location: "src/owasp-react/rsc-boundary-full-object.tsx",
    match: ["server/client boundary"],
    expectedTier: "none",
    gapKind: "measured-gap",
    note: "Sheet, SSR Security: 'Shape Data Explicitly at the Server/Client Boundary' — the sheet calls this the most critical architectural concern in SSR. Every prop crossing into a Client Component is serialized into the RSC flight payload the browser receives, so `<ClientProfile user={user} />` ships the row's passwordHash and billing identifiers over the wire whether or not anything renders them. MEASURED 2026-07-27: zero findings. Adjacent but NOT the same as the #1057 projection guards or SEC-PG-RESJSON excessive-data-exposure, which score what a route RETURNS as JSON; nothing scores the server-to-client component boundary. Tracked in #1238.",
  },
  {
    id: "P-OWASP-REACT-SSR-SANITIZER",
    kind: "positive",
    cls: "Browser-only sanitizer (DOMPurify) called in a server-rendered component",
    location: "src/owasp-react/ssr-browser-sanitizer.tsx",
    match: ["browser-only sanitizer"],
    expectedTier: "none",
    gapKind: "measured-gap",
    note: "Sheet, SSR Security: 'Use a Server-Compatible Sanitization Library for SSR HTML' — DOMPurify needs a browser DOM and cannot sanitize in Node. MEASURED 2026-07-27: zero findings, and the reason matters — every dangerouslySetInnerHTML rule EXCLUDES an import-bound sanitize() wrap (N-XSS-IMPORT-SANITIZE pins that exclusion deliberately), so a DOMPurify call in a Server Component is read as protection by exactly the rules that would otherwise fire. This is the #1066 no-op-sanitizer lesson recurring through a different mechanism: there the sanitizer was locally defined and fake, here it is a genuine library running where it cannot work. The sanitize-html form in the same fixture is the negative. Tracked in #1239.",
  },
  {
    id: "P-OWASP-REACT-RSC-SSRF",
    kind: "positive",
    cls: "Route param interpolated into a server-side fetch URL inside a Server Component page",
    location: "src/owasp-react/rsc-fetch-unvalidated.tsx",
    match: ["ssrf"],
    expectedTier: "none",
    gapKind: "measured-gap",
    note: "Sheet, SSR Security: 'Validate User Input Before Server-Side Fetch Calls'. A FACET GAP, not a class gap, and that is the interesting part: Harvey does catch this class — P-SSRF-APPROUTER scores App Router searchParams reaching a cross-file fetch wrapper — but the detector is anchored on the route-handler shape, and the sheet's own example (and this fixture) is an async Server Component page taking `{ params }`. MEASURED 2026-07-27: zero findings. A coverage claim of 'we detect SSRF' would have been true and still missed this, which is the kind of thing only a third-party answer key surfaces. Tracked in #1240.",
  },
  {
    id: "P-OWASP-REACT-URL-SECRET",
    kind: "positive",
    cls: "Password-reset token placed in a client-side navigation URL",
    location: "src/owasp-react/sensitive-data-in-url.tsx",
    match: ["token in the query string"],
    expectedTier: "none",
    gapKind: "measured-gap",
    note: "Sheet, Sensitive Data Exposure: 'Keep Sensitive Data Out of URLs'. `navigate(`/reset?token=${passwordResetToken}`)` writes the token to browser history, to the Referer header of every subsequent third-party request, and to any proxy or analytics log on the path. MEASURED 2026-07-27: zero findings. Weaker mechanically than the four above — deciding a query-parameter name carries a secret is a naming heuristic, so a narrow allowlist of names (token/secret/password/otp/session) is probably the only shippable form, and this may honestly belong at review tier. Tracked in #1237 alongside the prop-spread rule.",
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
    location: "src/owasp-react/prop-spread-injection.tsx",
    note: "ProfileFormAllowlisted filters the parsed object through ALLOWED_PROPS before spreading — the sheet's own remedy, and the form a future prop-spread rule must clear to be shippable. Confirmed silent 2026-07-27: the whole fixture produces zero findings today, so this is a forward guard rather than a passed test, and it is the row that will fail if #1237's rule ships flagging every spread.",
  },
  {
    id: "N-OWASP-REACT-SHAPED-BOUNDARY",
    kind: "negative",
    cls: "Server Component passes only the two fields the Client Component renders",
    location: "src/owasp-react/rsc-boundary-full-object.tsx",
    note: "UserProfileShaped passes name and avatarUrl individually instead of the row. Confirmed silent 2026-07-27. Same forward-guard status as the row above: it exists so #1238's detector cannot ship by flagging every RSC-to-client prop.",
  },
];
