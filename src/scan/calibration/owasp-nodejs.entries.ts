// OWASP Nodejs Security Cheat Sheet as an INDEPENDENT coverage corpus (#1191).
//
// PINNED SOURCE: cheatsheets/Nodejs_Security_Cheat_Sheet.md at OWASP/CheatSheetSeries commit
// da089462b18d27ed893ca1052ebd740cfe460175 ("Updated outdated contents", #2170) — the revision that
// was current on master when this corpus was built and measured on 2026-07-26, resolved and recorded
// 2026-07-27. It was originally written down as "master as read 2026-07-26", which is not a pin at
// all: master moves, and an answer key that can change underneath us without the diff showing is the
// exact property this corpus exists to avoid. Re-pin deliberately, never track HEAD.
// Companion to owasp-multitenant.entries.ts (#1190); the rationale for using a third-party checklist
// as an answer key is in that file's header and is not repeated here.
//
// ALREADY COVERED — accounted for, deliberately NOT re-planted. A large part of this sheet is already
// in the corpus under batches that predate it, and duplicating those rows would inflate an apparent
// coverage number without testing anything new. Cross-referenced rather than copied:
//   Server Security headers/cookies -> b5-headers.entries.ts (HSTS, X-Frame-Options,
//     X-Content-Type-Options, CSP with unsafe-inline, res.cookie HttpOnly/Secure/SameSite, session
//     cookie flags, CORS reflect-with-credentials, anti-CSRF on cookie-authed mutations, stack trace
//     echoed to client).
//   Platform Security "avoid eval()/child_process.exec()", "sanitize input to fs" -> b3-injection
//     (code injection via eval, OS command injection, argument injection CWE-88, path traversal,
//     zip-slip, prototype pollution via recursive merge, unsafe deserialization, XXE, SSTI).
//   "Keep packages up to date" / "run npm audit" -> b2-deps + b10-deps (OSV/CVE tier).
//   "Return only necessary fields from database queries" -> the #1057 projection guards.
// That is the honest good-news half of this measurement and it is why this file is short: what is
// left below is the residue the sheet asks for and Harvey does not do.
//
// THE HEADER/COOKIE GROUP, decided explicitly (#1191 asked for this, because "we don't check that"
// and "we deliberately don't check that" look identical from the outside and only one is acceptable):
//   DETECTED, by effect rather than by library — HSTS, X-Frame-Options, X-Content-Type-Options, CSP
//     with unsafe-inline, cookie HttpOnly/Secure/SameSite, session cookie flags. All in b5-headers
//     above. Checking the header an app actually sets is the right test; an app that sets them by
//     hand instead of through helmet is correct and must not be flagged.
//   RULED ON 2026-07-27 (#1204), and the two halves of that sheet line went OPPOSITE ways, which is
//     why they are now two entries rather than one. "Remove or obfuscate X-Powered-By" is DETECTED
//     (P-OWASP-NODE-POWERED-BY, review tier, src/scan/express-powered-by.ts) — it is a real, if
//     small, version disclosure, and the two things a static pass cannot see (a disable applied in
//     another module, a strip at a reverse proxy/CDN/ingress) are stated IN the emitted finding
//     rather than in a comment nobody downstream reads. "Use helmet middleware" is DECLINED
//     (P-OWASP-NODE-HELMET, gapKind "by-design") — an app that sets the same headers by hand is
//     correct, so flagging the missing import would be a false positive on working code, and the
//     headers themselves are already checked by effect in b5-headers. The decline is a recorded
//     decisional reason in src/scan/express-powered-by.ts; the detected half carries no gapKind at
//     all, because it is no longer a gap of any kind.
//
// MEASURED 2026-07-26 (`quick-scan --dir targets/calibration`, 472 findings): of the eight
// recommendations planted here, ZERO were detected as the recommendation under test.
//
// Six of the eight gaps closed across three follow-up batches (issues #1200/#1201/#1202/#1203,
// re-measured via `pnpm exec tsx src/cli/validate-calibration.ts` after each rule landed):
// VM-SANDBOX, BODY-LIMIT, SENSITIVE-CACHE (new harvey-*.yml rules, src/scan/rules/semgrep/
// owasp-node.yml), HPP and REDOS (same file), and EMITTER-ERROR (src/scan/emitter-error.ts, a
// same-file-only TS/AST heuristic — see its own note below for the disclosed limitation).
// BLOCKING-LOOP is closed too, but scored differently: it is an M7 (performance) class, produced
// by detectSyncIoInHandler (src/detectors/perf-code.ts), so it is tagged `module: "M7"` below and
// excluded from THIS gate's M1 mechanical scoring — see its own note and
// calibration.test.ts's "#1203 M7 blocking-loop" block for how it's actually proven caught.
// POWERED-BY was untouched by that round (out of scope for #1200-#1203) and is now closed by #1204,
// which split it: the X-Powered-By half is caught at review tier (re-measured after the rule landed,
// `quick-scan --dir targets/calibration`, 2026-07-27), the helmet half is a declined boundary. That
// makes all eight of the original recommendations accounted for — seven detected, one by design.
//
// THREE OF THE EIGHT FIXTURES DID PRODUCE FINDINGS — FOR DIFFERENT DEFECTS. This is the single most
// important thing in this file, and it is why every entry below carries a scoped `match`:
//   hpp-param-pollution.ts       -> harvey-client-trusted-role + two XSS rules (the `role.includes`
//                                   check and the interpolated res.send), never parameter pollution.
//   blocking-event-loop.ts       -> harvey-lib-path-traversal (the unvalidated template name),
//                                   never the synchronous-call-in-request-path concern.
//   sensitive-response-cached.ts -> SEC-PG-RESJSON excessive data exposure (the ssn field), never
//                                   the publicly-cacheable authenticated response.
// All three findings are CORRECT — realistic code carries several defects at once. But with an
// unscoped match each would have satisfied the relevance check and the gap would have recorded as
// COVERED. That is the #1062 masking shape — one probe's finding standing in for another's — reached
// through a corpus rather than a producer seam, and the corpus only avoids it because the matches were
// narrowed deliberately. A future batch that omits `match` will silently re-open it.
//
// A FOOTGUN THE GATE CAUGHT WHILE THIS FILE WAS BEING WRITTEN, worth stating for the next batch:
// `match` is tested against a finding's id/title/taxonomy/EVIDENCE, and evidence QUOTES THE SOURCE
// LINE, while the id is derived from the FILE PATH. So a keyword resembling source text or the fixture
// filename self-matches: "req.query.role" matched the quoted line in an XSS finding, and "Sync("
// matched `readFileSync(` in a path-traversal finding, turning two recorded gaps into GATE FAILs.
// Choose match phrases from the TAXONOMY vocabulary a future detector would use, with spaces where the
// filename has hyphens ("event loop" cannot match "blocking-event-loop"), and never from the fixture
// body. The gate failing loud here is the mechanism working — it refused to record a masked gap.
//
// OUT-OF-UNIVERSE (recorded, not dropped — no static source signal, or not a security property):
// "use flat promise chains instead of nested callbacks", "run SAST tools like ESLint", "enable strict
// mode", "follow security-by-design principles", "use CAPTCHA", "implement activity logging with
// Winston/Bunyan/Pino", "enable the Node permission model with --permission", "implement ACLs with
// the acl module", "use Object.defineProperty to set restrictive descriptors", "pass Error objects as
// the first callback argument", "monitor event loop performance with toobusy-js". Eleven items:
// library-adoption advice, tooling advice, and style guidance rather than detectable defects.

import type { CorpusEntry } from "./types.js";

export const owaspNodejsEntries: CorpusEntry[] = [
  {
    id: "P-OWASP-NODE-HPP",
    kind: "positive",
    cls: "Repeated query parameter parsed as an array where the code assumes a string",
    location: "src/owasp-node/hpp-param-pollution.ts",
    match: ["parameter pollution"],
    expectedTier: "review",
    note: "Sheet, Application Security: 'Use hpp middleware to prevent HTTP Parameter Pollution attacks.' Express turns `?role=user&role=admin` into a string[], so `role.includes(\"admin\")` becomes array membership instead of substring containment and the guard changes meaning without changing shape. Was MEASURED not detected as parameter pollution (2026-07-26); harvey-hpp-query-cast (src/scan/rules/semgrep/owasp-node.yml, #1202) now catches the `req.query.$P as string` cast reaching `.includes`/`.indexOf`, re-measured caught at review tier. Three OTHER findings still fire on this file too (see header) — match stays scoped so they cannot mask this one.",
  },
  {
    id: "N-OWASP-NODE-HPP-ARRAY-NORMALIZED",
    kind: "negative",
    cls: "Repeated-parameter array normalized (first element taken) before use",
    location: "src/owasp-node/hpp-param-normalized.ts",
    match: ["parameter pollution", "hpp-query-cast", "query.<param>"],
    note: "#1202 negative: `Array.isArray(v) ? v[0] : v` never takes the `as string` cast shape harvey-hpp-query-cast matches, so it stays silent.",
  },
  {
    id: "N-OWASP-NODE-HPP-SCHEMA-VALIDATED",
    kind: "negative",
    cls: "Repeated-parameter value validated by a schema parse instead of a raw cast",
    location: "src/owasp-node/hpp-param-normalized.ts",
    match: ["parameter pollution", "hpp-query-cast", "query.<param>"],
    note: "#1202 negative: `z.string().parse(req.query.role)` never takes the `as string` cast shape either — same file as the array-normalized negative, distinct function.",
  },
  {
    id: "P-OWASP-NODE-BODY-LIMIT",
    kind: "positive",
    cls: "Body parser with no size limit plus an unbounded raw-stream handler",
    location: "src/owasp-node/no-request-size-limit.ts",
    match: ["size limit", "body limit", "payload"],
    expectedTier: "review",
    note: "Sheet, Application Security: 'Set request size limits via middleware for different content types.' `express.json()` without `limit`, and a raw `req.on(\"data\")` accumulator with no cap — one request can exhaust process memory. Was MEASURED zero findings (2026-07-26); harvey-body-parser-no-limit (src/scan/rules/semgrep/owasp-node.yml, #1200) now catches the missing-`limit` shape, re-measured caught at review tier. DISCLOSED remaining scope: the raw `req.on(\"data\")` accumulator half is not separately covered (see the rule file's note) — this row is satisfied by the body-parser half alone, one relevant finding being enough.",
  },
  {
    id: "N-OWASP-NODE-BODY-LIMIT-SET",
    kind: "negative",
    cls: "Body parser with an explicit size limit set",
    location: "src/owasp-node/request-size-limit-set.ts",
    match: ["size limit", "body limit", "payload"],
    note: "#1200 negative: `express.json({ limit: \"100kb\" })` clears the missing-limit rule.",
  },
  {
    id: "P-OWASP-NODE-REDOS",
    kind: "positive",
    cls: "Catastrophic-backtracking regex in application source",
    location: "src/owasp-node/redos-regex.ts",
    match: ["redos", "backtrack", "regular expression"],
    expectedTier: "review",
    note: "Sheet, Platform Security: 'Test regular expressions for ReDoS vulnerabilities.' `/^([a-zA-Z0-9]+)+@example\\.com$/` is a nested quantifier over an overlapping class; a long non-matching input pins the event loop. Was MEASURED zero findings (2026-07-26); harvey-redos-literal (src/scan/rules/semgrep/owasp-node.yml, #1201) now catches a bare regex LITERAL with a nested quantifier (harvey-redos already caught the same shape inside `new RegExp(\"...\")` — a different AST node, hence the separate rule), re-measured caught at review tier on both regexes in this fixture. DISCLOSED limitation (Option 1 from the issue): this is a textual/structural nested-quantifier match, not a backtracking-complexity analyser — it will miss a dangerous regex assembled dynamically (e.g. built from a variable) or one whose catastrophic shape doesn't reduce to a literal `(...)...[+*]` motif. Note the distinction from the DEPENDENCY-CVE ReDoS check — Harvey ALSO catches ReDoS as a known-vulnerable package version (P-WS-REDOS-CVE in the deps batch); that is a different check from this source-level one, and a reader should not mistake one for coverage of the other.",
  },
  {
    id: "N-OWASP-NODE-REDOS-SAFE",
    kind: "negative",
    cls: "Linear-time regexes: a single quantified group with no nested quantifier, and an ordinary anchored regex with no groups",
    location: "src/owasp-node/redos-regex-safe.ts",
    match: ["redos", "backtrack", "regular expression"],
    note: "#1201 negative: `/^(ab)+$/` (one quantifier, no NESTED quantifier inside the group) and `/^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$/` (quantifiers, no groups at all) both clear harvey-redos-literal.",
  },
  {
    id: "P-OWASP-NODE-VM-SANDBOX",
    kind: "positive",
    cls: "vm.runInNewContext used as a security boundary, with require/process handed in",
    location: "src/owasp-node/vm-no-sandbox.ts",
    match: ["vm", "sandbox", "runInNewContext"],
    expectedTier: "high",
    note: "Sheet, Platform Security: 'Use vm module only within secure sandboxes.' Node's own documentation is explicit that `vm` is not a security mechanism; this fixture also passes `require` and `process` into the context, so the guest reaches the host realm directly. Was MEASURED zero findings (2026-07-26); harvey-vm-unsafe-sandbox (src/scan/rules/semgrep/owasp-node.yml, #1200) now catches `vm.runInNewContext`/`runInThisContext` on a non-literal first argument, re-measured caught at high (free-count) tier — the cheap, high-precision rule the issue predicted.",
  },
  {
    id: "N-OWASP-NODE-VM-LITERAL-SAFE",
    kind: "negative",
    cls: "vm.runInNewContext called with a fixed literal script",
    location: "src/owasp-node/vm-literal-safe.ts",
    match: ["vm", "sandbox", "runInNewContext"],
    note: "#1200 negative: the script text is a hardcoded literal, not a dynamic expression, so it clears the non-literal-argument rule.",
  },
  {
    id: "P-OWASP-NODE-EMITTER-ERROR",
    kind: "positive",
    cls: "EventEmitter emits 'error' with no error listener registered",
    location: "src/owasp-node/unhandled-rejection.ts",
    match: ["no registered listener"],
    expectedTier: "review",
    note: "Sheet, Error & Exception Handling: 'Always listen to error events when using EventEmitter objects' and 'Bind to uncaughtException event and clean up resources before exit.' An emitted 'error' with no listener terminates the process — a remote crash if the emit is reachable from a request. Was MEASURED zero findings (2026-07-26); src/scan/emitter-error.ts (#1202) now catches an `$E.emit(\"error\", ...)` with no same-file `$E.on(\"error\", ...)`/`.once(\"error\", ...)`, re-measured caught at review tier. DISCLOSED, chosen deliberately over declining: this is SAME-FILE ONLY — proving no listener exists ANYWHERE needs cross-file reasoning (a listener attached by whatever module imports this emitter is invisible to it), which is exactly the weaker-candidate caveat this entry originally recorded; review tier accounts for that blind spot rather than asserting certainty.",
  },
  {
    id: "N-OWASP-NODE-EMITTER-ERROR-HANDLED",
    kind: "negative",
    cls: "EventEmitter emits 'error' with a same-file listener registered",
    location: "src/owasp-node/emitter-error-handled.ts",
    match: ["no registered listener"],
    note: "#1202 negative: same emit shape as the positive, but a same-file `jobs.on(\"error\", ...)` listener clears it.",
  },
  {
    id: "P-OWASP-NODE-POWERED-BY",
    kind: "positive",
    cls: "Express app whose constructing module never disables X-Powered-By",
    location: "src/owasp-node/x-powered-by-exposed.ts",
    // NOT "x-powered-by" — that string is in the fixture's own PATH, so it matches any finding on
    // this file regardless of which rule produced it (the header note's self-match footgun). Nor
    // "helmet", which is the OTHER half of this sheet line and is deliberately not detected.
    match: ["version disclosed"],
    expectedTier: "review",
    note: "Sheet, Server Security: 'Remove or obfuscate X-Powered-By header.' Was MEASURED zero findings (2026-07-26). #1204 ruled DETECT: src/scan/express-powered-by.ts flags an Express app whose constructing module has no `disable(\"x-powered-by\")` / `set(\"x-powered-by\", false)` / `removeHeader` / helmet use, re-measured caught at review tier 2026-07-27. Review tier is the honest tier and the finding says why: a disable in a module this pass did not read, or a strip at a reverse proxy/CDN/ingress, is invisible to it — that bound is in the emitted evidence, not only here. The 'use helmet middleware' half of the same sheet line is a separate entry (P-OWASP-NODE-HELMET) and is declined by design.",
  },
  {
    id: "N-OWASP-NODE-POWERED-BY-DISABLED",
    kind: "negative",
    cls: "Express app that disables X-Powered-By in the same module",
    location: "src/owasp-node/x-powered-by-disabled.ts",
    match: ["version disclosed"],
    note: "#1204 negative: identical app shape to the positive plus `app.disable(\"x-powered-by\")`, which clears the check. Regression guard that the rule keys on the absent disable and not merely on `express()`.",
  },
  {
    id: "P-OWASP-NODE-HELMET",
    kind: "positive",
    cls: "Express app that adopts no header middleware and sets the same headers by hand",
    location: "src/owasp-node/security-headers-by-hand.ts",
    match: ["helmet"],
    expectedTier: "none",
    gapKind: "by-design",
    note: "Sheet, Server Security: 'Use helmet middleware to set appropriate security headers.' DECLINED by the #1204 operator ruling, and by-design rather than a measured gap: 'helmet is not imported' is a library-adoption check, not a defect. This fixture is the case that proves it — it sets HSTS, nosniff and X-Frame-Options by hand and is CORRECT, so a helmet-adoption rule would be a false positive on working code. The headers helmet would have set are checked by their effect instead (b5-headers), which is agnostic to which package set them. The reason block is recorded in src/scan/express-powered-by.ts (KIND: decisional, OWNER: operator, DECISION: #1204). Any rule that ever fires on this fixture fails the gate loud — that is the point of scoring a declined boundary rather than deleting the row.",
  },
  {
    id: "P-OWASP-NODE-SENSITIVE-CACHE",
    kind: "positive",
    cls: "Authenticated response marked publicly cacheable",
    location: "src/owasp-node/sensitive-response-cached.ts",
    match: ["Cache-Control", "cacheable", "caching"],
    expectedTier: "review",
    note: "Sheet, Server Security: 'Disable caching for pages containing sensitive information.' `Cache-Control: public, max-age=600` on a per-user record lets a shared proxy or CDN serve one user's data to the next requester. Was MEASURED not detected as a caching defect (2026-07-26) — SEC-PG-RESJSON fired on the same file for excessive data exposure, which is correct but a different finding, hence the scoped match. harvey-sensitive-response-cached (src/scan/rules/semgrep/owasp-node.yml, #1200) now catches `public`/a positive max-age set on a handler that also reads an identity header/cookie/session in the same function, re-measured caught at review tier.",
  },
  {
    id: "N-OWASP-NODE-SENSITIVE-CACHE-SAFE",
    kind: "negative",
    cls: "Same identity-reading handler shape, but Cache-Control is private/no-store",
    location: "src/owasp-node/sensitive-response-not-cached.ts",
    match: ["Cache-Control", "cacheable", "caching"],
    note: "#1200 negative: `Cache-Control: private, no-store` clears the public/positive-max-age check.",
  },
  {
    id: "P-OWASP-NODE-BLOCKING-LOOP",
    kind: "positive",
    module: "M7",
    cls: "Synchronous CPU-bound and filesystem calls in a request path",
    location: "src/owasp-node/blocking-event-loop.ts",
    match: ["event loop"],
    expectedTier: "review",
    note: "Sheet, Application Security: 'Avoid blocking the event loop with CPU-intensive operations.' `pbkdf2Sync` at 600k iterations and a `readFileSync` in a request path serialise every concurrent request behind them — a single-request denial of service. Was MEASURED not detected as blocking (2026-07-26) — harvey-lib-path-traversal fired on the same file for the unvalidated template name, correctly and for a different reason, hence the scoped match. #1203 filed this against M7 (performance), not M1, per CLAUDE.md's equal-weight doctrine: detectSyncIoInHandler (src/detectors/perf-code.ts) already flagged this shape by file path (App Router route.ts/pages/api); it now ALSO flags a sync call inside an EXPORTED function outside those recognised handler paths (this fixture is neither), tagged Review confidence with the reachability caveat disclosed in-finding. Retagged `module: \"M7\"` because detectSyncIoInHandler is not part of runMechanicalScan, so this entry is excluded from THIS gate's M1 scoring (see mechanicalCorpus) — proven caught instead by calibration.test.ts's dedicated \"#1203 M7 blocking-loop\" block (live detectPerfCodeFindings over this committed fixture) and by the m7-code.entries.ts heuristic-precision corpus (M7CODE-P-SYNC-IO-GENERIC / M7CODE-N-SYNC-IO-BUILD-SCRIPT).",
  },
];
