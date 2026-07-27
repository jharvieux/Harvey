// OWASP Nodejs Security Cheat Sheet as an INDEPENDENT coverage corpus (#1191).
//
// PINNED SOURCE: cheatsheets/Nodejs_Security_Cheat_Sheet.md at OWASP/CheatSheetSeries master as read
// 2026-07-26. Companion to owasp-multitenant.entries.ts (#1190); the rationale for using a
// third-party checklist as an answer key is in that file's header and is not repeated here.
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
// MEASURED 2026-07-26 (`quick-scan --dir targets/calibration`, 472 findings): of the eight
// recommendations planted here, ZERO were detected as the recommendation under test.
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
    expectedTier: "none",
    gapKind: "measured-gap",
    note: "Sheet, Application Security: 'Use hpp middleware to prevent HTTP Parameter Pollution attacks.' Express turns `?role=user&role=admin` into a string[], so `role.includes(\"admin\")` becomes array membership instead of substring containment and the guard changes meaning without changing shape. MEASURED: not detected as parameter pollution. Three OTHER findings fired on this file (see header) — match is scoped so they cannot mask this.",
  },
  {
    id: "P-OWASP-NODE-BODY-LIMIT",
    kind: "positive",
    cls: "Body parser with no size limit plus an unbounded raw-stream handler",
    location: "src/owasp-node/no-request-size-limit.ts",
    match: ["size limit", "body limit", "payload"],
    expectedTier: "none",
    gapKind: "measured-gap",
    note: "Sheet, Application Security: 'Set request size limits via middleware for different content types.' `express.json()` without `limit`, and a raw `req.on(\"data\")` accumulator with no cap — one request can exhaust process memory. MEASURED: zero findings. Tractable mechanically (the missing `limit` option is syntactic), and the raw accumulator without a byte ceiling is a recognisable shape.",
  },
  {
    id: "P-OWASP-NODE-REDOS",
    kind: "positive",
    cls: "Catastrophic-backtracking regex in application source",
    location: "src/owasp-node/redos-regex.ts",
    match: ["redos", "backtrack", "regular expression"],
    expectedTier: "none",
    gapKind: "measured-gap",
    note: "Sheet, Platform Security: 'Test regular expressions for ReDoS vulnerabilities.' `/^([a-zA-Z0-9]+)+@example\\.com$/` is a nested quantifier over an overlapping class; a long non-matching input pins the event loop. MEASURED: zero findings. Note the distinction — Harvey DOES catch ReDoS as a DEPENDENCY CVE (P-WS-REDOS-CVE in the deps batch), so a reader could mistake that for source-level ReDoS coverage. It is not the same check, and nothing covers the source-level one.",
  },
  {
    id: "P-OWASP-NODE-VM-SANDBOX",
    kind: "positive",
    cls: "vm.runInNewContext used as a security boundary, with require/process handed in",
    location: "src/owasp-node/vm-no-sandbox.ts",
    match: ["vm", "sandbox", "runInNewContext"],
    expectedTier: "none",
    gapKind: "measured-gap",
    note: "Sheet, Platform Security: 'Use vm module only within secure sandboxes.' Node's own documentation is explicit that `vm` is not a security mechanism; this fixture also passes `require` and `process` into the context, so the guest reaches the host realm directly. MEASURED: zero findings. Should be a cheap, high-precision rule — `vm.runInNewContext`/`runInThisContext` on a non-literal argument has few benign forms.",
  },
  {
    id: "P-OWASP-NODE-EMITTER-ERROR",
    kind: "positive",
    cls: "EventEmitter emits 'error' with no error listener registered",
    location: "src/owasp-node/unhandled-rejection.ts",
    match: ["EventEmitter", "error event", "uncaughtException"],
    expectedTier: "none",
    gapKind: "measured-gap",
    note: "Sheet, Error & Exception Handling: 'Always listen to error events when using EventEmitter objects' and 'Bind to uncaughtException event and clean up resources before exit.' An emitted 'error' with no listener terminates the process — a remote crash if the emit is reachable from a request. MEASURED: zero findings. Weaker candidate than the others: proving no listener exists anywhere needs cross-file reasoning, so this may honestly belong at review tier.",
  },
  {
    id: "P-OWASP-NODE-POWERED-BY",
    kind: "positive",
    cls: "Express app with neither helmet nor x-powered-by disabled",
    location: "src/owasp-node/x-powered-by-exposed.ts",
    match: ["x-powered-by", "helmet"],
    expectedTier: "none",
    gapKind: "measured-gap",
    note: "Sheet, Server Security: 'Remove or obfuscate X-Powered-By header' and 'Use helmet middleware to set appropriate security headers.' MEASURED: zero findings. WORTH A SCOPE DECISION RATHER THAN A DETECTOR: b5-headers already covers the headers that matter (HSTS, X-Frame-Options, nosniff, CSP) by their effect, and 'helmet is not imported' is a library-adoption check, not a defect — an app setting the same headers by hand is correct and would be a false positive. Version disclosure is Info at best. Recommend recording this as a deliberate, DISCLOSED scope boundary and re-tiering to gapKind 'by-design'; filed so that call is made explicitly rather than by silence.",
  },
  {
    id: "P-OWASP-NODE-SENSITIVE-CACHE",
    kind: "positive",
    cls: "Authenticated response marked publicly cacheable",
    location: "src/owasp-node/sensitive-response-cached.ts",
    match: ["Cache-Control", "cacheable", "caching"],
    expectedTier: "none",
    gapKind: "measured-gap",
    note: "Sheet, Server Security: 'Disable caching for pages containing sensitive information.' `Cache-Control: public, max-age=600` on a per-user record lets a shared proxy or CDN serve one user's data to the next requester. MEASURED: not detected as a caching defect — SEC-PG-RESJSON fired on the same file for excessive data exposure, which is correct but a different finding, hence the scoped match. Mechanically tractable: `public` or a positive max-age set on a handler that reads an identity header or session.",
  },
  {
    id: "P-OWASP-NODE-BLOCKING-LOOP",
    kind: "positive",
    cls: "Synchronous CPU-bound and filesystem calls in a request path",
    location: "src/owasp-node/blocking-event-loop.ts",
    match: ["event loop"],
    expectedTier: "none",
    gapKind: "measured-gap",
    note: "Sheet, Application Security: 'Avoid blocking the event loop with CPU-intensive operations.' `pbkdf2Sync` at 600k iterations and a `readFileSync` in a request path serialise every concurrent request behind them — a single-request denial of service. MEASURED: not detected as blocking — harvey-lib-path-traversal fired on the same file for the unvalidated template name, correctly and for a different reason, hence the scoped match. This one overlaps M7 (performance) more than M1; whichever module owns it, today neither does.",
  },
];
