// #975: CWE (and OWASP Top-10-2021) enrichment for AST-detector findings, keyed on the detector's
// stable `taxonomy` string. The harvey-* semgrep rules carry their own `metadata.cwe` (flowed to
// the finding in src/scan/semgrep.ts); the TS/AST detectors do not, so this registry is where each
// AST detector DECLARES its CWE — centralized by taxonomy rather than scattered across ~15 detector
// files. It is a fixed lookup, not a report-time inference: a taxonomy maps to exactly one CWE, the
// same way the semgrep metadata does.
//
// The product principle it serves is the same as the coverage guard: a CWE-indexed consumer (GitHub
// code scanning, an ASPM platform, a CWE-scored benchmark) must not silently under-credit a real
// detection because it lacks a CWE tag. So EVERY taxonomy a detector emits is accounted for here —
// a security taxonomy gets its CWE, and a non-security one (a quality/perf/coverage signal) is
// recorded as no-clean-CWE WITH A REASON. `owasp-cwe-map.test.ts` enumerates every `taxonomy: "…"`
// literal in the detector source and fails loud on any that is unclassified, so a new detector
// cannot quietly ship without a CWE decision.

import type { Finding } from "./findings.js";

const CWE: Record<string, string> = {
  "200": "CWE-200: Exposure of Sensitive Information to an Unauthorized Actor",
  "248": "CWE-248: Uncaught Exception",
  "250": "CWE-250: Execution with Unnecessary Privileges",
  "269": "CWE-269: Improper Privilege Management",
  "287": "CWE-287: Improper Authentication",
  "307": "CWE-307: Improper Restriction of Excessive Authentication Attempts",
  "345": "CWE-345: Insufficient Verification of Data Authenticity",
  "362": "CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')",
  "367": "CWE-367: Time-of-check Time-of-use (TOCTOU) Race Condition",
  "434": "CWE-434: Unrestricted Upload of File with Dangerous Type",
  "521": "CWE-521: Weak Password Requirements",
  "532": "CWE-532: Insertion of Sensitive Information into Log File",
  "538": "CWE-538: Insertion of Sensitive Information into Externally-Accessible File or Directory",
  "601": "CWE-601: URL Redirection to Untrusted Site ('Open Redirect')",
  "602": "CWE-602: Client-Side Enforcement of Server-Side Security",
  "613": "CWE-613: Insufficient Session Expiration",
  "639": "CWE-639: Authorization Bypass Through User-Controlled Key",
  "640": "CWE-640: Weak Password Recovery Mechanism for Forgotten Password",
  "668": "CWE-668: Exposure of Resource to Wrong Sphere",
  "693": "CWE-693: Protection Mechanism Failure",
  "732": "CWE-732: Incorrect Permission Assignment for Critical Resource",
  "754": "CWE-754: Improper Check for Unusual or Exceptional Conditions",
  "770": "CWE-770: Allocation of Resources Without Limits or Throttling",
  "778": "CWE-778: Insufficient Logging",
  "798": "CWE-798: Use of Hard-coded Credentials",
  "807": "CWE-807: Reliance on Untrusted Inputs in a Security Decision",
  "837": "CWE-837: Improper Enforcement of a Single, Unique Action",
  "862": "CWE-862: Missing Authorization",
  "89": "CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
  "79": "CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
  "918": "CWE-918: Server-Side Request Forgery (SSRF)",
};

const OWASP: Record<string, string> = {
  A01: "A01:2021 - Broken Access Control",
  A03: "A03:2021 - Injection",
  A04: "A04:2021 - Insecure Design",
  A07: "A07:2021 - Identification and Authentication Failures",
  A08: "A08:2021 - Software and Data Integrity Failures",
  A09: "A09:2021 - Security Logging and Monitoring Failures",
  A10: "A10:2021 - Server-Side Request Forgery (SSRF)",
};

// taxonomy string → [CWE short id, OWASP short id | null]. `null` = the CWE is not placed under any
// Top-10-2021 category by OWASP's official mapping (owasp is omitted, never forced to a wrong bucket).
const SECURITY: Record<string, [string, string | null]> = {
  // Object-level / tenant authorization (BOLA) — user-controlled key bypasses the ownership check.
  "Authz decision from client-controlled input": ["639", "A01"],
  "Object-level authorization gap: client-supplied id reaches a read-by-id repo function (pg-idor-repo-fn)": ["639", "A01"],
  "Object-level authorization gap: client-supplied owner id scopes the query": ["639", "A01"],
  // #1267: the cross-file complement of the row above — same weakness (a user-controlled key
  // selects the object), the query one module out. Same 639/A01 for that reason.
  "Object-level authorization gap across a module boundary": ["639", "A01"],
  "Object-level authorization gap: Drizzle query filtered by primary key with no tenant scope": ["639", "A01"],
  "Object-level authorization gap: Prisma query filtered by primary key with no tenant scope": ["639", "A01"],
  "Object-level authorization gap: tenant predicate populated from the request": ["639", "A01"],
  "Tenant GUC set with SET rather than SET LOCAL, leaking across a pooled connection": ["668", "A01"],
  "Cache key without a tenant discriminator (cross-tenant cache poisoning)": ["668", "A01"],
  "Storage object path without a tenant prefix (cross-tenant object read/overwrite)": ["639", "A01"],
  "Service-role query in a background-job path with no tenant predicate": ["639", "A01"],
  "Unscoped service-role UPDATE/DELETE (no WHERE)": ["639", "A01"],
  // #455's mapping is unambiguous: OWASP A10:2021 is literally titled "Server-Side Request Forgery
  // (SSRF)" — same CWE/OWASP pair harvey-ssrf-fetch's own semgrep metadata carries.
  "M1 — SSRF via an uncurated cross-file fetch wrapper": ["918", "A10"],
  // Server trusting client-side security enforcement.
  "Client-side authorization decision": ["602", "A04"],
  "Client-supplied payment amount trusted by server": ["602", "A04"],
  // #135/#1366 — Host / X-Forwarded-Host used to build an absolute link. CWE-807 (Reliance on
  // Untrusted Inputs in a Security Decision) rather than CWE-601 (open redirect): nothing here
  // redirects the CALLER anywhere, the header decides where a password-reset token gets DELIVERED,
  // to a third party who never made the request. A01 rather than A07 for the same reason — the
  // failure is that an attacker-set input governs a security-relevant destination, not that the
  // recovery mechanism itself is weak (CWE-640 would say the latter, and the fixed-origin twin
  // N-HOST-HEADER-FIXED-ORIGIN uses the identical recovery flow and is correct).
  "Host header trusted in URL construction": ["807", "A01"],
  // Missing authorization on a resource/route/channel.
  "Migration table without RLS (static)": ["862", "A01"],
  // #1425 — same outcome as the line above (no authorization on the table), reached by a later
  // migration turning row security off rather than by never turning it on. 862 like its sibling,
  // NOT 269: no privileged role is involved, the policies simply stop being consulted.
  "Migration disables RLS on a public table (static)": ["862", "A01"],
  // #1190: the two privileged-role bypasses of an otherwise-correct policy set. CWE-269 (Improper
  // Privilege Management) rather than 862 — the authorization check EXISTS and is right; the defect
  // is that the role it runs as is exempt from it.
  "Role with BYPASSRLS defeats row-level security (static)": ["269", "A01"],
  "RLS enabled without FORCE — owner bypasses policies (static)": ["269", "A01"],
  rls_disabled_in_public: ["862", "A01"],
  "Middleware matcher excludes /api routes": ["862", "A01"],
  "Unauthenticated debug/admin route": ["862", "A01"],
  "Edge Function verify_jwt disabled": ["862", "A01"],
  "draftMode().enable() reachable with no secret": ["862", "A01"],
  "Realtime channel lacks authorization": ["862", "A01"],
  "Leftover-auth grep": ["862", "A01"],
  // Resource exposed to the wrong sphere (public role / anon / broadcast).
  "Auto-exposed public-schema table": ["668", "A01"],
  "PostgREST schema exposure wider than intended": ["668", "A01"],
  "Realtime publication broadcasts an unprotected table": ["668", "A01"],
  "Public bucket with no policies": ["668", "A01"],
  // #1280 — prod-vs-migration drift. RLS switched off on the deployed table is the same exposure as
  // the auto-exposed row above (every row reachable by anyone holding the anon key), so it carries the
  // same CWE; what differs is only how it was found. The two POLICY rows are access-control
  // configuration whose direction depends on the policy that drifted (a dropped permissive policy
  // closes a table, a dropped restrictive one opens it), so they take the permission-assignment class
  // rather than an exposure class that would assert a direction this pass did not establish.
  "Prod-vs-migration drift — RLS disabled in production": ["668", "A01"],
  "Prod-vs-migration drift — policy missing in production": ["732", "A01"],
  "Prod-vs-migration drift — policy not in migrations": ["732", "A01"],
  // #1182 — the static twins of the row above: the same exposure read from committed migration SQL
  // instead of a live storage.buckets/pg_policies pull, so they carry the same CWE.
  "Public storage bucket declared in migration SQL (static)": ["668", "A01"],
  "storage.objects read policy open to anon (static)": ["668", "A01"],
  // #1183 — a read policy that admits every row of a table M10 classified as personal data. The
  // policy EXISTS and is syntactically fine; what it exposes is the defect, so this is the
  // information-exposure CWE rather than a missing-authorization one.
  "USING(true) read policy on an M10-classified PII table (static)": ["200", "A01"],
  "pg_graphql introspection enabled in production": ["200", "A01"],
  "Sensitive file in public/ directory": ["538", "A01"],
  "Sensitive value logged to console": ["532", "A09"],
  // Hard-coded / mishandled credentials.
  "Committed credential": ["798", "A07"],
  // #934: still a hard-coded credential FACT (same CWE) — the doc/example-context taxonomy only
  // changes the exploitability prior and the grading route, not the weakness class.
  "Committed credential — docs/example context": ["798", "A07"],
  "Supabase service_role key hardcoded as a JWT literal (service-role-literal)": ["798", "A07"],
  "pg_cron job embeds a secret-shaped literal": ["798", "A07"],
  "Edge function secret handling": ["798", "A07"],
  // Authentication configuration weaknesses.
  "Auth config: email confirmation disabled": ["287", "A07"],
  "Email confirmation disabled": ["287", "A07"],
  "Open signup enabled": ["287", "A07"],
  "Auth config: leaked-password protection off": ["521", "A07"],
  "Auth config: long OTP expiry": ["613", "A07"],
  "Auth config: wildcard redirect allowlist": ["601", "A01"],
  "Self-hosted GoTrue email-link poisoning": ["640", "A07"],
  "Self-hosted GoTrue OIDC issuer bypass": ["287", "A07"],
  "Missing rate limit on auth endpoint": ["307", "A07"],
  // #1046: a limiter that resets per serverless instance does not restrict attempts — the same
  // weakness as having none, which is why it shares CWE-307 with the check above.
  "In-memory rate limiter (per-instance, resets on cold start)": ["307", "A07"],
  // Unverified inbound data authenticity.
  "Inbound webhook with no signature verification": ["345", "A08"],
  "Unsigned/unverified webhook handler": ["345", "A08"],
  // Injection.
  "plpgsql dynamic SQL injection (static)": ["89", "A03"],
  "SQL injection": ["89", "A03"],
  // Unrestricted upload.
  "Upload to storage with no size/MIME limit": ["434", "A04"],
  // M9 boundary leaks that ARE security (the rest of M9 is rendering-correctness, no-CWE below).
  "M9 — Server→client data leak": ["200", "A01"],
  "M9 — Missing server-only guard": ["200", "A01"],
  // Generic missing-header protection (semgrep.ts synthetic rows) and CSP/sniff footguns.
  "Missing security headers": ["693", null],
  "missing security headers": ["693", null],
  // #1350 — the Express half of the same class. b5-headers only reads a next.config.js headers()
  // route, so this carries the identical weakness for an app class those rules cannot match.
  "Express app sets no security response headers": ["693", null],
  // Over-privileged database roles / grants — CWE is clean, OWASP does not categorize these.
  "Column-level grant to client role outside RLS model": ["732", null],
  "Default privileges grant future objects to client role": ["732", null],
  // #1212 — GITHUB_TOKEN scope. Same weakness as the two grants above (a critical resource handed
  // more permission than it needs), whether granted explicitly or inherited from a repository
  // default; OWASP does not place CWE-732 under a Top-10-2021 category.
  "GitHub Actions workflow grants write-all token permissions": ["732", null],
  "GitHub Actions workflow declares no token permissions": ["732", null],
  "SECURITY DEFINER granted to anon (static)": ["269", null],
  "pg_cron job calls a SECURITY DEFINER function": ["269", null],
  "pg_cron job runs as a superuser role": ["250", null],
  "Over-broad WebExtension permissions": ["250", null],
  // Race condition — CWE clean, not in a Top-10-2021 category.
  "Non-atomic read-modify-write race condition": ["362", null],
  // #1202: an EventEmitter 'error' emit with no listener crashes the process — a remote DoS if
  // reachable from a request. MEASURED against MITRE's own CWE-248 page (cwe.mitre.org/data/
  // definitions/248.html, 2026-07-27): Memberships lists OWASP Top Ten 2004 A9 and 2025 A10:2025,
  // no 2021 category — clean CWE, OWASP omitted.
  "EventEmitter emits 'error' with no registered listener": ["248", null],
  // #1200: an unbounded request-body accumulator. Same weakness class as the missing
  // `express.json({ limit })` option the semgrep half of this issue already tags CWE-770; OWASP
  // does not place CWE-770 under a Top-10-2021 category.
  "Request body accumulated with no size limit": ["770", null],
  // #1239: a browser-only sanitizer on the server. CWE-79 rather than CWE-693 (Protection Mechanism
  // Failure): the mechanism does not merely fail, it never runs, and what ships is unsanitized HTML
  // rendered into the page — which is CWE-79's definition, and the class the OWASP sheet names.
  "Browser-only sanitizer in a server-rendered component": ["79", "A03"],
  // #1252: a whole object with a sensitive field handed to a component as one prop. CWE-200 rather
  // than CWE-359 (Exposure of Private Personal Information): the fields are not necessarily
  // personal, and what the weakness is about is the value crossing a boundary it did not need to
  // cross. A01 is where OWASP's own mapping places CWE-200.
  "Sensitive fields in props": ["200", "A01"],
  // #1242: an audit trail that cannot be scoped to a tenant is the A09 class — the detective
  // control exists but does not record enough to reconstruct the access. CWE-778 is A09:2021's
  // canonical member, the same basis as "Sensitive value logged to console" → 532/A09 above.
  "Audit log entry without a tenant discriminator": ["778", "A09"],
  // #1230 / D-091 item 12: the signature check is present and wrong, so it is the same weakness
  // class as a missing one — matching the 345/A08 mapping the two webhook rows above already use.
  "Webhook signature decoded with the wrong encoding": ["345", "A08"],
  // #1230 / D-091 items 6, 22, 24, 10 — retry/concurrency integrity. None is placed under a
  // Top-10-2021 category by OWASP's mapping, so owasp is omitted rather than forced.
  "Quota gate consumed across a loop without re-reading": ["367", null],
  "Batch send stamped after dispatch instead of claimed before": ["362", null],
  // #1257 / D-091 item 25: a check-then-act across two round trips with no lock between them, which
  // is CWE-362's definition rather than CWE-367's — TOCTOU (367) is about the state changing between
  // a check and a use of the SAME resource handle, and both concurrent callers here act on a
  // correct read. Same basis as the sibling row above. No OWASP Top-10-2021 category.
  "SELECT-then-INSERT dedup with no unique constraint": ["362", null],
  "External send without a deterministic idempotency key": ["837", null],
  "Idempotency row written before the dispatched handler": ["754", null],
  // #1204: X-Powered-By names the server framework to any caller. MEASURED against MITRE's own
  // CWE-200 page (cwe.mitre.org/data/definitions/200.html, 2026-07-27): Memberships lists "OWASP
  // Top Ten 2021 Category A01:2021 - Broken Access Control".
  "Framework version disclosed via X-Powered-By": ["200", "A01"],
};

// Non-security taxonomies: recorded as no-clean-CWE WITH A REASON rather than left unclassified.
// First matching rule wins; a taxonomy that matches none is unclassified and fails the enumeration
// test (fail loud — someone added a detector without a CWE decision).
const NO_CWE: { match: (t: string) => boolean; reason: string }[] = [
  { match: (t) => t.startsWith("M5 —"), reason: "M5 slop / dead-code signal — a maintainability issue, not a security weakness class" },
  { match: (t) => t.startsWith("M6 —"), reason: "M6 maintainability / hand-rolled-reinvention indicator — not a security weakness class" },
  { match: (t) => t.startsWith("M7 —"), reason: "M7 performance signal — not a security weakness class" },
  { match: (t) => t.startsWith("M8 —"), reason: "M8 test-quality signal — not a security weakness class" },
  { match: (t) => t.startsWith("M9 —"), reason: "M9 server/client boundary & rendering-correctness signal — not a security weakness class" },
  { match: (t) => t.startsWith("Architecture —"), reason: "architecture-disclosure row (ORM/RLS posture) — a not-assessed disclosure, not a CWE finding" },
  { match: (t) => t.startsWith("Coverage —"), reason: "coverage disclosure (a scope not assessed) — a not-assessed row, not a finding with a CWE" },
  { match: (t) => t.startsWith("Env var"), reason: "environment-variable hygiene/completeness signal — configuration correctness, not a security weakness class" },
  // #1230 / D-091 item 13: the reader 500s because the schema moved under it. A deployment-ordering
  // correctness defect (expand-migrate-contract done out of order), not a weakness an attacker
  // reaches — forcing it into an availability CWE would overstate it.
  { match: (t) => t === "App code reads a column the migrations dropped", reason: "schema/app deployment-ordering correctness defect — the query breaks for everyone, not a weakness class an attacker exercises" },
  // #1280 — the two structural halves of prod-vs-migration drift. Neither is a weakness in itself: an
  // unmanaged table is a reproducibility/provenance defect (it vanishes on a rebuild from migrations),
  // and an unapplied migration is the deployment-ordering defect above reached from the other side.
  { match: (t) => t === "Prod-vs-migration drift — table not in migrations" || t === "Prod-vs-migration drift — migration not applied", reason: "schema-provenance drift — the deployed schema is not reproducible from the committed migrations; a version-control/deployment correctness defect, not a weakness class an attacker exercises" },
  { match: (t) => t.endsWith("— coverage not assessed") || t.endsWith("— reachability not assessed"), reason: "coverage/reachability disclosure — a not-assessed row, not a finding with a CWE" },
  // #1078: both are scope statements about the secret sweep, not detections. The first counts
  // matches deliberately not graded (public-by-design keys, sample/template paths); the second
  // states that TruffleHog ran verified-only and gitleaks never walked history.
  { match: (t) => t.endsWith("— suppressed by allowlist") || t.endsWith("— scope of assessment"), reason: "suppression count / scope disclosure — states what was deliberately not graded, not a weakness found" },
  // Supply-chain / dependency posture — the weakness lives in the third-party component; a per-CVE
  // CWE (when OSV provides one) travels on the individual finding, not this taxonomy label.
  { match: (t) => /^(Known-vulnerable|Known-malicious|Slopsquatted|Possible typosquat|Unpinned|Non-registry|Install lifecycle|Missing lockfile|Copyleft|Unknown\/missing dependency|EOL framework)/.test(t), reason: "supply-chain / dependency-posture signal — a per-CVE CWE (when available from OSV) travels on the individual finding, not this taxonomy label" },
  { match: (t) => t === "auth_rls_initplan (static)", reason: "Supabase RLS init-plan PERFORMANCE advisor (M7 overlap) — not a vulnerability" },
  { match: (t) => t === "Static secret verified with no rotation-pair acceptance window", reason: "key-rotation operational hygiene — no single code-level CWE identifies it" },
  { match: (t) => t === "Dangerous extension enabled", reason: "database-extension posture (Supabase advisor) — no single code-level CWE identifies it" },
  { match: (t) => t === "M1 — Multi-tenant security", reason: "module-summary label, not a specific weakness" },
  { match: (t) => t === "M10 — Data classification", reason: "data-classification (PII/PHI/PCI) label — a data-sensitivity row, not a vulnerability CWE" },
];

type CweClassification =
  | { kind: "cwe"; cwe: string[]; owasp?: string[] }
  | { kind: "none"; reason: string }
  | undefined;

// Classify a detector taxonomy. `{kind:"cwe"}` carries the CWE (+ OWASP when categorized);
// `{kind:"none"}` records a deliberate no-CWE with its reason; `undefined` means unclassified —
// a state the enumeration test forbids for any shipped detector taxonomy.
export function classifyTaxonomyCwe(taxonomy: string): CweClassification {
  const sec = SECURITY[taxonomy];
  if (sec) {
    const [cweId, owaspId] = sec;
    return { kind: "cwe", cwe: [CWE[cweId]!], ...(owaspId ? { owasp: [OWASP[owaspId]!] } : {}) };
  }
  const none = NO_CWE.find((r) => r.match(taxonomy));
  if (none) return { kind: "none", reason: none.reason };
  return undefined;
}

// Fill cwe/owasp on findings whose taxonomy is a known security class and that don't already carry
// one (a semgrep-sourced or OSV-sourced finding keeps its own). Idempotent — safe to apply at more
// than one assembly seam.
export function enrichFindingsCwe(findings: Finding[]): Finding[] {
  for (const f of findings) {
    if (f.cwe && f.cwe.length > 0) continue;
    const c = classifyTaxonomyCwe(f.taxonomy);
    if (c?.kind === "cwe") {
      f.cwe = c.cwe;
      if (c.owasp) f.owasp = c.owasp;
    }
  }
  return findings;
}
