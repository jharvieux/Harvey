// Calibration validation gate (issue #61). Encodes the corpus answer key — every planted
// POSITIVE that must be caught and every benign NEGATIVE that must NOT be flagged in the free
// count — as data, then scores a Finding[] against it into a coverage matrix (positive recall +
// negative precision per rule/class). The mechanical layer earns the "free count" claim only
// when every high-tier rule fires on its positive and stays silent on its negative lookalike
// (docs/design/mechanical-toolchain.md §7; targets/calibration/GROUND-TRUTH.md).
//
// Two consumers:
//   - src/scan/calibration.test.ts — UNIT tests against RECORDED scanner output (no binaries),
//     so `pnpm verify` proves the scorecard logic in binary-less CI.
//   - src/cli/validate-calibration.ts — LIVE run (`pnpm validate:calibration`) that scans the
//     real targets/calibration with the installed binaries.

import type { Finding, PrecisionTier } from "../findings.js";

export type CorpusKind = "positive" | "negative";

// "high"/"review" mirror PrecisionTier; "connected" marks entries only detectable against a live
// database (Supabase Advisor) — out of scope for a static run, reported as N/A, never a failure.
export type ExpectedTier = PrecisionTier | "connected";

export interface CorpusEntry {
  id: string;
  kind: CorpusKind;
  cls: string;
  // Substring expected in a relevant finding's `location` (file path / lockfile coordinate).
  location: string;
  // Optional keywords; a finding is relevant only if one appears in its id/title/taxonomy/
  // evidence. Disambiguates fixtures that share a file (e.g. the anon key vs. the mis-prefixed
  // secret, both in .env.local).
  match?: string[];
  // Positives: the tier we expect the detection at. Negatives: omit.
  expectedTier?: ExpectedTier;
  note: string;
}

// Answer key. Positives extend GROUND-TRUTH.md's planted bugs; negatives are the benign
// lookalikes from the FP catalog (docs/fp-rules.txt + corpus spec Task A).
export const CORPUS: CorpusEntry[] = [
  // --- POSITIVES (must be caught) ---
  { id: "P-SQLI-CONCAT", kind: "positive", cls: "SQL injection (string interpolation)", location: "search.js", match: ["sql"], expectedTier: "high", note: "Untrusted q interpolated into a template-literal SQL string on the service pool (#4)." },
  { id: "P-OPEN-REDIRECT", kind: "positive", cls: "Open redirect", location: "redirect.js", match: ["redirect"], expectedTier: "review", note: "req.query URL reaches res.redirect with no host allowlist (#8); review tier (MED conf)." },
  { id: "P-RLS-DISABLED", kind: "positive", cls: "Public table, RLS off", location: "audit_logs", expectedTier: "connected", note: "audit_logs never gets ENABLE RLS (#3). Supabase Advisor / config auditor, connected tier — validated in the 2026-07-08 live run (SB-EXPOSED), not re-run in this static build." },
  { id: "P-SRV-KEY-CLIENT", kind: "positive", cls: "Service-role key in Client Component", location: "AdminPanel", match: ["service-role", "service_role", "SUPABASE_SERVICE_ROLE"], expectedTier: "high", note: "'use client' module references SUPABASE_SERVICE_ROLE_KEY — ships to the browser bundle." },
  { id: "P-NEXTPUBLIC-SECRET", kind: "positive", cls: "Secret mis-prefixed NEXT_PUBLIC_", location: ".env.local", match: ["stripe", "next_public", "secret"], expectedTier: "review", note: "NEXT_PUBLIC_STRIPE_SECRET_KEY=sk_live_... inlined into the client bundle; gitleaks (review — unverified/publishable-key ambiguity keeps it out of the count)." },
  { id: "P-HARDCODED-KEY", kind: "positive", cls: "Hardcoded provider secret", location: "ai.js", match: ["anthropic", "credential", "api-key"], expectedTier: "review", note: "sk-ant-api03-... in source (fake, valid-shape). gitleaks provider pattern (review — TruffleHog can't verify a dead key)." },
  { id: "P-NEXT-CVE-29927", kind: "positive", cls: "Framework CVE — middleware auth bypass", location: "next", match: ["29927"], expectedTier: "high", note: "next@^14.2.5 is < 14.2.25, in the CVE-2025-29927 range (GHSA-f82v-jwr5-mffw)." },
  { id: "P-NEXT-CVE-RSC", kind: "positive", cls: "Framework CVE — React2Shell RSC RCE", location: "next", match: ["55182", "react2shell", "rsc"], expectedTier: "high", note: "next@^14.2.5 is < 14.2.35, in the React2Shell RSC RCE range (CVSS 10, KEV)." },
  { id: "P-DEP-CVE", kind: "positive", cls: "Known-vulnerable dependency", location: "lodash", match: ["lodash"], expectedTier: "review", note: "lodash@4.17.11 (prototype-pollution CVE). OSV-Scanner needs a committed lockfile — the calibration target ships none, so this is a no-op in a lockfile-less run (tracked as a follow-up)." },
  { id: "P-XSS-DSIH", kind: "positive", cls: "XSS via tainted dangerouslySetInnerHTML", location: "post.js", match: ["inner"], expectedTier: "high", note: "router.query.body flows unsanitized into __html." },
  { id: "P-CORS-WILDCARD", kind: "positive", cls: "Permissive CORS w/ credentials", location: "data.js", match: ["cors", "origin"], expectedTier: "high", note: "Access-Control-Allow-Origin '*' + Allow-Credentials true." },
  { id: "P-NO-CSP", kind: "positive", cls: "Missing security headers / CSP", location: "next.config", match: ["csp", "security-policy", "security headers"], expectedTier: "review", note: "next.config.js defines no CSP and no middleware sets one." },
  { id: "P-SSRF-FETCH", kind: "positive", cls: "SSRF via server-fetched user URL", location: "fetch-preview.js", match: ["ssrf"], expectedTier: "review", note: "fetch(req.query.url) with no host allow/deny; review (needs deploy-network context)." },
  { id: "P-SLOPSQUAT", kind: "positive", cls: "Slopsquatted / hallucinated dep", location: "react-supabase-helpers", match: ["react-supabase-helpers"], expectedTier: "review", note: "Nonexistent package in deps. Needs an npm-registry existence cross-check (not yet built) — the offline typosquat corpus only catches edit-distance-1 names, so this is a documented miss/follow-up." },
  { id: "P-POSTINSTALL", kind: "positive", cls: "Lifecycle-script supply-chain risk", location: "package.json (scripts)", match: ["lifecycle"], expectedTier: "review", note: "postinstall lifecycle script present; review (presence != malicious)." },
  { id: "P-DEBUG-ENDPOINT", kind: "positive", cls: "Debug/seed/admin route w/ no auth", location: "seed.js", match: ["debug", "seed", "route", "auth"], expectedTier: "review", note: "pages/api/dev/seed.js has no auth guard; leftover-auth sensitive-route heuristic (review). pages/api/admin/reset.js (isAdmin=true) is also flagged." },
  { id: "P-TODO-AUTH", kind: "positive", cls: "Placeholder/left-open auth", location: "create.js", match: ["todo"], expectedTier: "review", note: "// TODO: auth above an unguarded mutation; leftover-auth grep (review)." },

  // --- NEGATIVES (must NOT be flagged in the free count) ---
  { id: "N-ANON-KEY", kind: "negative", cls: "Public anon key looks like a secret", location: ".env.local", match: ["anon"], note: "NEXT_PUBLIC_SUPABASE_ANON_KEY (role:anon) is public by design. gitleaks allowlist (regexTarget=line) suppresses every rule on that line. The single most credibility-fatal FP." },
  { id: "N-ENV-EXAMPLE", kind: "negative", cls: "Placeholder secrets in a sample file", location: ".env.example", note: "Documented placeholders; .env.example path-allowlisted and unverifiable." },
  { id: "N-SECRET-NAME", kind: "negative", cls: "Variable named like a secret, holds none", location: "ResetForm", note: "passwordLabel / awaitingPasswordReset — name-only, no secret value (vs Sonar S2068)." },
  { id: "N-PARAM-QUERY", kind: "negative", cls: "Parameterized query looks like SQLi", location: "list.js", note: "pool.query('... $1', [req.x]) — bound param, not interpolation. SQLi rule must not fire." },
  { id: "N-DSIH-SANITIZED", kind: "negative", cls: "Sanitized/constant dangerouslySetInnerHTML", location: "about.js", note: "sanitizeHtml(...) and a constant literal. The custom rule clears both; a registry .audit rule may flag it at review tier only (triaged out)." },
  { id: "N-OBJ-INJECTION", kind: "negative", cls: "Benign obj[key] bracket access", location: "i18n.js", note: "translations[locale] with locale validated against an enum (vs eslint detect-object-injection)." },
  { id: "N-JSX-KEY", kind: "negative", cls: "Composite/stable JSX key", location: "List.jsx", note: "key={`${it.id}-${i}`} — quality rule, never in the security count (vs Sonar S6479)." },
  { id: "N-WEAK-HASH-CACHE", kind: "negative", cls: "Non-security md5 as cache key", location: "cache.js", note: "md5 as an ETag/cache tag, not auth/integrity (vs Sonar S4790)." },
  { id: "N-REDOS-SAFE", kind: "negative", cls: "Safe (linear) regex looks like ReDoS", location: "validate.js", note: "Linear email regex with negated classes; ReDoS stays out of the count (vs Sonar S5852)." },
  { id: "N-FS-STATIC", kind: "negative", cls: "Static/unrelated fs/.open() call", location: "read-config.js", note: "fs.readFileSync(path.join(__dirname,...)) + an unrelated widget.open() (vs eslint fs rules)." },
  { id: "N-DEV-DEP", kind: "negative", cls: "Vulnerable dep in devDependencies only", location: "webpack", note: "webpack@4.42.0 is dev-only. Excluded from the count; OSV/npm audit would list it at review/informational (needs a lockfile), never high." },
  { id: "N-SERVICE-ROLE-SERVER", kind: "negative", cls: "Legit server-only service-role use", location: "cron.js", note: "import 'server-only' + admin client, no 'use client' — service-role use is not a finding by itself (fp-rules)." },
  { id: "N-RLS-DENY-ALL", kind: "negative", cls: "RLS-enabled-no-policy, service-only table", location: "service_state", note: "RLS on + zero policies = deny-all by design. Advisor lint 0008 is informational, not a finding (connected tier)." },
  { id: "N-URL-ENV", kind: "negative", cls: "Operator/env config URL", location: "redis.js", note: "z.string().url() on process.env.REDIS_URL (redis://) — operator/env URLs are exempt (fp-rules)." },
  { id: "N-INMEM-CACHE", kind: "negative", cls: "Map used as cache, not limiter", location: "memo.js", note: "module-level Map for memoization, not a rate limiter (fp-rules)." },
];

function haystack(f: Finding): string {
  return `${f.id} ${f.title} ${f.taxonomy} ${f.evidence} ${f.location}`.toLowerCase();
}

// A finding is relevant to an entry when its location contains the entry's location substring
// and (if the entry lists keywords) at least one keyword appears anywhere in the finding text.
function relevantFindings(entry: CorpusEntry, findings: Finding[]): Finding[] {
  const loc = entry.location.toLowerCase();
  const keys = entry.match?.map((m) => m.toLowerCase());
  return findings.filter((f) => {
    if (!f.location.toLowerCase().includes(loc)) return false;
    if (!keys) return true;
    const hay = haystack(f);
    return keys.some((k) => hay.includes(k));
  });
}

function topTier(findings: Finding[]): PrecisionTier | undefined {
  if (findings.some((f) => f.precisionTier === "high")) return "high";
  if (findings.some((f) => f.precisionTier === "review")) return "review";
  return undefined;
}

export interface MatrixRow {
  id: string;
  kind: CorpusKind;
  cls: string;
  expectedTier?: ExpectedTier;
  caughtTier?: PrecisionTier; // best tier a relevant finding landed at (positives)
  highFlagged: boolean; // a relevant finding at HIGH (free-count) tier exists
  reviewFlagged: boolean; // a relevant finding at review tier exists
  pass: boolean;
  detail: string;
}

// Scoring:
//   positive (static): pass = caught at any tier. A "connected"-tier positive is N/A (never fails).
//   negative: pass = NO high-tier (free-count) finding is relevant. A review-tier hit is tolerated
//             (it gets triaged out of the count) but recorded. A "connected"-tier negative is N/A.
export function scoreEntry(entry: CorpusEntry, findings: Finding[]): MatrixRow {
  const relevant = relevantFindings(entry, findings);
  const highFlagged = relevant.some((f) => f.precisionTier === "high");
  const reviewFlagged = relevant.some((f) => f.precisionTier === "review");
  const caughtTier = topTier(relevant);

  if (entry.expectedTier === "connected") {
    return { id: entry.id, kind: entry.kind, cls: entry.cls, expectedTier: entry.expectedTier, caughtTier, highFlagged, reviewFlagged, pass: true, detail: "N/A — connected tier (live DB), not evaluated statically" };
  }

  if (entry.kind === "positive") {
    const pass = caughtTier !== undefined;
    const detail = pass
      ? `caught at ${caughtTier}${entry.expectedTier && entry.expectedTier !== caughtTier ? ` (expected ${entry.expectedTier})` : ""}`
      : "NOT caught by any rule";
    return { id: entry.id, kind: entry.kind, cls: entry.cls, expectedTier: entry.expectedTier, caughtTier, highFlagged, reviewFlagged, pass, detail };
  }

  // negative
  const pass = !highFlagged;
  const detail = highFlagged
    ? "FALSE POSITIVE in the free count"
    : reviewFlagged
      ? "cleared from the count (review-tier hit only, triaged out)"
      : "cleared — not flagged";
  return { id: entry.id, kind: entry.kind, cls: entry.cls, expectedTier: entry.expectedTier, caughtTier, highFlagged, reviewFlagged, pass, detail };
}

interface CoverageMatrix {
  rows: MatrixRow[];
  positivesTotal: number; // static positives (excludes connected tier)
  positivesCaught: number;
  positivesCaughtHigh: number;
  negativesTotal: number; // static negatives (excludes connected tier)
  negativesCleared: number;
  connectedNa: number;
  ok: boolean; // every static positive caught AND every static negative cleared
}

export function buildCoverageMatrix(findings: Finding[], corpus: CorpusEntry[] = CORPUS): CoverageMatrix {
  const rows = corpus.map((e) => scoreEntry(e, findings));
  const staticPos = rows.filter((r) => r.kind === "positive" && r.expectedTier !== "connected");
  const staticNeg = rows.filter((r) => r.kind === "negative" && r.expectedTier !== "connected");
  const positivesCaught = staticPos.filter((r) => r.pass).length;
  const negativesCleared = staticNeg.filter((r) => r.pass).length;
  return {
    rows,
    positivesTotal: staticPos.length,
    positivesCaught,
    positivesCaughtHigh: staticPos.filter((r) => r.highFlagged).length,
    negativesTotal: staticNeg.length,
    negativesCleared,
    connectedNa: rows.filter((r) => r.expectedTier === "connected").length,
    ok: positivesCaught === staticPos.length && negativesCleared === staticNeg.length,
  };
}
