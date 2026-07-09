// Base corpus batch — the original 17 positives + 15 negatives (issues #61/#52/#9). Moved
// verbatim from calibration.ts; see GROUND-TRUTH.md for the fixtures they score.

import type { CorpusEntry } from "./types.js";

export const baseEntries: CorpusEntry[] = [
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
