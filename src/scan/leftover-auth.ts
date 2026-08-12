// Leftover-auth greps: stubbed-out or forgotten auth guards left in from development.
// Pure text patterns — no tool binary, no AST — so every hit here is "review" precision:
// a grep can't tell a genuinely bypassed guard from `// TODO: auth` in a comment explaining
// why auth is deliberately deferred, or `isAdmin = true` in a test fixture.

import type { Finding } from "../findings.js";
import { mechanicalFinding } from "./common.js";

interface SourceFile {
  path: string; // relative to the scanned project root
  content: string;
}

const GREP_PATTERNS: { id: string; regex: RegExp; title: string }[] = [
  { id: "todo-auth", regex: /\/\/\s*TODO:?\s*auth/i, title: "TODO: auth left in source" },
  { id: "if-true", regex: /if\s*\(\s*true\s*\)/, title: "if (true) — possible stubbed-out or bypassed guard" },
  { id: "is-admin-true", regex: /isAdmin\s*=\s*true\b/, title: "isAdmin hardcoded to true" },
  { id: "bypass-auth", regex: /bypassAuth/i, title: "bypassAuth reference" },
];

const SENSITIVE_ROUTE_SEGMENT = /(^|\/)(debug|seed|admin|api\/dev)(\/|$|\.)/i;
// #568: recognize the BARE session-accessor wrappers (getUser/getSession/getCurrentUser/…), not only
// the stock supabase.auth.getUser() METHOD call. A route that reads the session through a plain
// top-level helper — `const user = await getUser(req)` (the vandyand app/api/admin/revenue shape) —
// authenticates just as authoritatively and must not be labelled "Unauthenticated debug/admin route"
// (the #562 false-premise class, fixed there for harvey-route-noauth). `auth()` covers next-auth v5.
// #586: the same false-premise class for CUSTOM-JWT auth — a route that establishes its session with
// `jwt.verify(...)` (jsonwebtoken) or a verifyToken/verifySession/verifyJwt/jwtVerify/decodeToken
// helper (jose/next-auth/Clerk/Lucia shapes) authenticates just as authoritatively as getUser, and
// must not be mislabelled "Unauthenticated" simply because the mechanism isn't Supabase.
const AUTH_HINT = /(getServerSession|getSession|getUser|getCurrentUser|getAuthUser|getAuthenticatedUser|auth\(\)|requireAuth|withAuth|assertAuth|supabase\.auth\.getUser|createServerClient|jwt\.verify|jwtVerify|verifyToken|verifySession|verifyJwt|verifyJWT|decodeToken)/;
const ROUTE_FILE = /(^|\/)(route\.(ts|tsx|js)|pages\/api\/.*\.(ts|tsx|js))$/;

// B7 (#71): a login/signup/OTP/password-reset route with no rate-limiter hint — an attacker can
// brute-force credentials/OTP codes with unlimited attempts. Same grep-and-hint shape as the
// sensitive-route check above (review tier — a limiter living in middleware/an edge config this
// file can't see is a false negative, not a gate concern).
const AUTH_SENSITIVE_ROUTE = /(^|\/)(login|signin|sign-in|signup|sign-up|register|otp|reset-password|forgot-password)(\/|$|\.)/i;
const RATE_LIMIT_HINT = /(rateLimit|ratelimit|Ratelimit|limiter\.)/;

// #1046 — the INVERSE of the check above, and the case it actively clears. AUTH-no-rate-limit fires
// on the ABSENCE of a limiter hint, so a limiter backed by a process-local Map matches the hint and
// is passed as safe. On a serverless host that limiter does not limit: every cold start begins with
// an empty counter and concurrent instances each keep their own, so the attacker's effective budget
// is (limit × instances) and resets whenever the platform recycles. Free-tier-advertised capability
// (docs/free-tier-scope.md) that had no detector at all until this.
//
// briefs/fp-rules.txt already carries the precision rule this must obey — "IN-PROCESS CACHES ARE NOT
// LIMITERS … only flag when the structure is acting as a RATE LIMIT / QUOTA / THROTTLE (name or
// usage reads like rate/limit/attempt/bucket/quota/hits AND it gates request admission)". So all
// four of these must hold:
//   1. the store is a MODULE-SCOPE mutable container (const/let/var/globalThis = new Map/Set/WeakMap
//      or an object/array literal) — request-scoped state is re-created per call, a different bug,
//   2. an identifier reads like a limiter counter (rate/limit/attempt/throttle/quota/bucket/hits),
//   3. it GATES ADMISSION — a 429, or a comparison of the counter against a numeric budget,
//   4. no shared-store hint anywhere (Redis/Upstash/KV/Memcached/Dynamo/Durable Objects/a SQL or
//      Supabase/Prisma call) — a limiter already talking to a shared backend is the CORRECT shape.
// (2) and (3) are read from CODE ONLY: this is a grep layer, and targets/calibration/lib/memo.js is
// a memo cache whose own comment says "not a rate limiter", which un-stripped content reads as intent.
const RATE_LIMIT_IDENTIFIER = /(rate.?limit|ratelimit|throttle|attempts?\b|quota|token.?bucket|\bhits\b)/i;
const ADMISSION_GATE = /(\b429\b|too.?many.?requests|[<>]=?\s*\d+|\d+\s*[<>]=?)/i;
// #1197: `new Map<string, number>()` — a generic type argument between the class name and the
// call parens — did not match here, so a module-scope counter declared with an explicit value
// type (the idiomatic TS form the fixture and most real code use) silently missed this detector
// entirely. `(?:<[^>]*>)?` admits it without weakening the Map/Set/WeakMap requirement.
const PROCESS_LOCAL_STORE = /^\s*(?:(?:export\s+)?(?:const|let|var)\s+[\w$]+|globalThis\.[\w$]+)\s*=\s*(?:new\s+(?:Map|Set|WeakMap)\s*(?:<[^>]*>)?\s*\(|\{\s*\}|\[\s*\])/m;
const SHARED_STORE_HINT = /(redis|upstash|@vercel\/kv|\bkv\.|memcach|dynamo|durable ?object|cloudflare|\.rpc\(|supabase|prisma|\bsql`|\bpool\.query|\bdb\.query)/i;

// Comments and the inside of `//`-style URLs are prose, not behaviour. Line comments are stripped
// only when not preceded by `:` so a "https://…" literal survives.
function stripComments(content: string): string {
  return content.replace(/\/\*[\s\S]*?\*\//g, "").replace(/(^|[^:])\/\/.*$/gm, "$1");
}

function usesProcessLocalRateLimiter(content: string): boolean {
  if (!PROCESS_LOCAL_STORE.test(content) || SHARED_STORE_HINT.test(content)) return false;
  const code = stripComments(content);
  return RATE_LIMIT_IDENTIFIER.test(code) && ADMISSION_GATE.test(code);
}

// #576 — client-trust-boundary: a role/privilege decision made in CLIENT code, gating what the
// browser renders/navigates to or an action it takes. Client code is fully attacker-controlled — a
// role read from Web Storage (user-editable) or from a user object, compared to a privilege literal
// to open a gate, is bypassable by editing storage or the bundle. Framework-neutral: fires on any
// client source (a Vite/no-code SPA component or a Next "use client" component), which is why it
// lives in the file-walking grep layer rather than a Next-shaped semgrep rule. Review tier — a grep
// can't prove the same decision isn't ALSO re-enforced server-side/RLS.
const PRIV_LITERAL = `['"](?:admin|owner|staff|superadmin|super-admin)['"]`;
// A role read from tamperable Web Storage: localStorage.getItem('...role...'), or a .role/.userRole
// property on localStorage/sessionStorage.
const STORAGE_ROLE_READ = /(?:localStorage|sessionStorage)\s*\.\s*(?:getItem\s*\(\s*['"][^'"]*role[^'"]*['"]\s*\)|[\w$]*role\b)/i;
// A user/session/auth object's role field compared against a privilege literal (either operand order).
const USER_ROLE_COMPARE = new RegExp(`\\.(?:user_metadata\\.|app_metadata\\.)?role\\s*[=!]==?\\s*${PRIV_LITERAL}|${PRIV_LITERAL}\\s*[=!]==?\\s*[\\w.$]*\\.(?:user_metadata\\.|app_metadata\\.)?role`, "i");
// Browser-only navigation/render gating. Deliberately narrow (no generic JSX): a legitimate
// server-side role check — `if (profile.role !== 'admin') return new Response(403)` — must NOT match,
// so the .role branch requires one of these client-gate signals to co-occur.
const CLIENT_GATE = /\b(?:useNavigate|navigate\s*\(|router\s*\.\s*(?:push|replace)|useState|useEffect)\b|window\.location|return\s+null|<Navigate\b/;

function isClientSideAuthz(content: string): boolean {
  if (STORAGE_ROLE_READ.test(content) && new RegExp(PRIV_LITERAL, "i").test(content)) return true;
  return USER_ROLE_COMPARE.test(content) && CLIENT_GATE.test(content);
}

// #135/#1366 — the Host header read, in the three forms the App Router and Express shapes use:
// `headers().get("host")`, `request.headers.get("x-forwarded-host")`, `req.headers["host"]` and
// `req.headers.host`.
const HOST_HEADER_READ_SRC = String.raw`(?:headers\s*\(\s*\)|(?:req|request)\s*\.\s*headers)\s*(?:\.\s*get\s*\(\s*['"]|\[\s*['"]|\.\s*)(?:x-forwarded-)?host\b`;
const HOST_HEADER_READ = new RegExp(HOST_HEADER_READ_SRC, "i");
const HOST_HEADER_BIND = new RegExp(String.raw`\b(?:const|let|var)\s+([\w$]+)\s*=\s*(?:await\s+)?[^;\n]*?` + HOST_HEADER_READ_SRC, "i");

// What makes this class rather than #984's header taint is the AUTHORITY POSITION: the header value
// becomes the host of an absolute URL (`//${host}` in a template, or `"https://" + host`). Reading
// the same header into a shell command (targets/calibration/pages/api/header-exec.js) or a DNS
// lookup is a different planted class and must not match here.
const urlAuthority = (expr: string): RegExp =>
  new RegExp(String.raw`(?:https?:)?//\$\{\s*` + expr + String.raw`\s*\}|['"](?:https?:)?//['"]\s*\+\s*` + expr, "i");

function buildsUrlFromHostHeader(content: string): boolean {
  const code = stripComments(content);
  if (!HOST_HEADER_READ.test(code)) return false;
  if (urlAuthority(HOST_HEADER_READ_SRC).test(code)) return true;
  const bound = HOST_HEADER_BIND.exec(code);
  if (bound === null) return false;
  return urlAuthority((bound[1] as string).replace(/\$/g, String.raw`\$`)).test(code);
}

// #991 — allowlist-grant / multi-hop authz decision from untrusted input. Broadens the
// direct-equality client-priv-header check to the shape BenchProctor and real code use: a privileged
// branch reached via an allowlist MEMBERSHIP test on request-derived input, or a role/"granted"
// value echoed straight back into the response. Discriminated from the safe twin — a verified-session
// identity check (authzCheck / req.session) that denies by default (403/forbidden) — which is excluded.
const AUTHZ_REQ_SOURCE = /(req|request)\.(body|query|params|headers)\b/i;
// An array/Set literal listing a privilege value, so a membership hit grants a privilege.
const PRIV_ALLOWLIST = /(?:\[|new\s+Set\s*\(\s*\[)[^\]]*['"](?:admin|owner|root|superadmin|super-admin|superuser|staff|privileged|elevated)['"][^\]]*\]/i;
const MEMBERSHIP_TEST = /\.\s*(?:includes|has)\s*\(/;
// A privilege/access grant written into the response body.
const ROLE_GRANT_RESPONSE = /(?:res|response)\s*\.\s*(?:json|send)\s*\(\s*\{[^}]*(?:role\s*:\s*['"](?:admin|owner|root|superadmin|super-admin|superuser|staff)['"]|access\s*:\s*['"]granted['"])/i;
// Safe twin: a verified-session identity decision that denies by default.
const VERIFIED_SESSION_GUARD = /(req|request)\.session|\bauthzCheck\s*\(|\bsession\.user\b/i;
const DENY_DEFAULT = /status\s*\(\s*40[13]\s*\)|['"](?:forbidden|unauthorized)['"]/i;

function hasAllowlistGrant(content: string): boolean {
  if (!AUTHZ_REQ_SOURCE.test(content)) return false;
  const grant = (PRIV_ALLOWLIST.test(content) && MEMBERSHIP_TEST.test(content)) || ROLE_GRANT_RESPONSE.test(content);
  if (!grant) return false;
  if (VERIFIED_SESSION_GUARD.test(content) && DENY_DEFAULT.test(content)) return false;
  return true;
}

// B14 (#71): app-logic heuristics — all "review" tier (a grep can't prove the missing check
// isn't enforced elsewhere, only that its shape is absent here). See
// docs/design/corpus-roadmap-to-100.md §3f and GROUND-TRUTH.md §B14.
const B14_CHECKS: { id: string; title: string; taxonomy: string; category: string; impact: string; fix: string; test: (f: SourceFile) => boolean }[] = [
  {
    id: "client-priv-header",
    title: "authorization decision made from client-controlled input",
    taxonomy: "Authz decision from client-controlled input",
    category: "Broken access control",
    impact: "A client can set the header/body/query value themselves and grant the privilege.",
    fix: "Derive the role from the verified session (e.g. supabase.auth.getUser().app_metadata), never from the request.",
    // A privilege literal (admin/owner/…) compared directly against a req header/body/query value.
    test: (f) => /(req|request)\.(headers\s*\[[^\]]+\]|(body|query)\.\w+)\s*={2,3}\s*['"](admin|superadmin|super-admin|owner|root|staff)['"]/i.test(f.content),
  },
  {
    // #991 — the allowlist-grant / multi-hop variant of the same class: the privilege is granted by
    // an allowlist membership test on request-derived input (or echoed back as a role/"granted"
    // response), rather than a direct `=== 'admin'` comparison. Same taxonomy/class as above.
    id: "client-authz-allowlist-grant",
    title: "authorization decision made from client-controlled input (allowlist grant)",
    taxonomy: "Authz decision from client-controlled input",
    category: "Broken access control",
    impact: "A client can supply a value that passes the allowlist (or drives the granted role), so the privileged branch runs on attacker-controlled input.",
    fix: "Derive the role/permission from the verified session and deny by default; never grant a privilege from a request-derived value passing an allowlist check.",
    test: (f) => hasAllowlistGrant(f.content),
  },
  {
    id: "client-payment-amount",
    title: "payment amount taken directly from the request",
    taxonomy: "Client-supplied payment amount trusted by server",
    category: "Business logic",
    impact: "A client can set the charge amount themselves and pay an arbitrary (or zero) price.",
    fix: "Recompute the amount server-side from the trusted DB price; the request should only name the product/quantity.",
    test: (f) => /\bamount\w*\s*:\s*(req|request)\.(body|query|params)\b/i.test(f.content),
  },
  {
    id: "sensitive-console-log",
    title: "a password/secret/token is written to the console",
    taxonomy: "Sensitive value logged to console",
    category: "Sensitive data exposure",
    impact: "The credential persists in log aggregation, CI output, and crash dumps.",
    fix: "Log only non-sensitive identifiers and the outcome; never the credential itself.",
    test: (f) => /console\.(log|error|info|warn|debug)\s*\([^)]*\b(password|passwd|pwd|secret|api[_-]?key|private[_-]?key|client[_-]?secret|credentials?)\b/i.test(f.content),
  },
  {
    // #576 — client-side authorization decision (Web Storage role or a user-object role gating the UI).
    id: "client-side-authz",
    title: "authorization decision enforced in client code (bypassable)",
    taxonomy: "Client-side authorization decision",
    category: "Broken access control",
    impact: "The role/privilege check runs in the browser, where the user controls Web Storage and the JS bundle — they can flip the gate open (edit storage, patch the bundle) and reach the privileged view/action. Any data the gate is supposed to protect is already in the client.",
    fix: "Enforce the privileged read/action server-side: an RLS policy, or a server route that re-derives the role from the verified session. Treat any client-side role as display-only, never as the gate.",
    test: (f) => isClientSideAuthz(f.content),
  },
  {
    // #135/#1366 — Host-header-trusted-in-URL-construction. Was recorded as "no mechanical rule …
    // needs taint-from-Host-into-URL reasoning" and carried as one of three permanent review-tier
    // recall misses; re-tested 2026-07-31 and the shape is a LOCAL, single-file dataflow fact.
    id: "host-header-url",
    title: "an absolute URL is built from the request's Host / X-Forwarded-Host header",
    taxonomy: "Host header trusted in URL construction",
    category: "Broken access control",
    impact:
      "Both Host and X-Forwarded-Host are set by the caller, and most proxies forward them untouched, so an attacker who triggers a password-reset/verification mail gets the victim's real token delivered inside a link pointing at a domain they control.",
    fix: "Build absolute links from a fixed deploy-time origin (an env var), or validate the incoming host against an allowlist before it reaches the URL.",
    test: (f) => buildsUrlFromHostHeader(f.content),
  },
];

const UPLOAD_SINK = /storage\s*\.\s*from\s*\([^)]*\)\s*\.\s*upload\s*\(/;
const UPLOAD_LIMIT_HINT = /content-?length|max[_-]?size|file[_-]?size|\.size\b|allowed[_-]?(types|mime)|mimetype|content-?type\s*[:=]|accept\s*:/i;
const WEBHOOK_PATH = /webhook/i;
const WEBHOOK_PRIVILEGED_WRITE = /\.(insert|update|delete|upsert|rpc)\s*\(|admin\.from|supabaseAdmin/i;
const WEBHOOK_SIG_HINT = /createHmac|constructEvent|timingSafeEqual|verif\w*Signature|x-signature|stripe-signature|hub-signature|svix|webhook[_-]?secret/i;

// #353 UPDATE-UNSCOPED: a raw UPDATE/DELETE SQL string with no WHERE clause, handed to a raw-SQL
// sink (`.query(`/`.execute(`/`.unsafe(`/`.raw(`) in a route handler. The SQL either scopes the
// write with a WHERE or it does not — a textual fact, like USING (true) (#333). The benign sibling
// adds `WHERE id = $2`. Review tier: a deliberate whole-table reset/backfill in a route is
// legitimate, so a grep can't prove intent — discriminator is the missing WHERE, FP shape the admin
// reset. Captures ONLY the string literal argument to the sink (not surrounding comments), so a
// nearby comment that says "WHERE" can't mask an actually-unscoped statement.
const SQL_SINK_ARG = /\.\s*(?:query|execute|unsafe|raw)\s*\(\s*(["'`])((?:(?!\1)[\s\S])*?)\1/gi;
const DML_STATEMENT = /^\s*(?:update\s+\S[\s\S]*?\bset\b|delete\s+from\b)/i;

// #354 P-MW-MATCHER-EXCLUDES-API: an exported Next.js middleware `config.matcher` whose
// negative-lookahead excludes `/api`, so the middleware (the app's auth layer) never runs for API
// routes. The benign sibling's matcher lists no `api` token in its lookahead. Review tier: excluding
// /api is correct when the API routes guard themselves — the discriminator is the api-in-lookahead
// contradiction with middleware presented as the gate, the FP shape is a self-guarded API surface.
const MW_MATCHER_EXCLUDES_API = /matcher\s*:\s*[\s\S]{0,200}?\(\?![^)]*\bapi\b/;

// #354 P-DRAFTMODE-NO-SECRET: `draftMode().enable()` reachable with no preceding secret/token
// comparison in the handler — any caller flips on preview mode. The benign sibling compares
// req.query.secret against process.env.*SECRET first. Review tier, shallow intra-file: a grep sees
// the enable call and the absence of a secret gate in THIS file, not a gate in a wrapper it can't
// see — discriminator is enable-without-secret, FP shape is an out-of-file guard.
const DRAFTMODE_ENABLE = /draftMode\s*\(\s*\)\s*\.\s*enable\s*\(/;
const DRAFTMODE_SECRET_HINT = /process\.env\.\w*(SECRET|TOKEN)|(req|request)\.(query|body|headers)[\s\S]{0,60}?secret|secret[\s\S]{0,20}?(===|!==|==|!=)/i;

function hasUnscopedDml(content: string): boolean {
  for (const m of content.matchAll(SQL_SINK_ARG)) {
    const sql = m[2] ?? "";
    if (DML_STATEMENT.test(sql) && !/\bwhere\b/i.test(sql)) return true;
  }
  return false;
}

function slug(path: string): string {
  return path.replace(/[^a-zA-Z0-9]+/g, "-").replace(/^-|-$/g, "");
}

export function classifyLeftoverAuth(file: SourceFile): Finding[] {
  const findings: Finding[] = [];
  for (const p of GREP_PATTERNS) {
    if (p.regex.test(file.content)) {
      findings.push(
        mechanicalFinding({
          id: `AUTH-${p.id}-${slug(file.path)}`,
          title: p.title,
          severity: "Medium",
          category: "Leftover auth",
          taxonomy: "Leftover-auth grep",
          location: file.path,
          evidence: `Pattern "${p.id}" matched in ${file.path}.`,
          impact: "May be a development-time auth bypass left in place; confirm it isn't reachable in production.",
          fix: "Remove the stub/bypass, or confirm and document why it's intentional (test fixture, dev-only branch).",
          precisionTier: "review",
        }),
      );
    }
  }
  if (ROUTE_FILE.test(file.path) && SENSITIVE_ROUTE_SEGMENT.test(file.path) && !AUTH_HINT.test(file.content)) {
    findings.push(
      mechanicalFinding({
        id: `AUTH-sensitive-route-${slug(file.path)}`,
        title: `${file.path} looks like a debug/seed/admin/dev route with no auth-call hint`,
        severity: "High",
        category: "Leftover auth",
        taxonomy: "Unauthenticated debug/admin route",
        location: file.path,
        evidence: `Route path matches /debug|seed|admin|api\\/dev/ and no auth-check call pattern was found in the file.`,
        impact: "If genuinely unauthenticated, this route is reachable by anyone who finds the path.",
        fix: "Add an auth/role check, or remove the route before shipping.",
        precisionTier: "review",
      }),
    );
  }
  if (ROUTE_FILE.test(file.path) && AUTH_SENSITIVE_ROUTE.test(file.path) && !RATE_LIMIT_HINT.test(file.content)) {
    findings.push(
      mechanicalFinding({
        id: `AUTH-no-rate-limit-${slug(file.path)}`,
        title: `${file.path} looks like a login/signup/OTP/reset route with no rate-limiter hint`,
        severity: "Medium",
        category: "Leftover auth",
        taxonomy: "Missing rate limit on auth endpoint",
        location: file.path,
        evidence: `Route path matches /login|signup|otp|reset-password/ and no rate-limiter call pattern was found in the file.`,
        impact: "An attacker can brute-force credentials/OTP codes with unlimited attempts.",
        fix: "Add a rate limiter (e.g. Upstash Ratelimit, a token-bucket middleware) in front of this route.",
        precisionTier: "review",
      }),
    );
  }
  if (usesProcessLocalRateLimiter(file.content)) {
    findings.push(
      mechanicalFinding({
        id: `AUTH-inmemory-rate-limit-${slug(file.path)}`,
        title: `${file.path} rate-limits with process-local state, which does not limit on a serverless host`,
        severity: "Medium",
        category: "Leftover auth",
        taxonomy: "In-memory rate limiter (per-instance, resets on cold start)",
        location: file.path,
        evidence: `Rate-limit intent plus a module-scope Map/Set/object counter store, and no shared-store (Redis/KV/DB) hint anywhere in ${file.path}.`,
        impact:
          "Each serverless instance keeps its own counter and every cold start resets it, so the real budget is the limit times the number of live instances — and an attacker who paces requests never hits it at all.",
        fix: "Move the counter to a store shared across instances (Redis/Upstash, Vercel KV, or a database row with an atomic increment).",
        precisionTier: "review",
      }),
    );
  }
  for (const c of B14_CHECKS) {
    if (c.test(file)) {
      findings.push(
        mechanicalFinding({
          id: `AUTH-${c.id}-${slug(file.path)}`,
          title: `${file.path} — ${c.title}`,
          severity: "High",
          category: c.category,
          taxonomy: c.taxonomy,
          location: file.path,
          evidence: `Heuristic "${c.id}" matched in ${file.path}.`,
          impact: c.impact,
          fix: c.fix,
          precisionTier: "review",
        }),
      );
    }
  }
  // Upload sink with no size/MIME limit in the same file.
  if (UPLOAD_SINK.test(file.content) && !UPLOAD_LIMIT_HINT.test(file.content)) {
    findings.push(
      mechanicalFinding({
        id: `AUTH-upload-no-limit-${slug(file.path)}`,
        title: `${file.path} writes an upload to storage with no size/MIME limit`,
        severity: "High",
        category: "Broken access control",
        taxonomy: "Upload to storage with no size/MIME limit",
        location: file.path,
        evidence: `Heuristic "upload-no-limit" matched a storage .upload() with no content-length/MIME guard in ${file.path}.`,
        impact: "An attacker can store arbitrarily large or executable content, or exhaust the storage quota.",
        fix: "Enforce a content-length cap and a MIME allowlist before the storage write.",
        precisionTier: "review",
      }),
    );
  }
  // Inbound webhook route doing a privileged write with no signature-verification hint.
  if (ROUTE_FILE.test(file.path) && WEBHOOK_PATH.test(file.path) && WEBHOOK_PRIVILEGED_WRITE.test(file.content) && !WEBHOOK_SIG_HINT.test(file.content)) {
    findings.push(
      mechanicalFinding({
        id: `AUTH-webhook-no-sig-${slug(file.path)}`,
        title: `${file.path} is an inbound webhook doing a privileged write with no signature verification`,
        severity: "High",
        category: "Broken access control",
        taxonomy: "Inbound webhook with no signature verification",
        location: file.path,
        evidence: `Heuristic "webhook-no-sig" matched a webhook-path route with a privileged write and no HMAC/signature check in ${file.path}.`,
        impact: "Anyone who finds the URL can forge events and drive the privileged side effect.",
        fix: "Verify the provider signature (HMAC / constructEvent) against a shared secret before any write.",
        precisionTier: "review",
      }),
    );
  }
  // #353 — raw UPDATE/DELETE with no WHERE, on a raw-SQL sink in a route handler.
  if (ROUTE_FILE.test(file.path) && hasUnscopedDml(file.content)) {
    findings.push(
      mechanicalFinding({
        id: `AUTH-unscoped-write-${slug(file.path)}`,
        title: `${file.path} runs a raw UPDATE/DELETE with no WHERE clause`,
        severity: "High",
        category: "Broken access control",
        taxonomy: "Unscoped service-role UPDATE/DELETE (no WHERE)",
        location: file.path,
        evidence: `Heuristic "unscoped-write" matched a raw-SQL UPDATE/DELETE string literal with no WHERE clause passed to a .query()/.execute() sink in ${file.path}.`,
        impact: "The write hits every row in the table (every tenant), not just the caller's — a single request rewrites or deletes all rows.",
        fix: "Scope the statement with a WHERE clause parameterised on the authenticated caller's id/tenant (e.g. `WHERE id = $2`).",
        precisionTier: "review",
      }),
    );
  }
  // #354 — Next.js middleware matcher whose lookahead excludes /api routes.
  if (MW_MATCHER_EXCLUDES_API.test(file.content)) {
    findings.push(
      mechanicalFinding({
        id: `AUTH-mw-matcher-excludes-api-${slug(file.path)}`,
        title: `${file.path} — middleware matcher excludes /api routes`,
        severity: "High",
        category: "Broken access control",
        taxonomy: "Middleware matcher excludes /api routes",
        location: file.path,
        evidence: `Heuristic "mw-matcher-excludes-api" matched an exported config.matcher whose negative-lookahead excludes paths beginning with "api" in ${file.path}.`,
        impact: "Every /api/* route is exempt from this middleware, so any auth/gate it enforces never runs for API routes — they are reachable directly.",
        fix: "Remove `api` from the matcher's exclusion lookahead, or confirm every API route enforces its own auth independently of the middleware.",
        precisionTier: "review",
      }),
    );
  }
  // #354 — draftMode().enable() reachable with no secret/token comparison in the same file.
  if (DRAFTMODE_ENABLE.test(file.content) && !DRAFTMODE_SECRET_HINT.test(file.content)) {
    findings.push(
      mechanicalFinding({
        id: `AUTH-draftmode-no-secret-${slug(file.path)}`,
        title: `${file.path} — draftMode().enable() with no secret check`,
        severity: "Medium",
        category: "Broken access control",
        taxonomy: "draftMode().enable() reachable with no secret",
        location: file.path,
        evidence: `Heuristic "draftmode-no-secret" matched a draftMode().enable() call with no secret/token comparison (process.env.*SECRET / req.*.secret) anywhere in ${file.path}.`,
        impact: "Any caller can flip on Next.js Draft/Preview mode and read unpublished/draft content on every page that honours it.",
        fix: "Compare a shared secret (e.g. req.query.secret against process.env.PREVIEW_SECRET) and return 401 before calling draftMode().enable().",
        precisionTier: "review",
      }),
    );
  }
  return findings;
}
