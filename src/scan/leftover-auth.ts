// Leftover-auth greps: stubbed-out or forgotten auth guards left in from development.
// Pure text patterns — no tool binary, no AST — so every hit here is "review" precision:
// a grep can't tell a genuinely bypassed guard from `// TODO: auth` in a comment explaining
// why auth is deliberately deferred, or `isAdmin = true` in a test fixture.

import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";
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
const AUTH_HINT = /(getServerSession|auth\(\)|requireAuth|withAuth|assertAuth|supabase\.auth\.getUser|createServerClient)/;
const ROUTE_FILE = /(^|\/)(route\.(ts|tsx|js)|pages\/api\/.*\.(ts|tsx|js))$/;

// B7 (#71): a login/signup/OTP/password-reset route with no rate-limiter hint — an attacker can
// brute-force credentials/OTP codes with unlimited attempts. Same grep-and-hint shape as the
// sensitive-route check above (review tier — a limiter living in middleware/an edge config this
// file can't see is a false negative, not a gate concern).
const AUTH_SENSITIVE_ROUTE = /(^|\/)(login|signin|sign-in|signup|sign-up|register|otp|reset-password|forgot-password)(\/|$|\.)/i;
const RATE_LIMIT_HINT = /(rateLimit|ratelimit|Ratelimit|limiter\.)/;

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
];

const UPLOAD_SINK = /storage\s*\.\s*from\s*\([^)]*\)\s*\.\s*upload\s*\(/;
const UPLOAD_LIMIT_HINT = /content-?length|max[_-]?size|file[_-]?size|\.size\b|allowed[_-]?(types|mime)|mimetype|content-?type\s*[:=]|accept\s*:/i;
const WEBHOOK_PATH = /webhook/i;
const WEBHOOK_PRIVILEGED_WRITE = /\.(insert|update|delete|upsert|rpc)\s*\(|admin\.from|supabaseAdmin/i;
const WEBHOOK_SIG_HINT = /createHmac|constructEvent|timingSafeEqual|verif\w*Signature|x-signature|stripe-signature|hub-signature|svix|webhook[_-]?secret/i;

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
  return findings;
}

const SKIP_DIRS = new Set(["node_modules", ".git", ".next", "dist", "build", "coverage"]);
const SOURCE_EXT = /\.(ts|tsx|js|jsx|mjs|cjs)$/;

function walk(dir: string, root: string, out: SourceFile[]): void {
  for (const entry of readdirSync(dir)) {
    if (SKIP_DIRS.has(entry)) continue;
    const full = join(dir, entry);
    const stat = statSync(full);
    if (stat.isDirectory()) {
      walk(full, root, out);
    } else if (SOURCE_EXT.test(entry)) {
      out.push({ path: relative(root, full), content: readFileSync(full, "utf8") });
    }
  }
}

export function scanLeftoverAuth(projectDir: string): Finding[] {
  const files: SourceFile[] = [];
  walk(projectDir, projectDir, files);
  return files.flatMap(classifyLeftoverAuth);
}
