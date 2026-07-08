// Supabase project-config checks that sit outside the Advisor lint set: Storage bucket
// policy coverage, auto-exposed public-schema tables, Auth config, dangerous extensions,
// and Edge Function secret/webhook-signature hygiene. See src/scan/supabase.ts for how each
// input is fetched (Management API / direct SQL against the project).

import type { Finding } from "../findings.js";
import { mechanicalFinding } from "./common.js";

export interface StorageBucket {
  id: string;
  name: string;
  public: boolean;
}

// policyCountByBucket: number of storage.objects RLS policies scoped to each bucket (by id).
// A public bucket is fully open regardless of policies (public buckets skip storage RLS for
// reads), but zero policies also means no write/delete restriction either — the highest-risk
// combination, and what the issue calls out specifically.
export function checkPublicBucketsWithNoPolicies(buckets: StorageBucket[], policyCountByBucket: Record<string, number>): Finding[] {
  return buckets
    .filter((b) => b.public && (policyCountByBucket[b.id] ?? 0) === 0)
    .map((b) =>
      mechanicalFinding({
        id: `SB-BUCKET-${b.id}`,
        title: `Public storage bucket "${b.name}" has zero access policies`,
        severity: "High",
        category: "Supabase config",
        taxonomy: "Public bucket with no policies",
        location: `storage bucket: ${b.name}`,
        evidence: `Bucket "${b.name}" (public=true) has 0 storage.objects policies scoped to it.`,
        impact: "Anyone can read every object, and with no policy restricting writes/deletes either, likely write/delete too.",
        fix: "Add object-level RLS policies scoping access, or set the bucket private and serve via signed URLs.",
        precisionTier: "high",
      }),
    );
}

export interface TableInfo {
  schema: string;
  name: string;
  rlsEnabled: boolean;
}

// public-schema tables are auto-exposed via PostgREST/pg_graphql. A SQL-migration-created
// table can land here before the Advisor cache picks it up, so this is checked directly
// against the live table list rather than only via the rls_disabled_in_public advisor lint.
export function checkAutoExposedTables(tables: TableInfo[]): Finding[] {
  return tables
    .filter((t) => t.schema === "public" && !t.rlsEnabled)
    .map((t) =>
      mechanicalFinding({
        id: `SB-EXPOSED-${t.schema}-${t.name}`,
        title: `public.${t.name} has RLS disabled and is auto-exposed via PostgREST`,
        severity: "Critical",
        category: "Supabase config",
        taxonomy: "Auto-exposed public-schema table",
        location: `${t.schema}.${t.name}`,
        evidence: `Table is in the public schema (auto-exposed by PostgREST/pg_graphql) with row-level security disabled.`,
        impact: "Every row is readable/writable (subject to grants) by anyone holding the anon key — no per-row restriction.",
        fix: "Enable RLS and add policies, or move the table out of the exposed API schema.",
        precisionTier: "high",
      }),
    );
}

// Field names below follow the commonly-documented Supabase Auth config keys
// (mailer_autoconfirm, security_captcha_enabled, password_hibp_enabled, otp_expiry,
// rate_limit_*, uri_allow_list). Not independently re-verified against a live
// GET /v1/projects/{ref}/config/auth response in this session — confirm the exact field
// names against that response before wiring to a real scan run, and adjust this interface
// if any differ.
export interface AuthConfig {
  mailer_autoconfirm?: boolean; // true = signups are auto-confirmed without email verification
  password_hibp_enabled?: boolean; // leaked-password (HaveIBeenPwned) protection
  otp_expiry?: number; // seconds
  uri_allow_list?: string; // comma-separated redirect/OAuth allowlist
  rate_limit_email_sent?: number;
}

const OTP_EXPIRY_WARN_SECONDS = 3600; // 1 hour — flag anything longer as worth a second look

export function checkAuthConfig(config: AuthConfig): Finding[] {
  const findings: Finding[] = [];

  if (config.mailer_autoconfirm === true) {
    findings.push(
      mechanicalFinding({
        id: "SB-AUTH-AUTOCONFIRM",
        title: "Email confirmation is disabled (auto-confirm on signup)",
        severity: "Medium",
        category: "Supabase config",
        taxonomy: "Auth config: email confirmation disabled",
        location: "Auth config",
        evidence: "mailer_autoconfirm=true.",
        impact: "Accounts can authenticate without proving ownership of the email address — enables mass fake-account signup and email-enumeration-free account takeover setups.",
        fix: "Disable auto-confirm unless deliberately building a frictionless-signup product with a compensating control.",
        precisionTier: "review",
      }),
    );
  }

  if (config.password_hibp_enabled === false) {
    findings.push(
      mechanicalFinding({
        id: "SB-AUTH-HIBP",
        title: "Leaked-password protection is disabled",
        severity: "Low",
        category: "Supabase config",
        taxonomy: "Auth config: leaked-password protection off",
        location: "Auth config",
        evidence: "password_hibp_enabled=false.",
        impact: "Users can set passwords already known to be compromised in public breach corpora.",
        fix: "Enable leaked-password protection in the Auth config.",
        precisionTier: "review",
      }),
    );
  }

  if (typeof config.otp_expiry === "number" && config.otp_expiry > OTP_EXPIRY_WARN_SECONDS) {
    findings.push(
      mechanicalFinding({
        id: "SB-AUTH-OTP-EXPIRY",
        title: `OTP expiry is ${config.otp_expiry}s — longer than the ${OTP_EXPIRY_WARN_SECONDS}s baseline`,
        severity: "Low",
        category: "Supabase config",
        taxonomy: "Auth config: long OTP expiry",
        location: "Auth config",
        evidence: `otp_expiry=${config.otp_expiry}.`,
        impact: "A longer-lived OTP widens the window for interception/replay.",
        fix: "Shorten OTP expiry unless there's a specific UX reason for the longer window.",
        precisionTier: "review",
      }),
    );
  }

  if (config.uri_allow_list?.includes("*")) {
    findings.push(
      mechanicalFinding({
        id: "SB-AUTH-REDIRECT-WILDCARD",
        title: "OAuth/redirect allowlist contains a wildcard",
        severity: "High",
        category: "Supabase config",
        taxonomy: "Auth config: wildcard redirect allowlist",
        location: "Auth config",
        evidence: `uri_allow_list="${config.uri_allow_list}".`,
        impact: "A wildcarded redirect allowlist enables open-redirect-based auth token theft.",
        fix: "Replace the wildcard with an explicit list of allowed redirect URIs.",
        precisionTier: "review",
      }),
    );
  }

  return findings;
}

export interface ExtensionInfo {
  name: string;
  schema: string | null;
  installed_version: string | null;
}

const DANGEROUS_EXTENSIONS = new Set(["pg_net", "http"]);

// Enabling pg_net/http is a deterministic fact (installed_version present); whether it's
// reachable from a permissive/SECURITY DEFINER path needs source review this check can't do
// on its own → "review" precision.
export function checkDangerousExtensions(extensions: ExtensionInfo[]): Finding[] {
  return extensions
    .filter((e) => DANGEROUS_EXTENSIONS.has(e.name) && e.installed_version)
    .map((e) =>
      mechanicalFinding({
        id: `SB-EXT-${e.name}`,
        title: `Extension "${e.name}" is enabled — outbound HTTP callable from the database`,
        severity: "Medium",
        category: "Supabase config",
        taxonomy: "Dangerous extension enabled",
        location: `extension: ${e.name}${e.schema ? ` (schema ${e.schema})` : ""}`,
        evidence: `${e.name}@${e.installed_version} is installed.`,
        impact: "If callable from a permissive role or a SECURITY DEFINER function with an attacker-influenceable URL, this is a DB-originated SSRF primitive.",
        fix: "Confirm no permissive/SECURITY DEFINER function calls this extension with an untrusted URL; revoke EXECUTE from anon/authenticated where not needed.",
        precisionTier: "review",
      }),
    );
}

export interface EdgeFunctionSource {
  name: string;
  content: string;
}

const HARDCODED_SECRET_HINT = /(SUPABASE_SERVICE_ROLE_KEY\s*=\s*["'][^"']|service_role["']?\s*:\s*["'][^"']{10,}|Authorization["']?\s*:\s*["']Bearer\s+sk_)/;

// Heuristic grep for a secret assigned as a literal instead of read from Deno.env — always
// "review" precision, same class as the leftover-auth greps.
export function checkEdgeFunctionSecrets(fns: EdgeFunctionSource[]): Finding[] {
  return fns
    .filter((f) => HARDCODED_SECRET_HINT.test(f.content))
    .map((f) =>
      mechanicalFinding({
        id: `SB-EDGE-SECRET-${f.name}`,
        title: `Edge function "${f.name}" may hardcode a secret instead of reading it from env`,
        severity: "High",
        category: "Supabase config",
        taxonomy: "Edge function secret handling",
        location: `edge function: ${f.name}`,
        evidence: `Pattern matching a literal secret assignment found in ${f.name}.`,
        impact: "A hardcoded secret ships with the function bundle and any git history it's committed to.",
        fix: "Read the secret from Deno.env.get(...) (backed by a Supabase project secret), not a literal.",
        precisionTier: "review",
      }),
    );
}

const SIGNATURE_CHECK_HINT = /(verifyWebhookSignature|constructEvent|x-webhook-signature|hmac|createHmac|timingSafeEqual)/i;

export function checkUnsignedWebhookHandlers(fns: EdgeFunctionSource[]): Finding[] {
  return fns
    .filter((f) => /webhook/i.test(f.name) && !SIGNATURE_CHECK_HINT.test(f.content))
    .map((f) =>
      mechanicalFinding({
        id: `SB-EDGE-WEBHOOK-${f.name}`,
        title: `Webhook handler "${f.name}" has no signature-verification hint`,
        severity: "High",
        category: "Supabase config",
        taxonomy: "Unsigned/unverified webhook handler",
        location: `edge function: ${f.name}`,
        evidence: `No HMAC/signature-check pattern found in ${f.name}, whose name implies it's a webhook receiver.`,
        impact: "An unsigned webhook endpoint accepts forged events from anyone who finds the URL.",
        fix: "Verify the provider's webhook signature (HMAC) before trusting the payload.",
        precisionTier: "review",
      }),
    );
}
