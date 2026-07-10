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

export interface RealtimeMessagesInfo {
  exists: boolean; // false when the realtime schema / messages table isn't present at all
  rlsEnabled: boolean;
}

// Realtime Authorization gates broadcast/presence through RLS policies on realtime.messages.
// If RLS is disabled on that table, every subscriber with the anon key receives every channel's
// messages regardless of channel privacy — the clear, DB-decidable misconfiguration. Whether an
// app that *does* keep RLS on has actually marked its channels private is a client-code fact this
// check can't see, so it only fires on the unambiguous RLS-off case and stays "review".
export function checkRealtimeAuthorization(realtime: RealtimeMessagesInfo): Finding[] {
  if (!realtime.exists || realtime.rlsEnabled) return [];
  return [
    mechanicalFinding({
      id: "SB-REALTIME-NO-AUTHZ",
      title: "Realtime messages table has RLS disabled — channels are unauthorized",
      severity: "High",
      category: "Supabase config",
      taxonomy: "Realtime channel lacks authorization",
      location: "realtime.messages",
      evidence: "realtime.messages has row-level security disabled.",
      impact: "Realtime Authorization is enforced by RLS on realtime.messages; with RLS off, any client holding the anon key can subscribe to broadcast/presence on any channel and receive other users' messages.",
      fix: "Enable RLS on realtime.messages and add policies scoping channel access, and mark private channels with { config: { private: true } } on the client.",
      precisionTier: "review",
    }),
  ];
}

// PostgREST auto-exposes the schemas listed in its db-schema config over the REST/GraphQL API.
// The Supabase default is public + graphql_public; any additional schema is directly reachable
// with the anon key, so a broader list than intended is an exposure. Whether the extra schema is
// *meant* to be public is a judgment call → "review".
const DEFAULT_EXPOSED_SCHEMAS = new Set(["public", "graphql_public"]);

export function checkExposedSchemas(exposedSchemas: string[]): Finding[] {
  return exposedSchemas
    .map((s) => s.trim())
    .filter((s) => s && !DEFAULT_EXPOSED_SCHEMAS.has(s))
    .map((schema) =>
      mechanicalFinding({
        id: `SB-API-SCHEMA-${schema}`,
        title: `Schema "${schema}" is exposed over the PostgREST API`,
        severity: "Medium",
        category: "Supabase config",
        taxonomy: "PostgREST schema exposure wider than intended",
        location: `exposed schema: ${schema}`,
        evidence: `PostgREST db-schema config exposes "${schema}" beyond the public/graphql_public default.`,
        impact: "Every table/function in the schema is reachable with the anon key (subject to grants/RLS) — an exposure surface that's easy to widen unintentionally.",
        fix: "Remove the schema from the exposed API schemas unless it's deliberately public; keep internal data in an unexposed schema.",
        precisionTier: "review",
      }),
    );
}

// pg_graphql serves a GraphQL API (with introspection) at the graphql_public schema. It's only
// reachable if the extension is installed AND graphql_public is in the exposed schema list;
// introspection then lets anyone enumerate the exposed graph. Both facts are read live.
export function checkGraphqlIntrospection(pgGraphqlInstalled: boolean, exposedSchemas: string[]): Finding[] {
  if (!pgGraphqlInstalled || !exposedSchemas.map((s) => s.trim()).includes("graphql_public")) return [];
  return [
    mechanicalFinding({
      id: "SB-GRAPHQL-INTROSPECTION",
      title: "pg_graphql API is exposed with introspection enabled",
      severity: "Medium",
      category: "Supabase config",
      taxonomy: "pg_graphql introspection enabled in production",
      location: "graphql_public",
      evidence: "pg_graphql is installed and graphql_public is in the exposed API schemas.",
      impact: "The GraphQL endpoint answers introspection queries, letting anyone with the anon key enumerate the full exposed schema graph — a reconnaissance aid for finding weakly-protected tables/functions.",
      fix: "Disable the GraphQL API in production if unused, or remove graphql_public from the exposed schemas; introspection can't be selectively disabled while the endpoint is live.",
      precisionTier: "review",
    }),
  ];
}

// Self-hosted GoTrue (Supabase Auth) version checks. Hosted Supabase auto-patches GoTrue, so
// these only matter for self-hosted deployments — the finding text says so. Version comes from
// the running auth server (GET {project}/auth/v1/health); providers from the auth config.
export interface GotrueInfo {
  version: string | null; // e.g. "v2.170.0" or "2.170.0"
  appleEnabled?: boolean;
  azureEnabled?: boolean;
}

// Compares dotted numeric versions ("2.170.0"). Returns -1 / 0 / 1. Non-numeric/short parts
// are treated as 0 so "v2.170" ~ "2.170.0".
export function compareVersions(a: string, b: string): number {
  const pa = a.replace(/^v/, "").split(".");
  const pb = b.replace(/^v/, "").split(".");
  for (let i = 0; i < 3; i++) {
    const na = Number(pa[i] ?? 0) || 0;
    const nb = Number(pb[i] ?? 0) || 0;
    if (na !== nb) return na < nb ? -1 : 1;
  }
  return 0;
}

export function checkGotrueVersion(gotrue: GotrueInfo): Finding[] {
  const { version } = gotrue;
  if (!version) return [];
  const findings: Finding[] = [];

  // GHSA-v36f-qvww-8w8m: OIDC issuer-verification bypass, fixed in 2.185.0, exploitable only
  // with the Apple or Azure provider enabled (they share the affected id-token path).
  if (compareVersions(version, "2.185.0") < 0 && (gotrue.appleEnabled || gotrue.azureEnabled)) {
    findings.push(
      mechanicalFinding({
        id: "SB-GOTRUE-OIDC-BYPASS",
        title: `Self-hosted GoTrue ${version} is vulnerable to OIDC issuer-verification bypass (GHSA-v36f-qvww-8w8m)`,
        severity: "High",
        category: "Supabase config",
        taxonomy: "Self-hosted GoTrue OIDC issuer bypass",
        location: `GoTrue ${version}`,
        evidence: `Running GoTrue ${version} (< 2.185.0) with Apple/Azure OIDC enabled.`,
        impact: "Applies to self-hosted Supabase Auth only. The issuer claim isn't verified, so a token from an attacker-controlled issuer can be accepted — account takeover via forged OIDC id-tokens.",
        fix: "Upgrade self-hosted GoTrue to ≥ 2.185.0. (Hosted Supabase projects are already patched.)",
        precisionTier: "review",
      }),
    );
  }

  // GHSA-3529-5m8x-rpv3: email-link poisoning via X-Forwarded-Host, affects 2.67.1–2.163.0.
  if (compareVersions(version, "2.67.1") >= 0 && compareVersions(version, "2.163.0") <= 0) {
    findings.push(
      mechanicalFinding({
        id: "SB-GOTRUE-HOST-POISON",
        title: `Self-hosted GoTrue ${version} is vulnerable to email-link poisoning via X-Forwarded-Host (GHSA-3529-5m8x-rpv3)`,
        severity: "High",
        category: "Supabase config",
        taxonomy: "Self-hosted GoTrue email-link poisoning",
        location: `GoTrue ${version}`,
        evidence: `Running GoTrue ${version} (in the affected 2.67.1–2.163.0 range).`,
        impact: "Applies to self-hosted Supabase Auth only. A spoofed X-Forwarded-Host header poisons confirmation/reset links in outbound emails, redirecting the token to an attacker's host.",
        fix: "Upgrade self-hosted GoTrue past 2.163.0 and constrain trusted proxy headers at the reverse proxy. (Hosted Supabase projects are already patched.)",
        precisionTier: "review",
      }),
    );
  }

  return findings;
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
