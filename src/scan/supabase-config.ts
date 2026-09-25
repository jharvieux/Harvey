// Supabase project-config checks that sit outside the Advisor lint set: Storage bucket
// policy coverage, auto-exposed public-schema tables, Auth config, dangerous extensions,
// and Edge Function secret/webhook-signature hygiene. See src/scan/supabase.ts for how each
// input is fetched (Management API / direct SQL against the project).

import type { SourceInput } from "../detectors/common.js";
import { assessWebhookVerification } from "./webhook-proof.js";
import type { Finding } from "../findings.js";
import { mechanicalFinding } from "./common.js";
import type { TableAuthorization } from "./supabase-authorization.js";

export interface StorageBucket {
  id: string;
  name: string;
  public: boolean;
}

// policyCountByBucket: number of storage.objects RLS policies scoped to each bucket (by id).
// Public object reads and SQL write authorization are separate contexts. A missing
// bucket-specific predicate is inventory, not evidence of an allowed write/delete path.
export function checkPublicBucketsWithNoPolicies(buckets: StorageBucket[], policyCountByBucket: Record<string, number>): Finding[] {
  return buckets
    .filter((b) => b.public && (policyCountByBucket[b.id] ?? 0) === 0)
    .map((b) =>
      mechanicalFinding({
        id: `SB-BUCKET-${b.id}`,
        title: `Public storage bucket "${b.name}" has zero access policies`,
        severity: "Info",
        category: "Supabase config",
        taxonomy: "Public bucket with no policies",
        location: `storage bucket: ${b.name}`,
        evidence: `Bucket "${b.name}" (public=true) has 0 storage.objects policies scoped to it.`,
        impact: "The public flag permits public object reads. This policy count establishes no write/delete access: enabled RLS denies ordinary roles without an applicable permissive policy, and generic policies may not name a bucket literally.",
        fix: "Confirm public reads are intended and review applicable write/delete policies separately; use private buckets and signed URLs for private objects.",
        precisionTier: "review",
      }),
    );
}

export interface TableInfo {
  schema: string;
  name: string;
  rlsEnabled: boolean;
}

// RLS state alone is posture. The effective-authorization pass owns row-read exposure.
export function checkAutoExposedTables(tables: TableInfo[], authorization: readonly TableAuthorization[] = []): Finding[] {
  return tables
    .filter((t) => t.schema === "public" && !t.rlsEnabled)
    .map((t) =>
      mechanicalFinding({
        id: `SB-EXPOSED-${t.schema}-${t.name}`,
        title: `public.${t.name} has RLS disabled; evaluate effective access`,
        severity: "Info",
        category: "Supabase config",
        taxonomy: "RLS-disabled table inventory",
        location: `${t.schema}.${t.name}`,
        evidence: `Table is in public with RLS disabled. ${authorization.find((a) => a.schema === t.schema && a.name === t.name)?.detail ?? "Effective grants, roles and API schema reachability were not established for this inventory row."}`,
        impact: "RLS-disabled metadata does not establish current client access. Schema usage, table/column grants and an API or SQL caller path must also be established.",
        fix: "Enable RLS and add policies, or move the table out of the exposed API schema.",
        precisionTier: "review",
      }),
    );
}

// Every field the scan reads off the Supabase Management API GET /v1/projects/{ref}/config/auth
// response, mapped to the JSON type that response declares for it. #1098: this list is the single
// source of truth — the AuthConfig type below is derived from it, and supabase-config.test.ts
// checks every entry against the captured AuthConfigResponse schema
// (src/scan/__fixtures__/supabase/, see its PROVENANCE.md). A key that only exists in the CLI's
// config.toml now fails the build instead of quietly never firing, which is how `otp_expiry` — the
// config.toml spelling of mailer_otp_exp — survived as a dead check.
export const AUTH_CONFIG_FIELDS = {
  mailer_autoconfirm: "boolean", // true = signups are auto-confirmed without email verification
  password_hibp_enabled: "boolean", // leaked-password (HaveIBeenPwned) protection
  mailer_otp_exp: "integer", // email OTP lifetime, seconds
  sms_otp_exp: "integer", // SMS OTP lifetime, seconds
  uri_allow_list: "string", // comma-separated redirect/OAuth allowlist
  rate_limit_email_sent: "integer",
  // #671 — which auth methods this project has enabled. An auth-config advisor that only protects a
  // specific method (leaked-password → password; email confirmation → email; OTP expiry → OTP) is a
  // not-applicable false positive on a project that doesn't use that method (ATC was OAuth-only, so
  // leaked-password protection had no password sign-up to protect). The same two enablement signals
  // appear as external.email / external.phone in the anon-key GoTrue /auth/v1/settings response
  // (verified live 2026-07-19).
  external_email_enabled: "boolean", // email provider (password sign-in + email magic-link/OTP)
  external_phone_enabled: "boolean", // phone provider (SMS OTP)
} as const;

type JsonType = { boolean: boolean; integer: number; string: string };

// Every field is optional: a response that drops one (or a source-tier caller that only knows some)
// must leave the corresponding check unrun rather than read undefined as a value.
export type AuthConfig = { [K in keyof typeof AUTH_CONFIG_FIELDS]?: JsonType[(typeof AUTH_CONFIG_FIELDS)[K]] };

// #671 — tri-state enablement of an auth method: true = confirmed enabled, false = confirmed
// disabled, undefined = could not confirm (a source-tier heuristic with no evidence, or a live
// response that didn't carry the flag). Only a confirmed-enabled method keeps an asserted severity.
export type AuthMethodState = boolean | undefined;

export interface AuthMethods {
  email: AuthMethodState; // email provider: password sign-in + email magic-link/OTP
  phone: AuthMethodState; // phone provider: SMS OTP
}

// True if EITHER method is enabled; false only when BOTH are confirmed off; otherwise unconfirmed.
export function eitherEnabled(a: AuthMethodState, b: AuthMethodState): AuthMethodState {
  if (a === true || b === true) return true;
  if (a === false && b === false) return false;
  return undefined;
}

export function deriveAuthMethods(config: Pick<AuthConfig, "external_email_enabled" | "external_phone_enabled">): AuthMethods {
  return { email: config.external_email_enabled, phone: config.external_phone_enabled };
}

type AuthAdvisorInput = Parameters<typeof mechanicalFinding>[0];

// #671 — an auth-config advisor only applies when the auth method it protects is actually in use.
// Confirmed-on → return the finding unchanged (asserted severity). Off OR unconfirmed → keep the
// finding (fail-loud: still surfaced, same id/taxonomy so a re-audit still matches it) but reframe
// it to an Info-tier conditional note, never an asserted Medium against an inapplicable method.
export function gateOnAuthMethod(input: AuthAdvisorInput, methodLabel: string, state: AuthMethodState): AuthAdvisorInput {
  if (state === true) return input;
  const situation =
    state === false
      ? `${methodLabel} is not enabled on this project, so this is not currently applicable`
      : `Harvey could not confirm whether ${methodLabel} is enabled for this engagement`;
  return {
    ...input,
    severity: "Info",
    confidence: "N/A",
    title: `${input.title} — conditional (applies only if ${methodLabel} is enabled)`,
    impact: `Only applies when ${methodLabel} is enabled: ${situation}. If it is enabled: ${input.impact} Re-assess if it is turned on.`,
  };
}

const OTP_EXPIRY_WARN_SECONDS = 3600; // 1 hour — flag anything longer as worth a second look

// #1098 — the API carries the two OTP lifetimes as separate fields, so each is gated on the
// provider that actually issues it: a long email-OTP window is not a finding on a phone-only
// project, and vice versa. (The advisor path's auth_otp_long_expiry lint reports one blended fact,
// so it still gates on eitherEnabled — see supabase-advisors.ts.)
const OTP_CHANNELS = [
  { key: "mailer_otp_exp", id: "SB-AUTH-OTP-EXPIRY-EMAIL", label: "email", method: "email" },
  { key: "sms_otp_exp", id: "SB-AUTH-OTP-EXPIRY-SMS", label: "SMS", method: "phone" },
] as const;

// #671 — authMethods gates the password/email/OTP-specific advisors below on whether that method is
// actually in use. Defaults to what the config itself carries (external_email_enabled /
// external_phone_enabled); the source tier passes an inferred value instead. The wildcard-redirect
// advisor is NOT gated — a redirect allowlist protects every redirect-based flow, OAuth included.
export function checkAuthConfig(config: AuthConfig, authMethods: AuthMethods = deriveAuthMethods(config)): Finding[] {
  const findings: Finding[] = [];

  if (config.mailer_autoconfirm === true) {
    findings.push(
      mechanicalFinding(gateOnAuthMethod({
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
      }, "email authentication", authMethods.email)),
    );
  }

  if (config.password_hibp_enabled === false) {
    findings.push(
      mechanicalFinding(gateOnAuthMethod({
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
      }, "password authentication", authMethods.email)),
    );
  }

  for (const channel of OTP_CHANNELS) {
    const seconds = config[channel.key];
    if (typeof seconds !== "number" || seconds <= OTP_EXPIRY_WARN_SECONDS) continue;
    findings.push(
      mechanicalFinding(gateOnAuthMethod({
        id: channel.id,
        title: `OTP expiry for ${channel.label} is ${seconds}s — longer than the ${OTP_EXPIRY_WARN_SECONDS}s baseline`,
        severity: "Low",
        category: "Supabase config",
        taxonomy: "Auth config: long OTP expiry",
        location: "Auth config",
        evidence: `${channel.key}=${seconds}.`,
        impact: "A longer-lived OTP widens the window for interception/replay.",
        fix: "Shorten OTP expiry unless there's a specific UX reason for the longer window.",
        precisionTier: "review",
      }, `${channel.label} OTP`, authMethods[channel.method])),
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
        title: `Extension "${e.name}" is installed; outbound access needs review`,
        severity: "Info",
        category: "Supabase config",
        taxonomy: "Dangerous extension enabled",
        location: `extension: ${e.name}${e.schema ? ` (schema ${e.schema})` : ""}`,
        evidence: `${e.name}@${e.installed_version} is installed. No attacker-controlled URL, executable function grant, or reachable caller path is established by extension presence.`,
        impact: "This is capability inventory, not a demonstrated outbound-access or SSRF finding. A concrete callable path and controllable destination require separate evidence.",
        fix: "Confirm no permissive/SECURITY DEFINER function calls this extension with an untrusted URL; revoke EXECUTE from anon/authenticated where not needed.",
        precisionTier: "review",
      }),
    );
}

export interface EdgeFunctionSource {
  name: string;
  content: string;
  /** Target-relative entrypoint path. Required for cross-file verifier proof. */
  path?: string;
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

// Realtime Authorization uses RLS policies on realtime.messages. Actual channel privacy,
// subscriber grants and the application's channel use depend on runtime context that this
// check can't see, so it only fires on the unambiguous RLS-off case and stays "review".
export function checkRealtimeAuthorization(realtime: RealtimeMessagesInfo): Finding[] {
  if (!realtime.exists || realtime.rlsEnabled) return [];
  return [
    mechanicalFinding({
      id: "SB-REALTIME-NO-AUTHZ",
      title: "Realtime messages table has RLS disabled; review channel authorization",
      severity: "Info",
      category: "Supabase config",
      taxonomy: "Realtime channel lacks authorization",
      location: "realtime.messages",
      evidence: "realtime.messages has row-level security disabled.",
      impact: "This is channel authorization posture. RLS state alone does not establish the subscriber's grants, channel configuration or a reachable broadcast/presence path; client access remains review.",
      fix: "Enable RLS on realtime.messages and add policies scoping channel access, and mark private channels with { config: { private: true } } on the client.",
      precisionTier: "review",
    }),
  ];
}

export interface PublishedTable {
  schema: string;
  name: string;
  rlsEnabled: boolean;
}

// Publication membership and RLS state are catalog posture. Effective subscriber grants and
// the Realtime caller path need separate evidence before asserting row delivery. Fires only
// on the unambiguous RLS-off case, so "review".
export function checkRealtimePublicationRls(published: PublishedTable[]): Finding[] {
  return published
    .filter((t) => !t.rlsEnabled)
    .map((t) =>
      mechanicalFinding({
        id: `SB-REALTIME-PUB-${t.schema}-${t.name}`,
        title: `Table ${t.schema}.${t.name} is published for Realtime with RLS disabled`,
        severity: "Info",
        category: "Supabase config",
        taxonomy: "Realtime publication broadcasts an unprotected table",
        location: `${t.schema}.${t.name}`,
        evidence: `${t.schema}.${t.name} is in the supabase_realtime publication and has row-level security disabled.`,
        impact: "Publication membership does not establish successful subscription or delivery to a client role. Effective grants and the Realtime caller path remain review; no cross-tenant row stream is proved by these two catalog facts.",
        fix: "Enable RLS with tenant-scoped policies on the table, or remove it from the supabase_realtime publication if it doesn't need live broadcast.",
        precisionTier: "review",
      }),
    );
}

// PostgREST makes configured schemas eligible for API routing; effective object privileges and
// row policies still govern access. Whether an extra schema beyond public + graphql_public is
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
        impact: "The schema is eligible for API routing. Current schema usage, object grants, row policies and function context determine which client operations are reachable.",
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

export interface DefaultAclGrant {
  schema: string;
  role: string;
  objectType: string; // decoded from pg_default_acl.defaclobjtype: "table" | "function" | "sequence" | ...
  privileges: string[];
  owner?: string;
}

const catalogIdPart = (value: string) => encodeURIComponent(value).replaceAll("-", "%2D");

// Default ACLs describe future objects created by the named owner, a posture the current
// tables checks above can't see. A deliberate public grant (e.g. a public read API) can be
// intended; keep its catalog record without asserting current exposure.
export function checkDefaultPrivilegesToClientRoles(grants: DefaultAclGrant[]): Finding[] {
  return grants.map((g) =>
    mechanicalFinding({
      id: `SB-DEFAULT-ACL-${[g.schema, g.role, g.objectType, ...(g.owner ? [g.owner] : [])].map(catalogIdPart).join("-")}`,
      title: `Default privileges auto-grant future ${g.objectType}s in schema "${g.schema}" to ${g.role}`,
      severity: "Info",
      category: "Supabase config",
      taxonomy: "Default privileges grant future objects to client role",
      location: `schema ${g.schema}: default privileges for ${g.role}`,
      evidence: `Default ACL in schema "${g.schema}" grants ${g.privileges.join(", ")} on future ${g.objectType}s to role "${g.role}"${g.owner ? ` when created by "${g.owner}"` : " (creating owner not supplied)"}.`,
      impact: "Future-object posture does not establish access to any current object. A current object's effective grants, schema usage, RLS and caller context determine exposure; later revokes also apply.",
      fix: `Confirm the creating owner's default grant is intentional; otherwise revoke the relevant default privileges${g.schema === "(global)" ? " globally" : ` in schema ${g.schema}`} for that owner and grant per object as needed.`,
      precisionTier: "review",
    }),
  );
}

export interface ColumnGrant {
  schema: string;
  tableName: string;
  columnName: string;
  role: string;
  privilegeType: string;
}

// Explicit column-level GRANTs (GRANT SELECT (col) ON table TO role) live in pg_attribute.attacl,
// separate from the table-wide ACL in pg_class.relacl. information_schema.role_column_grants was
// considered instead (per the issue brief) but it also surfaces every column of a table that only
// has a table-wide grant — which is Supabase's default anon/authenticated grant shape relying on
// RLS — so querying it directly would flood every project with false positives. attacl is only
// populated by an actual column-level grant. Those grants remain subject to row policies.
export function checkColumnGrantsToClientRoles(grants: ColumnGrant[], authorization: readonly TableAuthorization[] = []): Finding[] {
  return grants.map((g) =>
    mechanicalFinding({
      id: `SB-COLUMN-GRANT-${[g.schema, g.tableName, g.columnName, g.role, g.privilegeType].map(catalogIdPart).join("-")}`,
      title: `Column-level ${g.privilegeType} grant on ${g.schema}.${g.tableName}.${g.columnName} to ${g.role}`,
      severity: "Info",
      category: "Supabase config",
      taxonomy: "Column-level privilege inventory",
      location: `${g.schema}.${g.tableName}.${g.columnName}`,
      evidence: `${g.privilegeType} on column ${g.schema}.${g.tableName}.${g.columnName} is granted to role "${g.role}" directly or through PUBLIC/inheritance. ${authorization.find((a) => a.schema === g.schema && a.name === g.tableName)?.detail ?? "Effective row-policy and role context was not established for this inventory row."}`,
      impact: "A column grant permits the named operation on that column; it does not bypass enabled RLS. Ordinary roles remain limited by applicable policies, including deny-by-default when no permissive policy applies.",
      fix: "Confirm the column grant is deliberate; otherwise REVOKE it and rely on RLS policies (or a view) to control column-level exposure.",
      precisionTier: "review",
    }),
  );
}

export function checkUnsignedWebhookHandlers(fns: EdgeFunctionSource[], projectSources: readonly SourceInput[] = []): Finding[] {
  return fns
    .filter((f) => /webhook/i.test(f.name))
    .map((f) => ({ f, imported: assessWebhookVerification(f, projectSources) }))
    .filter(({ imported }) => !imported.verifiedBeforeEffect)
    .map(({ f, imported }) =>
      mechanicalFinding({
        id: `SB-EDGE-WEBHOOK-${f.name}`,
        title: `Webhook handler "${f.name}" has no proved signature-verification guard`,
        severity: "High",
        category: "Supabase config",
        taxonomy: "Unsigned/unverified webhook handler",
        location: `edge function: ${f.name}`,
        evidence: `Signature verification was not proved in ${f.name}; ${imported.provenance}. The call remains a review candidate because the request-to-verifier data flow and verification-before-effect order were not proved.`,
        impact: "Without a verified signature guard, forged webhook events can reach application effects.",
        fix: "Verify the provider's webhook signature (HMAC) before trusting the payload.",
        precisionTier: "review",
      }),
    );
}

export interface CronJob {
  jobid: number;
  schedule: string;
  command: string;
  nodename: string;
  database: string;
  username: string;
  active: boolean;
  isSuperuser: boolean;
}

const SECRET_LITERAL_HINT = /(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}|sk_[A-Za-z0-9]{16,}|['"][A-Za-z0-9+/]{32,}={0,2}['"])/;

// definerFunctionNames: unqualified names of SECURITY DEFINER functions in the target DB
// (pg_proc.prosecdef = true), used to flag a cron command that calls one. This is a
// name-matching cross-reference rather than running the full body classifier in
// src/definer-classifier.ts (which needs argNames/exposedTo/body from a separate live query
// only wired into the detect-deeper.ts pipeline) — matching the called function's name against
// the known-SECURITY-DEFINER set is enough signal for a review-tier finding without pulling
// that pipeline into this scan path.
export function checkCronJobs(jobs: CronJob[], definerFunctionNames: string[] = []): Finding[] {
  return jobs.flatMap((job) => {
    const findings: Finding[] = [];

    if (job.isSuperuser) {
      findings.push(
        mechanicalFinding({
          id: `SB-CRON-SUPERUSER-${job.jobid}`,
          title: `pg_cron job ${job.jobid} runs as superuser role "${job.username}"`,
          severity: "Medium",
          category: "Supabase config",
          taxonomy: "pg_cron job runs as a superuser role",
          location: `cron.job ${job.jobid} (${job.schedule})`,
          evidence: `cron.job row ${job.jobid} runs as "${job.username}" (superuser) on schedule "${job.schedule}".`,
          impact: "A scheduled job running with superuser privilege is an unreviewed, unattended surface — any command in it executes with full database privilege on every run.",
          fix: "Run scheduled jobs as a least-privilege role scoped to what the job needs, not a superuser role.",
          precisionTier: "review",
        }),
      );
    }

    const calledDefiner = definerFunctionNames.find((name) => new RegExp(`\\b${name}\\s*\\(`, "i").test(job.command));
    if (calledDefiner) {
      findings.push(
        mechanicalFinding({
          id: `SB-CRON-DEFINER-${job.jobid}`,
          title: `pg_cron job ${job.jobid} calls SECURITY DEFINER function "${calledDefiner}"`,
          severity: "Medium",
          category: "Supabase config",
          taxonomy: "pg_cron job calls a SECURITY DEFINER function",
          location: `cron.job ${job.jobid} (${job.schedule})`,
          evidence: `cron.job row ${job.jobid} command references SECURITY DEFINER function "${calledDefiner}": ${job.command}`,
          impact: "The job's privilege combines with whatever the SECURITY DEFINER function does internally — confirm the function's body doesn't do more than the scheduled task requires.",
          fix: "Review the called function's body for scope beyond the scheduled task, and confirm it isn't also EXECUTE-granted to anon/authenticated for unrelated reasons.",
          precisionTier: "review",
        }),
      );
    }

    if (SECRET_LITERAL_HINT.test(job.command)) {
      findings.push(
        mechanicalFinding({
          id: `SB-CRON-SECRET-${job.jobid}`,
          title: `pg_cron job ${job.jobid} command may embed a secret literal`,
          severity: "High",
          category: "Supabase config",
          taxonomy: "pg_cron job embeds a secret-shaped literal",
          location: `cron.job ${job.jobid} (${job.schedule})`,
          evidence: `cron.job row ${job.jobid} command matches a secret-shaped literal pattern (JWT/API-key/long base64 token).`,
          impact: "cron.job commands are stored in plaintext in the job table and readable by anyone able to query cron.job — an embedded secret there is exposed to any such reader.",
          fix: "Move the secret to Vault or an environment/config source read at execution time instead of a literal in the scheduled command.",
          precisionTier: "review",
        }),
      );
    }

    return findings;
  });
}
