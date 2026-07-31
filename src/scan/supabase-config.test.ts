import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
  AUTH_CONFIG_FIELDS,
  checkAuthConfig,
  checkAutoExposedTables,
  checkColumnGrantsToClientRoles,
  checkCronJobs,
  checkDangerousExtensions,
  checkDefaultPrivilegesToClientRoles,
  checkEdgeFunctionSecrets,
  checkExposedSchemas,
  checkGotrueVersion,
  checkGraphqlIntrospection,
  checkPublicBucketsWithNoPolicies,
  checkRealtimeAuthorization,
  checkRealtimePublicationRls,
  checkUnsignedWebhookHandlers,
  compareVersions,
  type CronJob,
} from "./supabase-config.js";

describe("checkPublicBucketsWithNoPolicies", () => {
  it("flags a public bucket with zero policies", () => {
    const findings = checkPublicBucketsWithNoPolicies([{ id: "b1", name: "avatars", public: true }], {});
    expect(findings).toHaveLength(1);
    expect(findings[0]?.precisionTier).toBe("high");
  });

  it("does not flag a public bucket that has policies", () => {
    expect(checkPublicBucketsWithNoPolicies([{ id: "b1", name: "avatars", public: true }], { b1: 2 })).toEqual([]);
  });

  it("does not flag a private bucket regardless of policy count", () => {
    expect(checkPublicBucketsWithNoPolicies([{ id: "b1", name: "invoices", public: false }], {})).toEqual([]);
  });
});

describe("checkAutoExposedTables", () => {
  it("flags a public-schema table with RLS disabled", () => {
    const findings = checkAutoExposedTables([{ schema: "public", name: "orders", rlsEnabled: false }]);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.severity).toBe("Critical");
  });

  it("does not flag a public table with RLS enabled", () => {
    expect(checkAutoExposedTables([{ schema: "public", name: "orders", rlsEnabled: true }])).toEqual([]);
  });

  it("does not flag a non-public schema table even without RLS", () => {
    expect(checkAutoExposedTables([{ schema: "internal", name: "audit_log", rlsEnabled: false }])).toEqual([]);
  });
});

describe("checkAuthConfig", () => {
  it("flags disabled email confirmation, disabled leaked-password protection, and wildcard redirects", () => {
    const findings = checkAuthConfig({ mailer_autoconfirm: true, password_hibp_enabled: false, uri_allow_list: "https://app.example.com/*,*" });
    const taxonomies = findings.map((f) => f.taxonomy);
    expect(taxonomies).toContain("Auth config: email confirmation disabled");
    expect(taxonomies).toContain("Auth config: leaked-password protection off");
    expect(taxonomies).toContain("Auth config: wildcard redirect allowlist");
  });

  it("flags an email OTP expiry over the 1-hour baseline", () => {
    const findings = checkAuthConfig({ mailer_otp_exp: 7200 });
    expect(findings).toHaveLength(1);
    expect(findings[0]?.taxonomy).toBe("Auth config: long OTP expiry");
    expect(findings[0]?.id).toBe("SB-AUTH-OTP-EXPIRY-EMAIL");
  });

  it("flags a long SMS OTP expiry separately from the email one", () => {
    const findings = checkAuthConfig({ mailer_otp_exp: 7200, sms_otp_exp: 86400 });
    expect(findings.map((f) => f.id)).toEqual(["SB-AUTH-OTP-EXPIRY-EMAIL", "SB-AUTH-OTP-EXPIRY-SMS"]);
    expect(findings[1]?.evidence).toContain("sms_otp_exp=86400");
  });

  it("returns no findings for a hardened config", () => {
    const findings = checkAuthConfig({ mailer_autoconfirm: false, password_hibp_enabled: true, mailer_otp_exp: 600, sms_otp_exp: 600, uri_allow_list: "https://app.example.com/callback" });
    expect(findings).toEqual([]);
  });
});

describe("checkAuthConfig — #671 auth-method gating", () => {
  const hibp = (findings: ReturnType<typeof checkAuthConfig>) => findings.find((f) => f.taxonomy === "Auth config: leaked-password protection off")!;

  it("keeps the leaked-password finding asserted when password (email) auth IS enabled", () => {
    const f = hibp(checkAuthConfig({ password_hibp_enabled: false, external_email_enabled: true }));
    expect(f.severity).toBe("Low");
    expect(f.confidence).not.toBe("N/A");
    expect(f.title).not.toContain("conditional");
  });

  it("reframes the leaked-password finding to an Info conditional when password auth is OFF (OAuth-only)", () => {
    const f = hibp(checkAuthConfig({ password_hibp_enabled: false, external_email_enabled: false }));
    // Still surfaced (fail-loud) and same taxonomy so a re-audit matches it — but never an asserted Medium/Low.
    expect(f.severity).toBe("Info");
    expect(f.confidence).toBe("N/A");
    expect(f.title).toContain("conditional");
    expect(f.taxonomy).toBe("Auth config: leaked-password protection off");
  });

  it("reframes to conditional when the method can't be confirmed (no enablement signal)", () => {
    const f = hibp(checkAuthConfig({ password_hibp_enabled: false }));
    expect(f.severity).toBe("Info");
    expect(f.title).toContain("conditional");
  });

  // #1098 — each OTP lifetime is its own API field, so each gates on the provider that issues it:
  // a long SMS window on an email-only project is a conditional note, not an asserted Low.
  it("gates each OTP expiry on its OWN provider", () => {
    const emailOnly = checkAuthConfig({ mailer_otp_exp: 7200, sms_otp_exp: 7200, external_email_enabled: true, external_phone_enabled: false });
    expect(emailOnly.find((f) => f.id === "SB-AUTH-OTP-EXPIRY-EMAIL")!.severity).toBe("Low");
    expect(emailOnly.find((f) => f.id === "SB-AUTH-OTP-EXPIRY-SMS")!.severity).toBe("Info");

    const neither = checkAuthConfig({ mailer_otp_exp: 7200, external_email_enabled: false, external_phone_enabled: false });
    expect(neither[0]!.severity).toBe("Info");
    expect(neither[0]!.taxonomy).toBe("Auth config: long OTP expiry");
  });

  it("never gates the wildcard-redirect advisor (applies to OAuth flows too)", () => {
    const f = checkAuthConfig({ uri_allow_list: "https://app.example.com/*,*", external_email_enabled: false });
    expect(f).toHaveLength(1);
    expect(f[0]!.severity).toBe("High");
    expect(f[0]!.title).not.toContain("conditional");
  });
});

describe("checkAuthConfig — Batch B8 planted config.toml shape", () => {
  // The planted values live in targets/calibration/supabase/config.toml (CLI spelling:
  // [auth.email] otp_expiry = 86400, auth.additional_redirect_urls includes "*") — see
  // GROUND-TRUTH.md §"Batch B8". The check reads the HOSTED Management API response, whose
  // spelling differs, so the CLI keys are translated here rather than passed through:
  // otp_expiry -> mailer_otp_exp, additional_redirect_urls -> uri_allow_list. #1098: passing the
  // CLI spelling straight in is what made this check dead on every real target while this test
  // stayed green — the conformance test below now blocks that shape at the type level.
  it("flags the planted 24h OTP expiry and wildcard redirect allowlist together", () => {
    const findings = checkAuthConfig({ mailer_autoconfirm: false, password_hibp_enabled: true, mailer_otp_exp: 86400, uri_allow_list: "https://127.0.0.1:3000,*" });
    const taxonomies = findings.map((f) => f.taxonomy);
    expect(taxonomies).toContain("Auth config: long OTP expiry");
    expect(taxonomies).toContain("Auth config: wildcard redirect allowlist");
    expect(findings).toHaveLength(2);
  });
});

// #1098 — the gate that would have caught the bug: every field the scan reads must exist, with the
// declared type, in Supabase's own published response schema for GET /projects/{ref}/config/auth.
// The fixture is a vendor capture, not a hand-written literal (see __fixtures__/supabase/PROVENANCE.md).
describe("AuthConfig conforms to the captured Management API response schema", () => {
  const schema = JSON.parse(
    readFileSync(new URL("./__fixtures__/supabase/auth-config-response-schema-2026-07-26.json", import.meta.url), "utf8"),
  ) as { properties: Record<string, { type?: string; anyOf?: { type: string }[] }> };

  // A field is declared either as {type} or as {anyOf:[{type},{type:"null"}]} for a nullable one.
  const declaredTypes = (name: string): string[] => {
    const prop = schema.properties[name];
    if (!prop) return [];
    return (prop.anyOf ?? [prop]).map((t) => t.type).filter((t): t is string => t !== undefined && t !== "null");
  };

  it.each(Object.entries(AUTH_CONFIG_FIELDS))("%s exists in the response schema as %s", (field, type) => {
    expect(declaredTypes(field)).toContain(type);
  });

  it("does not resurrect otp_expiry — the config.toml key that is not an API field", () => {
    expect(schema.properties).not.toHaveProperty("otp_expiry");
    expect(Object.keys(AUTH_CONFIG_FIELDS)).not.toContain("otp_expiry");
  });

  // #1291 — the schema lists every one of its 237 properties as `required`, and PROVENANCE.md used
  // to infer from that "a well-formed response carries every one of them". An adversarial review
  // obtained a live 200 that did NOT carry `nimbus_oauth_email_optional`, so the inference is false:
  // a vendor spec documenting a response is not the response. Nothing in the scan reasoned from
  // `required` when that was found — every AuthConfig field is optional and a missing one leaves its
  // check unrun — and this test is what keeps that true. The `required` list is read from the
  // fixture rather than named inline, so a re-capture moves the assertion with the schema.
  it("treats every schema-`required` field as optional — a response missing one leaves that check unrun", () => {
    const required = (JSON.parse(
      readFileSync(new URL("./__fixtures__/supabase/auth-config-response-schema-2026-07-26.json", import.meta.url), "utf8"),
    ) as { required: string[] }).required;
    for (const field of Object.keys(AUTH_CONFIG_FIELDS)) expect(required).toContain(field);

    // A response carrying only the ONE field each check reads must produce only that check's
    // finding — never a finding derived from a sibling the wire happened to omit.
    expect(checkAuthConfig({ mailer_autoconfirm: true, external_email_enabled: true }).map((f) => f.id)).toEqual(["SB-AUTH-AUTOCONFIRM"]);
    expect(checkAuthConfig({ password_hibp_enabled: false, external_email_enabled: true }).map((f) => f.id)).toEqual(["SB-AUTH-HIBP"]);
    // And an EMPTY response — every `required` property absent — produces nothing at all, rather
    // than reading each missing field as its unsafe value.
    expect(checkAuthConfig({})).toEqual([]);
  });
});

describe("checkDangerousExtensions", () => {
  it("flags pg_net when installed", () => {
    const findings = checkDangerousExtensions([{ name: "pg_net", schema: "extensions", installed_version: "0.20.3" }]);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.precisionTier).toBe("review");
  });

  it("does not flag pg_net when not installed", () => {
    expect(checkDangerousExtensions([{ name: "pg_net", schema: null, installed_version: null }])).toEqual([]);
  });

  it("does not flag an extension outside the dangerous set", () => {
    expect(checkDangerousExtensions([{ name: "pgcrypto", schema: "extensions", installed_version: "1.3" }])).toEqual([]);
  });
});

describe("checkEdgeFunctionSecrets", () => {
  it("flags a hardcoded service-role key literal", () => {
    const findings = checkEdgeFunctionSecrets([{ name: "sync", content: `const SUPABASE_SERVICE_ROLE_KEY = "eyJhbGciOiJIUzI1NiJ9.abc.def";` }]);
    expect(findings).toHaveLength(1);
  });

  it("does not flag a function reading the secret from Deno.env", () => {
    const findings = checkEdgeFunctionSecrets([{ name: "sync", content: `const key = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");` }]);
    expect(findings).toEqual([]);
  });
});

describe("checkRealtimeAuthorization", () => {
  it("flags realtime.messages with RLS disabled", () => {
    const findings = checkRealtimeAuthorization({ exists: true, rlsEnabled: false });
    expect(findings).toHaveLength(1);
    expect(findings[0]?.taxonomy).toBe("Realtime channel lacks authorization");
  });

  // ATC-prod live state (2026-07-10): realtime.messages rls_enabled=true — the negative case.
  it("does not flag realtime.messages with RLS enabled", () => {
    expect(checkRealtimeAuthorization({ exists: true, rlsEnabled: true })).toEqual([]);
  });

  it("does not flag when the realtime.messages table is absent", () => {
    expect(checkRealtimeAuthorization({ exists: false, rlsEnabled: false })).toEqual([]);
  });
});

describe("checkRealtimePublicationRls", () => {
  it("flags a published table with RLS disabled", () => {
    const findings = checkRealtimePublicationRls([{ schema: "public", name: "orders", rlsEnabled: false }]);
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({ severity: "High", taxonomy: "Realtime publication broadcasts an unprotected table", location: "public.orders" });
  });

  it("does not flag a published table with RLS enabled", () => {
    expect(checkRealtimePublicationRls([{ schema: "public", name: "orders", rlsEnabled: true }])).toEqual([]);
  });

  it("flags each unprotected published table and skips the protected ones", () => {
    const findings = checkRealtimePublicationRls([
      { schema: "public", name: "orders", rlsEnabled: false },
      { schema: "public", name: "messages", rlsEnabled: true },
      { schema: "public", name: "events", rlsEnabled: false },
    ]);
    expect(findings.map((f) => f.location)).toEqual(["public.orders", "public.events"]);
  });

  it("does not flag when the publication has no tables", () => {
    expect(checkRealtimePublicationRls([])).toEqual([]);
  });
});

describe("checkDefaultPrivilegesToClientRoles", () => {
  it("flags a default ACL granting future tables in a schema to anon", () => {
    const findings = checkDefaultPrivilegesToClientRoles([
      { schema: "public", role: "anon", objectType: "table", privileges: ["INSERT", "SELECT"] },
    ]);
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      taxonomy: "Default privileges grant future objects to client role",
      precisionTier: "review",
      location: "schema public: default privileges for anon",
    });
  });

  it("does not flag when there are no default ACLs granting to anon/authenticated", () => {
    expect(checkDefaultPrivilegesToClientRoles([])).toEqual([]);
  });
});

describe("checkColumnGrantsToClientRoles", () => {
  it("flags an explicit column-level grant to authenticated", () => {
    const findings = checkColumnGrantsToClientRoles([
      { schema: "public", tableName: "profiles", columnName: "ssn", role: "authenticated", privilegeType: "SELECT" },
    ]);
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      taxonomy: "Column-level grant to client role outside RLS model",
      location: "public.profiles.ssn",
      precisionTier: "review",
    });
  });

  it("does not flag when there are no column-level grants to anon/authenticated", () => {
    expect(checkColumnGrantsToClientRoles([])).toEqual([]);
  });
});

describe("checkExposedSchemas", () => {
  it("flags a schema exposed beyond the public/graphql_public default", () => {
    const findings = checkExposedSchemas(["public", "graphql_public", "internal"]);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.location).toBe("exposed schema: internal");
  });

  it("does not flag the default schemas", () => {
    expect(checkExposedSchemas(["public", "graphql_public"])).toEqual([]);
  });
});

describe("checkGraphqlIntrospection", () => {
  it("flags pg_graphql installed with graphql_public exposed", () => {
    const findings = checkGraphqlIntrospection(true, ["public", "graphql_public"]);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.taxonomy).toBe("pg_graphql introspection enabled in production");
  });

  // ATC-prod live state (2026-07-10): pg_graphql installed_version=null — the negative case.
  it("does not flag when pg_graphql is not installed", () => {
    expect(checkGraphqlIntrospection(false, ["public", "graphql_public"])).toEqual([]);
  });

  it("does not flag when graphql_public is not exposed", () => {
    expect(checkGraphqlIntrospection(true, ["public"])).toEqual([]);
  });
});

describe("compareVersions", () => {
  it("orders numeric dotted versions and tolerates a v prefix / short parts", () => {
    expect(compareVersions("2.160.0", "2.185.0")).toBe(-1);
    expect(compareVersions("v2.185.0", "2.185.0")).toBe(0);
    expect(compareVersions("2.200.0", "2.185.0")).toBe(1);
    expect(compareVersions("2.170", "2.170.0")).toBe(0);
  });
});

describe("checkGotrueVersion", () => {
  it("flags the OIDC bypass on an old version with Apple/Azure enabled", () => {
    const findings = checkGotrueVersion({ version: "2.170.0", appleEnabled: true });
    expect(findings.map((f) => f.taxonomy)).toContain("Self-hosted GoTrue OIDC issuer bypass");
  });

  it("does not flag the OIDC bypass without Apple/Azure enabled", () => {
    const findings = checkGotrueVersion({ version: "2.170.0", appleEnabled: false, azureEnabled: false });
    expect(findings.map((f) => f.taxonomy)).not.toContain("Self-hosted GoTrue OIDC issuer bypass");
  });

  it("flags email-link poisoning inside the 2.67.1–2.163.0 range", () => {
    const findings = checkGotrueVersion({ version: "2.100.0" });
    expect(findings.map((f) => f.taxonomy)).toContain("Self-hosted GoTrue email-link poisoning");
  });

  it("does not flag a patched version", () => {
    expect(checkGotrueVersion({ version: "2.185.0", appleEnabled: true })).toEqual([]);
  });

  it("returns nothing when the version is unknown", () => {
    expect(checkGotrueVersion({ version: null, appleEnabled: true })).toEqual([]);
  });
});

describe("checkCronJobs", () => {
  const baseJob: CronJob = {
    jobid: 1,
    schedule: "*/5 * * * *",
    command: "select public.rollup_daily_stats();",
    nodename: "localhost",
    database: "postgres",
    username: "postgres",
    active: true,
    isSuperuser: false,
  };

  it("flags a job running as a superuser role", () => {
    const findings = checkCronJobs([{ ...baseJob, isSuperuser: true }]);
    expect(findings.map((f) => f.taxonomy)).toContain("pg_cron job runs as a superuser role");
  });

  it("does not flag a job running as a non-superuser role", () => {
    expect(checkCronJobs([baseJob]).map((f) => f.taxonomy)).not.toContain("pg_cron job runs as a superuser role");
  });

  it("flags a job whose command calls a known SECURITY DEFINER function", () => {
    const findings = checkCronJobs([baseJob], ["rollup_daily_stats"]);
    expect(findings.map((f) => f.taxonomy)).toContain("pg_cron job calls a SECURITY DEFINER function");
  });

  it("does not flag when the command calls no known SECURITY DEFINER function", () => {
    const findings = checkCronJobs([baseJob], ["some_other_function"]);
    expect(findings.map((f) => f.taxonomy)).not.toContain("pg_cron job calls a SECURITY DEFINER function");
  });

  it("flags a command embedding a JWT-shaped secret literal", () => {
    const job = { ...baseJob, command: `select net.http_post('https://api.example.com', headers := '{"Authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.abcdefghijklmnop.signaturepart"}');` };
    const findings = checkCronJobs([job]);
    expect(findings.map((f) => f.taxonomy)).toContain("pg_cron job embeds a secret-shaped literal");
  });

  it("does not flag a plain command with no secret-shaped literal", () => {
    expect(checkCronJobs([baseJob]).map((f) => f.taxonomy)).not.toContain("pg_cron job embeds a secret-shaped literal");
  });

  it("returns no findings for a job with no privileged/definer/secret signal", () => {
    expect(checkCronJobs([baseJob])).toEqual([]);
  });
});

describe("checkUnsignedWebhookHandlers", () => {
  it("flags a webhook-named function with no signature check", () => {
    const findings = checkUnsignedWebhookHandlers([{ name: "stripe-webhook", content: `export default async (req) => { const body = await req.json(); }` }]);
    expect(findings).toHaveLength(1);
  });

  it("does not flag a webhook function that verifies a signature", () => {
    const findings = checkUnsignedWebhookHandlers([{ name: "stripe-webhook", content: `stripe.webhooks.constructEvent(body, sig, secret);` }]);
    expect(findings).toEqual([]);
  });

  it("does not flag a non-webhook function even with no signature check", () => {
    expect(checkUnsignedWebhookHandlers([{ name: "resize-image", content: `export default async () => {}` }])).toEqual([]);
  });
});
