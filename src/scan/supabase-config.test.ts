import { describe, expect, it } from "vitest";
import {
  checkAuthConfig,
  checkAutoExposedTables,
  checkDangerousExtensions,
  checkEdgeFunctionSecrets,
  checkExposedSchemas,
  checkGotrueVersion,
  checkGraphqlIntrospection,
  checkPublicBucketsWithNoPolicies,
  checkRealtimeAuthorization,
  checkUnsignedWebhookHandlers,
  compareVersions,
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

  it("flags an OTP expiry over the 1-hour baseline", () => {
    const findings = checkAuthConfig({ otp_expiry: 7200 });
    expect(findings).toHaveLength(1);
    expect(findings[0]?.taxonomy).toBe("Auth config: long OTP expiry");
  });

  it("returns no findings for a hardened config", () => {
    const findings = checkAuthConfig({ mailer_autoconfirm: false, password_hibp_enabled: true, otp_expiry: 600, uri_allow_list: "https://app.example.com/callback" });
    expect(findings).toEqual([]);
  });
});

describe("checkAuthConfig — Batch B8 planted config.toml shape", () => {
  // Mirrors targets/calibration/supabase/config.toml (auth.email.otp_expiry=86400,
  // auth.additional_redirect_urls includes "*") — see GROUND-TRUTH.md §"Batch B8". No live
  // Management API config was read; this proves the parsing logic against the exact planted
  // values offline.
  it("flags the planted 24h OTP expiry and wildcard redirect allowlist together", () => {
    const findings = checkAuthConfig({ mailer_autoconfirm: false, password_hibp_enabled: true, otp_expiry: 86400, uri_allow_list: "https://127.0.0.1:3000,*" });
    const taxonomies = findings.map((f) => f.taxonomy);
    expect(taxonomies).toContain("Auth config: long OTP expiry");
    expect(taxonomies).toContain("Auth config: wildcard redirect allowlist");
    expect(findings).toHaveLength(2);
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
