import { describe, expect, it } from "vitest";
import {
  checkAuthConfig,
  checkAutoExposedTables,
  checkDangerousExtensions,
  checkEdgeFunctionSecrets,
  checkPublicBucketsWithNoPolicies,
  checkUnsignedWebhookHandlers,
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
