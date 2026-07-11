import { describe, expect, it } from "vitest";
import { policyReviewFindings, reviewPolicy, type LivePolicy, type TenancyModel } from "./rls-policy-review.js";

// Tenancy model: rows are scoped to a tenant by tenant_id. Mirrors the b16 P-STORAGE-AUTH-NOT-OWNER
// class (policy checks auth, not the ownership/tenant column) — the live-DB equivalent.
const model: TenancyModel = { tenantKey: "tenant_id" };

// POSITIVE — keys on the caller's identity but never on the tenant column (wrong column).
const wrongColumn: LivePolicy = {
  schema: "public",
  table: "projects",
  name: "projects_select",
  cmd: "SELECT",
  qual: "auth.uid() = created_by",
  withCheck: null,
};

// POSITIVE — reads are tenant-scoped but WITH CHECK is weaker than USING (writes unconstrained).
const weakWithCheck: LivePolicy = {
  schema: "public",
  table: "invoices",
  name: "invoices_write",
  cmd: "ALL",
  qual: "tenant_id = current_tenant()",
  withCheck: "true",
};

// NEGATIVE — correctly tenant-scoped in both USING and WITH CHECK.
const tenantScoped: LivePolicy = {
  schema: "public",
  table: "projects",
  name: "projects_tenant",
  cmd: "ALL",
  qual: "tenant_id = (auth.jwt() ->> 'tenant_id')::uuid",
  withCheck: "tenant_id = (auth.jwt() ->> 'tenant_id')::uuid",
};

describe("reviewPolicy", () => {
  it("surfaces a policy that keys on caller identity but not the tenant column", () => {
    const r = reviewPolicy(wrongColumn, model);
    expect(r?.reason).toContain("wrong column");
  });

  it("surfaces a policy whose WITH CHECK is weaker than its USING", () => {
    const r = reviewPolicy(weakWithCheck, model);
    expect(r?.reason).toContain("WITH CHECK");
  });

  it("clears a policy that scopes both USING and WITH CHECK by the tenant key", () => {
    expect(reviewPolicy(tenantScoped, model)).toBeNull();
  });
});

describe("policyReviewFindings", () => {
  it("emits review-tier findings only for the semantically-suspect policies", () => {
    const findings = policyReviewFindings([wrongColumn, weakWithCheck, tenantScoped], model);
    expect(findings.map((f) => f.location)).toEqual(["public.projects.projects_select", "public.invoices.invoices_write"]);
    expect(findings.every((f) => f.precisionTier === "review" && f.confidence === "Review")).toBe(true);
  });
});
