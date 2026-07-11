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

// Per-user tenancy model (#206): ownership is auth.uid() keyed on whatever column the table uses.
const perUser: TenancyModel = { tenantKey: "", mode: "per-user" };

// NEGATIVE (per-user) — the AoP profiles shape: keyed on the table's own id = auth.uid(). Correct
// owner isolation even though the column isn't a "tenant key".
const ownById: LivePolicy = {
  schema: "public",
  table: "profiles",
  name: "profiles_select_own",
  cmd: "SELECT",
  qual: "(id = auth.uid())",
  withCheck: null,
};

// NEGATIVE (per-user) — ownership bound through a subquery-wrapped auth.uid() inside an EXISTS.
const ownViaSubquery: LivePolicy = {
  schema: "public",
  table: "match_players",
  name: "mp_select",
  cmd: "SELECT",
  qual: "(EXISTS ( SELECT 1 FROM match_players mp WHERE mp.user_id = ( SELECT auth.uid() AS uid)))",
  withCheck: null,
};

// POSITIVE (per-user) — references the caller but binds no row column: a bare presence check that
// exposes every authenticated user's rows.
const bareAuthCheck: LivePolicy = {
  schema: "public",
  table: "docs",
  name: "docs_any_authed",
  cmd: "SELECT",
  qual: "(auth.uid() IS NOT NULL)",
  withCheck: null,
};

// POSITIVE (per-user) — USING binds the row to the caller but WITH CHECK does not, so writes escape.
const writeDropsBinding: LivePolicy = {
  schema: "public",
  table: "saves",
  name: "saves_all",
  cmd: "ALL",
  qual: "(user_id = auth.uid())",
  withCheck: "true",
};

describe("reviewPolicy — per-user mode", () => {
  it("clears a policy that binds the row to auth.uid() (any column)", () => {
    expect(reviewPolicy(ownById, perUser)).toBeNull();
    expect(reviewPolicy(ownViaSubquery, perUser)).toBeNull();
  });

  it("flags a caller reference that binds no row column", () => {
    expect(reviewPolicy(bareAuthCheck, perUser)?.reason).toContain("never binds a row column");
  });

  it("flags a write whose WITH CHECK drops the owner binding", () => {
    expect(reviewPolicy(writeDropsBinding, perUser)?.reason).toContain("WITH CHECK does not");
  });

  it("does not apply the per-tenant wrong-column rule (the id=auth.uid() FP that motivated #206)", () => {
    // The same policy flags under the default per-tenant model but clears under per-user.
    expect(reviewPolicy(ownById, { tenantKey: "user_id" })?.reason).toContain("wrong column");
    expect(reviewPolicy(ownById, perUser)).toBeNull();
  });
});

describe("policyReviewFindings", () => {
  it("emits review-tier findings only for the semantically-suspect policies", () => {
    const findings = policyReviewFindings([wrongColumn, weakWithCheck, tenantScoped], model);
    expect(findings.map((f) => f.location)).toEqual(["public.projects.projects_select", "public.invoices.invoices_write"]);
    expect(findings.every((f) => f.precisionTier === "review" && f.confidence === "Review")).toBe(true);
  });

  it("carries the raw USING/WITH CHECK clauses into the evidence for offline adjudication", () => {
    const [wrong, weak] = policyReviewFindings([wrongColumn, weakWithCheck], model);
    expect(wrong?.evidence).toContain("auth.uid() = created_by");
    expect(weak?.evidence).toContain("WITH CHECK: true");
  });
});
