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

  it("clears an ownership binding written as an EXPRESSION, not a bare column (#220)", () => {
    // Supabase's standard one-folder-per-user storage pattern. Recognising only `<column> =
    // auth.uid()` flagged this correct policy — a false positive the static #220 feed hit first,
    // since storage policies are where the pattern is idiomatic.
    const ownFolder: LivePolicy = {
      schema: "storage",
      table: "objects",
      name: "user_files_select_own",
      cmd: "SELECT",
      qual: "bucket_id = 'user-files' and (storage.foldername(name))[1] = auth.uid()::text",
      withCheck: null,
    };
    expect(reviewPolicy(ownFolder, perUser)).toBeNull();
  });

  it("still flags a caller reference that only LOOKS owner-bound — auth.role(), not auth.uid()", () => {
    // The widened expression matching must not swallow the real bug it sits next to: a policy
    // gated on "is the caller logged in" binds no row to anyone.
    const authedOnly: LivePolicy = {
      schema: "storage",
      table: "objects",
      name: "user_files_select_authenticated",
      cmd: "SELECT",
      qual: "bucket_id = 'user-files' and auth.role() = 'authenticated'",
      withCheck: null,
    };
    expect(reviewPolicy(authedOnly, perUser)?.reason).toContain("never binds a row column");
  });

  it("does not apply the per-tenant wrong-column rule (the id=auth.uid() FP that motivated #206)", () => {
    // The same policy flags under the default per-tenant model but clears under per-user.
    expect(reviewPolicy(ownById, { tenantKey: "user_id" })?.reason).toContain("wrong column");
    expect(reviewPolicy(ownById, perUser)).toBeNull();
  });
});

// WITH CHECK (true) on a write policy (#256). The b16 P-STORAGE-UPLOAD-CHECK-TRUE shape: no USING
// at all, so every pre-existing rule (which keys off USING) let it through in both modes.
describe("reviewPolicy — WITH CHECK (true)", () => {
  const insertCheckTrue: LivePolicy = {
    schema: "storage",
    table: "objects",
    name: "user_files_insert_open",
    cmd: "INSERT",
    qual: null,
    withCheck: "true",
  };

  it("flags a no-USING INSERT policy with WITH CHECK (true) in per-user mode", () => {
    expect(reviewPolicy(insertCheckTrue, perUser)?.reason).toContain('WITH CHECK is "true"');
  });

  it("flags the same policy on a tenant-scoped table", () => {
    expect(reviewPolicy(insertCheckTrue, model)?.reason).toContain('WITH CHECK is "true"');
  });

  it("clears an INSERT policy whose WITH CHECK actually constrains the row", () => {
    // The benign twin: same shape, same lack of USING (INSERT policies cannot have one — Postgres
    // rejects it), but the check binds the row to the caller's own folder.
    const insertOwn: LivePolicy = {
      schema: "storage",
      table: "objects",
      name: "user_files_insert_own",
      cmd: "INSERT",
      qual: null,
      withCheck: "bucket_id = 'user-files' and (storage.foldername(name))[1] = auth.uid()::text",
    };
    expect(reviewPolicy(insertOwn, perUser)).toBeNull();
  });

  it("clears a SELECT/DELETE policy — WITH CHECK is write-only, so `true` there is not this defect", () => {
    const readOnly: LivePolicy = { schema: "public", table: "notes", name: "notes_read", cmd: "SELECT", qual: "tenant_id = current_tenant()", withCheck: null };
    expect(reviewPolicy(readOnly, model)).toBeNull();
  });

  it("keeps the weaker-than-USING wording when USING is scoped and the check is `true`", () => {
    // Both rules match this policy; the pre-existing one names the defect more precisely, so it
    // must stay ahead of the new fallthrough.
    expect(reviewPolicy(weakWithCheck, model)?.reason).toContain("WITH CHECK does not");
  });
});

// USING (true) on a read — the RLS-USING-TRUE plant (GROUND-TRUTH row 1). The read-side mirror of
// checkTrueReview above, which bailed on reads at its first line and left this Critical uncaught.
describe("reviewPolicy — USING (true)", () => {
  const selectUsingTrue: LivePolicy = {
    schema: "public",
    table: "documents",
    name: "documents_select_all",
    cmd: "SELECT",
    qual: "true",
    withCheck: null,
  };

  it("flags a SELECT policy with USING (true) on a tenant-scoped table", () => {
    expect(reviewPolicy(selectUsingTrue, model)?.reason).toContain('USING is "true"');
  });

  it("names the read consequence, not a generic one", () => {
    // The finding has to say what an operator loses: every tenant's rows, to anyone with the key.
    expect(reviewPolicy(selectUsingTrue, model)?.reason).toContain("reads every tenant's rows");
  });

  // THE point of the rule's scope. `USING (true)` is unambiguous about its effect and silent about
  // its intent: a published catalog is world-readable on purpose. The table's own schema is the
  // only static fact that separates the two, so a table with no tenant column is left alone.
  it("clears USING (true) on a table with no tenant column — the intentional public catalog", () => {
    const publicCatalog: LivePolicy = { schema: "public", table: "plans", name: "plans_select_public", cmd: "SELECT", qual: "true", withCheck: null };
    expect(reviewPolicy(publicCatalog, perUser)).toBeNull();
  });

  it("clears a tenant-scoped read — the rule keys off the clause, not the command", () => {
    const scopedRead: LivePolicy = { schema: "public", table: "reports", name: "reports_select_own_tenant", cmd: "SELECT", qual: "tenant_id = current_tenant()", withCheck: null };
    expect(reviewPolicy(scopedRead, model)).toBeNull();
  });

  it("does not widen into 'USING looks weak' — a scoped USING the rule cannot judge is left to the semantic tier", () => {
    // A read scoped by a column the reviewer has no opinion on. Only a literal `true` is
    // mechanical; anything else is the semantic tier's call and must not be manufactured here.
    const opaqueScope: LivePolicy = { schema: "public", table: "documents", name: "documents_select_shared", cmd: "SELECT", qual: "tenant_id = current_tenant() or is_shared = true", withCheck: null };
    expect(reviewPolicy(opaqueScope, model)).toBeNull();
  });

  it("flags UPDATE/DELETE, whose USING also gates which rows the caller reaches", () => {
    const deleteAny: LivePolicy = { schema: "public", table: "documents", name: "documents_delete_any", cmd: "DELETE", qual: "true", withCheck: null };
    expect(reviewPolicy(deleteAny, model)?.reason).toContain("can DELETE any tenant's rows");
  });

  it("keeps the weaker-than-USING wording ahead of the new rule when both match", () => {
    // An ALL policy with USING (true) and WITH CHECK (true) matches both rules; the write-side one
    // is ordered first, matching the ordering contract the surrounding rules already document.
    const allOpen: LivePolicy = { schema: "public", table: "documents", name: "documents_all_open", cmd: "ALL", qual: "true", withCheck: "true" };
    expect(reviewPolicy(allOpen, model)?.reason).toContain('WITH CHECK is "true"');
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
