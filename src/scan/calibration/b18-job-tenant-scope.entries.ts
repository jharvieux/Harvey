// Batch B18 (#684) — the #681 JOB-TENANT-SCOPE class graduates into the scored M1 recall corpus,
// mirroring how #433 (bola-owner) and #353 (counter-race) each earned a scored positive+negative.
// The detector (src/scan/job-tenant-scope.ts, registered as scanJobTenantScope in runMechanicalScan)
// flags a service-role `.from(X).select/update/delete(...)` in a background-job path (Inngest/cron/
// queue/worker) with NO tenant predicate — a job has no request or session, so the RLS-bypassing
// client returns/mutates rows across every tenant (ATC finding #2003). Stays REVIEW tier: the AST
// proves the in-chain predicate is missing, not that a wrapper/RPC enforces scoping out of view.
// The negative adds a tenant `.eq("tenant_id", …)` and must clear. See #681, #684, GROUND-TRUTH.md §B18.

import type { CorpusEntry } from "./types.js";

export const b18JobTenantScopeEntries: CorpusEntry[] = [
  {
    id: "P-JOB-TENANT-SCOPE",
    kind: "positive",
    cls: "service-role query in a background-job path with no tenant predicate (cross-tenant read/write)",
    location: "src/inngest/import-inbound.ts",
    match: ["job-tenant-scope"],
    expectedTier: "review",
    note: "#681/#684: src/inngest/import-inbound.ts runs admin.from(\"gmail_inbound_messages\").select(\"*\") on the RLS-bypassing service-role client inside an Inngest background-job path, with no tenant predicate. A job has no request/session, so nothing scopes the read — it returns every tenant's inbound messages (the shape of ATC finding #2003). scanJobTenantScope (src/scan/job-tenant-scope.ts) proves the service-rooted select/update/delete chain in a JOB_PATH carries no in-chain .eq/.in/.filter/.match on a tenant/owner column → review. Discriminator: the MISSING predicate itself, not the query's presence. Stays review: the AST can't see a wrapper/RPC enforcing scoping (suppress those with // d091-allow:service-role-tenant). The negative adds .eq(\"tenant_id\", …) and is cleared.",
  },
  {
    id: "N-JOB-TENANT-SCOPED",
    kind: "negative",
    cls: "same background-job service-role read, scoped by the job payload's tenant id via .eq(\"tenant_id\", …)",
    location: "src/inngest/import-inbound-safe.ts",
    match: ["job-tenant-scope"],
    note: "#681/#684: src/inngest/import-inbound-safe.ts runs the same admin.from(\"gmail_inbound_messages\").select(\"*\") but adds .eq(\"tenant_id\", event.data.tenantId) — the explicit tenant predicate confines the read to one tenant, so hasTenantPredicate() is satisfied and no finding fires. Cleared. Recorded to complete the corpus pair.",
  },
];
