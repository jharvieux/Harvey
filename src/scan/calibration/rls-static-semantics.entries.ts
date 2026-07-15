// Static RLS-policy semantics (#220) — the source-tier path to the class the 2026-07-12 public
// sweep proved matters most. Both real Criticals in that sweep lived in `create policy` statements
// in committed migration .sql, findable with no DB connection, yet our semantic reviewer
// (rls-policy-review.ts) ran connected-tier only and the sole static check looked for a missing
// ENABLE RLS. checkMigrationPolicySemantics (src/scan/supabase-static.ts, wired into
// runMechanicalScan) closes that gap: parsePolicies (src/migration-sql-parse.ts) extracts the
// USING / WITH CHECK bodies and the EXISTING reviewer judges them — one rule set, two feeds
// (live pg_policies and migration text).
//
// Every entry is expectedTier "review" BY DESIGN, not as a hedge: static text shows a policy's
// SHAPE but never its behavior against real data, so these surface as free-tier INDICATORS (#227)
// — loud, located, never counted in the grade. The connected-tier entries for the same classes
// (base.entries.ts P-RLS-DISABLED, b16 P-STORAGE-*) are unaffected and still N/A statically.
//
// Tenancy is inferred PER TABLE (a table declaring tenant_id is per-tenant; one without it is
// per-user), because a real app mixes both shapes and judging all tables against one model
// reproduces the #206 FP — that inference is what clears the storage own-folder policies below.

import type { CorpusEntry } from "./types.js";

export const rlsStaticSemanticsEntries: CorpusEntry[] = [
  // --- POSITIVES (must be caught) ---
  { id: "P-RLS-AUTH-ROLE-STATIC", kind: "positive", cls: "policy checks logged-in, not which tenant (read statically from migrations)", location: "20260708000002_rls.sql", match: ["invoices_select_authenticated"], expectedTier: "review", note: "create policy invoices_select_authenticated on public.invoices for select using (auth.role() = 'authenticated') — GROUND-TRUTH bug #2, previously invisible to the source tier. public.invoices declares tenant_id, so it reviews per-tenant: the policy references a caller-identity function but never the tenant key, so any authenticated user reads every tenant's invoices. Static counterpart of the connected-tier semantic pass (RLS-AUTH-ROLE)." },
  { id: "P-STORAGE-AUTH-NOT-OWNER-STATIC", kind: "positive", cls: "storage.objects read policy checks auth, not ownership (static)", location: "20260710000001_b15_storage_secdef_semantic.sql", match: ["user_files_select_authenticated"], expectedTier: "review", note: "create policy user_files_select_authenticated on storage.objects for select using (bucket_id = 'user-files' and auth.role() = 'authenticated') — every signed-in user reaches every tenant's files. storage.objects is never declared in the app's migrations, so it reviews per-user: the policy references the caller but binds no row value to auth.uid(). The b16 entry of the same name documents this as an LLM/vuln-scan class; #220 now also reaches it mechanically at review tier — both may fire, neither is free-count." },

  { id: "P-STORAGE-UPLOAD-CHECK-TRUE-STATIC", kind: "positive", cls: "storage.objects INSERT policy WITH CHECK (true) (static)", location: "20260710000001_b15_storage_secdef_semantic.sql", match: ["user_files_insert_open"], expectedTier: "review", note: "create policy user_files_insert_open on storage.objects for insert with check (true) — any caller writes any path in any bucket. The #256 tail of #220: every earlier rule keyed off USING, and an INSERT policy has none (Postgres REJECTS USING on INSERT: 'only WITH CHECK expression allowed'), so this fell through clean in both modes. Now caught by the shared reviewer, so the connected tier inherits it. The b16 entry of the same name documents the LLM/vuln-scan path and is no longer a static miss." },

  // --- NEGATIVES (must NOT be flagged in the free count) ---
  { id: "N-RLS-TENANT-SCOPED-STATIC", kind: "negative", cls: "correctly tenant-scoped policy, both USING and WITH CHECK", location: "20260708000002_rls.sql", match: ["notes_rw_own_tenant"], note: "create policy notes_rw_own_tenant on public.notes for all using (tenant_id = public.current_tenant_id()) with check (tenant_id = public.current_tenant_id()) — both clauses constrain by the tenant key, so reviewPolicy clears it outright. This is the shape a CORRECT policy takes: flagging it would make every indicator noise, which is the failure mode #227 exists to prevent. Same for counters_rw_own_tenant in the same file." },
  { id: "N-STORAGE-OWNERSHIP-SCOPED-STATIC", kind: "negative", cls: "storage read/insert policies scoped to the caller's own folder", location: "20260710000001_b15_storage_secdef_semantic.sql", match: ["user_files_select_own", "user_files_insert_own"], note: "create policy user_files_select_own … using (bucket_id = 'user-files' and (storage.foldername(name))[1] = auth.uid()::text) — the standard Supabase one-folder-per-user ownership pattern, and its insert sibling. Cleared by per-table inference (storage.objects declares no tenant column → per-user mode) plus OWNER_BINDING now recognising an EXPRESSION bound to auth.uid(), not just a bare column. Both were false positives on the first #220 run against this target." },
];
