// OWASP Multi-Tenant Application Security Cheat Sheet as an INDEPENDENT coverage corpus (#1190).
//
// PINNED SOURCE: cheatsheets/Multi_Tenant_Security_Cheat_Sheet.md at OWASP/CheatSheetSeries commit
// 46f8d0456686f4d1ef523c7cc65be58bd221ffed (the sheet is live; re-pin deliberately, never track HEAD).
//
// WHY THIS CORPUS EXISTS. Every other answer key in this directory traces to briefs/anti-patterns.md
// — a catalog we wrote, and then wrote detectors for. That measures internal consistency, not
// coverage: we cannot fail a check we authored to match what we already catch. This sheet is a
// third-party checklist we did not write and cannot quietly edit to match our detectors, which makes
// a miss here evidence rather than an oversight. Operator ruling 2026-07-26: the purpose is FINDING
// REAL GAPS to improve the product, NOT producing a coverage percentage.
//
// It also carries a forcing function. We filed OWASP/CheatSheetSeries#2309 proposing three additions
// to this sheet; two of them are asserted below as fixtures, so a regression in our own detection of
// what we publicly told OWASP mattered fails this gate.
//
// TRANSLATION CAVEAT (per #1190). The sheet's examples are Python/SQLAlchemy; M1's rules are JS/TS
// only (that is what M1-LANG-00 exists for). Every recommendation below was translated to its JS/TS
// or Postgres-DDL equivalent, and each `note` records the translation so a later reader can dispute
// it. A recommendation that cannot be faithfully translated is recorded as out-of-universe in the
// census at the bottom of this header, NOT silently dropped.
//
// HOW THE BUCKETS WERE ASSIGNED — MEASURED, NOT INSPECTED (2026-07-26,
// `pnpm exec tsx src/cli/quick-scan.ts --dir targets/calibration --findings-out …`, 467 findings):
// every fixture below was planted first and the scanner run second, so the tiers here record what
// Harvey actually did, not what it ought to do.
//
//   expectedTier "high"/"review" — measured CAUGHT.
//   expectedTier "none"          — measured NOT caught. Per types.ts this scores an INTENDED GAP
//                                  rather than a recall miss, AND FAILS THE GATE if any rule ever
//                                  fires on the class, forcing a re-tier. Used here for genuine
//                                  gaps, each naming its tracking issue — read "none" as "measured
//                                  gap, recorded so it cannot silently become a claimed catch",
//                                  not as "by design".
//
// THREE DETECTORS HAVE BEEN BUILT FROM THIS CORPUS. Two in src/scan/supabase-static.ts
// (checkMigrationRlsBypass): SB-RLS-BYPASSRLS-* and SB-RLS-NOFORCE-ROLLUP — before them, Harvey
// caught a table with NO row security and nothing about a table whose correct-looking policies are
// void for a privileged role. The third is src/scan/client-supplied-tenant.ts (#1194), which closed
// P-OWASP-MT-CLIENT-TENANT: a tenant predicate that is present and correct-looking but populated
// from the request. All three share a shape — Harvey checked whether a control EXISTED and not
// whether it was VOID — which is the kind of blind spot an answer key we wrote could not surface.
//
// OUT-OF-UNIVERSE recommendations (code-invisible; recorded, not dropped). These are deployment,
// process or operational controls with no static source signal, so they are not CorpusEntry rows at
// all rather than being scored as gaps: separate-database / separate-schema isolation strategy
// choice; per-tenant encryption keys; encrypt-files-at-rest; secure tenant provisioning; complete
// data deletion on offboarding (Harvey probes this DYNAMICALLY instead — M2 data-residue, #954);
// provisioning/deprovisioning audit trail; tenant data-export portability; monitor and alert on
// cross-tenant access attempts; alerts on isolation violations; per-tenant retention compliance;
// separate API keys per tenant. Eleven items. They are the sheet's operational half and belong in an
// engagement's interview, not in a scanner's answer key.

import type { CorpusEntry } from "./types.js";

export const owaspMultiTenantEntries: CorpusEntry[] = [
  // ---------------------------------------------------------------------------------------------
  // CAUGHT — sheet section 2 (Database Isolation Strategies)
  // ---------------------------------------------------------------------------------------------
  {
    id: "P-OWASP-MT-NO-RLS",
    kind: "positive",
    cls: "Tenant table created with no row-level security at all",
    location: "20260726000002_owasp_mt_isolation.sql",
    match: ["mt_invoices"],
    expectedTier: "high",
    expectedSeverity: "Critical",
    note: "Sheet section 2's first instruction ('Enable RLS on tenant tables'). public.mt_invoices carries a tenant_id and never gets `enable row level security`, so PostgREST exposes every tenant's rows to the anon key. Caught by the pre-existing checkMigrationRlsStatic at high tier — the one part of the sheet's row-level recipe Harvey already enforced. Critical is ground truth from the data exposure, not from what the code emits.",
  },
  {
    id: "P-OWASP-MT-BYPASSRLS",
    kind: "positive",
    cls: "Application role granted BYPASSRLS, voiding every policy in the schema",
    location: "20260726000002_owasp_mt_isolation.sql",
    match: ["BYPASSRLS", "bypassrls"],
    expectedTier: "high",
    expectedSeverity: "Critical",
    note: "The gap we proposed adding to the sheet upstream (OWASP/CheatSheetSeries#2309 item 1): the sheet documents `FORCE ROW LEVEL SECURITY` but not the bypass FORCE does not close. Postgres docs: 'Superusers and roles with the BYPASSRLS attribute always bypass the row security system when accessing a table.' `create role mt_app_worker login bypassrls` makes every policy in this migration decorative for that role. NOT CAUGHT before this corpus; checkMigrationRlsBypass was written for it and measured 1 hit with 0 false fires across the whole calibration corpus. A Supabase service-role key is this role, which is why it is Critical rather than a hardening note.",
  },
  {
    id: "P-OWASP-MT-NOFORCE",
    kind: "positive",
    cls: "RLS enabled with a correct tenant policy but never FORCEd, so the owning role bypasses it",
    location: "20260724000001_rls_drop_policy_broken.sql",
    match: ["force row level security", "NOFORCE"],
    expectedTier: "review",
    note: "Sheet section 2 flags this explicitly ('Force RLS for table owners too (important!)') and its own example gets it right. Harvey did not check it. Now SB-RLS-NOFORCE-ROLLUP — deliberately ONE rolled-up review-tier Low, not one High per table: written per-table at high tier it fired on 21 of this corpus's tables, and on stock hosted Supabase the public-schema owner is `postgres` while PostgREST serves requests as anon/authenticated, so the owner-bypass is not on the request path. Review tier because whether an owner-role connection reaches runtime is a deployment fact migration SQL cannot answer. Location is the rollup's anchor (first unforced table), not a per-table site.",
  },

  // ---------------------------------------------------------------------------------------------
  // MEASURED GAPS — planted, scanned, nothing fired. Each names its tracking issue.
  // ---------------------------------------------------------------------------------------------
  {
    id: "P-OWASP-MT-CLIENT-TENANT",
    kind: "positive",
    cls: "Tenant discriminator taken from the request body/query and used as the query scope",
    location: "src/owasp-mt/client-supplied-tenant.ts",
    match: ["tenant"],
    expectedTier: "high",
    expectedSeverity: "High",
    note: "The sheet's single most important rule ('Never trust client-supplied tenant IDs' / 'Bind tenant context to authenticated user sessions', section 1) and arguably Harvey's core differentiator. WAS a measured gap (MEASURED 2026-07-26: zero findings) — the root cause was a SHAPE ASSUMPTION in the existing tenant-scope detectors (prisma-tenant-scope.ts #760, drizzle-tenant-scope.ts #901): they look for a query with NO tenant predicate, and here the predicate is PRESENT and correct-looking (`where: { tenantId: body.tenantId }`) while its VALUE is attacker-controlled, so both read it as properly scoped. CLOSED by #1194's client-supplied-tenant.ts, which asks where the predicate's value came from rather than whether it exists — both call sites in the fixture (a `req.json()` body and a `searchParams.get()` query param) now fire at high tier. High tier, unlike its two review-tier siblings, because the AST proves a PRESENCE (the request value reaches the predicate) rather than an ABSENCE that unseen middleware might fill in. Paired with N-OWASP-MT-SESSION-TENANT, which must stay silent.",
  },
  {
    id: "P-OWASP-MT-CLIENT-TENANT-SUPABASE",
    kind: "positive",
    cls: "Supabase/PostgREST .eq() tenant predicate populated from the request",
    location: "src/owasp-mt/client-supplied-tenant.ts",
    match: [".eq(\"tenant_id\""],
    expectedTier: "high",
    expectedSeverity: "High",
    note: "The #1194 remainder (#1210): the same defect as P-OWASP-MT-CLIENT-TENANT, through the PostgREST builder idiom `.eq(\"tenant_id\", body.tenant_id)` rather than a Prisma/Drizzle object key — a string-literal-first-argument sink the original detector did not cover. WAS a measured gap. CLOSED by extending client-supplied-tenant.ts with a supabaseHits matcher (also covers .in()/.match()/.filter()). match is scoped to the exact sink phrase (only present in THIS finding's evidence, not the Prisma-sourced ones sharing the file) so the two do not mask each other. Paired with the Supabase case added to N-OWASP-MT-SESSION-TENANT, which must stay silent.",
  },
  {
    id: "P-OWASP-MT-GUC-SESSION",
    kind: "positive",
    cls: "Tenant GUC set with SET rather than SET LOCAL, so it outlives its transaction under pooling",
    location: "src/owasp-mt/tenant-guc-session-scoped.ts",
    match: ["current_tenant"],
    expectedTier: "review",
    expectedSeverity: "High",
    note: "Our OWASP/CheatSheetSeries#2309 item 2. The sheet's own policy reads current_setting('app.current_tenant') and never mentions SET LOCAL or transaction-mode pooling. `SET app.current_tenant = …` on a pooled connection persists after release, so a later request is evaluated against the PREVIOUS tenant's id — a cross-tenant read in which policy, schema and application code all still look correct. WAS a measured gap (MEASURED 2026-07-26: zero findings). CLOSED by #1195's tenant-guc-scope.ts — a line-scoped grep for a query call whose SET/set_config text names a tenant/org GUC with no LOCAL / no third `true` argument. Review tier: it cannot see whether the pool is actually in transaction mode, only that the syntax is the risky one. Tracked in #1195.",
  },
  {
    id: "P-OWASP-MT-CACHE-KEY",
    kind: "positive",
    cls: "Cache key derived from the resource id with no tenant discriminator",
    location: "src/owasp-mt/cache-key-no-tenant.ts",
    match: ["cache-tenant-scope"],
    expectedTier: "review",
    expectedSeverity: "Medium",
    note: "Sheet section 4 ('Prefix all cache keys with tenant identifier'). The first tenant to populate `dashboard:${boardId}` serves its rows to every other tenant requesting the same id. WAS a measured gap (MEASURED 2026-07-26: zero findings). CLOSED by #1196's cache-tenant-scope.ts, narrowed two ways to hold the FP risk down: only a function that ALREADY has a tenant/org-like parameter in scope is considered (a cache with no tenant context at all may be intentionally global), and only a .get/.set read-through PAIR sharing the identical key counts, not a bare write. Confirmed by running the scanner over the fixture (not by inspection) — the negative below is the pair's other half.",
  },
  {
    id: "P-OWASP-MT-RATE-LIMIT",
    kind: "positive",
    cls: "Rate limiter backed by a module-level Map, so it is per-instance and not per-tenant",
    location: "src/owasp-mt/rate-limit-not-per-tenant.ts",
    match: ["resets on cold start"],
    expectedTier: "review",
    expectedSeverity: "Medium",
    note: "Sheet section 5 ('per-tenant rate limiting and quotas') and the sheet's 'Noisy Neighbor' risk. This is ALSO briefs/anti-patterns.md D-091 item 19. WAS a measured gap (MEASURED 2026-07-26: zero findings) — but NOT because no detector existed: AUTH-inmemory-rate-limit (#1046, leftover-auth.ts) already covers exactly this class, and was silent here for an unrelated reason — its PROCESS_LOCAL_STORE regex required `new Map(` with no generic type argument, and the fixture's idiomatic `new Map<string, number>()` did not match. #1197 fixed the regex (`(?:<[^>]*>)?` after the class name); the D-091-coverage audit this issue also asked for is recorded separately (see docs note below). Confirmed by running the scanner over the fixture.",
  },
  {
    id: "P-OWASP-MT-STORAGE-PATH",
    kind: "positive",
    cls: "Storage object path is the caller-supplied filename, with no tenant prefix or ownership check",
    location: "src/owasp-mt/storage-path-no-tenant.ts",
    match: ["without a tenant prefix"],
    expectedTier: "review",
    expectedSeverity: "High",
    note: "Sheet section 6 ('tenant-prefixed paths', 'validate tenant ownership before serving files'). One tenant overwrites and reads another's objects in a shared bucket. WAS a measured gap (MEASURED 2026-07-26: zero findings FOR THIS CLASS — AUTH-upload-no-limit DID fire on this file at High, but for an unrelated defect, no size/MIME limit). CLOSED by #1198's storage-tenant-scope.ts, own taxonomy 'Storage object path without a tenant prefix (cross-tenant object read/overwrite)' — `match` is scoped to that exact phrase so this entry cannot be satisfied by AUTH-upload-no-limit's finding on the same file, which is the #1062 masking shape this corpus already warns about. Confirmed by running the scanner over the fixture.",
  },
  {
    id: "P-OWASP-MT-LOG-TENANT",
    kind: "positive",
    cls: "Audit log records actor and action but no tenant context",
    location: "src/owasp-mt/audit-log-no-tenant.ts",
    match: ["tenant"],
    expectedTier: "none",
    gapKind: "measured-gap",
    note: "GAP, and the weakest candidate of the set — recorded rather than filed. Sheet section 8 ('Include tenant context in all log entries'). A cross-tenant access cannot be reconstructed afterwards, which undercuts the sheet's own detective control. MEASURED: zero findings. Detecting 'this log line omits a field' needs to know which fields matter for this app, so it is a plausible review-tier question and a poor mechanical rule; kept here so the recommendation is accounted for either way.",
  },

  // ---------------------------------------------------------------------------------------------
  // NEGATIVES — the correct forms. Must stay silent, or the detectors above are blinding.
  // ---------------------------------------------------------------------------------------------
  {
    id: "N-OWASP-MT-FORCED",
    kind: "negative",
    cls: "RLS enabled, policy present, and FORCEd — the sheet's complete recipe",
    location: "20260726000002_owasp_mt_isolation.sql",
    match: ["mt_contracts"],
    note: "public.mt_contracts does all three: enable, tenant policy, force. Confirmed silent 2026-07-26 — it is absent from SB-RLS-NOFORCE-ROLLUP's table list while mt_ledger (same file, no force) is present, so the rollup is discriminating on the force statement and not merely counting tenant tables.",
  },
  {
    id: "N-OWASP-MT-SESSION-TENANT",
    kind: "negative",
    cls: "Tenant discriminator derived from the verified session, and the caller-supplied form guarded against it",
    location: "src/owasp-mt/session-derived-tenant.ts",
    note: "The correct form of P-OWASP-MT-CLIENT-TENANT, and the negative #1194's detector had to clear to ship. Four shapes, all silent: (1) `where: { tenantId: session.user.tenantId }` — never touches the request; (2) a caller-supplied tenantId COMPARED against the session's before the query, which is the sheet's own remedy for an account switcher; (3) `where: { id: body.id, tenantId: … }` — a primary key from the request is the ordinary IDOR class that prisma-tenant-scope.ts and bola-owner.ts already own, and this detector must not double-report it; (4) added by #1210, the Supabase `.eq(\"tenant_id\", session.user.tenantId)` builder form. Without (1)/(2)/(4) a rule for this class would flag every tenant-scoped query in every multi-tenant codebase, which is the failure mode that makes such a rule unshippable.",
  },
  {
    id: "N-OWASP-MT-CACHE-SCOPED",
    kind: "negative",
    cls: "Cache key carrying the tenant discriminator",
    location: "src/owasp-mt/cache-key-tenant-scoped.ts",
    note: "`t:${tenantId}:dashboard:${boardId}` — the correct form from sheet section 4. Confirmed silent by #1196's cache-tenant-scope.ts: the key mentions the in-scope tenantId parameter, so the read-through pair clears.",
  },
  {
    id: "N-OWASP-MT-GUC-LOCAL",
    kind: "negative",
    cls: "Tenant GUC set with SET LOCAL, scoped correctly to the current transaction",
    location: "src/owasp-mt/tenant-guc-session-scoped.ts",
    match: ["withTenantLocal"],
    note: "withTenantLocal's `SET LOCAL app.current_tenant = …`, the negative #1195's tenant-guc-scope.ts had to clear to ship. Confirmed silent: the SET_NOT_LOCAL regex's negative lookahead excludes LOCAL explicitly. match scoped to this function's name so the entry isn't spuriously satisfied by the sibling positive's finding sharing this file.",
  },
  {
    id: "N-OWASP-MT-GUC-SET-CONFIG-TRUE",
    kind: "negative",
    cls: "Tenant GUC set via set_config with is_local=true, scoped correctly to the current transaction",
    location: "src/owasp-mt/tenant-guc-session-scoped.ts",
    match: ["withTenantSetConfig"],
    note: "withTenantSetConfig's `set_config('app.current_tenant', $1, true)`, the function-form negative. Confirmed silent: SET_CONFIG_UNSAFE only matches a literal `false` third argument.",
  },
  {
    id: "N-OWASP-MT-STORAGE-PATH-SCOPED",
    kind: "negative",
    cls: "Storage object path prefixed with the tenant id off the verified session",
    location: "src/owasp-mt/storage-path-no-tenant.ts",
    match: ["uploadAttachmentScoped"],
    note: "uploadAttachmentScoped's `${session.user.tenantId}/${filename}` path, the negative #1198's storage-tenant-scope.ts had to clear to ship. Confirmed silent: the path resolves (through the local `path` binding) to text mentioning `session`/`tenantId`, which clears the finding.",
  },
];
