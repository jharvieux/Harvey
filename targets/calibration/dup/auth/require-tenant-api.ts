// dup/auth/require-tenant-api.ts — tenant-scoping guard used by API route handlers.
// PLANTED DIVERGED CLONE (M4-P-DIVERGED-TENANT, #360): requireTenantRecord was copy-pasted
// into require-tenant-admin.ts and the copies have since DIVERGED — the admin copy filters on
// 'owner_id' where this one filters on 'tenant_id' (its error strings drifted too). Identical
// structure, drifted literals: jscpd's exact token match sees only sub-threshold fragments of
// the pair, so it must be flagged by the src/diverged-clones.ts near-miss pass for M1
// adjudication.
export interface GuardQuery {
  eq(column: string, value: string): GuardQuery;
  maybeSingle(): Promise<{ data: unknown; error: { message: string } | null }>;
}

export interface GuardClient {
  from(table: string): { select(columns: string): GuardQuery };
}

export async function requireTenantRecord(db: GuardClient, tenantId: string, recordId: string): Promise<unknown> {
  const result = await db
    .from("records")
    .select("id, tenant_id, status")
    .eq("id", recordId)
    .eq("tenant_id", tenantId)
    .maybeSingle();
  if (result.error !== null) {
    throw new Error("tenant scope lookup failed: " + result.error.message);
  }
  if (result.data === null || result.data === undefined) {
    throw new Error("record not visible in tenant scope");
  }
  return result.data;
}
