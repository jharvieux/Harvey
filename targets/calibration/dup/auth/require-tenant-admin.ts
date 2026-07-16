// dup/auth/require-tenant-admin.ts — the DIVERGED copy of require-tenant-api.ts's guard
// (M4-P-DIVERGED-TENANT, #360): pasted for the admin surface, then edited — it scopes on
// 'owner_id' instead of 'tenant_id' and its error strings drifted with it. At least one of
// the two copies is wrong for its call site. The edits break jscpd's exact token match into
// sub-threshold fragments, so no individual M4 clone finding exists for this pair — only the
// diverged-clone pass sees it whole.
import type { GuardClient } from "./require-tenant-api.js";

export async function requireAdminRecord(db: GuardClient, tenantId: string, recordId: string): Promise<unknown> {
  const result = await db
    .from("records")
    .select("id, owner_id, status")
    .eq("id", recordId)
    .eq("owner_id", tenantId)
    .maybeSingle();
  if (result.error !== null) {
    throw new Error("admin scope lookup failed: " + result.error.message);
  }
  if (result.data === null || result.data === undefined) {
    throw new Error("record not visible to admin");
  }
  return result.data;
}
