"use client";

export function tenantClientFor(session: { tenantId: string }) {
  return new TenantClient({ tenantId: session.tenantId });
}
