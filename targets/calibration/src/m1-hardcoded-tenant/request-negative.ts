export async function loadTenantDocuments(session: { tenantId: string }) {
  return fetch("/api/documents", {
    headers: { "X-Tenant-ID": session.tenantId },
  });
}
