export async function loadTenantDocuments() {
  return fetch("/api/documents", {
    headers: { "X-Tenant-ID": "tenant_acme-prod-4821" },
  });
}
