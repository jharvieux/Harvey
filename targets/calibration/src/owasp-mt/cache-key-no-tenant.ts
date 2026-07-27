import { cache } from "./redis";

// OWASP Multi-Tenant CS section 4: "Prefix all cache keys with tenant identifier".
// The key is derived from the resource alone, so the first tenant to populate the entry serves its
// rows to every other tenant that asks for the same resource id.

export async function getDashboard(tenantId: string, boardId: string) {
  const cached = await cache.get(`dashboard:${boardId}`);
  if (cached) return JSON.parse(cached);
  const fresh = await loadDashboard(tenantId, boardId);
  await cache.set(`dashboard:${boardId}`, JSON.stringify(fresh));
  return fresh;
}

async function loadDashboard(tenantId: string, boardId: string) {
  return { tenantId, boardId, widgets: [] };
}
