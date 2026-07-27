import { cache } from "./redis";

// OWASP Multi-Tenant CS section 4, the CORRECT form -- negative fixture. The cache key carries the
// tenant discriminator, so entries cannot collide across tenants.

export async function getDashboardScoped(tenantId: string, boardId: string) {
  const key = `t:${tenantId}:dashboard:${boardId}`;
  const cached = await cache.get(key);
  if (cached) return JSON.parse(cached);
  const fresh = { tenantId, boardId, widgets: [] };
  await cache.set(key, JSON.stringify(fresh));
  return fresh;
}
