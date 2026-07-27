// OWASP Multi-Tenant CS section 5: "Implement per-tenant rate limiting and quotas".
// One global counter for every tenant, held in process memory: a single noisy tenant exhausts the
// budget for all of them (the sheet's "Noisy Neighbor" risk), and the limit resets on redeploy and
// is per-instance rather than shared.

const hits = new Map<string, number>();

export function allowRequest(route: string): boolean {
  const n = (hits.get(route) ?? 0) + 1;
  hits.set(route, n);
  return n < 1000;
}
