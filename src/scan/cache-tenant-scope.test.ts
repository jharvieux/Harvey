// #1196 — a cache key derived from the resource id alone, with no tenant discriminator, in a
// function that has one to hand. The negatives are the shipping condition: a tenant-scoped cache
// key, and a cache with no tenant parameter at all (legitimately global), must both stay silent.

import { describe, expect, it } from "vitest";
import { detectCacheTenantScopeFindings } from "./cache-tenant-scope.js";

const scan = (text: string, path = "src/lib/dashboard.ts") => detectCacheTenantScopeFindings([{ path, text }]);

describe("cache-tenant-scope — fires when the key omits an in-scope tenant discriminator", () => {
  it("catches a read-through cache keyed on the resource id alone", () => {
    const out = scan(`
      export async function getDashboard(tenantId: string, boardId: string) {
        const cached = await cache.get(\`dashboard:\${boardId}\`);
        if (cached) return JSON.parse(cached);
        const fresh = await loadDashboard(tenantId, boardId);
        await cache.set(\`dashboard:\${boardId}\`, JSON.stringify(fresh));
        return fresh;
      }
    `);
    expect(out).toHaveLength(1);
    expect(out[0]!.taxonomy).toContain("Cache key without a tenant discriminator");
    expect(out[0]!.precisionTier).toBe("review");
  });

  it("catches it through a `const key = …` binding shared by get and set", () => {
    const out = scan(`
      export async function getDashboard(orgId: string, boardId: string) {
        const key = \`dashboard:\${boardId}\`;
        const cached = await cache.get(key);
        if (cached) return JSON.parse(cached);
        const fresh = await loadDashboard(orgId, boardId);
        await cache.set(key, JSON.stringify(fresh));
        return fresh;
      }
    `);
    expect(out).toHaveLength(1);
  });
});

describe("cache-tenant-scope — silent on the correct forms", () => {
  it("is silent when the cache key carries the tenant discriminator", () => {
    expect(
      scan(`
        export async function getDashboardScoped(tenantId: string, boardId: string) {
          const key = \`t:\${tenantId}:dashboard:\${boardId}\`;
          const cached = await cache.get(key);
          if (cached) return JSON.parse(cached);
          const fresh = { tenantId, boardId, widgets: [] };
          await cache.set(key, JSON.stringify(fresh));
          return fresh;
        }
      `),
    ).toHaveLength(0);
  });

  it("is silent when the function has no tenant-like parameter at all (legitimately global cache)", () => {
    expect(
      scan(`
        export async function getFeatureFlags() {
          const cached = await cache.get("feature-flags");
          if (cached) return JSON.parse(cached);
          const fresh = await loadFlags();
          await cache.set("feature-flags", JSON.stringify(fresh));
          return fresh;
        }
      `),
    ).toHaveLength(0);
  });

  it("is silent on a bare .set with no paired .get (no read-through pair)", () => {
    expect(
      scan(`
        export async function warmCache(tenantId: string, boardId: string) {
          await cache.set(\`dashboard:\${boardId}\`, JSON.stringify(await loadDashboard(tenantId, boardId)));
        }
      `),
    ).toHaveLength(0);
  });

  it("is silent on non-shipping paths", () => {
    const text = `
      export async function getDashboard(tenantId: string, boardId: string) {
        const cached = await cache.get(\`dashboard:\${boardId}\`);
        if (cached) return JSON.parse(cached);
        await cache.set(\`dashboard:\${boardId}\`, "x");
      }
    `;
    expect(scan(text, "src/lib/__tests__/dashboard.ts")).toHaveLength(0);
  });
});
