// #1196 — a cache key derived from the resource id alone, with no tenant discriminator, in a
// function that has one to hand. The negatives are the shipping condition: a tenant-scoped cache
// key, and a cache with no tenant parameter at all (legitimately global), must both stay silent.

import { describe, expect, it } from "vitest";
import { detectCacheTenantScopeFindings } from "./cache-tenant-scope.js";

// #1362 split the return into two kinds: the defect rows (CACHE-key-no-tenant) and the coverage
// row that counts the cache sites the heuristic declined to judge (CACHE-SCOPE-00). `scan` returns
// the defect rows so every pre-#1362 assertion still means what it said; `disclosure` reads the
// other one.
const scanAll = (text: string, path = "src/lib/dashboard.ts") => detectCacheTenantScopeFindings([{ path, text }]);
const scan = (text: string, path = "src/lib/dashboard.ts") => scanAll(text, path).filter((f) => f.id !== "CACHE-SCOPE-00");
const disclosure = (text: string, path = "src/lib/dashboard.ts") => scanAll(text, path).find((f) => f.id === "CACHE-SCOPE-00");

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
    expect(scanAll(text, "src/lib/__tests__/dashboard.ts")).toHaveLength(0);
  });
});

// #1362 — MEASURED 2026-07-27: of four spellings of the SAME defect, only the parameter one fired.
// (b) and (c) are the App Router shapes, where the tenant is derived inside the handler rather than
// passed in. Each has a paired negative in the same spelling, so a rule that merely fires more
// would fail the negatives.
describe("cache-tenant-scope — tenant derived inside the function (#1362)", () => {
  it("(b) fires when the tenant comes from a destructured session binding, not a parameter", () => {
    const out = scan(`
      export async function sessionSpelling(boardId: string) {
        const { tenantId } = await getSession();
        const cached = await cache.get(\`dashboard:\${boardId}\`);
        if (cached) return JSON.parse(cached);
        const fresh = await loadDashboard(tenantId, boardId);
        await cache.set(\`dashboard:\${boardId}\`, JSON.stringify(fresh));
        return fresh;
      }
    `);
    expect(out).toHaveLength(1);
    expect(out[0]!.taxonomy).toContain("Cache key without a tenant discriminator");
  });

  it("(b) stays silent when that same session-derived tenant IS in the key", () => {
    expect(
      scan(`
        export async function sessionSpellingScoped(boardId: string) {
          const { tenantId } = await getSession();
          const key = \`t:\${tenantId}:dashboard:\${boardId}\`;
          const cached = await cache.get(key);
          if (cached) return JSON.parse(cached);
          await cache.set(key, JSON.stringify(await loadDashboard(tenantId, boardId)));
        }
      `),
    ).toHaveLength(0);
  });

  it("(c) fires when the tenant is a property on a session parameter", () => {
    expect(
      scan(`
        export async function sessionParamSpelling(session: { tenantId: string }, boardId: string) {
          const cached = await cache.get(\`dashboard:\${boardId}\`);
          if (cached) return JSON.parse(cached);
          const fresh = await loadDashboard(session.tenantId, boardId);
          await cache.set(\`dashboard:\${boardId}\`, JSON.stringify(fresh));
          return fresh;
        }
      `),
    ).toHaveLength(1);
  });

  it("(c) stays silent when the key is built from that same property", () => {
    expect(
      scan(`
        export async function sessionParamScoped(session: { tenantId: string }, boardId: string) {
          const key = \`t:\${session.tenantId}:dashboard:\${boardId}\`;
          const cached = await cache.get(key);
          if (cached) return JSON.parse(cached);
          await cache.set(key, JSON.stringify(await loadDashboard(session.tenantId, boardId)));
        }
      `),
    ).toHaveLength(0);
  });

  it("a per-USER cache key still does not qualify a function — the tenant vocabulary is deliberately narrow", () => {
    expect(
      scan(`
        export async function userSpelling(boardId: string) {
          const { userId } = await getSession();
          const cached = await cache.get(\`dashboard:\${boardId}\`);
          if (cached) return JSON.parse(cached);
          await cache.set(\`dashboard:\${boardId}\`, JSON.stringify(await loadDashboard(userId, boardId)));
        }
      `),
    ).toHaveLength(0);
  });
});

// #1362: "if a bound remains, it is disclosed in the output rather than only in a comment."
describe("CACHE-SCOPE-00 — the declined sites are counted, not silent (#1362)", () => {
  it("counts a read-through pair in a function with no tenant identifier in scope", () => {
    const row = disclosure(`
      export async function getFeatureFlags() {
        const cached = await cache.get("feature-flags");
        if (cached) return JSON.parse(cached);
        await cache.set("feature-flags", JSON.stringify(await loadFlags()));
      }
    `);
    expect(row?.evidence).toContain("1 read-through cache get/set pair");
    expect(row?.confidence).toBe("N/A");
  });

  it("counts a write-only cache separately, naming the #1196 narrowing", () => {
    const row = disclosure(`
      export async function warmCache(tenantId: string, boardId: string) {
        await cache.set(\`dashboard:\${boardId}\`, JSON.stringify(await loadDashboard(tenantId, boardId)));
      }
    `);
    expect(row?.evidence).toContain("1 cache write has");
  });

  it("emits NOTHING when the population is zero — a limit with no cases is a guess, not a limit", () => {
    expect(
      disclosure(`
        export async function getDashboardScoped(tenantId: string, boardId: string) {
          const key = \`t:\${tenantId}:dashboard:\${boardId}\`;
          const cached = await cache.get(key);
          if (cached) return JSON.parse(cached);
          await cache.set(key, JSON.stringify({ tenantId, boardId }));
        }
      `),
    ).toBeUndefined();
  });
});
