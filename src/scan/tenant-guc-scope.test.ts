// #1195 — a tenant GUC set with SET (not SET LOCAL) outlives its transaction under pooling. The
// negatives are the shipping condition: SET LOCAL and set_config(..., true) must stay silent, or
// every correct pooled-tenant implementation gets flagged.

import { describe, expect, it } from "vitest";
import { detectTenantGucScopeFindings } from "./tenant-guc-scope.js";

const scan = (text: string, path = "src/db/pool.ts") => detectTenantGucScopeFindings([{ path, text }]);

describe("tenant-guc-scope — fires on SET without LOCAL", () => {
  it("catches SET on a tenant GUC", () => {
    const out = scan(`
      export async function withTenant(tenantId: string, run: () => Promise<void>) {
        const client = await pool.connect();
        await client.query(\`SET app.current_tenant = '\${tenantId}'\`);
        await run();
      }
    `);
    expect(out).toHaveLength(1);
    expect(out[0]!.severity).toBe("High");
    expect(out[0]!.precisionTier).toBe("review");
    expect(out[0]!.taxonomy).toContain("SET rather than SET LOCAL");
  });

  it("catches set_config with is_local=false", () => {
    const out = scan(`await client.query("SELECT set_config('app.current_tenant', $1, false)", [tenantId]);`);
    expect(out).toHaveLength(1);
  });
});

describe("tenant-guc-scope — silent on the correct forms", () => {
  it("is silent on SET LOCAL", () => {
    expect(scan(`await client.query(\`SET LOCAL app.current_tenant = '\${tenantId}'\`);`)).toHaveLength(0);
  });

  it("is silent on set_config with is_local=true", () => {
    expect(scan(`await client.query("SELECT set_config('app.current_tenant', $1, true)", [tenantId]);`)).toHaveLength(0);
  });

  it("is silent on a non-tenant GUC", () => {
    expect(scan(`await client.query(\`SET statement_timeout = '5s'\`);`)).toHaveLength(0);
  });

  it("is silent on non-shipping paths", () => {
    const content = `await client.query(\`SET app.current_tenant = '\${tenantId}'\`);`;
    expect(scan(content, "src/db/__tests__/pool.ts")).toHaveLength(0);
  });
});
