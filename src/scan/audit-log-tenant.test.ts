// #1242 — an audit entry that names the actor and a state change but no tenant. The negatives are
// the shipping condition and they are the whole argument: without them this is "flag every log
// line", which is why the issue doubted it was shippable at all.

import { describe, expect, it } from "vitest";
import { detectAuditLogTenantFindings } from "./audit-log-tenant.js";

const scan = (text: string, path = "src/lib/audit.ts") => detectAuditLogTenantFindings([{ path, text }]);

describe("audit-log-tenant — fires on an audit-shaped entry with no tenant", () => {
  it("catches an actor + mutation record with no discriminator", () => {
    const out = scan(`
      export function recordDeletion(userId: string, invoiceId: string) {
        logger.info(\`user \${userId} deleted invoice \${invoiceId}\`);
      }
    `);
    expect(out).toHaveLength(1);
    expect(out[0]!.taxonomy).toBe("Audit log entry without a tenant discriminator");
    expect(out[0]!.precisionTier).toBe("review");
  });

  it("catches the structured form and a destructured actor parameter", () => {
    const out = scan(`
      export function recordGrant({ actorId, roleId }: { actorId: string; roleId: string }) {
        audit.write({ actorId, action: "role.granted", roleId });
      }
    `);
    expect(out).toHaveLength(1);
  });

  it("names the assumption it cannot check, rather than asserting the finding is certain", () => {
    const out = scan(`
      export function recordExport(userId: string, reportId: string) {
        logger.info(\`user \${userId} exported report \${reportId}\`);
      }
    `);
    expect(out[0]!.evidence).toContain("bound child logger is invisible");
  });
});

describe("audit-log-tenant — silent on everything that is not an audit gap", () => {
  it("is silent when the entry carries the tenant", () => {
    expect(
      scan(`
        export function recordDeletion(tenantId: string, userId: string, invoiceId: string) {
          logger.info({ tenantId, userId, action: "invoice.deleted", invoiceId });
        }
      `),
    ).toEqual([]);
  });

  it("is silent on a diagnostic breadcrumb — an actor id but no state change", () => {
    expect(
      scan(`
        export function traceLookup(userId: string, invoiceId: string) {
          logger.debug(\`resolving invoice \${invoiceId} for user \${userId}\`);
        }
      `),
    ).toEqual([]);
  });

  it("is silent on a state change with no actor", () => {
    expect(
      scan(`
        export function recordSweep(invoiceCount: number) {
          logger.info(\`archived \${invoiceCount} invoices in the nightly sweep\`);
        }
      `),
    ).toEqual([]);
  });

  it("is silent on console — diagnostics are nobody's detective control", () => {
    expect(
      scan(`
        export function recordDeletion(userId: string, invoiceId: string) {
          console.log(\`user \${userId} deleted invoice \${invoiceId}\`);
        }
      `),
    ).toEqual([]);
  });

  it("does not scan test files", () => {
    expect(
      scan(
        `export function recordDeletion(userId: string, invoiceId: string) {
           logger.info(\`user \${userId} deleted invoice \${invoiceId}\`);
         }`,
        "src/lib/audit.test.ts",
      ),
    ).toEqual([]);
  });
});
