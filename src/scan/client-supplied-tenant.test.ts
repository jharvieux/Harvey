// #1194 — the tenant predicate is present, names the right column, and is fed from the request.
// The tests that matter here are the SILENCE ones: a rule for this class that cannot tell
// `session.user.tenantId` from `body.tenantId` would flag every tenant-scoped query in every
// multi-tenant codebase, so each negative below is a shipping condition, not a nicety.

import { describe, expect, it } from "vitest";
import { detectClientSuppliedTenantFindings } from "./client-supplied-tenant.js";

const scan = (text: string, path = "src/api/route.ts") => detectClientSuppliedTenantFindings([{ path, text }]);

describe("client-supplied-tenant — fires when the tenant value comes from the request", () => {
  it("catches an awaited JSON body reaching a Prisma where clause", () => {
    const out = scan(`
      export async function GET(req: Request) {
        const body = (await req.json()) as { tenantId: string };
        return prisma.invoice.findMany({ where: { tenantId: body.tenantId } });
      }
    `);
    expect(out).toHaveLength(1);
    expect(out[0]!.severity).toBe("High");
    expect(out[0]!.precisionTier).toBe("high");
    expect(out[0]!.evidence).toContain("req.json()");
    expect(out[0]!.taxonomy).toContain("populated from the request");
  });

  it("catches a query-string value, through a ?? default", () => {
    const out = scan(`
      export async function GET(searchParams: URLSearchParams) {
        const tenant = searchParams.get("org") ?? "";
        return prisma.ledgerEntry.findMany({ where: { tenantId: tenant } });
      }
    `);
    expect(out).toHaveLength(1);
    expect(out[0]!.evidence).toContain('searchParams.get("org")');
  });

  it("catches req.body without any intermediate binding", () => {
    const out = scan(`
      export async function handler(req, res) {
        const rows = await prisma.doc.findMany({ where: { organizationId: req.body.orgId } });
        res.json(rows);
      }
    `);
    expect(out).toHaveLength(1);
  });

  it("catches a destructured body binding", () => {
    const out = scan(`
      export async function POST(request: Request) {
        const { workspaceId } = await request.json();
        return prisma.page.findMany({ where: { workspaceId } });
      }
    `);
    expect(out).toHaveLength(1);
  });

  it("catches the Drizzle builder idiom", () => {
    const out = scan(`
      export async function GET(req: Request) {
        const body = await req.json();
        return db.select().from(invoices).where(eq(invoices.tenantId, body.tenantId));
      }
    `);
    expect(out).toHaveLength(1);
    expect(out[0]!.evidence).toContain("eq");
  });

  it("sees taint through a nested callback in the same handler", () => {
    const out = scan(`
      export async function GET(req: Request) {
        const body = await req.json();
        return Promise.all(ids.map((id) => prisma.item.findFirst({ where: { id, tenantId: body.tenantId } })));
      }
    `);
    expect(out).toHaveLength(1);
  });

  // The #989 lesson: a guard model has to be justified by an adversarial POSITIVE, not only by the
  // negatives it quiets. Membership in a list is existence, not ownership by THIS caller, so it
  // must NOT clear — a rule that accepted it would silently drop the real bug below.
  it("catches the Supabase .eq() builder idiom", () => {
    const out = scan(`
      export async function GET(req: Request) {
        const body = await req.json();
        return supabase.from("invoices").select("*").eq("tenant_id", body.tenant_id);
      }
    `);
    expect(out).toHaveLength(1);
    expect(out[0]!.evidence).toContain('.eq("tenant_id"');
  });

  it("catches the Supabase .match() builder idiom", () => {
    const out = scan(`
      export async function GET(req: Request) {
        const body = await req.json();
        return supabase.from("invoices").select("*").match({ tenant_id: body.tenant_id });
      }
    `);
    expect(out).toHaveLength(1);
  });

  it("still fires when the request value is merely checked for existence in a list", () => {
    const out = scan(`
      export async function GET(req: Request) {
        const body = await req.json();
        if (!allTenants.includes(body.tenantId)) throw new Error("unknown tenant");
        return prisma.invoice.findMany({ where: { tenantId: body.tenantId } });
      }
    `);
    expect(out).toHaveLength(1);
  });
});

describe("client-supplied-tenant — silent on the correct forms", () => {
  it("is silent when the tenant comes off the verified session", () => {
    expect(
      scan(`
        export async function GET() {
          const session = await auth();
          return prisma.invoice.findMany({ where: { tenantId: session.user.tenantId } });
        }
      `),
    ).toHaveLength(0);
  });

  it("is silent when a caller-supplied tenant is compared against the session first", () => {
    expect(
      scan(`
        export async function GET(req: Request) {
          const session = await auth();
          const body = await req.json();
          if (body.tenantId !== session.user.tenantId) throw new Error("rejected");
          return prisma.ledgerEntry.findMany({ where: { tenantId: body.tenantId } });
        }
      `),
    ).toHaveLength(0);
  });

  it("does not report a primary key taken from the request — that is the IDOR class other detectors own", () => {
    expect(
      scan(`
        export async function GET(req: Request) {
          const body = await req.json();
          return prisma.invoice.findUnique({ where: { id: body.id } });
        }
      `),
    ).toHaveLength(0);
  });

  it("is silent on the Supabase .eq() builder when the value comes off the session", () => {
    expect(
      scan(`
        export async function GET() {
          const session = await auth();
          return supabase.from("invoices").select("*").eq("tenant_id", session.user.tenantId);
        }
      `),
    ).toHaveLength(0);
  });

  it("does not treat an .eq() call unrelated to a .from(...) chain as a sink", () => {
    expect(
      scan(`
        export async function GET(req: Request) {
          const body = await req.json();
          return someMap.eq("tenant_id", body.tenant_id);
        }
      `),
    ).toHaveLength(0);
  });

  it("does not treat a request read in an unrelated function as taint", () => {
    expect(
      scan(`
        export async function logIt(req: Request) {
          const body = await req.json();
          console.log(body);
        }
        export async function listInvoices(tenantId: string) {
          return prisma.invoice.findMany({ where: { tenantId } });
        }
      `),
    ).toHaveLength(0);
  });

  it("is silent on non-shipping paths", () => {
    const text = `
      export async function GET(req: Request) {
        const body = await req.json();
        return prisma.invoice.findMany({ where: { tenantId: body.tenantId } });
      }
    `;
    expect(scan(text, "src/api/__tests__/route.ts")).toHaveLength(0);
    expect(scan(text, "src/api/route.test.ts")).toHaveLength(0);
  });
});
