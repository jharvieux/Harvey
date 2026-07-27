import { prisma } from "../db/client";

// OWASP Multi-Tenant CS section 1: "Never trust client-supplied tenant IDs" /
// "Bind tenant context to authenticated user sessions".
// The tenant discriminator arrives in the request body and is used verbatim as the scope, so any
// caller reads any tenant by editing one field. The session is never consulted.

export async function listInvoices(req: Request) {
  const body = (await req.json()) as { tenantId: string };
  return prisma.invoice.findMany({ where: { tenantId: body.tenantId } });
}

export async function exportLedger(searchParams: URLSearchParams) {
  const tenant = searchParams.get("org") ?? "";
  return prisma.ledgerEntry.findMany({ where: { tenantId: tenant } });
}
