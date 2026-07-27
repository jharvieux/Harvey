import { prisma } from "../db/client";
import { auth } from "../auth";
import { supabase } from "../db/supabase";

// OWASP Multi-Tenant CS section 1, done CORRECTLY — the negative for client-supplied-tenant.ts.
// Same query, same column, same-looking `where` clause. The only difference is where the value
// comes from, which is the entire question the detector has to answer.

// The tenant comes off the verified session and the request never touches it.
export async function listInvoices() {
  const session = await auth();
  return prisma.invoice.findMany({ where: { tenantId: session.user.tenantId } });
}

// The caller MAY name a tenant — an account switcher — but it is compared against the session's
// tenant before the query runs, which is the sheet's own remedy. Must stay silent.
export async function exportLedger(req: Request) {
  const session = await auth();
  const body = (await req.json()) as { tenantId: string };
  if (body.tenantId !== session.user.tenantId) throw new Error("cross-tenant request rejected");
  return prisma.ledgerEntry.findMany({ where: { tenantId: body.tenantId } });
}

// A primary-key filter fed from the request is the ORDINARY IDOR class, owned by
// prisma-tenant-scope.ts / bola-owner.ts. This detector must not also report it, or every
// find-by-id route in every codebase doubles up.
export async function getInvoice(req: Request) {
  const body = (await req.json()) as { id: string };
  return prisma.invoice.findUnique({ where: { id: body.id, tenantId: (await auth()).user.tenantId } });
}

// #1210 — the Supabase/PostgREST negative. Same `.eq()` sink, session-derived value: must stay silent.
export async function listInvoicesSupabase() {
  const session = await auth();
  return supabase.from("invoices").select("*").eq("tenant_id", session.user.tenantId);
}
