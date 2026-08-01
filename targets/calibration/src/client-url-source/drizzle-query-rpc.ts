// #1708 NEGATIVE (N-CLIENT-URL-DRIZZLE-QUERY). The `.query.` arm of the same source block, which
// was `$RT.query.$K` with an unbound receiver — the pages-router `router.query.id` shape written
// so that it also matches Drizzle's relational query builder, `db.query.<table>`. detectOrm
// resolves Drizzle as a first-class ORM (#869/#901), so `db.query.invoices` is ordinary product
// code in a supported architecture, and it reaches the ERROR/HIGH graded RPC sink here.
declare const db: { query: { invoices: { findFirst(): Promise<{ label: string }> } } };
declare const serviceClient: { rpc(fn: string, args: Record<string, unknown>): Promise<unknown> };

export async function labelRollup() {
  const invoice = await db.query.invoices.findFirst();
  return serviceClient.rpc("exec_sql", { query: `select '${invoice.label}'` });
}
