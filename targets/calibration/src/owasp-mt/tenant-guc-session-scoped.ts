import { pool } from "./pg-pool";

// OWASP Multi-Tenant CS section 2 + our proposed addition (CheatSheetSeries#2309 item 2):
// the RLS policy reads current_setting('app.current_tenant'), but this sets it with SET rather than
// SET LOCAL. Under transaction-mode pooling the setting outlives the transaction and stays on the
// connection when it returns to the pool, so a later request on that connection is evaluated
// against the PREVIOUS tenant's identifier -- a cross-tenant read in which the policy, the schema
// and this code all still look correct.

export async function withTenant<T>(tenantId: string, run: () => Promise<T>): Promise<T> {
  const client = await pool.connect();
  try {
    await client.query(`SET app.current_tenant = '${tenantId}'`);
    return await run();
  } finally {
    client.release();
  }
}
