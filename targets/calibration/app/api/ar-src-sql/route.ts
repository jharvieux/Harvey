import { pool } from "../../../lib/db";

// PLANTED BUG (P-SQLI-JSON-BODY, #1221): the tenant filter comes from the App Router JSON body and
// is interpolated into a raw SQL string. harvey-sql-injection-template was one of the 17 of 21
// server-side taint rules blind to `await req.json()`, so this was silent before #1221.
export async function POST(req: Request) {
  const { tenant } = await req.json();
  const rows = await pool.query(`SELECT * FROM invoices WHERE tenant = '${tenant}'`);
  return Response.json(rows);
}
