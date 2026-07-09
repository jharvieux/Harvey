import { admin } from "../../lib/supabaseAdmin";

// PLANTED BUG (P-SQLI-RPC): `id` is untrusted and interpolated into a raw SQL string that is
// then run via an exec_sql-style RPC — SQL injection. The value is executed as SQL text, not
// bound as a parameter. e.g. id=1); drop table reports;--
export default async function handler(req, res) {
  const { id } = req.query;

  const sql = `select id, tenant_id, total from reports where id = ${id}`;
  const { data } = await admin.rpc("exec_sql", { query: sql });

  res.status(200).json(data);
}
