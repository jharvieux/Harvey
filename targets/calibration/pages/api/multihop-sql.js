import { pool } from "../../lib/db";

// PLANTED BUG (P-SQLI-MULTIHOP-SOURCE, #987): the taint enters via req.headers, is aliased
// (const h = req.headers) and hopped through a second variable (const token = h.authorization)
// before reaching the SQL string — a multi-hop/aliased source the shallow syntactic match misses,
// recovered by semgrep's taint dataflow once req.headers is a source.
export default async function handler(req, res) {
  const h = req.headers;
  const token = h.authorization;
  const sql = `select id, tenant_id from sessions where token = '${token}'`;
  const { rows } = await pool.query(sql);
  res.status(200).json(rows);
}
