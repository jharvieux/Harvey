import { pool } from "../../lib/db";

// N-PARAM-QUERY (NEGATIVE — must NOT be flagged): a PARAMETERIZED query. The untrusted
// value (req.query.tenant_id) is passed as a bound parameter ($1), never interpolated into
// the SQL text. This is the safe shape that SQLi taint rules sometimes FP on; the SQLi rule
// must fire only on template-literal/string interpolation of untrusted input (see search.js).
export default async function handler(req, res) {
  const { rows } = await pool.query(
    "select id, title from notes where tenant_id = $1 order by created_at desc",
    [req.query.tenant_id],
  );
  res.status(200).json(rows);
}
