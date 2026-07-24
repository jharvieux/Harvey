import { pool } from "../../lib/db";

// N-SQLI-PARSEFLOAT (NEGATIVE — must NOT be flagged, #986): the untrusted amount is coerced with
// parseFloat before interpolation — a number cannot carry SQL metacharacters. (a1) sanitizer subset.
export default async function handler(req, res) {
  const amount = parseFloat(req.query.amount);
  const sql = `select id from orders where total > ${amount}`;
  const { rows } = await pool.query(sql);
  res.status(200).json(rows);
}
