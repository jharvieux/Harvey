import { pool } from "../../lib/db";

// N-SQLI-NUMBER (NEGATIVE — must NOT be flagged, #986): the untrusted page value is coerced with
// Number() before interpolation — a number cannot carry SQL metacharacters. (a1) sanitizer subset.
export default async function handler(req, res) {
  const page = Number(req.query.page);
  const sql = `select id from notes order by created_at desc limit 20 offset ${page}`;
  const { rows } = await pool.query(sql);
  res.status(200).json(rows);
}
