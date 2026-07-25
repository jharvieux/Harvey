import { pool } from "../../lib/db";

// P-SQLI-GUARD-NO-RETURN (POSITIVE — must STILL be flagged, #989): the allowlist test is anchored
// and positive, but its failure branch only LOGS — execution falls through to the query with the
// rejected value intact. Soundness guard: the (a2) sanitizer must match the whole guard STATEMENT
// including the early return, not just the test expression, or it silently clears this.
export default async function handler(req, res) {
  const col = req.query.sort;
  if (!/^[a-zA-Z0-9_]+$/.test(col)) {
    console.warn("unexpected sort key", col);
  }
  const sql = `select id, title from documents order by ${col}`;
  const { rows } = await pool.query(sql);
  res.status(200).json(rows);
}
