import { pool } from "../../lib/db";

// N-SQLI-REGEX-GUARD (NEGATIVE — must NOT be flagged, #989): the untrusted sort key is gated by an
// ANCHORED POSITIVE allowlist regex that returns on failure. Nothing outside [A-Za-z0-9_] can reach
// the SQL string — the (a2) validator-guard subset, cleared by control-flow-shaped taint rather
// than by a transformation. The unguarded twin (search.js, P-SQLI-CONCAT) still fires.
export default async function handler(req, res) {
  const col = req.query.sort;
  if (!/^[a-zA-Z0-9_]+$/.test(col)) {
    res.status(400).json({ error: "invalid sort key" });
    return;
  }
  const sql = `select id, title from documents order by ${col}`;
  const { rows } = await pool.query(sql);
  res.status(200).json(rows);
}
