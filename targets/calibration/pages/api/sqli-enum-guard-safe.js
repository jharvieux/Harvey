import { pool } from "../../lib/db";

// N-SQLI-ENUM-GUARD (NEGATIVE — must NOT be flagged, #989): the untrusted sort key is gated by an
// enum allowlist that returns on failure, so only one of three constants can reach the SQL string.
// The (a2) validator-guard subset — an allowlist membership test, not a transformation.
export default async function handler(req, res) {
  const col = req.query.sort;
  if (!["title", "created_at", "id"].includes(col)) {
    res.status(400).json({ error: "invalid sort key" });
    return;
  }
  const sql = `select id, title from documents order by ${col}`;
  const { rows } = await pool.query(sql);
  res.status(200).json(rows);
}
