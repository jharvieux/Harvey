import { pool } from "../../lib/db";

// PLANTED BUG (P-SQLI-UNANCHORED-GUARD-BRACELESS, #1236 SOUNDNESS): the braceless twin of
// P-SQLI-UNANCHORED-GUARD. Positive class, braceless early return, but UNANCHORED — it matches
// anywhere, so `id; drop table documents--` passes on its leading `id`. Must STILL fire at high.
export default async function handler(req, res) {
  const col = req.query.sort;
  if (!/[a-zA-Z0-9_]+/.test(col)) return res.status(400).json({ error: "invalid sort key" });
  const sql = `select id, title from documents order by ${col}`;
  const { rows } = await pool.query(sql);
  res.status(200).json(rows);
}
