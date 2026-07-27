import { pool } from "../../lib/db";

// PLANTED BUG (P-SQLI-MFLAG-GUARD-BRACELESS, #1236 SOUNDNESS): the braceless twin of
// P-SQLI-MFLAG-GUARD. Anchored, positive class, braceless early return — every constraint met
// except that /m makes ^ and $ match at line breaks, so `"id\n; drop table documents--"` passes.
// The #1066 [isuvy] flag group must survive the widening: must STILL fire at high.
export default async function handler(req, res) {
  const col = req.query.sort;
  if (!/^[a-zA-Z0-9_]+$/m.test(col)) return res.status(400).json({ error: "invalid sort key" });
  const sql = `select id, title from documents order by ${col}`;
  const { rows } = await pool.query(sql);
  res.status(200).json(rows);
}
