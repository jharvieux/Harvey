import { pool } from "../../lib/db";

// PLANTED BUG (P-SQLI-DENYLIST-GUARD-BRACELESS, #1236 SOUNDNESS): the braceless twin of
// P-SQLI-DENYLIST-GUARD. Anchored and early-returning — the widened safe-twin shape — but the
// class is NEGATED, so it strips control characters while quotes, semicolons and comment markers
// pass. The anchoring/positive-class metavariable-regex is untouched by the widening, and this
// proves it: must STILL fire at high.
export default async function handler(req, res) {
  const col = req.query.sort;
  if (!/^[^\x00-\x1f]+$/.test(col)) return res.status(400).json({ error: "invalid sort key" });
  const sql = `select id, title from documents order by ${col}`;
  const { rows } = await pool.query(sql);
  res.status(200).json(rows);
}
