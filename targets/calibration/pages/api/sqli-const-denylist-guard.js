import { pool } from "../../lib/db";

// PLANTED BUG (P-SQLI-CONST-DENYLIST-GUARD, #1363 SOUNDNESS): the hoisted-constant twin of
// P-SQLI-DENYLIST-GUARD. Anchored, early-returning, and still broken — a NEGATED character class
// is a denylist, and `documents; drop table users` clears `[^;]` only until the first semicolon,
// which is exactly the character it needs to allow through to matter. The positive-class half of
// the anchoring constraint has to survive the move to $LIT. Must STILL fire at high.
const SORT_KEY = /^[^;']+$/;

export default async function handler(req, res) {
  const col = req.query.sort;
  if (!SORT_KEY.test(col)) return res.status(400).json({ error: "invalid sort key" });
  const sql = `select id, title from documents order by ${col}`;
  const { rows } = await pool.query(sql);
  res.status(200).json(rows);
}
