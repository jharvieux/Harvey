import { pool } from "../../lib/db";

// N-SQLI-CONST-GUARD-BRACELESS (NEGATIVE — must NOT be flagged, #1363): the braceless twin of
// N-SQLI-CONST-GUARD. The two spellings failed IDENTICALLY before the fix, which is what showed
// this was not a #1236 regression — the braced form is the pre-#1236 shape and missed too.
const SORT_KEY = /^[a-zA-Z0-9_]+$/;

export default async function handler(req, res) {
  const col = req.query.sort;
  if (!SORT_KEY.test(col)) return res.status(400).json({ error: "invalid sort key" });
  const sql = `select id, title from documents order by ${col}`;
  const { rows } = await pool.query(sql);
  res.status(200).json(rows);
}
