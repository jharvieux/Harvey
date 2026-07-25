import { pool } from "../../lib/db";

// P-SQLI-DENYLIST-GUARD (POSITIVE — must STILL be flagged, #989): the guard has the same shape as
// the (a2) safe twins — anchored regex, returns on failure — but the character class is NEGATED,
// making it a DENYLIST that strips only control characters. Quotes, semicolons and comment markers
// all pass, so this is a real SQL injection. Soundness guard: the (a2) sanitizer must require a
// POSITIVE allowlist, or it silently clears this.
export default async function handler(req, res) {
  const col = req.query.sort;
  if (!/^[^\x00-\x1f]+$/.test(col)) {
    res.status(400).json({ error: "invalid sort key" });
    return;
  }
  const sql = `select id, title from documents order by ${col}`;
  const { rows } = await pool.query(sql);
  res.status(200).json(rows);
}
