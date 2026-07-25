import { pool } from "../../lib/db";

// P-SQLI-UNANCHORED-GUARD (POSITIVE — must STILL be flagged, #989): the allowlist regex is
// UNANCHORED, so it matches anywhere in the string — "id; drop table documents--" passes on its
// leading "id". A broken safeguard, not a sanitizer. Soundness guard: the (a2) sanitizer must
// require ^…$ anchoring, or it silently clears this real injection.
export default async function handler(req, res) {
  const col = req.query.sort;
  if (!/[a-zA-Z0-9_]+/.test(col)) {
    res.status(400).json({ error: "invalid sort key" });
    return;
  }
  const sql = `select id, title from documents order by ${col}`;
  const { rows } = await pool.query(sql);
  res.status(200).json(rows);
}
