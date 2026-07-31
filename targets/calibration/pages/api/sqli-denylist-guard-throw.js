import { pool } from "../../lib/db";

// P-SQLI-DENYLIST-GUARD-THROW (POSITIVE — must STILL fire, #1248): the throwing twin of
// P-SQLI-DENYLIST-GUARD. `/^[^\x00-\x1f]+$/` is anchored and the branch exits, but the class is
// NEGATED — a denylist that strips control characters while quotes, semicolons and comment
// markers pass straight through.
export default async function handler(req, res) {
  const col = req.query.sort;
  if (!/^[^\x00-\x1f]+$/.test(col)) throw new Error("invalid sort key");
  const sql = `select id, title from documents order by ${col}`;
  const { rows } = await pool.query(sql);
  res.status(200).json(rows);
}
