import { pool } from "../../lib/db";

// P-SQLI-CONST-THROW-SWALLOWED (POSITIVE — must STILL fire, #1248): the swallowed-throw shape on
// the #1363 HOISTED-CONSTANT arm. That arm binds its anchoring constraint through a
// `pattern-inside`, a different conjunct from the guard statement, so it needs its own proof that
// the try exclusion reaches it.
const SORT_KEY = /^[a-zA-Z0-9_]+$/;

export default async function handler(req, res) {
  const col = req.query.sort;
  try {
    if (!SORT_KEY.test(col)) throw new Error("invalid sort key");
  } catch (err) {
    res.setHeader("x-sort-warning", "1");
  }
  const sql = `select id, title from documents order by ${col}`;
  const { rows } = await pool.query(sql);
  res.status(200).json(rows);
}
