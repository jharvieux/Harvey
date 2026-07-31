import { pool } from "../../lib/db";

// P-SQLI-THROW-SWALLOWED (POSITIVE — must STILL fire, #1248): the shape that makes a throw
// different from a return. Every #989 constraint is satisfied — anchored, positive class, the
// failure branch leaves the if — but the guard sits inside a `try` whose `catch` swallows, so
// `id; drop table documents--` reaches the query with the rejection logged and ignored. A return
// has no analogue of this: nothing can catch a return.
export default async function handler(req, res) {
  const col = req.query.sort;
  try {
    if (!/^[a-zA-Z0-9_]+$/.test(col)) throw new Error("invalid sort key");
  } catch (err) {
    res.setHeader("x-sort-warning", "1");
  }
  const sql = `select id, title from documents order by ${col}`;
  const { rows } = await pool.query(sql);
  res.status(200).json(rows);
}
