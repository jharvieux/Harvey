import { pool } from "../../lib/db";

const SORTABLE = ["title", "created_at", "id"];

// P-SQLI-THROW-FINALLY (POSITIVE — must STILL fire, #1248): the second non-exit shape, and the
// one a `catch`-only exclusion misses. There is no catch here, so the throw does propagate — but
// `finally` runs first, and the query is in it, so the rejected sort key reaches the SQL string
// before the error leaves the function.
export default async function handler(req, res) {
  const col = req.query.sort;
  try {
    if (!SORTABLE.includes(col)) throw new Error("invalid sort key");
  } finally {
    const sql = `select id, title from documents order by ${col}`;
    const { rows } = await pool.query(sql);
    res.status(200).json(rows);
  }
}
