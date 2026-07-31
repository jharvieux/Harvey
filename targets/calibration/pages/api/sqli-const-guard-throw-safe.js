import { pool } from "../../lib/db";

// N-SQLI-CONST-GUARD-THROW (NEGATIVE — must NOT be flagged, #1248): the throwing twin of
// N-SQLI-CONST-GUARD — the #1363 hoisted-constant arm, in its BLOCK form so the throw is proven
// on `{ … throw … }` as well as on the braceless spelling above.
const SORT_KEY = /^[a-zA-Z0-9_]+$/;

export default async function handler(req, res) {
  const col = req.query.sort;
  if (!SORT_KEY.test(col)) {
    req.log?.warn("rejected sort key");
    throw new Error("invalid sort key");
  }
  const sql = `select id, title from documents order by ${col}`;
  const { rows } = await pool.query(sql);
  res.status(200).json(rows);
}
