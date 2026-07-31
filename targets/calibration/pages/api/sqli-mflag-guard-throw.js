import { pool } from "../../lib/db";

// P-SQLI-MFLAG-GUARD-THROW (POSITIVE — must STILL fire, #1248): the throwing twin of
// P-SQLI-MFLAG-GUARD. Anchored, positive class, the branch exits — but /m makes ^ and $ match at
// line breaks, so `/^[a-zA-Z0-9_]+$/m.test("id\n; drop table documents--")` is TRUE. The #1066
// [isuvy] flag group has to survive the throw widening.
export default async function handler(req, res) {
  const col = req.query.sort;
  if (!/^[a-zA-Z0-9_]+$/m.test(col)) throw new Error("invalid sort key");
  const sql = `select id, title from documents order by ${col}`;
  const { rows } = await pool.query(sql);
  res.status(200).json(rows);
}
