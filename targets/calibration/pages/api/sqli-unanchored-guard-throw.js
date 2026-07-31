import { pool } from "../../lib/db";

// P-SQLI-UNANCHORED-GUARD-THROW (POSITIVE — must STILL fire, #1248): the throwing twin of
// P-SQLI-UNANCHORED-GUARD. `/[a-zA-Z0-9_]+/` matches anywhere, so `id; drop table documents--`
// passes on its leading `id`. The anchoring constraint is a separate conjunct from the guard
// shape and the throw widening must not disturb it.
export default async function handler(req, res) {
  const col = req.query.sort;
  if (!/[a-zA-Z0-9_]+/.test(col)) throw new Error("invalid sort key");
  const sql = `select id, title from documents order by ${col}`;
  const { rows } = await pool.query(sql);
  res.status(200).json(rows);
}
