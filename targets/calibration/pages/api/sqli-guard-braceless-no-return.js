import { pool } from "../../lib/db";

const SORTABLE = ["title", "created_at", "id"];

// PLANTED BUG (P-SQLI-GUARD-BRACELESS-NO-RETURN, #1236 SOUNDNESS): the braceless twin of
// P-SQLI-GUARD-NO-RETURN, and the shape the widening most risks swallowing — a braceless
// consequent that is NOT a return. The rejection is written to the response and execution falls
// straight through to the query with the rejected value intact. The widened arm matches
// `return ...;` as the whole consequent, so a bare statement there is not a guard: must STILL fire.
export default async function handler(req, res) {
  const col = req.query.sort;
  if (!SORTABLE.includes(col)) res.status(400).json({ error: "invalid sort key" });
  const sql = `select id, title from documents order by ${col}`;
  const { rows } = await pool.query(sql);
  res.status(200).json(rows);
}
