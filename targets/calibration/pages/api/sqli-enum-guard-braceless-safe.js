import { pool } from "../../lib/db";

const SORTABLE = ["title", "created_at", "id"];

// N-SQLI-ENUM-GUARD-BRACELESS (NEGATIVE — must NOT be flagged, #1236): the braceless twin of
// N-SQLI-ENUM-GUARD — the array-`.includes` arm of the (a2) guard, early-returning a response
// value rather than falling into a block.
export default async function handler(req, res) {
  const col = req.query.sort;
  if (!SORTABLE.includes(col)) return res.status(400).json({ error: "invalid sort key" });
  const sql = `select id, title from documents order by ${col}`;
  const { rows } = await pool.query(sql);
  res.status(200).json(rows);
}
