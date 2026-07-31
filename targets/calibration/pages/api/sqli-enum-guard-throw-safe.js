import { pool } from "../../lib/db";

const SORTABLE = ["title", "created_at", "id"];

// N-SQLI-ENUM-GUARD-THROW (NEGATIVE — must NOT be flagged, #1248): the throwing twin of
// N-SQLI-ENUM-GUARD — the array-`.includes` arm of the (a2) guard, rejecting by throw.
export default async function handler(req, res) {
  const col = req.query.sort;
  if (!SORTABLE.includes(col)) throw new Error("invalid sort key");
  const sql = `select id, title from documents order by ${col}`;
  const { rows } = await pool.query(sql);
  res.status(200).json(rows);
}
