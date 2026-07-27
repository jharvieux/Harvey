import { pool } from "../../lib/db";

// N-SQLI-REGEX-GUARD-BRACELESS (NEGATIVE — must NOT be flagged, #1236): the braceless twin of
// N-SQLI-REGEX-GUARD. Identical protection — an ANCHORED POSITIVE allowlist regex whose failure
// branch leaves the function before the SQL string is built — spelled without a block. Uses the
// bare `return;` form, so the widened arm is proven to cover a return with no value as well as
// `return <expr>;`.
export default async function handler(req, res) {
  const col = req.query.sort;
  if (!/^[a-zA-Z0-9_]+$/.test(col)) return;
  const sql = `select id, title from documents order by ${col}`;
  const { rows } = await pool.query(sql);
  res.status(200).json(rows);
}
