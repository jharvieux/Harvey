import { pool } from "../../lib/db";

// PLANTED BUG (P-SQLI-CONST-UNANCHORED-GUARD, #1363 SOUNDNESS): the hoisted-constant twin of
// P-SQLI-UNANCHORED-GUARD. The named-const arm moves the anchoring metavariable-regex from $RE to
// the LITERAL it is bound to, precisely so this keeps failing: the regex is UNANCHORED, so
// `id; drop table documents--` passes on its leading `id`. Accepting a named const unconditionally
// would clear this row, which is the whole reason that option was rejected. Must STILL fire at high.
const SORT_KEY = /[a-zA-Z0-9_]+/;

export default async function handler(req, res) {
  const col = req.query.sort;
  if (!SORT_KEY.test(col)) return res.status(400).json({ error: "invalid sort key" });
  const sql = `select id, title from documents order by ${col}`;
  const { rows } = await pool.query(sql);
  res.status(200).json(rows);
}
