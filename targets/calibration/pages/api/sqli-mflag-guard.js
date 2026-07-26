import { pool } from "../../lib/db";

// PLANTED BUG (P-SQLI-MFLAG-GUARD, #1066): the allowlist regex is anchored and its class is
// positive — it satisfies both #989 soundness constraints — but it carries the /m flag, which makes
// ^ and $ match at LINE BREAKS rather than at string boundaries. `/^[a-zA-Z0-9_]+$/m.test("id\n;
// drop table documents--")` is TRUE, so the payload passes a guard the rule treated as proof of
// safety. The (a2) sanitizer's flag group is [isuvy], excluding m, so this must STILL fire.
export default async function handler(req, res) {
  const col = req.query.sort;
  if (!/^[a-zA-Z0-9_]+$/m.test(col)) {
    res.status(400).json({ error: "invalid sort key" });
    return;
  }
  const sql = `select id, title from documents order by ${col}`;
  const { rows } = await pool.query(sql);
  res.status(200).json(rows);
}
