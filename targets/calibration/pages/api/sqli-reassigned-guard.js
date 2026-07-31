import { pool } from "../../lib/db";

// PLANTED BUG (P-SQLI-REASSIGNED-GUARD, #1363 SOUNDNESS): the reason the new arm binds a `const`
// declaration rather than a bare `$RE = $LIT` assignment. An anchored allowlist is declared and
// then REPLACED by a permissive one before the guard runs, so the guard admits everything.
// MEASURED 2026-07-31: with `$RE = $LIT` as the binding pattern semgrep matches the FIRST
// assignment, the anchoring constraint is satisfied by a literal that is no longer in force, and
// this handler goes silent — a sanitizer clearing a real bug. A `const` binding rules the shape
// out by construction, and this row is what keeps the choice honest. Must fire at high.
let SORT_KEY = /^[a-zA-Z0-9_]+$/;
SORT_KEY = /.*/;

export default async function handler(req, res) {
  const col = req.query.sort;
  if (!SORT_KEY.test(col)) return res.status(400).json({ error: "invalid sort key" });
  const sql = `select id, title from documents order by ${col}`;
  const { rows } = await pool.query(sql);
  res.status(200).json(rows);
}
