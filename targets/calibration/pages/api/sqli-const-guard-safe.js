import { pool } from "../../lib/db";

// N-SQLI-CONST-GUARD (NEGATIVE — must NOT be flagged, #1363): the same protection as
// N-SQLI-REGEX-GUARD with the allowlist regex HOISTED to a module constant — the normal way to
// write it once the regex is reused, and the shape that avoids recompiling it per request.
// MEASURED 2026-07-31 before the fix: this correct handler was reported as a Critical SQL
// injection, because metavariable-regex reads $RE's matched TEXT and $RE binds to `SORT_KEY`.
const SORT_KEY = /^[a-zA-Z0-9_]+$/;

export default async function handler(req, res) {
  const col = req.query.sort;
  if (!SORT_KEY.test(col)) {
    res.status(400).json({ error: "invalid sort key" });
    return;
  }
  const sql = `select id, title from documents order by ${col}`;
  const { rows } = await pool.query(sql);
  res.status(200).json(rows);
}
