import { pool } from "../../lib/db";

// N-SQLI-REGEX-GUARD-THROW (NEGATIVE — must NOT be flagged, #1248): the throwing twin of
// N-SQLI-REGEX-GUARD. An ANCHORED POSITIVE allowlist regex whose failure branch THROWS — the
// idiomatic guard under a Next.js error boundary, where a bare `return` renders an empty page
// instead of erroring. Nothing between the guard and the query catches, so the throw leaves the
// function before the SQL string is built. MEASURED 2026-07-31 before the widening: reported as
// a Critical SQL injection.
export default async function handler(req, res) {
  const col = req.query.sort;
  if (!/^[a-zA-Z0-9_]+$/.test(col)) throw new Error("invalid sort key");
  const sql = `select id, title from documents order by ${col}`;
  const { rows } = await pool.query(sql);
  res.status(200).json(rows);
}
