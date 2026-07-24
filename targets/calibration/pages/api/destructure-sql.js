import { pool } from "../../lib/db";

// PLANTED BUG (P-SQLI-DESTRUCTURE-SOURCE, #987): the taint enters via a DESTRUCTURED cookie
// (const { id } = req.cookies) then reaches the SQL string — a destructuring form the literal
// req.cookies.$K match misses, recovered by semgrep taint once req.cookies is a source.
export default async function handler(req, res) {
  const { id } = req.cookies;
  const sql = `select id, title from documents where id = '${id}'`;
  const { rows } = await pool.query(sql);
  res.status(200).json(rows);
}
