import { pool } from "../../lib/db";

// PLANTED BUG (P-SQLI-COOKIE-SOURCE, #984): the session token is read from req.cookies — an
// attacker-controllable request source (cookies/headers were NOT in the taint source set before
// #984) — and interpolated into a raw SQL string reaching pool.query. e.g. a forged cookie value
// "x' OR '1'='1" alters the query. harvey-sql-injection-template taint (req.cookies → .query) → high.
export default async function handler(req, res) {
  const token = req.cookies.session_token;
  const sql = `select id, tenant_id from sessions where token = '${token}'`;
  const { rows } = await pool.query(sql);
  res.status(200).json(rows);
}
