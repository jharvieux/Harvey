import { pool } from "../../lib/db";

// Document search. Runs against the service DB connection (RLS does not apply).
export default async function handler(req, res) {
  const { q } = req.query;

  // PLANTED BUG (SQL injection): `q` is untrusted user input concatenated straight
  // into the SQL text. e.g. q=' UNION SELECT id, encrypted_password FROM auth.users --
  const sql = `select id, tenant_id, title from documents where title ilike '%${q}%'`;

  const { rows } = await pool.query(sql);
  res.status(200).json(rows);
}
