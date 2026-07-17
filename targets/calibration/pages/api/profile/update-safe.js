import { pool } from "../../../lib/db";

// TRUE NEGATIVE (N-UPDATE-SCOPED, #353): the same "update my profile role" action on the same raw
// `pool` connection, but the UPDATE is scoped with `WHERE id = $2`, parameterised on the
// authenticated caller's id — so it rewrites only the caller's own row. Contrast update.js
// (P-UPDATE-UNSCOPED), whose UPDATE has no WHERE clause and rewrites every tenant's rows.
export default async function handler(req, res) {
  const { role } = req.body;
  const userId = req.session.user.id;

  const { rowCount } = await pool.query("UPDATE public.profiles SET role = $1 WHERE id = $2", [role, userId]);

  res.status(200).json({ updated: rowCount });
}
