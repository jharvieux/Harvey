import { pool } from "../../../lib/db";

// "Update my profile role" — meant to change only the caller's own profile row.
export default async function handler(req, res) {
  const { role } = req.body;

  // PLANTED BUG (unscoped update): this runs on the raw service DB connection (same
  // `pool` as /api/search), which bypasses RLS *and* PostgREST's WHERE-clause guard —
  // and the UPDATE has no WHERE clause — so this rewrites `role` on EVERY profile in
  // EVERY tenant with a single request. A correct version would scope the write with
  // `WHERE id = $2`, parameterised on the authenticated user's id.
  const { rowCount } = await pool.query("UPDATE public.profiles SET role = $1", [role]);

  res.status(200).json({ updated: rowCount });
}
