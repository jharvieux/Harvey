// PLANTED BUG (P-PG-RESJSON-SELECTSTAR, #701): `SELECT * FROM users` pulls every column, and
// the fetched row is handed straight back to res.json(...) with no narrowing — any column the
// table carries (password_hash, is_admin, ...) reaches the client. harvey-pg-resjson-exposure-
// select-star fires when the same-function query result of a literal "SELECT *" flows directly
// into res.json(...).
export async function getUser(req, res) {
  const result = await pool.query("SELECT * FROM users WHERE id = $1", [req.params.id]);
  res.json(result.rows[0]);
}
