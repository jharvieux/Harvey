// NEGATIVE (N-PG-RESJSON-SELECTSTAR-SAFE, #701): the same "SELECT *" query is used, but the
// handler destructures an explicit field allowlist before calling res.json(...) — the full row
// expression never reaches the sink. harvey-pg-resjson-exposure-select-star matches the exact
// row-reference expression flowing into res.json(...), not any value merely derived from it, so
// this narrowed shape stays dark.
export async function getUser(req, res) {
  const result = await pool.query("SELECT * FROM users WHERE id = $1", [req.params.id]);
  const { id, email } = result.rows[0];
  res.json({ id, email });
}
