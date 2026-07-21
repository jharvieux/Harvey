import { pool } from "./db.js";

// NEGATIVE (N-PG-MASS-ASSIGN-ALLOWLIST, #663): only an explicit allowlist of fields reaches the
// pg write function — the bare `req.body` expression never reaches the call as an argument.
// harvey-pg-mass-assignment matches the literal `req.body` AST node, not any value merely
// derived from it, so a reconstructed object stays dark.
export async function updateUser(req, res) {
  const allowed = { name: req.body.name, email: req.body.email };
  await updateUserRow(req.params.id, allowed);
  res.json({ ok: true });
}

function updateUserRow(id, fields) {
  return pool.query("UPDATE users SET name = $2, email = $3 WHERE id = $1", [id, fields.name, fields.email]);
}
