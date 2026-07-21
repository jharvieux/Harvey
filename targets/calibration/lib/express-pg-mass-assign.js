import { pool } from "./db.js";

// PLANTED BUG (P-PG-MASS-ASSIGN, #663): the entire parsed request body is passed straight to a
// name-gated pg write function (updateUserRow) with no field allowlist — mass assignment. Any
// caller can set a column never meant to be client-writable (role/is_admin/price) by adding it
// to the JSON body. harvey-pg-mass-assignment fires on $FN($_, req.body) name-gated to a
// write-verb prefix (update|insert|create|save|set).
export async function updateUser(req, res) {
  await updateUserRow(req.params.id, req.body);
  res.json({ ok: true });
}

function updateUserRow(id, fields) {
  return pool.query("UPDATE users SET data = $2 WHERE id = $1", [id, fields]);
}
