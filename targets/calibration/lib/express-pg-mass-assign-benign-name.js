import { pool } from "./db.js";

// NEGATIVE (N-PG-MASS-ASSIGN-BENIGN-NAME, #663): the same bare req.body argument reaches a
// function whose name does NOT match the write-verb gate (update|insert|create|save|set) — a
// logging helper — so it stays dark. Regression guard that harvey-pg-mass-assignment keys on the
// function name, not merely on "$FN($_, req.body)".
export async function auditRequest(req, res) {
  logRequestBody(req.params.id, req.body);
  res.json({ ok: true });
}

function logRequestBody(id, body) {
  return pool.query("INSERT INTO audit_log (subject_id, payload) VALUES ($1, $2)", [id, body]);
}
