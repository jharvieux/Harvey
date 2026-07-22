// NEGATIVE (N-PG-RESJSON-DIRECT-SAFE, #701): the object literal returned by res.json(...) names
// only ordinary DTO fields — no curated sensitive field name appears anywhere in it.
// harvey-pg-resjson-exposure-direct requires a curated sensitive field name as a direct
// property; a clean projection stays dark.
export function getUser(req, res) {
  const id = req.params.id;
  res.json({ id, email: "a@example.com", createdAt: "2026-01-01" });
}
