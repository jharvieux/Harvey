// NEGATIVE (N-PG-RESJSON-SPREAD-SAFE, #701): the spread variable's own object-literal
// declaration in this function never names a curated sensitive field — an ordinary DTO.
// harvey-pg-resjson-exposure-spread requires the spread identifier's SAME-function literal
// declaration to name a sensitive field; this one doesn't, so it stays dark.
export function getUser(req, res) {
  const user = { id: req.params.id, email: "a@example.com", createdAt: "2026-01-01" };
  res.json({ ...user });
}
