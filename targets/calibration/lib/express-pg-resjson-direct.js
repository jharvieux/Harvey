// PLANTED BUG (P-PG-RESJSON-DIRECT, #701): a top-level property of the object literal passed
// to res.json(...) is literally named for a curated sensitive field (passwordHash) — the
// client receives the credential hash alongside the rest of the profile. harvey-pg-resjson-
// exposure-direct fires on any curated sensitive field name as a direct property of the
// object literal argument.
export function getUser(req, res) {
  const id = req.params.id;
  res.json({ id, email: "a@example.com", passwordHash: "$2b$10$abc" });
}
