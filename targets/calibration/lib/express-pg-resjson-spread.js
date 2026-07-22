// PLANTED BUG (P-PG-RESJSON-SPREAD, #701): `user` is declared in the SAME function via an
// object literal that names a curated sensitive field (refreshToken), then spread whole into
// res.json(...) — the credential rides along even though no field is named at the call site
// itself. harvey-pg-resjson-exposure-spread fires when a spread identifier's same-function
// object-literal declaration names a curated sensitive field.
export function getUser(req, res) {
  const user = { id: req.params.id, email: "a@example.com", refreshToken: "rt_abc123" };
  res.json({ ...user });
}
