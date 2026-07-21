// NEGATIVE (N-PG-IDOR-BENIGN-NAME, #663): the repo function name does not match the read-by-id
// gate (find|get|fetch|load ... By(Id|Pk)) — a logging helper — so it stays dark. Regression
// guard that harvey-pg-idor-repo-fn keys on the function name, not on any $FN(req.params.$K)
// call in an authenticated handler.
export function auditOrder(req, res) {
  const role = req.user.role;
  logOrderAccess(req.params.id);
  res.json({ ok: true, role });
}
