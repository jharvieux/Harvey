// PLANTED BUG (P-CLIENT-TRUSTED-ROLE, #614): an Express handler reads the caller's admin status
// straight from the request body and uses it as an authorization gate. Any caller can escalate by
// adding "isAdmin": true to the JSON body. harvey-client-trusted-role → review (privilege must come
// from the verified session, never the request).
export function updateRole(req, res) {
  if (req.body.isAdmin === true) {
    grantAdmin(req.body.userId);
  }
  res.json({ ok: true });
}
