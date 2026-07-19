// NEGATIVE (N-SESSION-DERIVED-ROLE, #614): the admin decision is taken from the verified session,
// not the request body. harvey-client-trusted-role gates its source root on req/request, so a
// session-derived role never matches — cleared.
export function updateRole(req, res, session) {
  if (session.user.role === "admin") {
    grantAdmin(req.body.userId);
  }
  res.json({ ok: true });
}
