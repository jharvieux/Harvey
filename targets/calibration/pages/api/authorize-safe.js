// N-AUTHZ-SESSION-GATED (NEGATIVE — must NOT be flagged, #991): the precision twin of authorize.js.
// It has the SAME allowlist-membership shape on request-derived input, but the privileged branch is
// gated by a verified-session identity check (authzCheck(req.session.user, …)) that DENIES BY
// DEFAULT (403 forbidden). The only thing that clears this negative is that deny-default guard —
// exactly the discriminator #991 relies on. leftover-auth's client-authz-allowlist-grant excludes it.
function authzCheck(user, resource) {
  return Boolean(user) && Array.isArray(user.roles) && user.roles.includes(String(resource));
}

export default function handler(req, res) {
  const data = String(req.body.action || "");
  const allowedActions = ["read", "write", "admin"];
  if (!authzCheck(req.session.user, data)) {
    res.status(403).json({ error: "forbidden" });
    return;
  }
  if (allowedActions.includes(data)) {
    res.json({ ok: true });
  }
}
