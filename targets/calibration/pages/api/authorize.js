// PLANTED BUG (P-CLIENT-AUTHZ-ALLOWLIST, #991): the privileged branch is reached by an allowlist
// membership test on a request-derived value (multi-hop: req.body.action → String → allowlist), and
// the granted role is echoed straight back to the client. A client picks a value that passes the
// allowlist and is handed role:"admin". Same class as client-priv-header (Authz decision from
// client-controlled input), the allowlist-grant shape the direct-equality grep missed.
export default function handler(req, res) {
  const userInput = req.body.action || "";
  const data = String(userInput).split(",").join(",");
  const allowedActions = ["read", "write", "admin"];
  if (allowedActions.includes(String(data))) {
    res.json({ access: "granted", role: "admin" });
    return;
  }
  res.json({ done: true });
}
