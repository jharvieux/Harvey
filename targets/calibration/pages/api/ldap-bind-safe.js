import { Client } from "ldapts";

const client = new Client({ url: "ldap://directory.internal:389" });

// N-LDAP-BIND-FN-PROTOTYPE (NEGATIVE — must NOT be flagged, #1273 follow-up): `Function.prototype
// .bind` in a file that also imports an LDAP client. The bind arm is `$C.bind($DN, ...)` focused
// on the FIRST argument, which in this idiom is the `this` value, not the tainted one — so the
// generic method name does not turn every partial application inside an LDAP module into an LDAP
// finding. Boundary guard for widening the bind arm.
function tag(prefix, msg) {
  return `${prefix}: ${msg}`;
}

export default async function handler(req, res) {
  const tagged = tag.bind(null, req.query.uid);
  await client.bind("cn=svc,dc=example,dc=com", "static-password");
  res.status(200).json({ line: tagged("ok") });
}
