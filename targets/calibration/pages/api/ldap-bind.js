import { Client } from "ldapts";

const client = new Client({ url: "ldap://directory.internal:389" });

// PLANTED BUG (P-LDAP-BIND-DN, #1273 follow-up): the request's `uid` is concatenated into the
// BIND DN rather than a search filter. MEASURED 2026-07-31: harvey-ldap-injection's bind/compare/
// modify arms were DEAD — a single `focus-metavariable: $OPTS` covered the whole sink block and
// those three patterns never bind `$OPTS` — so this fired nothing while the rule's own message
// advertised all four call sites. Each arm now focuses its own argument; this fixture is the
// bind half's proof, and its silence would mean the arms went dead again.
export default async function handler(req, res) {
  await client.bind(`uid=${req.query.uid},ou=users,dc=example,dc=com`, "static-password");
  res.status(200).json({ ok: true });
}
