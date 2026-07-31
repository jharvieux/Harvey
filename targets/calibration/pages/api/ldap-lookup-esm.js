import { Client } from "ldapts";

const client = new Client({ url: "ldap://directory.internal:389" });

// PLANTED BUG (P-LDAP-INJECTION-ESM, #1273 follow-up): the same concatenated search filter as
// ldap-lookup.js, reached through the ESM `import` form and the `ldapts` client. MEASURED
// 2026-07-31: with the rule's `pattern-inside` bound to `require("ldapjs")` alone this file
// produced NOTHING — so "LDAP injection is covered" held only for CommonJS ldapjs, while the ESM
// form is the dominant one in the Next.js/TS apps this product audits and `ldapts` is named in
// the rule's own remediation text.
export default async function handler(req, res) {
  const { searchEntries } = await client.search("ou=users,dc=example,dc=com", {
    filter: `(uid=${req.query.uid})`,
    scope: "sub",
  });
  res.status(200).json({ count: searchEntries.length });
}
