const ldap = require("ldapjs");

const client = ldap.createClient({ url: "ldap://directory.internal:389" });

// PLANTED BUG (P-LDAP-INJECTION, #1273): the request's `uid` is concatenated into the LDAP search
// FILTER. `*)(uid=*` closes the intended clause and opens a wildcard one, so a single-account
// lookup becomes a directory dump; against an LDAP-backed login the same rewrite authenticates as
// anyone. Review tier: taint-gated, the AST proves the request value reaches the filter.
module.exports = function handler(req, res) {
  client.search("ou=users,dc=example,dc=com", { filter: `(uid=${req.query.uid})`, scope: "sub" }, (err, result) => {
    if (err) return res.status(500).json({ error: "search failed" });
    res.status(200).json({ ok: true });
  });
};
