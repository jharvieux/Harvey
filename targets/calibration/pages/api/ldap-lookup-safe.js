const ldap = require("ldapjs");

const client = ldap.createClient({ url: "ldap://directory.internal:389" });

// N-LDAP-CONSTANT-FILTER (NEGATIVE — must NOT be flagged, #1273): the filter is a server-owned
// constant listing the group's members; the request value is compared against the RESULT in
// JavaScript after the search returns. No request taint reaches the filter, so
// harvey-ldap-injection stays dark. Boundary guard: a rule matching `client.search` on presence
// rather than on taint would fire here.
module.exports = function handler(req, res) {
  client.search("ou=users,dc=example,dc=com", { filter: "(objectClass=inetOrgPerson)", scope: "sub" }, (err, result) => {
    if (err) return res.status(500).json({ error: "search failed" });
    res.status(200).json({ wanted: String(req.query.uid) });
  });
};
