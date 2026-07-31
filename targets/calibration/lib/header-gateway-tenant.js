// PLANTED BUG (P-GATEWAY-HEADER-SINK, #1295): an mTLS-gateway-injected identity header
// interpolated into raw SQL. This is the OTHER side of the header-trust decision and it is a
// decision, not an oversight: `x-tenant-id` is an arbitrary custom header name, indistinguishable
// by a static scan from one the client invented, and the failure that matters is the deployment
// where nothing injects it. So it STAYS in the free count at ERROR + HIGH — unlike
// header-platform-realip.js next door, whose header name is on the platform-set list.
module.exports = async function invoices(req, res) {
  const tenant = req.headers["x-tenant-id"];
  const rows = await db.query(`SELECT * FROM invoices WHERE tenant = '${tenant}'`);
  res.json(rows);
};
