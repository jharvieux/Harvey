// PLANTED BUG (P-PG-IDOR, #663): an authenticated Express handler (req.user is read) passes the
// client-supplied :id straight into a read-by-id pg repo function, with no comparison anywhere
// in the body between the caller's identity and the returned row. Any signed-in user can
// substitute another user's id and read that order (IDOR, OWASP API1).
export function getOrder(req, res) {
  const role = req.user.role;
  const order = findOrderById(req.params.id);
  res.json({ order, role });
}
