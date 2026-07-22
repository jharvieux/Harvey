// NEGATIVE (N-PG-IDOR-COMPARED, #663): the handler compares the fetched row's owner against the
// caller's session id before returning it — an explicit ownership check. harvey-pg-idor-repo-fn
// requires NO comparison anywhere in the body involving req.user/session.user; this has one, so
// it clears.
export function getOrder(req, res) {
  const order = findOrderById(req.params.id);
  if (order.userId !== req.user.id) return res.status(403).json({ error: "forbidden" });
  res.json({ order });
}
