// NEGATIVE (N-PG-IDOR-UNAUTH, #663): the handler never reads req.user/session.user — an
// unauthenticated surface, which belongs to the missing-auth class (harvey-route-noauth), not
// this one. Regression guard that harvey-pg-idor-repo-fn requires the authenticated context
// before firing.
export function getPublicOrder(req, res) {
  const order = findOrderById(req.params.id);
  res.json({ order });
}
