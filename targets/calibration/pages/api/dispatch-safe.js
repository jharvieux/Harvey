const actions = {
  create: (p) => ({ created: p }),
  remove: (p) => ({ removed: p }),
};

// NEGATIVE (N-DISPATCH-ALLOWLIST): the action name is checked against an explicit allowlist before
// dispatch, so no request-tainted key reaches the computed call. Cleared.
export default function handler(req, res) {
  const action = req.body.action;
  if (action !== "create" && action !== "remove") return res.status(400).end();
  const fn = action === "create" ? actions.create : actions.remove;
  res.json(fn(req.body.payload));
}
