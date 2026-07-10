const actions = {
  create: (p) => ({ created: p }),
  remove: (p) => ({ removed: p }),
};

// PLANTED BUG (P-DYNAMIC-DISPATCH): obj[userInput]() dispatches to a method named by request input
// with no allowlist — a caller can reach any property on the object (including inherited ones).
// harvey-dynamic-dispatch (taint req -> computed-member call).
export default function handler(req, res) {
  const result = actions[req.body.action](req.body.payload);
  res.json(result);
}
