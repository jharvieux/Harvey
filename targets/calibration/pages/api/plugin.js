// PLANTED BUG (P-DYNAMIC-REQUIRE): require() with a request-tainted argument loads and executes an
// attacker-chosen module path. harvey-dynamic-require (taint req -> require).
export default function handler(req, res) {
  const mod = require(req.query.module);
  res.json({ loaded: typeof mod });
}
