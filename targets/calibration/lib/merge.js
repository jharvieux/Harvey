import merge from "lodash.merge";

// PLANTED BUG (P-PROTO-POLLUTION): the request body is recursively merged into a config object.
// A `__proto__` / `constructor.prototype` key in the body mutates Object.prototype for the whole
// process. Review tier. e.g. body = {"__proto__":{"isAdmin":true}}
export default function handler(req, res) {
  const config = { theme: "light", limits: { rows: 100 } };
  const merged = merge(config, req.body);
  res.status(200).json(merged);
}
