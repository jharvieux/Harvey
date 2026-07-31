// N-LOCAL-STRINGIFY-NOT-CSV (NEGATIVE — must NOT be flagged, #1273 follow-up): `stringify` is a
// LOCAL one-line helper, not csv-stringify's named export, and this route emits no CSV. The bare
// `stringify($X, ...)` sink arm MEASURED 2026-07-31 as firing here purely on the callee's NAME.
// Boundary guard: the bare-name arms must require the file to import a CSV module.
function stringify(o) {
  return String(o);
}

module.exports = function handler(req, res) {
  res.status(200).json({ label: stringify(req.query.label) });
};
