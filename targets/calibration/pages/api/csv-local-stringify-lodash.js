const _ = require("lodash");

// N-LOCAL-STRINGIFY-NON-CSV-MODULE (NEGATIVE — must NOT be flagged, #1694): the second half of the
// csv-stringify/fast-csv arm's module binding. csv-local-stringify.js already proves the arm needs
// SOME import to be present — delete the `pattern-inside` and it fires there. It cannot prove the
// module ALLOW-LIST is doing anything, because that file imports nothing at all, so the allow-list
// regex is never consulted. MEASURED 2026-08-01: widening $MOD to ^.*$ leaves csv-local-stringify.js
// silent for that reason, and this file — which imports a real module that is not a CSV serializer —
// is the one that lights up. Two conjuncts, two fixtures.
function stringify(o) {
  return String(o);
}

module.exports = function handler(req, res) {
  const row = stringify(req.query.label);
  res.status(200).send(_.escape(row));
};
