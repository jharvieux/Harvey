const protobuf = require("protobufjs");

// N-UNPARSE-NOT-PAPA (NEGATIVE — must NOT be flagged, #1694): the papaparse/SheetJS arm's RECEIVER
// binding, which had no fixture of any kind. `unparse` is not a papaparse-only verb — here it is a
// wire-format decoder's, and it writes no spreadsheet. MEASURED 2026-08-01: widening $P to ^.*$
// makes harvey-csv-formula-injection report CWE-1236 formula injection on this protobuf decode and
// reds the calibration gate; as shipped the arm's receiver regex refuses `codec`, so it is silent.
//
// Paired with csv-papaparse-export.js the way xml-parse-expat.js is paired with csv-export.js: one
// fixture shows the arm fires on its own class, one shows the binding is what keeps it off a
// same-shaped call that is not that class.
const codec = protobuf.Root.fromJSON({ nested: {} });

module.exports = function handler(req, res) {
  const decoded = codec.unparse({ label: req.query.label });
  res.status(200).json({ ok: true, decoded });
};
