const { Parser: Json2csvParser } = require("json2csv");
const { XMLParser } = require("fast-xml-parser");

// N-CSV-IMPORT-XML-CONSTRUCTOR (NEGATIVE — must NOT be flagged, #1694): the mirror of
// xml-parse-destructured.js, and the fixture that makes the CONSTRUCTOR half of
// harvey-csv-formula-injection's json2csv arm independently load-bearing. This file genuinely
// imports json2csv — it exports a CSV further down — so the arm's module gate is SATISFIED. The
// tainted `.parse()` call is fast-xml-parser's, which the constructor-name regex refuses.
//
// A realistic shape rather than a contrived one: a handler that parses an uploaded XML payload and
// separately exports a server-owned catalogue as CSV is exactly the file where both bindings are
// present at once and only their conjunction is correct. MEASURED 2026-08-01: widening $P to ^.*$
// makes harvey-csv-formula-injection fire here and reds the calibration gate; as shipped it is
// silent. The json2csv call itself stays dark for the separate reason that CATALOGUE is a
// server-owned constant, which is N-CSV-FORMULA-CONSTANT's guard, not this one's.
const CATALOGUE = [
  { sku: "A-100", label: "Widget" },
  { sku: "A-200", label: "Sprocket" },
];

module.exports = function handler(req, res) {
  const parsed = new XMLParser({ ignoreAttributes: false }).parse(req.body.xml);
  const csv = new Json2csvParser({ fields: ["sku", "label"] }).parse(CATALOGUE);
  res.status(200).json({ ok: true, parsed, csv });
};
