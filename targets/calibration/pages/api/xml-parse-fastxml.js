const { XMLParser } = require("fast-xml-parser");

// N-FASTXML-NOT-CSV (NEGATIVE — must NOT be flagged, #1273 follow-up): the second `new C(opts)
// .parse(x)` shape the unconstrained CSV constructor metavariable MEASURED as matching on
// 2026-07-31 — fast-xml-parser, whose `parse` builds a JS object from XML and writes no
// spreadsheet at all. Boundary guard paired with xml-parse-expat.js: the constructor NAME alone
// is not a discriminator, so the arm is bound to a json2csv import as well.
module.exports = function handler(req, res) {
  const parsed = new XMLParser({ ignoreAttributes: false }).parse(req.body.xml);
  res.status(200).json({ ok: true, parsed });
};
