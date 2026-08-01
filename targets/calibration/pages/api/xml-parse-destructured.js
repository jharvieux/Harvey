const { Parser } = require("node-expat");

// N-XML-PARSER-DESTRUCTURED (NEGATIVE — must NOT be flagged, #1694): the shape
// harvey-csv-formula-injection's own comment names as the reason its json2csv arm needs a MODULE
// binding on top of the constructor-name regex — "node-expat also exports a `Parser` that can be
// destructured out of its require". Until #1694 no fixture anywhere had it, so the import half of
// that conjunction had nothing that could fail on it: xml-parse-expat.js binds `expat.Parser`,
// which the constructor regex alone already blocks.
//
// Here the constructor is the BARE name `Parser`, which the regex DOES admit. The only thing
// standing between this file and a CWE-1236 "formula injection" report on an XML parse is the
// requirement that the file import json2csv — and it imports node-expat. MEASURED 2026-08-01:
// widening $CSVMOD to ^.*$ makes harvey-csv-formula-injection fire here and reds the calibration
// gate; as shipped it is silent.
module.exports = function handler(req, res) {
  const parsed = new Parser("UTF-8").parse(req.body.xml);
  res.status(200).json({ ok: true, parsed });
};
