const expat = require("node-expat");

// N-XML-PARSER-NOT-CSV (NEGATIVE — must NOT be flagged, #1273 follow-up): an XML pull parser fed
// request input. It is a `new C(opts).parse(x)` call, which is json2csv's CSV shape too, and an
// UNCONSTRAINED constructor metavariable in harvey-csv-formula-injection MEASURED 2026-07-31 as
// firing here — reporting CWE-1236 "formula injection" on an XML parse, which is the one shape
// this ruleset deliberately declines as an XXE sink, so a decline turned into a wrong finding.
// Boundary guard: the CSV rule's json2csv arm must stay bound to json2csv's own module and
// constructor names.
module.exports = function handler(req, res) {
  const parsed = new expat.Parser("UTF-8").parse(req.body.xml);
  res.status(200).json({ ok: true, parsed });
};
