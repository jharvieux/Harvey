const Papa = require("papaparse");

// P-CSV-FORMULA-PAPAPARSE (POSITIVE — must be caught, #1694): request input serialized straight
// into a papaparse CSV export with no formula-prefix neutralization. Same class as
// P-CSV-FORMULA (csv-export.js), a different ARM of harvey-csv-formula-injection.
//
// Why it exists: MEASURED 2026-08-01, `targets/calibration` contained no `unparse`/`json_to_sheet`
// call at all, so the papaparse/SheetJS arm had never been shown to fire on anything — the rule's
// corpus pairing is scored per RULE, and the csv-stringify arm's positive was carrying the whole
// rule. An arm nothing exercises is an arm that can be deleted without a gate noticing.
module.exports = function handler(req, res) {
  const csv = Papa.unparse([{ label: req.query.label, sku: "A-100" }]);
  res.setHeader("Content-Type", "text/csv");
  res.status(200).send(csv);
};
