import { stringify } from "csv-stringify/sync";

const LABELS = ["invoices", "receipts", "credits"];

// N-CSV-FORMULA-CONSTANT (NEGATIVE — must NOT be flagged, #1273): the exported cells are a
// server-owned constant list; the request value only SELECTS which of them to export, it never
// becomes a cell. No request taint reaches the serializer, so harvey-csv-formula-injection stays
// dark. Boundary guard: a rule matching `stringify(...)` on presence rather than on taint would
// fire here.
export default function handler(req, res) {
  const wanted = LABELS.filter((l) => l.startsWith(String(req.query.prefix ?? "")));
  const csv = stringify(wanted.map((label) => ({ label, count: 1 })), { header: true });
  res.setHeader("Content-Type", "text/csv");
  res.status(200).send(csv);
}
