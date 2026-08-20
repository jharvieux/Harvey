import { Parser } from "json2csv";

export function exportJson2csv(req: { query: { label: string } }) {
  return new Parser({ fields: ["label"] }).parse([{ label: req.query.label }]);
}
