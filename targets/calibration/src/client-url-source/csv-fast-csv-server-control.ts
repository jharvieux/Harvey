import { writeToString } from "@fast-csv/format";

export function exportFastCsv(req: { query: { label: string } }) {
  return writeToString([{ label: req.query.label }]);
}
