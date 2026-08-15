import * as XLSX from "xlsx";

export function exportXlsx(req: { query: { label: string } }) {
  return XLSX.utils.json_to_sheet([{ label: req.query.label }]);
}
