// dup/wide/export-config-b.ts — XLSX export job config builder used by the reports feature.
// PLANTED WHOLE-REPO DIVERGED CLONE (M4-P-DIVERGED-WIDE, #809): buildExportJobConfig was
// copy-pasted from export-config-a.ts and this copy's row-limit literal has since drifted to
// 2000. See export-config-a.ts for the full note.
export function buildExportJobConfig(rows: string[], format: string): Record<string, unknown> {
  const config = {
    rows,
    format,
    delimiter: ",",
    maxRows: 2000,
  };
  if (rows.length === 0) {
    throw new Error("no rows to export");
  }
  return config;
}
