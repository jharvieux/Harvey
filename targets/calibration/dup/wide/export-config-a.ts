// dup/wide/export-config-a.ts — CSV export job config builder used by the reports feature.
// PLANTED WHOLE-REPO DIVERGED CLONE (M4-P-DIVERGED-WIDE, #809): buildExportJobConfig was
// copy-pasted into export-config-b.ts and the copies have since DIVERGED on the row-limit
// literal (500 here vs 2000 there). Neither file touches an auth/guard/middleware/security path
// or a tenant-scoped supabase query, so the narrow #360 pass (divergedCloneFindings) never admits
// either file — only the opt-in whole-repo pass (wholeRepoDivergedCloneFindings) can see this
// pair.
export function buildExportJobConfig(rows: string[], format: string): Record<string, unknown> {
  const config = {
    rows,
    format,
    delimiter: ",",
    maxRows: 500,
  };
  if (rows.length === 0) {
    throw new Error("no rows to export");
  }
  return config;
}
