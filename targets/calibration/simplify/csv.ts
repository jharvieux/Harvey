// WHY: our only CSV input is the bank's settlement export — comma-separated, double-quote
// escaping, never embedded newlines (their published spec). A parser dependency (papaparse /
// csv-parse) would be a new install and audit surface for one bounded format we don't control
// growing. Reimplemented deliberately; revisit if a second CSV source or embedded-newline rows
// ever appear.
export function parseSettlementLine(line: string): string[] {
  const fields: string[] = [];
  let current = "";
  let inQuotes = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (inQuotes) {
      if (ch === '"' && line[i + 1] === '"') {
        current += '"';
        i++;
      } else if (ch === '"') {
        inQuotes = false;
      } else {
        current += ch;
      }
    } else if (ch === '"') {
      inQuotes = true;
    } else if (ch === ",") {
      fields.push(current);
      current = "";
    } else {
      current += ch;
    }
  }
  fields.push(current);
  return fields;
}
