// Minimal ambient types for pii-classify.mjs's exported surface, so TS callers (e.g.
// src/cli/dry-run.ts) can import it under strict mode without an implicit-any error.
// Keep in sync with the JSDoc in pii-classify.mjs — this file has no runtime effect.

export interface ClassifyResult {
  infotype: string;
  category: "PII" | "SENSITIVE_PII" | "PHI" | "PCI" | "SECRET";
  confidence: "high" | "medium" | "low";
}

export interface ColumnInfo {
  table_name: string;
  column_name: string;
  data_type?: string;
}

export interface TableDataMapEntry {
  columns: ({ column: string } & ClassifyResult)[];
  infotypes: string[];
  categories: string[];
  severityScore: number;
  severity: "Critical" | "High" | "Medium" | "Low" | "Info";
  phi: boolean;
  pci: boolean;
  secret: boolean;
}

export function classifyColumn(column: string, sqlType?: string, tableName?: string): ClassifyResult | null;
export function buildDataMap(
  columns: ColumnInfo[],
  resolve?: (col: ColumnInfo) => ClassifyResult | null,
): Record<string, TableDataMapEntry>;
export function classifyMigrationSql(sql: string): { columns: ColumnInfo[]; dataMap: Record<string, TableDataMapEntry> };
