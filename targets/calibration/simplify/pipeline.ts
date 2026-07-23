export type ExportTransform = (rows: Record<string, unknown>[]) => Record<string, unknown>[];

const transforms: ExportTransform[] = [];

export function registerExportTransform(step: ExportTransform): void {
  transforms.push(step);
}

export function runExportPipeline(rows: Record<string, unknown>[]): Record<string, unknown>[] {
  return transforms.reduce((acc, step) => step(acc), rows);
}

registerExportTransform((rows) => rows.filter((row) => row.deleted_at == null));
