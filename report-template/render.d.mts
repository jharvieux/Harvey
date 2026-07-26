// Minimal ambient types for render.mjs's exported surface, so TS callers (src/report-render.test.ts)
// can import it under strict mode. Keep in sync with render.mjs — this file has no runtime effect.
// Same pattern, and the same reason, as rollup.d.mts / sections.d.mts.

import type { CoverageRow, FindingsDocument, ReportMeta } from "../src/findings.js";

export declare function buildHtml(data: FindingsDocument): string;
export declare function healthGauge(v: number): string;
export declare function severityDonut(counts: Record<string, number>): string;
export declare function completenessBanner(rows: CoverageRow[] | undefined): string;
export declare function coverageSection(rows: CoverageRow[], m: ReportMeta): string;
export declare function limitationsSection(rows: CoverageRow[]): string;
