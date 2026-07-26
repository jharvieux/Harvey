// Minimal ambient types for sections.mjs's exported surface, so TS callers (src/report-sections.test.ts)
// can import it under strict mode. Keep in sync with sections.mjs — this file has no runtime effect.
// Same pattern, and the same reason, as rollup.d.mts.

import type { CoverageRow, FindingsDocument, TestQuality, TestQualityRow } from "../src/findings.js";

export declare const DRAFT_NOTICE: string;
export declare const DRAFT_TERMS: [string, string][];

export declare function esc(s: unknown): string;
export declare function tenantIsolationPill(coverage: CoverageRow[] | undefined): string;
export declare function testQualityAction(row: TestQualityRow): string;
export declare function testQualitySection(tq: TestQuality): string;
export declare function testQualityBlock(data: FindingsDocument): string;
export declare function derivedScopeLimits(coverage: CoverageRow[] | undefined): string;
export declare function legalTermsSection(data: FindingsDocument): string;
export declare function draftTermsBadge(data: FindingsDocument): string;
