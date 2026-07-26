// Minimal ambient types for sections.mjs's exported surface, so TS callers (src/report-sections.test.ts)
// can import it under strict mode. Keep in sync with sections.mjs — this file has no runtime effect.
// Same pattern, and the same reason, as rollup.d.mts.

import type { FindingsDocument, TestQuality, TestQualityRow } from "../src/findings.js";

export declare function esc(s: unknown): string;
export declare function testQualityAction(row: TestQualityRow): string;
export declare function testQualitySection(tq: TestQuality): string;
export declare function testQualityBlock(data: FindingsDocument): string;
