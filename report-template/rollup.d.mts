// Minimal ambient types for rollup.mjs's exported surface, so TS callers (src/report-rollup.test.ts)
// can import it under strict mode. Keep in sync with rollup.mjs — this file has no runtime effect.
// Generic over the finding shape: rollup only reads taxonomy/severity/category, so it works on both
// the full src/findings.ts Finding and the renderer's enriched plain objects.

export interface RollupShape {
  taxonomy: string;
  severity: string;
  category: string;
}

export interface RollupSingle<F> {
  kind: "finding";
  finding: F;
}

export interface RollupGroup<F> {
  kind: "group";
  taxonomy: string;
  severity: string;
  category: string;
  count: number;
  representatives: F[];
  withheld: F[];
}

export type RollupItem<F> = RollupSingle<F> | RollupGroup<F>;

export declare const ROLLUP_THRESHOLD: number;
export declare const ROLLUP_REPRESENTATIVES: number;
export declare const ACTION_PLAN_MAX_ROWS: number;

export declare function rollupFindings<F extends RollupShape>(
  findings: F[],
  opts?: { threshold?: number; representatives?: number },
): RollupItem<F>[];

export declare function capActionPlan<F>(actions: F[], max?: number): { shown: F[]; withheldCount: number };
