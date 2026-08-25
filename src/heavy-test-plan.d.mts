export interface HeavyWorkload {
  id: string;
  testFile: string;
  weightSeconds: number;
  paths: string[];
}

export interface HeavyRegistry {
  version: 1;
  globalPaths: string[];
  workloads: HeavyWorkload[];
}

export interface HeavySelection {
  mode: "full" | "scoped" | "skipped";
  selected: string[];
  changedPaths: string[];
  reasons: string[];
  unmatched: string[];
}

export interface HeavyMatrix {
  include: { shard: number; total: number; files: string[]; workloadIds: string[]; gates: string[] }[];
}

export interface HeavyPlan extends HeavySelection {
  matrix: HeavyMatrix;
  digest: string;
}

export function loadHeavyRegistry(path?: string): HeavyRegistry;
export function selectHeavyWorkloads(
  registry: HeavyRegistry,
  changedPaths: string[],
  options?: { forceFull?: boolean; reason?: string },
): HeavySelection;
export function shardSelectedWorkloads(registry: HeavyRegistry, selectedIds: string[], maxShards?: number): HeavyMatrix;
export function buildHeavyPlan(
  registry: HeavyRegistry,
  changedPaths: string[],
  options?: { forceFull?: boolean; reason?: string; maxShards?: number },
): HeavyPlan;
