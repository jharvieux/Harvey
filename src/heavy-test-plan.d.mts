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
  gates: { id: string; weightSeconds: number }[];
  weightProvenance: {
    version: 1;
    kind: "hosted-observation";
    head: string;
    capturedAt: string;
    event: string;
    selectedPopulation: string;
    planDigest: string;
    run: string;
    method: string;
    jobs: { id: number; shard: number; wallSeconds: number; suiteSeconds: number; note: string }[];
    workloads: { id: string; observedSeconds: number; jobId: number }[];
    gates: { id: string; observedSeconds: number; jobId: number }[];
  };
}

export interface HeavySelection {
  mode: "full" | "scoped" | "skipped";
  selected: string[];
  changedPaths: string[];
  reasons: string[];
  unmatched: string[];
}

export interface HeavyMatrix {
  include: { shard: number; total: number; files: string[]; workloadIds: string[]; gates: string[]; estimatedSeconds: number }[];
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
export function weightEvidenceStatus(
  registry: HeavyRegistry,
  head: string,
  options?: { dirty?: boolean },
): { status: "current" | "stale"; evidenceHead: string; reason: string };
