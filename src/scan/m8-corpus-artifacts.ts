import { isNotRun, type ExternalTarget } from "./external-corpus.js";
import type { M8CorpusConfig } from "./m8-corpus.js";

const M8_TARGET_PHASES = ["clone", "dependency preparation", "test baseline", "mutation", "scoring"] as const;
type M8TargetPhase = (typeof M8_TARGET_PHASES)[number];

interface M8CorpusPlan {
  configured: string[];
  unconfigured: { target: string; reason: string }[];
}

export interface M8TargetResult {
  schemaVersion: 1;
  target: string;
  status: "passed" | "failed";
  exitCode: number;
  durationMs: number;
  phases: Record<M8TargetPhase, number> | null;
  scorecard: { rows: unknown[]; findings: Record<string, unknown[]> } | null;
  error?: string;
}

interface M8AggregateReport {
  configuredTargets: string[];
  unconfiguredTargets: { target: string; reason: string }[];
  targets: Array<M8TargetResult & { phases: Record<M8TargetPhase | "aggregation", number> | null }>;
  criticalPath: { target: string; durationMs: number };
  aggregateRunnerCostMs: number;
  passed: number;
  failed: number;
  ok: boolean;
}

export function m8PhasesFromOutput(
  output: string,
  target: string,
  durationMs: number,
  mutationCliStartedMs: number,
): Record<M8TargetPhase, number> {
  const escapedTarget = target.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const banner = output.match(new RegExp(`\\b${escapedTarget}: \\d+s — ([^\\n]+)`));
  const cloneMs = Number(banner?.[1]?.match(/clone ([\d.]+)s/)?.[1]) * 1000;
  const stryker = output.match(/M8 PHASES: test baseline ([\d.]+)s, mutation ([\d.]+)s, line coverage ([\d.]+)s/);
  if (!Number.isFinite(cloneMs) || !stryker) {
    throw new Error(`${target}: required clone/dependency/Stryker timing markers were not emitted`);
  }
  const testBaselineMs = Number(stryker[1]) * 1000;
  const mutationMs = Number(stryker[2]) * 1000;
  const dependencyPreparationMs = Math.max(0, mutationCliStartedMs - cloneMs);
  return {
    clone: cloneMs,
    "dependency preparation": dependencyPreparationMs,
    "test baseline": testBaselineMs,
    mutation: mutationMs,
    scoring: Math.max(0, durationMs - cloneMs - dependencyPreparationMs - testBaselineMs - mutationMs),
  };
}

export function buildM8CorpusPlan(
  corpus: readonly ExternalTarget[],
  configs: Readonly<Record<string, M8CorpusConfig>>,
): M8CorpusPlan {
  const configured = Object.keys(configs).sort();
  const corpusBySlug = new Map(corpus.map((target) => [target.slug, target]));
  for (const target of configured) {
    if (!corpusBySlug.get(target)?.m8) throw new Error(`${target}: M8 config is not attached to an external-corpus target`);
  }

  const unconfigured = corpus
    .filter((target) => !configs[target.slug])
    .map((target) => {
      const baseline = target.modules.M8;
      const reason = isNotRun(baseline)
        ? baseline.reason
        : "counted by the source-tier M8 baseline instead of mutation scoring: " + baseline.note;
      if (!reason.trim()) throw new Error(`${target.slug}: unconfigured M8 target has no counted reason`);
      return { target: target.slug, reason };
    })
    .sort((a, b) => a.target.localeCompare(b.target));

  if (configured.length + unconfigured.length !== corpus.length) {
    throw new Error(`M8 plan accounts for ${configured.length + unconfigured.length}/${corpus.length} targets`);
  }
  return { configured, unconfigured };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function finiteNonNegative(value: unknown): value is number {
  return typeof value === "number" && Number.isFinite(value) && value >= 0;
}

export function parseM8TargetResult(raw: string, source: string): M8TargetResult {
  let value: unknown;
  try {
    value = JSON.parse(raw);
  } catch (error) {
    throw new Error(`${source}: corrupt JSON (${(error as Error).message})`);
  }
  if (!isRecord(value)) throw new Error(`${source}: artifact must be a JSON object`);
  if (value.schemaVersion !== 1) throw new Error(`${source}: unsupported schemaVersion ${String(value.schemaVersion)}`);
  if (typeof value.target !== "string" || !value.target) throw new Error(`${source}: target must be a non-empty string`);
  if (value.status !== "passed" && value.status !== "failed") throw new Error(`${source}: status must be passed or failed`);
  if (!Number.isInteger(value.exitCode)) throw new Error(`${source}: exitCode must be an integer`);
  if (!finiteNonNegative(value.durationMs)) throw new Error(`${source}: durationMs must be finite and non-negative`);
  if (value.error !== undefined && typeof value.error !== "string") throw new Error(`${source}: error must be a string when present`);

  let phases: M8TargetResult["phases"] = null;
  if (value.phases !== null) {
    if (!isRecord(value.phases)) throw new Error(`${source}: phases must be an object or null`);
    phases = {} as Record<M8TargetPhase, number>;
    for (const phase of M8_TARGET_PHASES) {
      if (!finiteNonNegative(value.phases[phase])) throw new Error(`${source}: phase ${phase} must be finite and non-negative`);
      phases[phase] = value.phases[phase];
    }
  }

  let scorecard: M8TargetResult["scorecard"] = null;
  if (value.scorecard !== null) {
    if (!isRecord(value.scorecard) || !Array.isArray(value.scorecard.rows) || !isRecord(value.scorecard.findings)) {
      throw new Error(`${source}: scorecard must carry rows and findings`);
    }
    scorecard = value.scorecard as unknown as NonNullable<M8TargetResult["scorecard"]>;
  }
  if (value.status === "passed" && (!phases || !scorecard || value.exitCode !== 0)) {
    throw new Error(`${source}: a passed target must carry complete phases + scorecard and exitCode 0`);
  }
  return {
    schemaVersion: 1,
    target: value.target,
    status: value.status,
    exitCode: value.exitCode as number,
    durationMs: value.durationMs,
    phases,
    scorecard,
    ...(value.error === undefined ? {} : { error: value.error }),
  };
}

function validateScorecard(result: M8TargetResult): void {
  if (!result.scorecard) return;
  const rows = result.scorecard.rows.filter((row): row is Record<string, unknown> => isRecord(row));
  if (rows.length !== result.scorecard.rows.length) throw new Error(`${result.target}: scorecard contains a non-object row`);
  const targetRows = rows.filter((row) => row.slug === result.target && row.check === "M8 mutation baseline");
  if (targetRows.length !== 1 || rows.length !== 1) {
    throw new Error(`${result.target}: scorecard must contain exactly one M8 mutation baseline row for its target`);
  }
  if (result.status === "passed" && targetRows[0]?.pass !== true) {
    throw new Error(`${result.target}: passed artifact carries a failing baseline row`);
  }
}

export function aggregateM8TargetResults(plan: M8CorpusPlan, results: readonly M8TargetResult[]): M8AggregateReport {
  const expected = new Set(plan.configured);
  const seen = new Set<string>();
  const aggregationMsByTarget = new Map<string, number>();
  for (const result of results) {
    const started = performance.now();
    if (!expected.has(result.target)) throw new Error(`${result.target}: artifact is not in the configured M8 target set`);
    if (seen.has(result.target)) throw new Error(`${result.target}: duplicate target artifact`);
    seen.add(result.target);
    validateScorecard(result);
    aggregationMsByTarget.set(result.target, performance.now() - started);
  }
  const missing = plan.configured.filter((target) => !seen.has(target));
  if (missing.length) throw new Error(`missing target artifact(s): ${missing.join(", ")}`);

  const sorted = [...results].sort((a, b) => a.target.localeCompare(b.target));
  const targets = sorted.map((result) => ({
    ...result,
    phases: result.phases ? { ...result.phases, aggregation: aggregationMsByTarget.get(result.target) ?? 0 } : null,
  }));
  const critical = sorted.reduce((longest, result) => result.durationMs > longest.durationMs ? result : longest);
  const failed = sorted.filter((result) => result.status === "failed").length;
  const aggregationMs = [...aggregationMsByTarget.values()].reduce((sum, duration) => sum + duration, 0);
  return {
    configuredTargets: [...plan.configured],
    unconfiguredTargets: [...plan.unconfigured],
    targets,
    criticalPath: { target: critical.target, durationMs: critical.durationMs + (aggregationMsByTarget.get(critical.target) ?? 0) },
    aggregateRunnerCostMs: sorted.reduce((sum, result) => sum + result.durationMs, aggregationMs),
    passed: sorted.length - failed,
    failed,
    ok: failed === 0,
  };
}
