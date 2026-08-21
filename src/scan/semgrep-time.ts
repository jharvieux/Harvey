/**
 * Semgrep's `--time` envelope mixes semantic coverage evidence with volatile profiling data.
 * Keep the two semantic populations and name every profiling child we intentionally discard so a
 * future Semgrep field cannot silently disappear behind a catch-all telemetry deletion.
 */
const PROFILING_TIME_CHILDREN = new Set([
  "rules_parse_time",
  "profiling_times",
  "parsing_time",
  "scanning_time",
  "matching_time",
  "tainting_time",
  "prefiltering",
  "targets",
  "total_bytes",
  "max_memory_bytes",
]);

export interface SemgrepFixpointTimeout {
  error_type?: string;
  severity?: string;
  message?: string;
  location?: {
    path?: string;
    start?: { line?: number; col?: number; offset?: number; [key: string]: unknown };
    end?: { line?: number; col?: number; offset?: number; [key: string]: unknown };
    [key: string]: unknown;
  };
  [key: string]: unknown;
}

export interface SemgrepSemanticTime {
  rules: string[];
  fixpoint_timeouts: SemgrepFixpointTimeout[];
  [key: string]: unknown;
}

function stable(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stable).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.entries(value as Record<string, unknown>)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([key, item]) => `${JSON.stringify(key)}:${stable(item)}`)
      .join(",")}}`;
  }
  return JSON.stringify(value) ?? "undefined";
}

function uniqueSorted<T>(items: readonly T[]): T[] {
  return [...new Map(items.map((item) => [stable(item), item])).entries()]
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([, item]) => item);
}

/** Retain exactly the semantic `--time` evidence and reject every unclassified child. */
export function canonicalizeSemgrepTime(value: unknown): SemgrepSemanticTime {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("Semgrep --time evidence is missing or malformed");
  }
  const record = value as Record<string, unknown>;
  const unknown = Object.keys(record)
    .filter((key) => key !== "rules" && key !== "fixpoint_timeouts" && !PROFILING_TIME_CHILDREN.has(key))
    .sort();
  if (unknown.length > 0) throw new Error(`Semgrep --time contains unclassified child evidence: ${unknown.join(", ")}`);
  if (!Array.isArray(record.rules) || record.rules.some((rule) => typeof rule !== "string" || rule.length === 0)) {
    throw new Error("Semgrep --time rules population is missing or malformed");
  }
  if (!Array.isArray(record.fixpoint_timeouts)
    || record.fixpoint_timeouts.some((timeout) => !timeout || typeof timeout !== "object" || Array.isArray(timeout))) {
    throw new Error("Semgrep --time fixpoint_timeouts population is missing or malformed");
  }
  return {
    rules: [...new Set(record.rules as string[])].sort(),
    fixpoint_timeouts: uniqueSorted(record.fixpoint_timeouts as SemgrepFixpointTimeout[]),
  };
}
