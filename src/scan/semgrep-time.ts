/**
 * Semgrep's `--time` envelope mixes coverage evidence with experimental profiling data.
 * Rule ids are semantic. Fixpoint timeout rows are one-way telemetry: their presence means
 * taint coverage was incomplete, but their volatile text/location/count/order is not a replay
 * identity. We still validate and retain every raw row so malformed scanner output fails closed.
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
  error_type: string;
  severity: string;
  message: string;
  location: {
    path: string;
    start: { line: number; col: number; offset: number };
    end: { line: number; col: number; offset: number };
  };
}

interface SemgrepSemanticTime {
  rules: string[];
  fixpoint_timeouts: SemgrepFixpointTimeout[];
  [key: string]: unknown;
}

export const SEMGREP_TIMEOUT_POLICY = "fixpoint-family-not-assessed-v1" as const;

export class SemgrepTimeoutTelemetryError extends Error {
  readonly rawEvidence: unknown;

  constructor(message: string, rawEvidence: unknown) {
    super(message);
    this.name = "SemgrepTimeoutTelemetryError";
    this.rawEvidence = rawEvidence;
  }
}

function exactKeys(value: Record<string, unknown>, expected: readonly string[]): boolean {
  const wanted = [...expected].sort();
  const actual = Object.keys(value).sort();
  return actual.length === wanted.length && actual.every((key, index) => key === wanted[index]);
}

function validateTimeout(raw: unknown): SemgrepFixpointTimeout {
  const reject = (reason: string): never => {
    throw new SemgrepTimeoutTelemetryError(`Semgrep fixpoint timeout ${reason}`, raw);
  };
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) reject("row is missing or malformed");
  const row = raw as Record<string, unknown>;
  if (!exactKeys(row, ["error_type", "severity", "message", "location"])) reject("row contains an unknown or missing key");
  if (typeof row.error_type !== "string" || row.error_type.length === 0
    || typeof row.severity !== "string" || row.severity.length === 0
    || typeof row.message !== "string" || row.message.length === 0) reject("type, severity, or message is malformed");
  if (!row.location || typeof row.location !== "object" || Array.isArray(row.location)) reject("location is malformed");
  const location = row.location as Record<string, unknown>;
  if (!exactKeys(location, ["path", "start", "end"]) || typeof location.path !== "string" || location.path.length === 0) {
    reject("location contains an unknown or missing key");
  }
  const point = (value: unknown, label: string): { line: number; col: number; offset: number } => {
    if (!value || typeof value !== "object" || Array.isArray(value)) reject(`${label} span is malformed`);
    const record = value as Record<string, unknown>;
    if (!exactKeys(record, ["line", "col", "offset"])
      || !Number.isInteger(record.line) || (record.line as number) <= 0
      || !Number.isInteger(record.col) || (record.col as number) <= 0
      || !Number.isInteger(record.offset) || (record.offset as number) < 0) reject(`${label} span contains an unknown or invalid value`);
    return { line: record.line as number, col: record.col as number, offset: record.offset as number };
  };
  return {
    error_type: row.error_type as string,
    severity: row.severity as string,
    message: row.message as string,
    location: { path: location.path as string, start: point(location.start, "start"), end: point(location.end, "end") },
  };
}

/** Retain semantic rule ids plus exact, validated raw timeout telemetry. */
export function canonicalizeSemgrepTime(value: unknown, _ownedRuleIds?: readonly string[], input: "raw" | "canonical" = "raw"): SemgrepSemanticTime {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("Semgrep --time evidence is missing or malformed");
  const record = value as Record<string, unknown>;
  const unknown = Object.keys(record).filter((key) => key !== "rules" && key !== "fixpoint_timeouts" && !PROFILING_TIME_CHILDREN.has(key)).sort();
  if (unknown.length > 0) throw new Error(`Semgrep --time contains unclassified child evidence: ${unknown.join(", ")}`);
  if (!Array.isArray(record.rules) || record.rules.some((rule) => typeof rule !== "string" || rule.length === 0)) {
    throw new Error("Semgrep --time rules population is missing or malformed");
  }
  if (input === "raw" && !Array.isArray(record.fixpoint_timeouts)) throw new Error("Semgrep --time fixpoint_timeouts population is missing or malformed");
  if (record.fixpoint_timeouts !== undefined && !Array.isArray(record.fixpoint_timeouts)) throw new Error("Semgrep --time fixpoint_timeouts population is malformed");
  return {
    rules: [...new Set(record.rules as string[])].sort(),
    // Preserve input order and multiplicity. These rows are evidence, never semantic identity.
    fixpoint_timeouts: ((record.fixpoint_timeouts ?? []) as unknown[]).map(validateTimeout),
  };
}
