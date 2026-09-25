import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import type { AuditModule } from "./audit-coverage.js";
import { statSafe } from "./fs-walk.js";
import type { SemgrepExecutionPlanReceipt } from "./scan/semgrep-family-cache.js";
import { assertSuccessfulSemgrepExecutionReceipt } from "./scan/semgrep-family-cache.js";

export const PRODUCER_EXECUTION_RECEIPT_SCHEMA = 3 as const;
export const COMMAND_EXECUTION_RECEIPT_SCHEMA = 2 as const;

export type CommandTerminalState =
  | "policy-denied"
  | "spawn-failed"
  | "exited"
  | "signaled"
  | "timed-out"
  | "cancelled"
  | "unknown-exit";

export interface CommandArtifactReceipt {
  readonly role: "report" | "stdout" | "stderr" | "raw-output" | "other";
  readonly path: string;
  readonly bytes: number;
  readonly sha256: string;
}

interface CommandArtifactFailure {
  readonly role: CommandArtifactReceipt["role"];
  readonly path: string;
  readonly reason: "missing" | "unreadable";
  readonly errorCode?: string;
}

export interface CommandExecutionReceipt {
  readonly schema: typeof COMMAND_EXECUTION_RECEIPT_SCHEMA;
  readonly invocationId: string;
  readonly attempt: number;
  readonly command: { readonly executable: string; readonly argv: readonly string[]; readonly cwd: string };
  readonly target: { readonly identity: string; readonly sha256: string };
  readonly toolchain: readonly { readonly name: string; readonly version: string; readonly sha256?: string }[];
  readonly configuration: { readonly identity: string; readonly sha256: string };
  readonly startedAt: string;
  readonly finishedAt: string;
  readonly outcome: {
    readonly state: CommandTerminalState;
    readonly exitCode: number | null;
    readonly signal: string | null;
    readonly errorCode?: string;
  };
  readonly timeoutPolicy: { readonly timeoutMs: number | null; readonly killSignal: string };
  readonly cancellationPolicy: "pre-start-only" | "unsupported";
  readonly stdout: { readonly bytes: number; readonly sha256: string };
  readonly stderr: { readonly bytes: number; readonly sha256: string };
  readonly artifacts: readonly CommandArtifactReceipt[];
  /** Output failures do not overwrite the actual child exit or signal. */
  readonly artifactFailures: readonly CommandArtifactFailure[];
  readonly comparisonIdentity?: { readonly sourceSha256: string; readonly selectionSha256: string; readonly toolchainSha256: string };
  readonly measurements?: {
    readonly completedTests?: number;
    readonly testsDiscovered?: number;
    readonly suiteLoadErrors?: number;
  };
  readonly sha256: string;
}

interface CommandExecutionReceiptInput {
  readonly invocationId: string;
  readonly attempt?: number;
  readonly command: { readonly executable: string; readonly argv: readonly string[]; readonly cwd: string };
  readonly target: { readonly identity: string; readonly value: unknown };
  readonly toolchain: readonly { readonly name: string; readonly version: string; readonly sha256?: string }[];
  readonly configuration: { readonly identity: string; readonly value: unknown };
  readonly startedAt: string;
  readonly finishedAt: string;
  readonly outcome: CommandExecutionReceipt["outcome"];
  readonly timeoutPolicy?: { readonly timeoutMs?: number | null; readonly killSignal?: string };
  readonly cancellationPolicy?: CommandExecutionReceipt["cancellationPolicy"];
  readonly comparisonIdentity?: CommandExecutionReceipt["comparisonIdentity"];
  readonly stdout?: string | Buffer;
  readonly stderr?: string | Buffer;
  readonly artifacts?: readonly { readonly role: CommandArtifactReceipt["role"]; readonly path: string }[];
  readonly measurements?: CommandExecutionReceipt["measurements"];
  /** Exact values are replaced everywhere in argv before anything is retained or hashed. */
  readonly secretValues?: readonly string[];
}

export const PRODUCER_ROUTE_EDGE_KINDS = [
  "semantic-call",
  "callback",
  "registry-iteration",
  "command",
  "semgrep-family",
  "artifact-produce",
  "artifact-ingest",
  "conservation-consume",
  "client-delivery",
] as const;

export type ProducerRouteEdgeKind = (typeof PRODUCER_ROUTE_EDGE_KINDS)[number];

export interface ProducerRouteEdge {
  readonly ordinal: number;
  readonly kind: ProducerRouteEdgeKind;
  readonly from: string;
  readonly to: string;
  /** Content identity of the runtime observation which caused this edge to be emitted. */
  readonly evidenceSha256: string;
}

export interface ProducerExecutionReceipt {
  readonly schema: typeof PRODUCER_EXECUTION_RECEIPT_SCHEMA;
  readonly status: "succeeded";
  readonly executionId: string;
  readonly producerId: string;
  readonly implementationId: string;
  readonly module: AuditModule;
  readonly tier: "free" | "connected" | "dynamic" | "paid";
  readonly findingFamilyIds: readonly string[];
  readonly findingIds: readonly string[];
  readonly edges: readonly ProducerRouteEdge[];
  readonly sha256: string;
}

type ReceiptBody = Omit<ProducerExecutionReceipt, "schema" | "status" | "sha256" | "edges"> & {
  readonly edges: readonly Omit<ProducerRouteEdge, "ordinal" | "evidenceSha256">[];
  /** Optional source evidence. It is hashed and discarded so secrets/raw output never enter receipts. */
  readonly evidence?: unknown;
};

const byBytes = (left: string, right: string): number => Buffer.compare(Buffer.from(left), Buffer.from(right));

function canonical(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value as Record<string, unknown>)
      .sort(([left], [right]) => byBytes(left, right))
      .map(([key, item]) => [key, canonical(item)]));
  }
  return value;
}

function canonicalReceiptJson(value: unknown): string {
  return JSON.stringify(canonical(value));
}

function receiptSha256(value: unknown): string {
  return createHash("sha256").update(canonicalReceiptJson(value)).digest("hex");
}

const SECRET_OPTION = /(?:^|[-_])(authorization|cookie|credential|key|password|passwd|secret|session|token)(?:$|[-_])/i;

function redactUrlSecrets(value: string): string {
  try {
    const parsed = new URL(value);
    if (parsed.username) parsed.username = "<redacted>";
    if (parsed.password) parsed.password = "<redacted>";
    for (const key of [...parsed.searchParams.keys()]) if (SECRET_OPTION.test(key)) parsed.searchParams.set(key, "<redacted>");
    return parsed.toString();
  } catch {
    return value;
  }
}

function sanitizeReceiptValue(value: unknown, secretValues: readonly string[]): unknown {
  if (Array.isArray(value)) return value.every((item) => typeof item === "string")
    ? sanitizeCommandArgv(value, secretValues)
    : value.map((item) => sanitizeReceiptValue(item, secretValues));
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value as Record<string, unknown>).map(([key, item]) => [
      key,
      SECRET_OPTION.test(key) ? "<redacted>" : sanitizeReceiptValue(item, secretValues),
    ]));
  }
  if (typeof value !== "string") return value;
  let sanitized = sanitizeCommandArgv([value])[0]!;
  for (const secret of secretValues.filter(Boolean).sort((left, right) => right.length - left.length)) sanitized = sanitized.split(secret).join("<redacted>");
  return sanitized;
}

/** Redact credential-bearing options and exact caller-provided secret values before persistence. */
function sanitizeCommandArgv(argv: readonly string[], secretValues: readonly string[] = []): string[] {
  const secrets = secretValues.filter(Boolean).sort((left, right) => right.length - left.length);
  let redactNext = false;
  return argv.map((raw) => {
    if (redactNext) {
      redactNext = false;
      return "<redacted>";
    }
    const equals = raw.indexOf("=");
    if (raw.startsWith("--") && equals === -1 && SECRET_OPTION.test(raw.slice(2))) {
      redactNext = true;
      return raw;
    }
    let value = raw;
    if (raw.startsWith("--") && equals > 2 && SECRET_OPTION.test(raw.slice(2, equals))) {
      value = `${raw.slice(0, equals + 1)}<redacted>`;
    } else {
      value = redactUrlSecrets(raw);
      if (value === raw && equals > 0) value = `${raw.slice(0, equals + 1)}${redactUrlSecrets(raw.slice(equals + 1))}`;
    }
    for (const secret of secrets) value = value.split(secret).join("<redacted>");
    return value;
  });
}

function streamReceipt(value: string | Buffer | undefined): { bytes: number; sha256: string } {
  const bytes = Buffer.isBuffer(value) ? value : Buffer.from(value ?? "", "utf8");
  return { bytes: bytes.byteLength, sha256: createHash("sha256").update(bytes).digest("hex") };
}

function commandReceiptWithoutDigest(receipt: CommandExecutionReceipt): Omit<CommandExecutionReceipt, "sha256"> {
  const body = { ...receipt } as Record<string, unknown>;
  delete body.sha256;
  return body as unknown as Omit<CommandExecutionReceipt, "sha256">;
}

/** Finalize only after the child has terminated and every declared artifact has settled on disk. */
export function createCommandExecutionReceipt(input: CommandExecutionReceiptInput): CommandExecutionReceipt {
  const secretValues = input.secretValues ?? [];
  const artifactFailures: CommandArtifactFailure[] = [];
  const artifacts = [...(input.artifacts ?? [])]
    .flatMap(({ role, path: declaredPath }): CommandArtifactReceipt[] => {
      const path = resolve(input.command.cwd, declaredPath);
      try {
        const bytes = readFileSync(path);
        return [{ role, path, bytes: bytes.byteLength, sha256: createHash("sha256").update(bytes).digest("hex") }];
      } catch (error) {
        const errorCode = (error as NodeJS.ErrnoException).code;
        artifactFailures.push({ role, path, reason: errorCode === "ENOENT" ? "missing" : "unreadable", ...(errorCode ? { errorCode } : {}) });
        return [];
      }
    })
    .sort((left, right) => byBytes(`${left.role}\0${left.path}`, `${right.role}\0${right.path}`));
  const body: Omit<CommandExecutionReceipt, "sha256"> = {
    schema: COMMAND_EXECUTION_RECEIPT_SCHEMA,
    invocationId: input.invocationId,
    attempt: input.attempt ?? 1,
    command: {
      executable: input.command.executable,
      argv: sanitizeCommandArgv(input.command.argv, input.secretValues),
      cwd: input.command.cwd,
    },
    target: { identity: input.target.identity, sha256: receiptSha256(sanitizeReceiptValue(input.target.value, secretValues)) },
    toolchain: [...input.toolchain].sort((left, right) => byBytes(`${left.name}\0${left.version}`, `${right.name}\0${right.version}`)),
    configuration: { identity: input.configuration.identity, sha256: receiptSha256(sanitizeReceiptValue(input.configuration.value, secretValues)) },
    startedAt: input.startedAt,
    finishedAt: input.finishedAt,
    outcome: input.outcome,
    timeoutPolicy: {
      timeoutMs: input.timeoutPolicy?.timeoutMs ?? null,
      killSignal: input.timeoutPolicy?.killSignal ?? "SIGTERM",
    },
    cancellationPolicy: input.cancellationPolicy ?? "unsupported",
    stdout: streamReceipt(input.stdout),
    stderr: streamReceipt(input.stderr),
    artifacts,
    artifactFailures: artifactFailures.sort((left, right) => byBytes(`${left.role}\0${left.path}`, `${right.role}\0${right.path}`)),
    ...(input.comparisonIdentity ? { comparisonIdentity: input.comparisonIdentity } : {}),
    ...(input.measurements ? { measurements: input.measurements } : {}),
  };
  const receipt = { ...body, sha256: receiptSha256(body) };
  assertCommandExecutionReceipt(receipt);
  return receipt;
}

export function assertCommandExecutionReceipt(value: unknown): asserts value is CommandExecutionReceipt {
  const receipt = value as CommandExecutionReceipt;
  if (!receipt || receipt.schema !== COMMAND_EXECUTION_RECEIPT_SCHEMA) throw new Error("command execution receipt uses an unsupported schema");
  if (!receipt.invocationId?.trim() || !Number.isInteger(receipt.attempt) || receipt.attempt < 1) throw new Error("command execution receipt has an invalid invocation identity");
  if (!receipt.command?.executable?.trim() || !receipt.command.cwd?.trim() || !Array.isArray(receipt.command.argv)) throw new Error("command execution receipt has an invalid command");
  if (receipt.command.argv.some((arg) => typeof arg !== "string")) throw new Error("command execution receipt argv is malformed");
  if (!receipt.target?.identity?.trim() || !/^[a-f0-9]{64}$/.test(receipt.target.sha256)) throw new Error("command execution receipt has an invalid target identity");
  if (!receipt.configuration?.identity?.trim() || !/^[a-f0-9]{64}$/.test(receipt.configuration.sha256)) throw new Error("command execution receipt has an invalid configuration identity");
  if (!Array.isArray(receipt.toolchain) || receipt.toolchain.length === 0 || receipt.toolchain.some((tool) => !tool.name?.trim() || !tool.version?.trim() || (tool.sha256 !== undefined && !/^[a-f0-9]{64}$/.test(tool.sha256)))) throw new Error("command execution receipt has an invalid toolchain identity");
  const started = Date.parse(receipt.startedAt);
  const finished = Date.parse(receipt.finishedAt);
  if (Number.isNaN(started) || Number.isNaN(finished) || finished < started) throw new Error("command execution receipt has invalid execution times");
  if (!["policy-denied", "spawn-failed", "exited", "signaled", "timed-out", "cancelled", "unknown-exit"].includes(receipt.outcome?.state)) throw new Error("command execution receipt has an unknown terminal state");
  if (receipt.outcome.state === "exited" && (!Number.isInteger(receipt.outcome.exitCode) || receipt.outcome.signal !== null)) throw new Error("exited command receipt needs a numeric exit and no signal");
  if (receipt.outcome.state === "signaled" && (receipt.outcome.exitCode !== null || !receipt.outcome.signal)) throw new Error("signaled command receipt needs a signal and no exit code");
  if (["policy-denied", "spawn-failed", "cancelled", "unknown-exit"].includes(receipt.outcome.state) && receipt.outcome.exitCode !== null) throw new Error(`${receipt.outcome.state} command receipt cannot claim an exit code`);
  if (!receipt.timeoutPolicy || (receipt.timeoutPolicy.timeoutMs !== null && (!Number.isInteger(receipt.timeoutPolicy.timeoutMs) || receipt.timeoutPolicy.timeoutMs < 1)) || !receipt.timeoutPolicy.killSignal?.trim()) throw new Error("command execution receipt has an invalid timeout policy");
  if (!["pre-start-only", "unsupported"].includes(receipt.cancellationPolicy)) throw new Error("command execution receipt has an invalid cancellation policy");
  for (const stream of [receipt.stdout, receipt.stderr]) if (!Number.isInteger(stream?.bytes) || stream.bytes < 0 || !/^[a-f0-9]{64}$/.test(stream.sha256)) throw new Error("command execution receipt has an invalid output digest");
  if (!Array.isArray(receipt.artifacts)) throw new Error("command execution receipt artifacts are missing");
  for (const artifact of receipt.artifacts) if (!artifact.path?.trim() || !["report", "stdout", "stderr", "raw-output", "other"].includes(artifact.role) || !Number.isInteger(artifact.bytes) || artifact.bytes < 0 || !/^[a-f0-9]{64}$/.test(artifact.sha256)) throw new Error("command execution receipt has an invalid artifact digest");
  if (!Array.isArray(receipt.artifactFailures)) throw new Error("command execution receipt artifact failures are missing");
  for (const artifact of receipt.artifactFailures) if (!artifact.path?.trim() || !["report", "stdout", "stderr", "raw-output", "other"].includes(artifact.role) || !["missing", "unreadable"].includes(artifact.reason)) throw new Error("command execution receipt has an invalid artifact failure");
  if (receipt.comparisonIdentity && [receipt.comparisonIdentity.sourceSha256, receipt.comparisonIdentity.selectionSha256, receipt.comparisonIdentity.toolchainSha256].some((sha) => !/^[a-f0-9]{64}$/.test(sha))) throw new Error("command execution receipt has an invalid comparison identity");
  for (const metric of Object.values(receipt.measurements ?? {})) if (!Number.isInteger(metric) || metric < 0) throw new Error("command execution receipt measurements must be non-negative integers");
  if (!/^[a-f0-9]{64}$/.test(receipt.sha256) || receipt.sha256 !== receiptSha256(commandReceiptWithoutDigest(receipt))) throw new Error("command execution receipt digest is invalid");
}

export function commandReceiptSucceeded(receipt: CommandExecutionReceipt): boolean {
  assertCommandExecutionReceipt(receipt);
  return receipt.outcome.state === "exited" && receipt.outcome.exitCode === 0 && receipt.artifactFailures.length === 0;
}

/** Re-read every output named by the receipt; regeneration or cross-run substitution fails loud. */
export function verifyCommandExecutionReceiptArtifacts(receipt: CommandExecutionReceipt): void {
  assertCommandExecutionReceipt(receipt);
  if (receipt.artifactFailures.length) throw new Error(`command receipt declared artifact is ${receipt.artifactFailures[0]!.reason}: ${receipt.artifactFailures[0]!.path}`);
  for (const artifact of receipt.artifacts) {
    if (!existsSync(artifact.path)) throw new Error(`command receipt artifact is missing: ${artifact.path}`);
    const stat = statSafe(artifact.path);
    if (!stat) throw new Error(`command receipt artifact cannot be read: ${artifact.path}`);
    const digest = createHash("sha256").update(readFileSync(artifact.path)).digest("hex");
    if (stat.size !== artifact.bytes || digest !== artifact.sha256) throw new Error(`command receipt artifact changed after invocation ${receipt.invocationId}: ${artifact.path}`);
  }
}

function receiptWithoutDigest(receipt: Omit<ProducerExecutionReceipt, "sha256"> | ProducerExecutionReceipt): Omit<ProducerExecutionReceipt, "sha256"> {
  return {
    schema: receipt.schema,
    status: receipt.status,
    executionId: receipt.executionId,
    producerId: receipt.producerId,
    implementationId: receipt.implementationId,
    module: receipt.module,
    tier: receipt.tier,
    findingFamilyIds: receipt.findingFamilyIds,
    findingIds: receipt.findingIds,
    edges: receipt.edges,
  };
}

export function createProducerExecutionReceipt(input: ReceiptBody): ProducerExecutionReceipt {
  const findingFamilyIds = [...new Set(input.findingFamilyIds)].sort(byBytes);
  const findingIds = [...input.findingIds];
  const baseEvidence = receiptSha256(input.evidence ?? {
    executionId: input.executionId,
    producerId: input.producerId,
    implementationId: input.implementationId,
    findingIds,
  });
  const edges = input.edges.map((edge, ordinal) => ({ ...edge, ordinal, evidenceSha256: receiptSha256({ baseEvidence, ordinal, edge }) }));
  const body: Omit<ProducerExecutionReceipt, "sha256"> = {
    schema: PRODUCER_EXECUTION_RECEIPT_SCHEMA,
    status: "succeeded",
    executionId: input.executionId,
    producerId: input.producerId,
    implementationId: input.implementationId,
    module: input.module,
    tier: input.tier,
    findingFamilyIds,
    findingIds,
    edges,
  };
  const receipt = { ...body, sha256: receiptSha256(body) };
  assertProducerExecutionReceipt(receipt);
  return receipt;
}

export function assertProducerExecutionReceipt(value: unknown): asserts value is ProducerExecutionReceipt {
  const receipt = value as Partial<ProducerExecutionReceipt>;
  if (!receipt || receipt.schema !== PRODUCER_EXECUTION_RECEIPT_SCHEMA || receipt.status !== "succeeded") {
    throw new Error("producer execution receipt is missing, planned, failed, or uses an unsupported schema");
  }
  for (const [label, field] of [["executionId", receipt.executionId], ["producerId", receipt.producerId], ["implementationId", receipt.implementationId]] as const) {
    if (typeof field !== "string" || !field.trim()) throw new Error(`producer execution receipt has an empty ${label}`);
  }
  if (!/^M(?:10|[1-9])$/.test(receipt.module ?? "")) throw new Error("producer execution receipt has an invalid module");
  if (!["free", "connected", "dynamic", "paid"].includes(receipt.tier ?? "")) throw new Error("producer execution receipt has an invalid tier");
  if (!Array.isArray(receipt.findingFamilyIds) || !Array.isArray(receipt.findingIds) || !Array.isArray(receipt.edges) || receipt.edges.length === 0) {
    throw new Error("producer execution receipt is missing family, finding, or route evidence");
  }
  if (new Set(receipt.findingFamilyIds).size !== receipt.findingFamilyIds.length
    || JSON.stringify([...receipt.findingFamilyIds].sort(byBytes)) !== JSON.stringify(receipt.findingFamilyIds)) {
    throw new Error("producer execution receipt finding families are duplicated or non-canonical");
  }
  receipt.edges.forEach((edge, ordinal) => {
    if (edge.ordinal !== ordinal) throw new Error("producer execution receipt edge ordering is malformed");
    if (!PRODUCER_ROUTE_EDGE_KINDS.includes(edge.kind)) throw new Error(`producer execution receipt has unknown edge kind ${edge.kind}`);
    if (!edge.from?.trim() || !edge.to?.trim() || !/^[a-f0-9]{64}$/.test(edge.evidenceSha256 ?? "")) {
      throw new Error("producer execution receipt edge identity is malformed");
    }
    if (ordinal > 0 && receipt.edges![ordinal - 1]!.to !== edge.from) {
      throw new Error("producer execution receipt edges do not form one ordered route");
    }
  });
  if (!/^[a-f0-9]{64}$/.test(receipt.sha256 ?? "") || receipt.sha256 !== receiptSha256(receiptWithoutDigest(receipt as ProducerExecutionReceipt))) {
    throw new Error("producer execution receipt digest is invalid");
  }
}

export function assertUniqueProducerExecutionReceipts(values: readonly unknown[]): asserts values is readonly ProducerExecutionReceipt[] {
  const ids = new Set<string>();
  for (const value of values) {
    assertProducerExecutionReceipt(value);
    const receipt = value as ProducerExecutionReceipt;
    if (ids.has(receipt.executionId)) throw new Error(`duplicate producer execution receipt ${receipt.executionId}`);
    ids.add(receipt.executionId);
  }
}

export function extendProducerExecutionReceipt(
  receipt: ProducerExecutionReceipt,
  edge: Omit<ProducerRouteEdge, "ordinal" | "evidenceSha256">,
  evidence?: unknown,
): ProducerExecutionReceipt {
  assertProducerExecutionReceipt(receipt);
  const previous = receipt.edges.at(-1)!;
  if (previous.to !== edge.from) throw new Error(`producer route cannot continue from ${previous.to} to ${edge.from}`);
  return createProducerExecutionReceipt({
    executionId: receipt.executionId,
    producerId: receipt.producerId,
    implementationId: receipt.implementationId,
    module: receipt.module,
    tier: receipt.tier,
    findingFamilyIds: receipt.findingFamilyIds,
    findingIds: receipt.findingIds,
    edges: [...receipt.edges.map(({ kind, from, to }) => ({ kind, from, to })), edge],
    evidence: { prior: receipt.sha256, evidence },
  });
}

/** Preserve one execution while applying the same project scope suffix used by delivered findings. */
export function remapProducerExecutionReceiptFindingIds(
  receipt: ProducerExecutionReceipt,
  mapping: Readonly<Record<string, string>>,
): ProducerExecutionReceipt {
  assertProducerExecutionReceipt(receipt);
  const remapEndpoint = (value: string): string => value.startsWith("finding:")
    ? `finding:${mapping[value.slice("finding:".length)] ?? value.slice("finding:".length)}`
    : value;
  return createProducerExecutionReceipt({
    executionId: receipt.executionId,
    producerId: receipt.producerId,
    implementationId: receipt.implementationId,
    module: receipt.module,
    tier: receipt.tier,
    findingFamilyIds: receipt.findingFamilyIds,
    findingIds: receipt.findingIds.map((id) => mapping[id] ?? id),
    edges: receipt.edges.map((edge) => ({ kind: edge.kind, from: remapEndpoint(edge.from), to: remapEndpoint(edge.to) })),
    evidence: { priorReceiptSha256: receipt.sha256, findingIdMapping: mapping },
  });
}

/** Adapt only PR1954's validated schema-8 *successful runtime* receipt. Plans/failures are rejected. */
export function semgrepProducerExecutionReceipts(value: unknown): ProducerExecutionReceipt[] {
  assertSuccessfulSemgrepExecutionReceipt(value);
  const receipt = value as SemgrepExecutionPlanReceipt;
  return receipt.families.flatMap((family) => {
    if (family.sourceKind === "registry-pack") {
      return [createProducerExecutionReceipt({
        executionId: `semgrep:${family.ordinal}:${family.id}`,
        producerId: `semgrep:registry:${family.sourceId}`,
        implementationId: `src/scan/semgrep.ts#${family.sourceId}`,
        module: "M1",
        tier: "free",
        findingFamilyIds: family.loadedRuleIds,
        findingIds: [],
        edges: [{ kind: "semgrep-family", from: `semgrep-family:${family.id}`, to: `producer:semgrep:registry:${family.sourceId}` }],
        evidence: { ownershipSha256: receipt.ownershipSha256, family },
      })];
    }
    return family.loadedRuleIds.map((ruleId, ruleOrdinal) => createProducerExecutionReceipt({
      executionId: `semgrep:${family.ordinal}:${ruleOrdinal}:${family.id}:${ruleId}`,
      producerId: `semgrep:local:${ruleId}`,
      implementationId: `src/scan/rules/semgrep/${family.sourceId}#${ruleId}`,
      module: "M1",
      tier: "free",
      findingFamilyIds: [ruleId],
      findingIds: [],
      edges: [{ kind: "semgrep-family", from: `semgrep-family:${family.id}`, to: `producer:semgrep:local:${ruleId}` }],
      evidence: { ownershipSha256: receipt.ownershipSha256, family },
    }));
  });
}

export function receiptHasRoute(
  receipt: ProducerExecutionReceipt,
  kinds: readonly ProducerRouteEdgeKind[],
): boolean {
  assertProducerExecutionReceipt(receipt);
  let cursor = 0;
  for (const edge of receipt.edges) if (edge.kind === kinds[cursor]) cursor += 1;
  return cursor === kinds.length;
}
