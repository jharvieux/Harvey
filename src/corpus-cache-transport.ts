import { createHash } from "node:crypto";
import { copyFileSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { readEntriesLstatSafe, readRecursiveSafe, statSafe } from "./fs-walk.js";
import { MECHANICAL_PHASES } from "./scan/mechanical-phase-cache.js";

export const CORPUS_CACHE_MAX_PAYLOAD_BYTES = 6 * 1024 * 1024 * 1024;

export type CorpusCacheTransportFamily = "run" | "main" | "benchmark";

interface CorpusCachePayloadReceipt {
  bytes: number;
  maxBytes: number;
  symlinks: 0;
}

export interface CorpusCacheTransportManifest {
  schema: 4;
  key: string;
  family: CorpusCacheTransportFamily;
  event: string;
  ref: string;
  runId: string;
  runAttempt: string;
  headSha: string;
  writtenAt: string;
  payload: CorpusCachePayloadReceipt;
  benchmarkSeed?: string;
}

interface CorpusCacheRestoreContext {
  matchedKey: string;
  event: string;
  ref: string;
  runId: string;
  defaultRef: string;
  platform: string;
  namespace: string;
  headSha: string;
  benchmarkSeed?: string;
}

interface CorpusCacheTransportDecision {
  accepted: boolean;
  reason: string;
  source?: CorpusCacheTransportManifest;
}

const MANIFEST = "transport-provenance.json";
const KEY = /^corpus-phase-(run|main)-v6-([A-Za-z0-9_.-]+)-shard([1-9]\d*)-(\d+)-(\d+)-([0-9a-f]{40})$/;
const BENCHMARK_KEY = /^corpus-phase-benchmark-v6-([A-Za-z0-9_.-]+)-seed([0-9a-f]{16})-shard([1-9]\d*)-(\d+)-(\d+)-([0-9a-f]{40})$/;

function sha256(value: string | Buffer): string {
  return createHash("sha256").update(value).digest("hex");
}

function benchmarkSeedDigest(seed: string): string {
  if (seed.trim().length === 0) throw new Error("benchmark transport requires a non-empty seed");
  return sha256(seed).slice(0, 16);
}

interface ParsedTransportKey {
  family: CorpusCacheTransportFamily;
  platform: string;
  namespace: string;
  runId: string;
  runAttempt: string;
  headSha: string;
  seedDigest?: string;
}

function parseTransportKey(value: string): ParsedTransportKey | undefined {
  const ordinary = KEY.exec(value);
  if (ordinary) {
    const [, family, platform, namespace, runId, runAttempt, headSha] = ordinary;
    return { family: family as "run" | "main", platform: platform!, namespace: namespace!, runId: runId!, runAttempt: runAttempt!, headSha: headSha! };
  }
  const benchmark = BENCHMARK_KEY.exec(value);
  if (!benchmark) return undefined;
  const [, platform, seedDigest, namespace, runId, runAttempt, headSha] = benchmark;
  return { family: "benchmark", platform: platform!, seedDigest: seedDigest!, namespace: namespace!, runId: runId!, runAttempt: runAttempt!, headSha: headSha! };
}

export function corpusCacheTransportKey(input: {
  family: CorpusCacheTransportFamily;
  platform: string;
  namespace: string;
  runId: string;
  runAttempt: string;
  headSha: string;
  benchmarkSeed?: string;
}): string {
  if (!/^[A-Za-z0-9_.-]+$/.test(input.platform)) throw new Error("transport provenance platform is invalid");
  if (!/^[1-9]\d*$/.test(input.namespace)) throw new Error("transport provenance namespace is invalid");
  if (!/^\d+$/.test(input.runId) || !/^\d+$/.test(input.runAttempt)) throw new Error("transport provenance run identity is invalid");
  if (!/^[0-9a-f]{40}$/.test(input.headSha)) throw new Error("transport provenance headSha is not a 40-character lowercase commit SHA");
  if (input.family === "benchmark") {
    return `corpus-phase-benchmark-v6-${input.platform}-seed${benchmarkSeedDigest(input.benchmarkSeed ?? "")}-shard${input.namespace}-${input.runId}-${input.runAttempt}-${input.headSha}`;
  }
  if (input.benchmarkSeed !== undefined) throw new Error(`${input.family} transport must not carry a benchmark seed`);
  return `corpus-phase-${input.family}-v6-${input.platform}-shard${input.namespace}-${input.runId}-${input.runAttempt}-${input.headSha}`;
}

function inspectPayload(dir: string): { bytes: number; symlinks: string[] } {
  let bytes = 0;
  const symlinks: string[] = [];
  const walk = (current: string): void => {
    if (!existsSync(current)) return;
    for (const entry of readEntriesLstatSafe(current)) {
      const path = entry.path;
      if (relative(dir, path) === MANIFEST) continue;
      if (entry.isSymbolicLink) {
        symlinks.push(relative(dir, path).replaceAll("\\", "/"));
      } else if (entry.isDirectory) {
        walk(path);
      } else if (entry.isFile) {
        bytes += entry.size;
      }
    }
  };
  walk(dir);
  return { bytes, symlinks: symlinks.sort() };
}

function payloadReceipt(dir: string): CorpusCachePayloadReceipt {
  const payload = inspectPayload(dir);
  if (payload.symlinks.length > 0) {
    throw new Error(`transport payload contains path-bound link(s): ${payload.symlinks.slice(0, 3).join(", ")}`);
  }
  if (payload.bytes > CORPUS_CACHE_MAX_PAYLOAD_BYTES) {
    throw new Error(`transport payload ${payload.bytes} bytes exceeds ${CORPUS_CACHE_MAX_PAYLOAD_BYTES}-byte ceiling`);
  }
  return { bytes: payload.bytes, maxBytes: CORPUS_CACHE_MAX_PAYLOAD_BYTES, symlinks: 0 };
}

function parseManifest(value: unknown): CorpusCacheTransportManifest {
  const manifest = value as Partial<CorpusCacheTransportManifest>;
  if (manifest.schema !== 4) throw new Error("unsupported transport provenance schema");
  for (const field of ["key", "event", "ref", "runId", "runAttempt", "headSha", "writtenAt", "family"] as const) {
    if (typeof manifest[field] !== "string" || manifest[field]!.length === 0) throw new Error(`transport provenance is missing ${field}`);
  }
  if (!/^\d{4}-\d{2}-\d{2}T/.test(manifest.writtenAt!)) throw new Error("transport provenance writtenAt is not an ISO timestamp");
  const key = parseTransportKey(manifest.key!);
  if (!key) throw new Error("transport provenance key does not encode platform, namespace, run, attempt, and headSha");
  if (manifest.family !== "run" && manifest.family !== "main" && manifest.family !== "benchmark") throw new Error("transport provenance family is invalid");
  if (manifest.family === "benchmark" && (typeof manifest.benchmarkSeed !== "string" || manifest.benchmarkSeed.trim().length === 0)) throw new Error("benchmark transport provenance is missing benchmarkSeed");
  if (manifest.family !== "benchmark" && manifest.benchmarkSeed !== undefined) throw new Error(`${manifest.family} transport provenance must not carry benchmarkSeed`);
  const expected = corpusCacheTransportKey({ family: manifest.family, platform: key.platform, namespace: key.namespace, runId: manifest.runId!, runAttempt: manifest.runAttempt!, headSha: manifest.headSha!, ...(manifest.benchmarkSeed === undefined ? {} : { benchmarkSeed: manifest.benchmarkSeed }) });
  if (manifest.key !== expected || key.family !== manifest.family || key.runId !== manifest.runId || key.runAttempt !== manifest.runAttempt || key.headSha !== manifest.headSha) {
    throw new Error("transport provenance key disagrees with its claimed run, attempt, or headSha");
  }
  const payload = manifest.payload as Partial<CorpusCachePayloadReceipt> | undefined;
  if (payload?.maxBytes !== CORPUS_CACHE_MAX_PAYLOAD_BYTES || payload.bytes === undefined || !Number.isSafeInteger(payload.bytes) || payload.bytes < 0 || payload.symlinks !== 0) {
    throw new Error("transport provenance payload receipt is missing or invalid");
  }
  return manifest as CorpusCacheTransportManifest;
}

export function decideCorpusCacheRestore(
  source: CorpusCacheTransportManifest,
  current: CorpusCacheRestoreContext,
): CorpusCacheTransportDecision {
  try {
    source = parseManifest(source);
  } catch (error) {
    return { accepted: false, source, reason: `invalid transport provenance: ${error instanceof Error ? error.message : String(error)}` };
  }
  if (source.key !== current.matchedKey) {
    return { accepted: false, source, reason: `matched key ${current.matchedKey} disagrees with provenance key ${source.key}` };
  }
  const matched = parseTransportKey(source.key);
  if (!matched || matched.platform !== current.platform || matched.namespace !== current.namespace) {
    return { accepted: false, source, reason: `source key ${source.key} is not for ${current.platform} shard${current.namespace}` };
  }
  if (source.family === "main" && source.ref === current.defaultRef && source.event === "push") {
    return { accepted: true, source, reason: `trusted default-branch seed from ${source.event} ${source.ref}` };
  }
  if (source.family === "run" && source.ref === current.ref && source.runId === current.runId && source.headSha === current.headSha) {
    return { accepted: true, source, reason: `same-run retry/fallback from ${source.event} ${source.ref}` };
  }
  if (source.family === "benchmark"
    && source.ref === current.ref
    && source.headSha === current.headSha
    && source.benchmarkSeed === current.benchmarkSeed) {
    return { accepted: true, source, reason: `exact benchmark seed ${source.benchmarkSeed} on ${source.ref} at ${source.headSha}` };
  }
  return {
    accepted: false,
    source,
    reason: `untrusted cache scope: ${source.event} ${source.ref} run ${source.runId} sha ${source.headSha} is neither ${current.defaultRef} nor current run ${current.runId} sha ${current.headSha} on ${current.ref}`,
  };
}

export function validateCorpusCacheTransport(dir: string, current: CorpusCacheRestoreContext): CorpusCacheTransportDecision {
  if (current.matchedKey.length === 0) return { accepted: true, reason: "Actions cache miss; no transport artifact was restored" };
  const path = join(dir, MANIFEST);
  if (!existsSync(path)) return { accepted: false, reason: `restored key ${current.matchedKey} has no ${MANIFEST}` };
  try {
    const manifest = parseManifest(JSON.parse(readFileSync(path, "utf8")));
    const payload = payloadReceipt(dir);
    if (payload.bytes !== manifest.payload.bytes) {
      return { accepted: false, source: manifest, reason: `transport payload byte count ${payload.bytes} disagrees with receipt ${manifest.payload.bytes}` };
    }
    return decideCorpusCacheRestore(manifest, current);
  } catch (error) {
    return { accepted: false, reason: `invalid transport provenance: ${error instanceof Error ? error.message : String(error)}` };
  }
}

export function rejectCorpusCacheTransport(dir: string): void {
  rmSync(dir, { recursive: true, force: true });
  mkdirSync(dir, { recursive: true });
}

export function writeCorpusCacheTransport(dir: string, manifest: Omit<CorpusCacheTransportManifest, "payload">): CorpusCacheTransportManifest {
  mkdirSync(dir, { recursive: true });
  const complete = parseManifest({ ...manifest, payload: payloadReceipt(dir) });
  writeFileSync(join(dir, MANIFEST), `${JSON.stringify(complete, null, 2)}\n`);
  return complete;
}

interface CorpusCacheMergeSource {
  dir: string;
  matchedKey: string;
  namespace: string;
}

interface CorpusCacheMergeReceipt {
  schema: 1;
  destination: string;
  benchmarkSeed: string;
  headSha: string;
  requiredNamespaces: string[];
  sources: Array<{
    namespace: string;
    key: string;
    runId: string;
    runAttempt: string;
    headSha: string;
    benchmarkSeed: string;
    payloadBytes: number;
  }>;
  files: Array<{ path: string; sha256: string; bytes: number; sourceNamespaces: string[] }>;
  aggregateSha256: string;
  duplicatePaths: number;
  conflicts: 0;
}

const CONTENT_ROOTS = new Set<string>([
  ...MECHANICAL_PHASES,
  "semgrep-families",
  "corpus-scanners",
  "dependency-preparation",
]);

function portableCachePath(path: string): boolean {
  const parts = path.split("/");
  const root = parts[0];
  if (!root || !CONTENT_ROOTS.has(root)) return false;
  if (root === "semgrep-families") return parts.length === 3 && /^[0-9a-f]{64}\.json$/.test(parts[2] ?? "");
  if (root === "corpus-scanners") return parts.length === 3 && /^[0-9a-f]{64}\.json$/.test(parts[2] ?? "");
  if (root === "dependency-preparation") {
    if (parts[1] === "receipts") return parts.length === 3 && /^[0-9a-f]{64}\.json$/.test(parts[2] ?? "");
    return parts[1] === "stores" && parts.length >= 4;
  }
  return parts.length === 2 && /^[0-9a-f]{64}\.json$/.test(parts[1] ?? "");
}

/** Merge trusted shard transports at the content-addressed layer so a 3→4 move keeps its artifacts. */
export function mergeCorpusCacheTransports(options: {
  sources: readonly CorpusCacheMergeSource[];
  destination: string;
  current: Omit<CorpusCacheRestoreContext, "namespace" | "matchedKey">;
  requiredNamespaces: readonly string[];
}): CorpusCacheMergeReceipt {
  if (!options.current.benchmarkSeed) throw new Error("cross-shard cache merge requires an exact benchmark seed");
  const expectedNamespaces = [...new Set(options.requiredNamespaces)].sort();
  if (expectedNamespaces.length === 0) throw new Error("cross-shard cache merge requires at least one source namespace");
  const accepted = options.sources.flatMap((source) => {
    if (source.matchedKey.length === 0) return [];
    const decision = validateCorpusCacheTransport(source.dir, {
      ...options.current,
      matchedKey: source.matchedKey,
      namespace: source.namespace,
    });
    if (!decision.accepted || !decision.source) throw new Error(`shard${source.namespace}: ${decision.reason}`);
    if (decision.source.family !== "benchmark") throw new Error(`shard${source.namespace}: only exact benchmark-seed transports may cross shard namespaces`);
    return [{ source, manifest: decision.source }];
  });
  const received = new Set(accepted.map(({ source }) => source.namespace));
  const missing = expectedNamespaces.filter((namespace) => !received.has(namespace));
  const unknown = [...received].filter((namespace) => !expectedNamespaces.includes(namespace));
  if (missing.length > 0 || unknown.length > 0 || received.size !== accepted.length) {
    throw new Error(`cross-shard cache seed population is not exact: ${missing.length ? `missing ${missing.join(", ")}` : ""}${missing.length && unknown.length ? "; " : ""}${unknown.length ? `unknown ${unknown.join(", ")}` : ""}${received.size !== accepted.length ? "; duplicate namespace" : ""}`);
  }
  if (existsSync(options.destination) && readRecursiveSafe(options.destination).length > 0) {
    throw new Error(`cross-shard cache merge destination is not empty: ${options.destination}`);
  }
  mkdirSync(options.destination, { recursive: true });
  const rows = new Map<string, { sha256: string; bytes: number; sourceNamespaces: string[] }>();
  let duplicatePaths = 0;
  for (const { source } of accepted.sort((left, right) => left.source.namespace.localeCompare(right.source.namespace))) {
    for (const path of readRecursiveSafe(source.dir).sort()) {
      if (path === MANIFEST || path === "cache-merge-receipt.json") continue;
      const absolute = join(source.dir, path);
      const stat = statSafe(absolute);
      if (!stat?.isFile()) continue;
      if (!portableCachePath(path)) throw new Error(`shard${source.namespace}: transport contains non-content-addressed path ${path}`);
      const body = readFileSync(absolute);
      const digest = sha256(body);
      const prior = rows.get(path);
      if (prior) {
        if (prior.sha256 !== digest || prior.bytes !== body.byteLength) {
          throw new Error(`cross-shard cache conflict at ${path}: ${prior.sha256} != ${digest}`);
        }
        prior.sourceNamespaces.push(source.namespace);
        duplicatePaths += 1;
        continue;
      }
      rows.set(path, { sha256: digest, bytes: body.byteLength, sourceNamespaces: [source.namespace] });
      const destination = join(options.destination, path);
      mkdirSync(dirname(destination), { recursive: true });
      copyFileSync(absolute, destination);
    }
  }
  const files = [...rows].sort(([left], [right]) => left.localeCompare(right)).map(([path, row]) => ({ path, ...row }));
  const aggregateSha256 = sha256(JSON.stringify(files));
  return {
    schema: 1,
    destination: options.destination,
    benchmarkSeed: options.current.benchmarkSeed,
    headSha: options.current.headSha,
    requiredNamespaces: expectedNamespaces,
    sources: accepted.map(({ source, manifest }) => ({
      namespace: source.namespace,
      key: manifest.key,
      runId: manifest.runId,
      runAttempt: manifest.runAttempt,
      headSha: manifest.headSha,
      benchmarkSeed: manifest.benchmarkSeed!,
      payloadBytes: manifest.payload.bytes,
    })),
    files,
    aggregateSha256,
    duplicatePaths,
    conflicts: 0,
  };
}
