import { createHash } from "node:crypto";
import { closeSync, existsSync, mkdirSync, openSync, readFileSync, readSync, rmSync, writeFileSync } from "node:fs";
import { isAbsolute, join, relative } from "node:path";
import { readEntriesLstatSafe } from "./fs-walk.js";
import {
  assertPartitionCoversEveryTarget,
  compareUtf8Bytes,
  CORPUS_CACHE_PARTITION_POLICY,
  CORPUS_CACHE_SHARD_COUNT,
  DEFAULT_SCAN_SECONDS,
  partitionTargets,
  TARGET_SCAN_SECONDS,
} from "./scan/corpus-shards.js";

export const CORPUS_CACHE_MAX_PAYLOAD_BYTES = 6 * 1024 * 1024 * 1024;
export type CorpusCacheTransportFamily = "run" | "main";

interface CorpusCacheScopeTarget {
  slug: string;
  repo: string;
  commit: string;
  vendoredSubtrees?: readonly string[];
  scanRoots?: Readonly<Record<string, string>>;
  installFlags?: readonly string[];
}

export interface CorpusCacheOwnershipScope {
  schema: 1;
  policy: typeof CORPUS_CACHE_PARTITION_POLICY;
  shardCount: typeof CORPUS_CACHE_SHARD_COUNT;
  namespace: number;
  defaultWeightSeconds: number;
  weights: Array<{ slug: string; seconds: number }>;
  partitions: Array<{ namespace: number; targets: string[] }>;
  population: Array<{
    slug: string;
    repo: string;
    commit: string;
    vendoredSubtrees: string[];
    scanRoots: Record<string, string>;
    installFlags: string[];
  }>;
  owners: string[];
}

interface CorpusCachePayloadClassReceipt {
  name: string;
  files: number;
  bytes: number;
}

interface CorpusCachePayloadReceipt {
  bytes: number;
  files: number;
  inventorySha256: string;
  classes: CorpusCachePayloadClassReceipt[];
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
  scope: CorpusCacheOwnershipScope;
  scopeSha256: string;
  payload: CorpusCachePayloadReceipt;
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
  scope: CorpusCacheOwnershipScope;
}

interface CorpusCacheTransportDecision {
  accepted: boolean;
  reason: string;
  source?: CorpusCacheTransportManifest;
}

const MANIFEST = "transport-provenance.json";
const SHA256 = /^[0-9a-f]{64}$/;
const KEY = /^corpus-phase-(run|main)-v6-([A-Za-z0-9_.-]+)-shard([1-9]\d*)-scope([0-9a-f]{64})-(\d+)-(\d+)-([0-9a-f]{40})$/;
function stable(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stable).join(",")}]`;
  if (value && typeof value === "object") {
    const object = value as Record<string, unknown>;
    return `{${Object.keys(object).sort(compareUtf8Bytes).map((key) => `${JSON.stringify(key)}:${stable(object[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

export function corpusCacheOwnershipScope(
  targets: readonly CorpusCacheScopeTarget[],
  namespace: number,
  weights: Readonly<Record<string, number>> = TARGET_SCAN_SECONDS,
): CorpusCacheOwnershipScope {
  if (!Number.isInteger(namespace) || namespace < 1 || namespace > CORPUS_CACHE_SHARD_COUNT) {
    throw new Error(`corpus cache namespace must be within 1..${CORPUS_CACHE_SHARD_COUNT}, got ${namespace}`);
  }
  const slugs = targets.map((target) => target.slug);
  if (new Set(slugs).size !== slugs.length) throw new Error("corpus cache scope contains a duplicate target slug");
  const shards = partitionTargets(slugs, CORPUS_CACHE_SHARD_COUNT, weights);
  assertPartitionCoversEveryTarget(slugs, shards);
  const population = [...targets].sort((a, b) => compareUtf8Bytes(a.slug, b.slug)).map((target) => ({
    slug: target.slug,
    repo: target.repo,
    commit: target.commit,
    vendoredSubtrees: [...(target.vendoredSubtrees ?? [])].sort(compareUtf8Bytes),
    scanRoots: Object.fromEntries(Object.entries(target.scanRoots ?? {}).sort(([a], [b]) => compareUtf8Bytes(a, b))),
    installFlags: [...(target.installFlags ?? [])],
  }));
  return {
    schema: 1,
    policy: CORPUS_CACHE_PARTITION_POLICY,
    shardCount: CORPUS_CACHE_SHARD_COUNT,
    namespace,
    defaultWeightSeconds: DEFAULT_SCAN_SECONDS,
    weights: Object.entries(weights)
      .sort(([a], [b]) => compareUtf8Bytes(a, b))
      .map(([slug, seconds]) => ({ slug, seconds })),
    partitions: shards.map((members, index) => ({ namespace: index + 1, targets: [...members] })),
    population,
    owners: [...shards[namespace - 1]!].sort(compareUtf8Bytes),
  };
}

export function corpusCacheScopeSha256(scope: CorpusCacheOwnershipScope): string {
  return createHash("sha256").update(stable(scope)).digest("hex");
}

export function corpusCacheTransportKey(input: {
  family: CorpusCacheTransportFamily;
  platform: string;
  namespace: string;
  scopeSha256: string;
  runId: string;
  runAttempt: string;
  headSha: string;
}): string {
  if (!/^[A-Za-z0-9_.-]+$/.test(input.platform)) throw new Error("transport provenance platform is invalid");
  if (!/^[1-9]\d*$/.test(input.namespace)) throw new Error("transport provenance namespace is invalid");
  if (!SHA256.test(input.scopeSha256)) throw new Error("transport provenance scopeSha256 is invalid");
  if (!/^\d+$/.test(input.runId) || !/^\d+$/.test(input.runAttempt)) throw new Error("transport provenance run identity is invalid");
  if (!/^[0-9a-f]{40}$/.test(input.headSha)) throw new Error("transport provenance headSha is not a 40-character lowercase commit SHA");
  return `corpus-phase-${input.family}-v6-${input.platform}-shard${input.namespace}-scope${input.scopeSha256}-${input.runId}-${input.runAttempt}-${input.headSha}`;
}

function fileSha256(path: string): string {
  const hash = createHash("sha256");
  const fd = openSync(path, "r");
  const buffer = Buffer.allocUnsafe(1024 * 1024);
  try {
    for (;;) {
      const length = readSync(fd, buffer, 0, buffer.length, null);
      if (length === 0) break;
      hash.update(buffer.subarray(0, length));
    }
  } finally {
    closeSync(fd);
  }
  return hash.digest("hex");
}

function canonicalPayloadPath(root: string, path: string): string {
  const rel = relative(root, path);
  if (!rel || isAbsolute(rel) || rel === ".." || rel.startsWith("../") || rel.includes("\\") || rel.split("/").some((part) => part === "" || part === "." || part === "..")) {
    throw new Error(`transport payload contains noncanonical path: ${rel || "(root)"}`);
  }
  if (/^dependency-preparation\/stores\/[^/]+\/pnpm\/v\d+\/(?:projects|links)(?:\/|$)/.test(rel)) {
    throw new Error(`transport payload contains path-bound pnpm data: ${rel}`);
  }
  return rel;
}

function payloadReceipt(dir: string): CorpusCachePayloadReceipt {
  const discovered: Array<{ path: string; type: "file"; bytes: number; diskPath: string }> = [];
  const symlinks: string[] = [];
  const specials: string[] = [];
  const walk = (current: string): void => {
    if (!existsSync(current)) return;
    for (const entry of readEntriesLstatSafe(current)) {
      const rel = canonicalPayloadPath(dir, entry.path);
      if (rel === MANIFEST) continue;
      if (entry.isSymbolicLink) symlinks.push(rel);
      else if (entry.isDirectory) walk(entry.path);
      else if (entry.isFile) discovered.push({ path: rel, type: "file", bytes: entry.size, diskPath: entry.path });
      else specials.push(rel);
    }
  };
  walk(dir);
  if (symlinks.length > 0) throw new Error(`transport payload contains path-bound link(s): ${symlinks.sort(compareUtf8Bytes).slice(0, 3).join(", ")}`);
  if (specials.length > 0) throw new Error(`transport payload contains unsupported special file(s): ${specials.sort(compareUtf8Bytes).slice(0, 3).join(", ")}`);
  discovered.sort((a, b) => compareUtf8Bytes(a.path, b.path));
  const bytes = discovered.reduce((total, file) => total + file.bytes, 0);
  if (!Number.isSafeInteger(bytes)) throw new Error("transport payload byte count exceeds safe integer range");
  if (bytes > CORPUS_CACHE_MAX_PAYLOAD_BYTES) throw new Error(`transport payload ${bytes} bytes exceeds ${CORPUS_CACHE_MAX_PAYLOAD_BYTES}-byte ceiling`);
  // Bound first, then read bytes. An oversized sparse or corrupt transport must fail in the cheap
  // metadata pass instead of spending the remaining job timeout hashing data we will reject.
  const files = discovered.map(({ diskPath, ...file }) => ({ ...file, sha256: fileSha256(diskPath) }));
  const classes = new Map<string, { files: number; bytes: number }>();
  for (const file of files) {
    const name = file.path.split("/")[0]!;
    const current = classes.get(name) ?? { files: 0, bytes: 0 };
    current.files += 1;
    current.bytes += file.bytes;
    classes.set(name, current);
  }
  return {
    bytes,
    files: files.length,
    inventorySha256: createHash("sha256").update(stable(files)).digest("hex"),
    classes: [...classes].sort(([a], [b]) => compareUtf8Bytes(a, b)).map(([name, value]) => ({ name, ...value })),
    maxBytes: CORPUS_CACHE_MAX_PAYLOAD_BYTES,
    symlinks: 0,
  };
}

function parseManifest(value: unknown): CorpusCacheTransportManifest {
  const manifest = value as Partial<CorpusCacheTransportManifest>;
  if (manifest.schema !== 4) throw new Error("unsupported transport provenance schema");
  for (const field of ["key", "event", "ref", "runId", "runAttempt", "headSha", "writtenAt", "family", "scopeSha256"] as const) {
    if (typeof manifest[field] !== "string" || manifest[field]!.length === 0) throw new Error(`transport provenance is missing ${field}`);
  }
  if (!/^\d{4}-\d{2}-\d{2}T/.test(manifest.writtenAt!)) throw new Error("transport provenance writtenAt is not an ISO timestamp");
  const key = KEY.exec(manifest.key!);
  if (!key) throw new Error("transport provenance key does not encode platform, namespace, scope, run, attempt, and headSha");
  const [, family, platform, namespace, scopeSha256, runId, runAttempt, headSha] = key;
  if (manifest.family !== "run" && manifest.family !== "main") throw new Error("transport provenance family is invalid");
  if (!manifest.scope || typeof manifest.scope !== "object") throw new Error("transport provenance ownership scope is missing");
  const recomputedScopeSha256 = corpusCacheScopeSha256(manifest.scope);
  if (manifest.scopeSha256 !== recomputedScopeSha256 || scopeSha256 !== recomputedScopeSha256) throw new Error("transport provenance ownership scope digest disagrees with scope");
  if (manifest.scope.schema !== 1 || manifest.scope.policy !== CORPUS_CACHE_PARTITION_POLICY || manifest.scope.shardCount !== CORPUS_CACHE_SHARD_COUNT || manifest.scope.namespace !== Number(namespace)) {
    throw new Error("transport provenance ownership scope policy, count, or namespace is invalid");
  }
  const expected = corpusCacheTransportKey({ family: manifest.family, platform: platform!, namespace: namespace!, scopeSha256: manifest.scopeSha256!, runId: manifest.runId!, runAttempt: manifest.runAttempt!, headSha: manifest.headSha! });
  if (manifest.key !== expected || family !== manifest.family || runId !== manifest.runId || runAttempt !== manifest.runAttempt || headSha !== manifest.headSha) {
    throw new Error("transport provenance key disagrees with its claimed scope, run, attempt, or headSha");
  }
  const payload = manifest.payload as Partial<CorpusCachePayloadReceipt> | undefined;
  if (payload?.maxBytes !== CORPUS_CACHE_MAX_PAYLOAD_BYTES || !Number.isSafeInteger(payload.bytes) || payload.bytes! < 0 || !Number.isSafeInteger(payload.files) || payload.files! < 0 || !SHA256.test(payload.inventorySha256 ?? "") || payload.symlinks !== 0 || !Array.isArray(payload.classes)) {
    throw new Error("transport provenance payload receipt is missing or invalid");
  }
  if (payload.classes.some((row) => !row || typeof row.name !== "string" || !Number.isSafeInteger(row.files) || row.files < 0 || !Number.isSafeInteger(row.bytes) || row.bytes < 0)) {
    throw new Error("transport provenance payload class census is invalid");
  }
  if (payload.classes.reduce((n, row) => n + row.files, 0) !== payload.files || payload.classes.reduce((n, row) => n + row.bytes, 0) !== payload.bytes) {
    throw new Error("transport provenance payload class census does not conserve files and bytes");
  }
  return manifest as CorpusCacheTransportManifest;
}

export function decideCorpusCacheRestore(source: CorpusCacheTransportManifest, current: CorpusCacheRestoreContext): CorpusCacheTransportDecision {
  try {
    source = parseManifest(source);
  } catch (error) {
    return { accepted: false, source, reason: `invalid transport provenance: ${error instanceof Error ? error.message : String(error)}` };
  }
  if (source.key !== current.matchedKey) return { accepted: false, source, reason: `matched key ${current.matchedKey} disagrees with provenance key ${source.key}` };
  const matched = KEY.exec(source.key);
  const expectedScopeSha256 = corpusCacheScopeSha256(current.scope);
  if (!matched || matched[2] !== current.platform || matched[3] !== current.namespace) return { accepted: false, source, reason: `source key ${source.key} is not for ${current.platform} shard${current.namespace}` };
  if (source.scopeSha256 !== expectedScopeSha256 || stable(source.scope) !== stable(current.scope)) {
    return { accepted: false, source, reason: `source ownership scope ${source.scopeSha256} is not current scope ${expectedScopeSha256}` };
  }
  if (source.family === "main" && source.ref === current.defaultRef && source.event === "push") return { accepted: true, source, reason: `trusted default-branch seed from ${source.event} ${source.ref}` };
  if (source.family === "run" && source.ref === current.ref && source.runId === current.runId && source.headSha === current.headSha) return { accepted: true, source, reason: `same-run retry/fallback from ${source.event} ${source.ref}` };
  return { accepted: false, source, reason: `untrusted cache scope: ${source.event} ${source.ref} run ${source.runId} sha ${source.headSha} is neither ${current.defaultRef} nor current run ${current.runId} sha ${current.headSha} on ${current.ref}` };
}

export function validateCorpusCacheTransport(dir: string, current: CorpusCacheRestoreContext): CorpusCacheTransportDecision {
  if (current.matchedKey.length === 0) return { accepted: true, reason: "Actions cache miss; no transport artifact was restored" };
  const path = join(dir, MANIFEST);
  if (!existsSync(path)) return { accepted: false, reason: `restored key ${current.matchedKey} has no ${MANIFEST}` };
  try {
    const manifest = parseManifest(JSON.parse(readFileSync(path, "utf8")));
    const payload = payloadReceipt(dir);
    if (stable(payload) !== stable(manifest.payload)) return { accepted: false, source: manifest, reason: `transport payload inventory ${payload.inventorySha256}/${payload.files}/${payload.bytes} disagrees with receipt ${manifest.payload.inventorySha256}/${manifest.payload.files}/${manifest.payload.bytes}` };
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
