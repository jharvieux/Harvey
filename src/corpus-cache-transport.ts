import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join, relative } from "node:path";
import { readEntriesLstatSafe } from "./fs-walk.js";

export const CORPUS_CACHE_MAX_PAYLOAD_BYTES = 6 * 1024 * 1024 * 1024;

export type CorpusCacheTransportFamily = "run" | "main";

interface CorpusCachePayloadReceipt {
  bytes: number;
  maxBytes: number;
  symlinks: 0;
}

export interface CorpusCacheTransportManifest {
  schema: 3;
  key: string;
  family: CorpusCacheTransportFamily;
  event: string;
  ref: string;
  runId: string;
  runAttempt: string;
  headSha: string;
  writtenAt: string;
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
}

interface CorpusCacheTransportDecision {
  accepted: boolean;
  reason: string;
  source?: CorpusCacheTransportManifest;
}

const MANIFEST = "transport-provenance.json";
const KEY = /^corpus-phase-(run|main)-v5-([A-Za-z0-9_.-]+)-shard([1-9]\d*)-(\d+)-(\d+)-([0-9a-f]{40})$/;

export function corpusCacheTransportKey(input: {
  family: CorpusCacheTransportFamily;
  platform: string;
  namespace: string;
  runId: string;
  runAttempt: string;
  headSha: string;
}): string {
  if (!/^[A-Za-z0-9_.-]+$/.test(input.platform)) throw new Error("transport provenance platform is invalid");
  if (!/^[1-9]\d*$/.test(input.namespace)) throw new Error("transport provenance namespace is invalid");
  if (!/^\d+$/.test(input.runId) || !/^\d+$/.test(input.runAttempt)) throw new Error("transport provenance run identity is invalid");
  if (!/^[0-9a-f]{40}$/.test(input.headSha)) throw new Error("transport provenance headSha is not a 40-character lowercase commit SHA");
  return `corpus-phase-${input.family}-v5-${input.platform}-shard${input.namespace}-${input.runId}-${input.runAttempt}-${input.headSha}`;
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
  if (manifest.schema !== 3) throw new Error("unsupported transport provenance schema");
  for (const field of ["key", "event", "ref", "runId", "runAttempt", "headSha", "writtenAt", "family"] as const) {
    if (typeof manifest[field] !== "string" || manifest[field]!.length === 0) throw new Error(`transport provenance is missing ${field}`);
  }
  if (!/^\d{4}-\d{2}-\d{2}T/.test(manifest.writtenAt!)) throw new Error("transport provenance writtenAt is not an ISO timestamp");
  const key = KEY.exec(manifest.key!);
  if (!key) throw new Error("transport provenance key does not encode platform, namespace, run, attempt, and headSha");
  const [, family, platform, namespace, runId, runAttempt, headSha] = key;
  if (manifest.family !== "run" && manifest.family !== "main") throw new Error("transport provenance family is invalid");
  const expected = corpusCacheTransportKey({ family: manifest.family, platform: platform!, namespace: namespace!, runId: manifest.runId!, runAttempt: manifest.runAttempt!, headSha: manifest.headSha! });
  if (manifest.key !== expected || family !== manifest.family || runId !== manifest.runId || runAttempt !== manifest.runAttempt || headSha !== manifest.headSha) {
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
  const matched = KEY.exec(source.key);
  if (!matched || matched[2] !== current.platform || matched[3] !== current.namespace) {
    return { accepted: false, source, reason: `source key ${source.key} is not for ${current.platform} shard${current.namespace}` };
  }
  if (source.family === "main" && source.ref === current.defaultRef && source.event === "push") {
    return { accepted: true, source, reason: `trusted default-branch seed from ${source.event} ${source.ref}` };
  }
  if (source.family === "run" && source.ref === current.ref && source.runId === current.runId && source.headSha === current.headSha) {
    return { accepted: true, source, reason: `same-run retry/fallback from ${source.event} ${source.ref}` };
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
