import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";

export interface CorpusCacheTransportManifest {
  schema: 2;
  key: string;
  event: string;
  ref: string;
  runId: string;
  runAttempt: string;
  headSha: string;
  writtenAt: string;
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
const KEY = /^corpus-phase-v4-([A-Za-z0-9_.-]+)-shard([1-9]\d*)-(\d+)-(\d+)-([0-9a-f]{40})$/;

export function corpusCacheTransportKey(input: {
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
  return `corpus-phase-v4-${input.platform}-shard${input.namespace}-${input.runId}-${input.runAttempt}-${input.headSha}`;
}

function parseManifest(value: unknown): CorpusCacheTransportManifest {
  const manifest = value as Partial<CorpusCacheTransportManifest>;
  if (manifest.schema !== 2) throw new Error("unsupported transport provenance schema");
  for (const field of ["key", "event", "ref", "runId", "runAttempt", "headSha", "writtenAt"] as const) {
    if (typeof manifest[field] !== "string" || manifest[field]!.length === 0) throw new Error(`transport provenance is missing ${field}`);
  }
  if (!/^\d{4}-\d{2}-\d{2}T/.test(manifest.writtenAt!)) throw new Error("transport provenance writtenAt is not an ISO timestamp");
  const key = KEY.exec(manifest.key!);
  if (!key) throw new Error("transport provenance key does not encode platform, namespace, run, attempt, and headSha");
  const [, platform, namespace, runId, runAttempt, headSha] = key;
  const expected = corpusCacheTransportKey({ platform: platform!, namespace: namespace!, runId: manifest.runId!, runAttempt: manifest.runAttempt!, headSha: manifest.headSha! });
  if (manifest.key !== expected || runId !== manifest.runId || runAttempt !== manifest.runAttempt || headSha !== manifest.headSha) {
    throw new Error("transport provenance key disagrees with its claimed run, attempt, or headSha");
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
  if (!matched || matched[1] !== current.platform || matched[2] !== current.namespace) {
    return { accepted: false, source, reason: `source key ${source.key} is not for ${current.platform} shard${current.namespace}` };
  }
  if (source.ref === current.defaultRef && ["push", "schedule", "workflow_dispatch"].includes(source.event)) {
    return { accepted: true, source, reason: `trusted default-branch seed from ${source.event} ${source.ref}` };
  }
  if (source.ref === current.ref && source.runId === current.runId && source.headSha === current.headSha) {
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
    return decideCorpusCacheRestore(parseManifest(JSON.parse(readFileSync(path, "utf8"))), current);
  } catch (error) {
    return { accepted: false, reason: `invalid transport provenance: ${error instanceof Error ? error.message : String(error)}` };
  }
}

export function rejectCorpusCacheTransport(dir: string): void {
  rmSync(dir, { recursive: true, force: true });
  mkdirSync(dir, { recursive: true });
}

export function writeCorpusCacheTransport(dir: string, manifest: CorpusCacheTransportManifest): void {
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, MANIFEST), `${JSON.stringify(parseManifest(manifest), null, 2)}\n`);
}
