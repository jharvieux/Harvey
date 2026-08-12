import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";

export interface CorpusCacheTransportManifest {
  schema: 1;
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
}

interface CorpusCacheTransportDecision {
  accepted: boolean;
  reason: string;
  source?: CorpusCacheTransportManifest;
}

const MANIFEST = "transport-provenance.json";

function parseManifest(value: unknown): CorpusCacheTransportManifest {
  const manifest = value as Partial<CorpusCacheTransportManifest>;
  if (manifest.schema !== 1) throw new Error("unsupported transport provenance schema");
  for (const field of ["key", "event", "ref", "runId", "runAttempt", "headSha", "writtenAt"] as const) {
    if (typeof manifest[field] !== "string" || manifest[field]!.length === 0) throw new Error(`transport provenance is missing ${field}`);
  }
  if (!/^\d{4}-\d{2}-\d{2}T/.test(manifest.writtenAt!)) throw new Error("transport provenance writtenAt is not an ISO timestamp");
  return manifest as CorpusCacheTransportManifest;
}

export function decideCorpusCacheRestore(
  source: CorpusCacheTransportManifest,
  current: CorpusCacheRestoreContext,
): CorpusCacheTransportDecision {
  if (source.key !== current.matchedKey) {
    return { accepted: false, source, reason: `matched key ${current.matchedKey} disagrees with provenance key ${source.key}` };
  }
  if (source.ref === current.defaultRef && ["push", "schedule", "workflow_dispatch"].includes(source.event)) {
    return { accepted: true, source, reason: `trusted default-branch seed from ${source.event} ${source.ref}` };
  }
  if (source.ref === current.ref && source.runId === current.runId) {
    return { accepted: true, source, reason: `same-run retry/fallback from ${source.event} ${source.ref}` };
  }
  return {
    accepted: false,
    source,
    reason: `untrusted cache scope: ${source.event} ${source.ref} run ${source.runId} is neither ${current.defaultRef} nor current run ${current.runId} on ${current.ref}`,
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
