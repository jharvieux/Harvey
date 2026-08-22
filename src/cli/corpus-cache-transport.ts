import "./sync-stdio.js";
import {
  corpusCacheOwnershipScope,
  corpusCacheScopeSha256,
  corpusCacheTransportKey,
  rejectCorpusCacheTransport,
  validateCorpusCacheTransport,
  writeCorpusCacheTransport,
  type CorpusCacheTransportManifest,
} from "../corpus-cache-transport.js";
import { EXTERNAL_CORPUS } from "../scan/external-corpus.js";
import { CORPUS_CACHE_SHARD_COUNT } from "../scan/corpus-shards.js";

const args = process.argv.slice(2);
const command = args[0];
const optionalFlag = (name: string): string | undefined => {
  const at = args.indexOf(name);
  return at >= 0 ? args[at + 1] : undefined;
};
const flag = (name: string): string => {
  const value = optionalFlag(name);
  if (!value) {
    console.error(`corpus-cache-transport: missing ${name}`);
    process.exit(2);
  }
  return value;
};

const scopeTargets = EXTERNAL_CORPUS.map((target) => ({
  slug: target.slug,
  repo: target.repo,
  commit: target.commit,
  vendoredSubtrees: target.vendoredSubtrees,
  scanRoots: target.scanRoots,
  installFlags: target.m8?.installFlags,
}));
const scopeFor = (namespace: string) => corpusCacheOwnershipScope(scopeTargets, Number(namespace));

if (command === "scopes") {
  for (let namespace = 1; namespace <= CORPUS_CACHE_SHARD_COUNT; namespace += 1) {
    const scope = scopeFor(String(namespace));
    console.log(`scope${namespace}=${corpusCacheScopeSha256(scope)}`);
  }
} else if (command === "restore") {
  const dir = flag("--dir");
  const namespace = flag("--namespace");
  const decision = validateCorpusCacheTransport(dir, {
    matchedKey: optionalFlag("--matched-key") ?? "",
    event: flag("--event"),
    ref: flag("--ref"),
    runId: flag("--run-id"),
    defaultRef: flag("--default-ref"),
    platform: flag("--platform"),
    namespace,
    headSha: flag("--head-sha"),
    scope: scopeFor(namespace),
  });
  const source = decision.source
    ? `; source=${decision.source.event} ${decision.source.ref} run=${decision.source.runId} attempt=${decision.source.runAttempt} sha=${decision.source.headSha}`
    : "";
  if (decision.accepted) {
    console.log(`CACHE TRANSPORT ACCEPT: key=${optionalFlag("--matched-key") || "(miss)"}; ${decision.reason}${source}`);
  } else {
    console.error(`CACHE TRANSPORT REJECT: key=${flag("--matched-key")}; ${decision.reason}${source}; restored bytes will not be reused`);
    rejectCorpusCacheTransport(dir);
  }
} else if (command === "save") {
  const dir = flag("--dir");
  const family = flag("--family");
  if (family !== "run" && family !== "main") {
    console.error("corpus-cache-transport: --family must be run or main");
    process.exit(2);
  }
  const namespace = flag("--namespace");
  const scope = scopeFor(namespace);
  const scopeSha256 = corpusCacheScopeSha256(scope);
  const manifest: Omit<CorpusCacheTransportManifest, "payload"> = {
    schema: 4,
    family,
    key: corpusCacheTransportKey({
      family,
      platform: flag("--platform"),
      namespace,
      scopeSha256,
      runId: flag("--run-id"),
      runAttempt: flag("--run-attempt"),
      headSha: flag("--head-sha"),
    }),
    event: flag("--event"),
    ref: flag("--ref"),
    runId: flag("--run-id"),
    runAttempt: flag("--run-attempt"),
    headSha: flag("--head-sha"),
    writtenAt: new Date().toISOString(),
    scope,
    scopeSha256,
  };
  const written = writeCorpusCacheTransport(dir, manifest);
  console.log(`CACHE TRANSPORT SAVE: key=${written.key}; scope=${written.scopeSha256}; owners=${written.scope.owners.join(",")}; source=${written.event} ${written.ref} run=${written.runId} attempt=${written.runAttempt} sha=${written.headSha}; payload=${written.payload.bytes}/${written.payload.maxBytes} bytes in ${written.payload.files} files; inventory=${written.payload.inventorySha256}; classes=${JSON.stringify(written.payload.classes)}; symlinks=${written.payload.symlinks}`);
} else {
  console.error("usage: corpus-cache-transport <scopes|restore|save> [--dir <path>] ...");
  process.exit(2);
}
