import "./sync-stdio.js";
import {
  corpusCacheTransportKey,
  mergeCorpusCacheTransports,
  rejectCorpusCacheTransport,
  validateCorpusCacheTransport,
  writeCorpusCacheTransport,
  type CorpusCacheTransportManifest,
} from "../corpus-cache-transport.js";
import { readFileSync, writeFileSync } from "node:fs";

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

const dir = flag("--dir");
if (command === "restore") {
  const decision = validateCorpusCacheTransport(dir, {
    matchedKey: optionalFlag("--matched-key") ?? "",
    event: flag("--event"),
    ref: flag("--ref"),
    runId: flag("--run-id"),
    defaultRef: flag("--default-ref"),
    platform: flag("--platform"),
    namespace: flag("--namespace"),
    headSha: flag("--head-sha"),
    ...(optionalFlag("--benchmark-seed") ? { benchmarkSeed: optionalFlag("--benchmark-seed") } : {}),
    ...(optionalFlag("--benchmark-seed-run-id") ? { benchmarkSeedRunId: optionalFlag("--benchmark-seed-run-id") } : {}),
    ...(optionalFlag("--benchmark-seed-run-attempt") ? { benchmarkSeedRunAttempt: optionalFlag("--benchmark-seed-run-attempt") } : {}),
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
  const family = flag("--family");
  if (family !== "run" && family !== "main" && family !== "benchmark") {
    console.error("corpus-cache-transport: --family must be run, main, or benchmark");
    process.exit(2);
  }
  const manifest: Omit<CorpusCacheTransportManifest, "payload"> = {
    schema: 4,
    family,
    key: corpusCacheTransportKey({
      family,
      platform: flag("--platform"),
      namespace: flag("--namespace"),
      runId: flag("--run-id"),
      runAttempt: flag("--run-attempt"),
      headSha: flag("--head-sha"),
      ...(optionalFlag("--benchmark-seed") ? { benchmarkSeed: optionalFlag("--benchmark-seed") } : {}),
    }),
    event: flag("--event"),
    ref: flag("--ref"),
    runId: flag("--run-id"),
    runAttempt: flag("--run-attempt"),
    headSha: flag("--head-sha"),
    writtenAt: new Date().toISOString(),
    ...(optionalFlag("--benchmark-seed") ? { benchmarkSeed: optionalFlag("--benchmark-seed") } : {}),
  };
  const written = writeCorpusCacheTransport(dir, manifest);
  console.log(`CACHE TRANSPORT SAVE: key=${written.key}; source=${written.event} ${written.ref} run=${written.runId} attempt=${written.runAttempt} sha=${written.headSha}; payload=${written.payload.bytes}/${written.payload.maxBytes} bytes; symlinks=${written.payload.symlinks}`);
} else if (command === "merge") {
  const sources = JSON.parse(readFileSync(flag("--sources-json"), "utf8")) as Array<{ dir: string; matchedKey: string; namespace: string }>;
  const receipt = mergeCorpusCacheTransports({
    sources,
    destination: dir,
    current: {
      event: flag("--event"),
      ref: flag("--ref"),
      runId: flag("--run-id"),
      defaultRef: flag("--default-ref"),
      platform: flag("--platform"),
      headSha: flag("--head-sha"),
      benchmarkSeed: flag("--benchmark-seed"),
      benchmarkSeedRunId: flag("--benchmark-seed-run-id"),
      benchmarkSeedRunAttempt: flag("--benchmark-seed-run-attempt"),
    },
    requiredNamespaces: flag("--required-namespaces").split(","),
  });
  writeFileSync(flag("--out"), `${JSON.stringify(receipt, null, 2)}\n`);
  console.log(`CACHE TRANSPORT MERGE: ${receipt.sources.length} source namespace(s), ${receipt.files.length} content-addressed file(s), ${receipt.duplicatePaths} identical duplicate path(s), digest=${receipt.aggregateSha256}`);
} else {
  console.error("usage: corpus-cache-transport <restore|save|merge> --dir <path> ...");
  process.exit(2);
}
