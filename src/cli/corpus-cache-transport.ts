import "./sync-stdio.js";
import {
  corpusCacheTransportKey,
  rejectCorpusCacheTransport,
  validateCorpusCacheTransport,
  writeCorpusCacheTransport,
  type CorpusCacheTransportManifest,
} from "../corpus-cache-transport.js";

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
  if (family !== "run" && family !== "main") {
    console.error("corpus-cache-transport: --family must be run or main");
    process.exit(2);
  }
  const manifest: Omit<CorpusCacheTransportManifest, "payload"> = {
    schema: 3,
    family,
    key: corpusCacheTransportKey({
      family,
      platform: flag("--platform"),
      namespace: flag("--namespace"),
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
  };
  const written = writeCorpusCacheTransport(dir, manifest);
  console.log(`CACHE TRANSPORT SAVE: key=${written.key}; source=${written.event} ${written.ref} run=${written.runId} attempt=${written.runAttempt} sha=${written.headSha}; payload=${written.payload.bytes}/${written.payload.maxBytes} bytes; symlinks=${written.payload.symlinks}`);
} else {
  console.error("usage: corpus-cache-transport <restore|save> --dir <path> ...");
  process.exit(2);
}
