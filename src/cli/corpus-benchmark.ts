import "./sync-stdio.js";
import { readFileSync, writeFileSync } from "node:fs";
import { evaluateCorpusBenchmark, evaluateCorpusBenchmarkPilot, type CorpusBenchmarkPilotDecision, type CorpusBenchmarkSample } from "../corpus-benchmark.js";

const args = process.argv.slice(2);
const flag = (name: string): string | undefined => {
  const index = args.indexOf(name);
  return index < 0 ? undefined : args[index + 1];
};
const input = flag("--samples");
const out = flag("--out");
const pilot = args.includes("--pilot");
const pilotDecisionPath = flag("--pilot-decision");
if (!input || !out || (!pilot && !pilotDecisionPath)) {
  console.error("usage: corpus-benchmark --samples <samples.json> --out <decision.json> [--pilot | --pilot-decision <pilot.json>]");
  process.exit(2);
}
let samples: CorpusBenchmarkSample[];
try {
  const parsed = JSON.parse(readFileSync(input, "utf8")) as CorpusBenchmarkSample[] | { samples?: CorpusBenchmarkSample[] };
  samples = Array.isArray(parsed) ? parsed : (parsed.samples ?? []);
} catch (error) {
  console.error(`corpus-benchmark: samples are unreadable: ${error instanceof Error ? error.message : String(error)}`);
  process.exit(2);
}
try {
  if (pilot) {
    const decision = evaluateCorpusBenchmarkPilot(samples);
    writeFileSync(out, `${JSON.stringify(decision, null, 2)}\n`);
    console.error(`CORPUS BENCHMARK PILOT: design=${decision.concurrency.selected.design}/${decision.concurrency.selected.concurrency}; next=${decision.next.stage}/${decision.next.requiredRuns.length}; profiles=${decision.next.requiredProfiles.join("+")}; repeats=${decision.next.repeats.join(",") || "none"}; rerun-pilot=${decision.next.rerunPilotAfter}; threshold=${decision.thresholdVersion}; runs=${decision.provenance.sampleRunIds.join(",")}`);
  } else {
    const pilotDecision = JSON.parse(readFileSync(pilotDecisionPath!, "utf8")) as CorpusBenchmarkPilotDecision;
    const decision = evaluateCorpusBenchmark(samples, pilotDecision);
    writeFileSync(out, `${JSON.stringify(decision, null, 2)}\n`);
    console.error(`CORPUS BENCHMARK DECISION: design=${decision.concurrency.selected.design}/${decision.concurrency.selected.concurrency}; PR runner=${decision.runners.pr.selected}; schedule runner=${decision.runners.schedule.selected}; shards=${decision.shards.selected}; next=${decision.next.stage}/${decision.next.requiredRuns.length}; threshold=${decision.thresholdVersion}; runs=${decision.provenance.sampleRunIds.join(",")}`);
  }
} catch (error) {
  console.error(`CORPUS BENCHMARK REJECT: ${error instanceof Error ? error.message : String(error)}`);
  process.exit(1);
}
