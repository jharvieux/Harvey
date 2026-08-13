import "./sync-stdio.js";
import { readFileSync, writeFileSync } from "node:fs";
import { evaluateCorpusBenchmark, type CorpusBenchmarkSample } from "../corpus-benchmark.js";

const args = process.argv.slice(2);
const flag = (name: string): string | undefined => {
  const index = args.indexOf(name);
  return index < 0 ? undefined : args[index + 1];
};
const input = flag("--samples");
const out = flag("--out");
if (!input || !out) {
  console.error("usage: corpus-benchmark --samples <samples.json> --out <decision.json>");
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
  const decision = evaluateCorpusBenchmark(samples);
  writeFileSync(out, `${JSON.stringify(decision, null, 2)}\n`);
  console.error(`CORPUS BENCHMARK DECISION: design=${decision.concurrency.selected.design}/${decision.concurrency.selected.concurrency}; PR runner=${decision.runners.pr.selected}; schedule runner=${decision.runners.schedule.selected}; shards=${decision.shards.selected}; threshold=${decision.thresholdVersion}; runs=${decision.provenance.sampleRunIds.join(",")}`);
} catch (error) {
  console.error(`CORPUS BENCHMARK REJECT: ${error instanceof Error ? error.message : String(error)}`);
  process.exit(1);
}
