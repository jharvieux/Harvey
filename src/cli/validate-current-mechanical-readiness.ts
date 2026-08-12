import "./sync-stdio.js";
import { readFileSync, writeFileSync } from "node:fs";
import {
  compareCurrentMechanicalExecutions,
  mergeCurrentMechanicalShards,
  type CurrentMechanicalExecutionArtifact,
} from "../corpus-mechanical-readiness.js";

const args = process.argv.slice(2);
const flag = (name: string): string | undefined => {
  const index = args.indexOf(name);
  return index >= 0 ? args[index + 1] : undefined;
};
const read = (path: string): CurrentMechanicalExecutionArtifact => JSON.parse(readFileSync(path, "utf8")) as CurrentMechanicalExecutionArtifact;
const merge = flag("--merge");
if (merge) {
  const out = flag("--out");
  if (!out) throw new Error("--merge requires --out");
  const paths = merge.split(",").filter(Boolean);
  const merged = mergeCurrentMechanicalShards(paths.map(read), merge);
  writeFileSync(out, `${JSON.stringify(merged, null, 2)}\n`);
  console.log(`CURRENT MECHANICAL ${merged.side.toUpperCase()} MERGED — ${Object.keys(merged.targets).length} target(s)`);
  process.exit(0);
}
const producer = flag("--producer");
const replay = flag("--replay");
if (!producer || !replay) throw new Error("usage: validate-current-mechanical-readiness --producer <producer.json> --replay <replay.json> | --merge <parts> --out <merged.json>");
compareCurrentMechanicalExecutions(read(producer), read(replay));
console.log("CURRENT REGISTRY PRODUCER ↔ INDEPENDENT REPLAY EQUIVALENCE PASS — two fresh exact-head executions match field-for-field, row-for-row, producer-for-producer, and examined-unit-for-examined-unit. This is readiness evidence only; it is NOT #1851 criteria 6/7 historical manual→registry proof, which remains exclusively open in #1886.");
