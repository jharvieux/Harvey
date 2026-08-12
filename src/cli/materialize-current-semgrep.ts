import "./sync-stdio.js";
import { mkdirSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { semgrepPackReceipt } from "../corpus-mechanical-readiness.js";
import { materializeRegistryPacks } from "../scan/semgrep.js";

const args = process.argv.slice(2);
const flag = (name: string): string | undefined => {
  const index = args.indexOf(name);
  return index >= 0 ? args[index + 1] : undefined;
};
const dir = resolve(flag("--dir") ?? ".harvey-current-semgrep");
const out = resolve(flag("--out") ?? `${dir}/receipt.json`);
mkdirSync(dir, { recursive: true });
const snapshot = materializeRegistryPacks(dir, "refresh");
if (!snapshot.identity || !snapshot.files || snapshot.failure) throw new Error(snapshot.failure ?? "Semgrep registry snapshot did not materialize");
const receipt = semgrepPackReceipt(snapshot.files, snapshot.identity);
writeFileSync(out, `${JSON.stringify(receipt, null, 2)}\n`);
console.log(`CURRENT SEMGREP PACK MATERIALIZED — ${receipt.files.length} exact YAML file(s), aggregate sha256:${receipt.aggregateSha256}`);
