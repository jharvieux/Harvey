import "./sync-stdio.js";
import { mkdirSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { semgrepPackReceipt, validateRestoredSemgrepPackArtifact } from "../corpus-mechanical-readiness.js";
import { materializeRegistryPacks } from "../scan/semgrep.js";

const args = process.argv.slice(2);
const flag = (name: string): string | undefined => {
  const index = args.indexOf(name);
  return index >= 0 ? args[index + 1] : undefined;
};
const dir = resolve(flag("--dir") ?? ".harvey-current-semgrep");
const out = resolve(flag("--out") ?? `${dir}/receipt.json`);
if (args.includes("--validate-only")) {
  const restored = validateRestoredSemgrepPackArtifact(dir);
  console.log(`CURRENT SEMGREP PACK RESTORE VALID — ${restored.files.length} exact YAML file(s), aggregate sha256:${restored.identity}`);
  process.exit(0);
}
mkdirSync(dir, { recursive: true });
rmSync(out, { force: true });
const snapshot = materializeRegistryPacks(dir, "refresh");
if (!snapshot.identity || !snapshot.files || snapshot.failure) throw new Error(snapshot.failure ?? "Semgrep registry snapshot did not materialize");
const receipt = semgrepPackReceipt(snapshot.files, snapshot.identity);
const temporaryReceipt = `${out}.${process.pid}.tmp`;
try {
  writeFileSync(temporaryReceipt, `${JSON.stringify(receipt, null, 2)}\n`);
  renameSync(temporaryReceipt, out);
  validateRestoredSemgrepPackArtifact(dir);
} catch (error) {
  rmSync(temporaryReceipt, { force: true });
  rmSync(out, { force: true });
  rmSync(resolve(dir, "registry-packs/current.json"), { force: true });
  throw error;
}
const retried = snapshot.transport?.packs.filter((pack) => pack.retries.length > 0)
  .map((pack) => `${pack.pack}=${pack.attempts}[${pack.retries.join(",")}]`).join(";") || "none";
console.log(`CURRENT SEMGREP PACK MATERIALIZED — ${receipt.files.length} exact YAML file(s), aggregate sha256:${receipt.aggregateSha256}; transport=${snapshot.transport?.policy ?? "reuse"}; attempts=${snapshot.transport?.totalAttempts ?? 0}; retries=${retried}`);
