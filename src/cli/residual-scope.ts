import "./sync-stdio.js";
import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { buildResidualScopeInventory } from "../residual-scope.js";

try {
  const args = process.argv.slice(2);
  const value = (name: string): string | undefined => { const i = args.indexOf(name); return i < 0 ? undefined : args[i + 1]; };
  const target = value("--target");
  const revision = value("--revision");
  const out = value("--out");
  if (!target || !revision || !out) throw new Error("usage: residual-scope --target <dir> --revision <sha> --out <json> [--findings <json>] [--vitals <json>] [--label <name>]");
  const readJson = (name: string): unknown => { const path = value(name); return path ? JSON.parse(readFileSync(resolve(path), "utf8")) : undefined; };
  const findingsInput = readJson("--findings") as { findings?: unknown[] } | undefined;
  const inventory = buildResidualScopeInventory(resolve(target), { revision, label: value("--label"), priorFindings: findingsInput?.findings as never[] | undefined, vitalsArtifact: readJson("--vitals") });
  const attached = findingsInput ? { ...findingsInput, residualScope: inventory } : inventory;
  writeFileSync(resolve(out), `${JSON.stringify(attached, null, 2)}\n`);
  console.log(`Residual scope: ${inventory.summary.rows} rows, ${inventory.summary.unresolved} unresolved population unit(s), ${inventory.summary.filesExamined} files examined.`);
} catch (error) {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
}
