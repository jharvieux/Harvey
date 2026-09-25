import "./sync-stdio.js";
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { buildResidualScopeInventory } from "../residual-scope.js";
import { validateFindings } from "../findings.js";

try {
  const args = process.argv.slice(2);
  const value = (name: string): string | undefined => { const i = args.indexOf(name); return i < 0 ? undefined : args[i + 1]; };
  const target = value("--target");
  const revision = value("--revision");
  const out = value("--out");
  if (!target || !revision || !out) throw new Error("usage: residual-scope --target <dir> --revision <sha> --out <json> [--findings <json>] [--vitals <json>] [--label <name>]");
  const readJson = (name: string): unknown => { const path = value(name); return path ? JSON.parse(readFileSync(resolve(path), "utf8")) : undefined; };
  const findingsInput = readJson("--findings") as { meta?: { commit?: unknown }; findings?: unknown[] } | undefined;
  if (value("--findings")) {
    // The previous inventory is replaced by this invocation, while findings and source metadata stay intact.
    const validation = validateFindings({ ...findingsInput, residualScope: undefined });
    if (!validation.ok) throw new Error(`Supplied findings document is invalid: ${validation.errors.join("; ")}`);
    if (findingsInput?.meta?.commit !== revision) throw new Error("Findings document revision does not match the requested residual target revision; retain separate evidence for different source states.");
  }
  const vitalsPath = value("--vitals");
  const vitalsBytes = vitalsPath ? readFileSync(resolve(vitalsPath)) : undefined;
  const inventory = buildResidualScopeInventory(resolve(target), { revision, label: value("--label"), priorFindings: findingsInput?.findings as never[] | undefined, vitalsArtifact: vitalsBytes ? JSON.parse(vitalsBytes.toString("utf8")) : undefined, vitalsArtifactSha256: vitalsBytes ? createHash("sha256").update(vitalsBytes).digest("hex") : undefined });
  const attached = findingsInput ? { ...findingsInput, residualScope: inventory } : inventory;
  if (findingsInput) {
    const validation = validateFindings(attached);
    if (!validation.ok) throw new Error(`Residual findings document is invalid: ${validation.errors.join("; ")}`);
  }
  writeFileSync(resolve(out), `${JSON.stringify(attached, null, 2)}\n`);
  console.log(`Residual scope: ${inventory.summary.rows} rows, ${inventory.summary.unresolved} unresolved population unit(s), ${inventory.summary.filesExamined} target file paths inventoried.`);
} catch (error) {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
}
