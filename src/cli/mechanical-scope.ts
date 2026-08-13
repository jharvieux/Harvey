import "./sync-stdio.js";
import { writeFileSync } from "node:fs";
import { operatorMechanicalScopeRows, validateMechanicalEngineRegistry } from "../scan/mechanical-engine-registry.js";

const repoRoot = new URL("../..", import.meta.url).pathname;

export function renderMechanicalScope(): string {
  const rows = operatorMechanicalScopeRows();
  const lines = ["# Mechanical producer scope", "", `Producers: ${rows.length}`, ""];
  for (const row of rows) {
    lines.push(
      `## ${row.phase}:${row.id} (${row.module})`, "",
      `- Selector: ${row.selector}`,
      `- Examined units: ${row.examinedUnits}`,
      `- Prerequisites: ${row.prerequisites.length > 0 ? row.prerequisites.join("; ") : "none"}`,
      `- Fallback: ${row.fallback}`,
      `- Taxonomies: ${row.taxonomies.join("; ")}`,
      `- Positive fixture: ${row.positiveFixture.status} — ${row.positiveFixture.path ?? row.positiveFixture.detail}`,
      `- Benign twin: ${row.benignTwin.status} — ${row.benignTwin.path ?? row.benignTwin.detail}`,
      `- Conservation: ${row.conservation.status} — ${row.conservation.path ?? row.conservation.detail}`,
      `- Corpus: ${row.corpus.status} — ${row.corpus.path ?? row.corpus.detail}`,
      `- Cadence: ${row.cadence.status} — ${row.cadence.path ?? row.cadence.detail}`,
      "",
    );
  }
  return `${lines.join("\n")}\n`;
}

function main(): void {
  const problems = validateMechanicalEngineRegistry(repoRoot);
  if (problems.length > 0) throw new Error(`mechanical registry invalid:\n${problems.join("\n")}`);
  const jsonIndex = process.argv.indexOf("--json-out");
  if (jsonIndex >= 0) {
    const path = process.argv[jsonIndex + 1];
    if (!path) throw new Error("--json-out requires a path");
    writeFileSync(path, `${JSON.stringify({ producers: operatorMechanicalScopeRows() }, null, 2)}\n`);
    return;
  }
  process.stdout.write(renderMechanicalScope());
}

if (process.argv[1] && import.meta.url === new URL(`file://${process.argv[1]}`).href) main();
