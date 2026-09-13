import "./sync-stdio.js";
import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { buildEnvironmentInventory, compareEnvironmentInventory, summarizeEnvironmentInventory } from "../environment-dependency-census.js";
import { readCensusSnapshot } from "../environment-dependency-census-discovery.js";
import { censusJson } from "../environment-dependency-census-schema.js";

try {
  const args = process.argv.slice(2);
  const options: Record<string, string> = {};
  let check = false;
  for (let i = 0; i < args.length; i++) {
    const arg = args[i]!;
    if (arg === "--check") { if (check) throw new Error("duplicate --check"); check = true; }
    else if (["--root", "--ref", "--out", "--inventory"].includes(arg)) {
      const value = args[++i];
      if (!value || value.startsWith("--") || options[arg]) throw new Error(`${arg} needs one value`);
      options[arg] = value;
    } else throw new Error(`unknown argument ${arg}`);
  }
  if (check && options["--out"]) throw new Error("--check cannot rewrite an inventory; omit --out");
  if (!check && options["--inventory"]) throw new Error("--inventory is only valid with --check");
  const root = resolve(options["--root"] ?? fileURLToPath(new URL("../..", import.meta.url)));
  const snapshot = readCensusSnapshot(root, options["--ref"], check && !options["--ref"]);
  const inventory = buildEnvironmentInventory(snapshot);
  if (check) {
    const recorded = JSON.parse(readFileSync(resolve(options["--inventory"] ?? `${root}/src/environment-dependency-inventory.json`), "utf8")) as unknown;
    const comparison = compareEnvironmentInventory(inventory, recorded);
    console.log(summarizeEnvironmentInventory(inventory));
    if (!comparison.ok) {
      console.error(comparison.problems.join("\n"));
      console.error("Census differs. Review changed evidence and unresolved rows, then regenerate from a committed revision; check mode never rewrites evidence.");
      process.exitCode = 1;
    } else console.log("Completeness comparison passed; unresolved/dynamic rows remain disclosed.");
  } else if (options["--out"]) {
    writeFileSync(resolve(options["--out"]), censusJson(inventory));
    console.log(summarizeEnvironmentInventory(inventory));
  } else process.stdout.write(censusJson(inventory));
} catch (error) {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
}
