import "./sync-stdio.js";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { arg, assertKnownFlags } from "./args.js";
import { readRecursiveSafe } from "../fs-walk.js";
import { compareM9TaxonomyDocs, type SourceText } from "../detectors/m9-taxonomy-docs.js";

assertKnownFlags(["--root"]);

const DEFAULT_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const root = resolve(arg("--root") ?? DEFAULT_ROOT);

function loadSources(): SourceText[] {
  const sourceRoot = join(root, "src");
  return readRecursiveSafe(sourceRoot)
    .filter((path) => /\.(?:ts|tsx|mts|cts)$/.test(path) && !path.endsWith(".test.ts") && !path.endsWith(".test.tsx"))
    .map((path) => ({ path: `src/${path}`, text: readFileSync(join(sourceRoot, path), "utf8") }));
}

try {
  const report = compareM9TaxonomyDocs(loadSources(), readFileSync(join(root, "docs", "m9-app-router.md"), "utf8"));
  console.log(
    `M9 TAXONOMY POPULATION — ${report.registry.emittedM9Taxonomies.length} emitted spellings, ` +
      `${report.registry.canonicalM9Families.length} canonical M9 families, ${report.headers.length} documented check headers`,
  );
  for (const taxonomy of report.registry.canonicalM9Families) console.log(`  FAMILY     ${taxonomy}`);
  for (const alias of report.registry.aliases) console.log(`  ALIAS      ${alias.emitted} -> ${alias.documentedAs}`);
  for (const exclusion of report.registry.exclusions) {
    console.log(`  EXCLUDED   ${exclusion.kind.padEnd(14)} ${exclusion.path}:${exclusion.line} ${exclusion.expression}`);
  }
  if (report.violations.length > 0) {
    console.log(`M9 TAXONOMY DOC GATE FAIL — ${report.violations.length} violation(s)`);
    for (const violation of report.violations) console.log(`  - ${violation}`);
    process.exit(1);
  }
  console.log("M9 TAXONOMY DOC GATE PASS — every shipped M9 family and every documented check header agree");
} catch (error) {
  console.error(`M9 TAXONOMY DOC GATE UNAVAILABLE — ${error instanceof Error ? error.message : String(error)}`);
  process.exit(2);
}
