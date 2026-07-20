// pnpm brief-freshness <target-repo> [--vendored <path>] [--target-catalog <path>]
//
// Diffs Harvey's vendored D-091 catalog (docs/runbooks/anti-patterns.md) against the same catalog
// shipped inside a target repo, and fails loud (exit 1) when the vendored copy is BEHIND the target
// — i.e. the target catalogs anti-pattern classes Harvey's brief doesn't yet cover (#678). Run it at
// engagement start for an ATC-lineage target. A target that ships no D-091 catalog (the common case
// for a client repo) exits 0 with a note — nothing to compare against.

import { existsSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { diffCatalog } from "../brief-freshness.js";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const CATALOG_REL = join("docs", "runbooks", "anti-patterns.md");

function flagValue(flag: string): string | undefined {
  const i = process.argv.indexOf(flag);
  return i >= 0 ? process.argv[i + 1] : undefined;
}

const target = process.argv[2];
if (!target || target.startsWith("--")) {
  console.error("usage: pnpm brief-freshness <target-repo> [--vendored <path>] [--target-catalog <path>]");
  process.exit(2);
}

const vendoredPath = flagValue("--vendored") ?? join(REPO_ROOT, CATALOG_REL);
const targetCatalogPath = flagValue("--target-catalog") ?? join(target, CATALOG_REL);

if (!existsSync(targetCatalogPath)) {
  console.log(`ℹ ${target} ships no D-091 catalog (${CATALOG_REL}) — nothing to diff. Vendored brief assumed current.`);
  process.exit(0);
}

const { missing, vendoredExtra } = diffCatalog(
  readFileSync(vendoredPath, "utf8"),
  readFileSync(targetCatalogPath, "utf8"),
);

for (const c of vendoredExtra) console.log(`+ vendored-only class (not in target): ${c}`);

if (missing.length === 0) {
  console.log(`✓ vendored D-091 brief covers every class in ${targetCatalogPath}.`);
  process.exit(0);
}

console.error(`✗ vendored D-091 brief is BEHIND ${targetCatalogPath} — ${missing.length} class(es) not yet incorporated:`);
for (const c of missing) console.error(`  - ${c}`);
console.error("\nRe-sync docs/runbooks/anti-patterns.md and docs/scan-extras.txt from the canonical catalog before relying on the M1 semantic brief.");
process.exit(1);
