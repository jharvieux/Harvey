// #1689 — the per-detector file-count census over the pinned external corpus.
//
//   pnpm exec tsx src/cli/path-scope-census.ts [--cache <dir>]
//
// Answers "which path-scoped detectors read zero files against the pinned corpus, and how many did
// each read?" by cloning every pinned commit and running the DETECTORS' OWN exported filters
// (src/scan/path-scope.ts) over the walked source tree. It never re-implements a filter, so the
// counts are about the shipped scan and not about this file.
//
// Network + minutes per run, like corpus-drift: not part of `pnpm verify`. Exits 0 whatever it
// measures — a zero here is a fact to publish, not a regression, and the row that makes it visible
// in a deliverable is `pathScopeNotAssessedRows`, gated by src/scan/path-scope.test.ts.

import "./sync-stdio.js";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { arg, assertKnownFlags } from "./args.js";
import { cloneAtPinCached } from "../scan/corpus-clone.js";
import { walkSourceFiles } from "../scan/common.js";
import { EXTERNAL_CORPUS } from "../scan/external-corpus.js";
import { PATH_SCOPED_DETECTORS, pathScopeCensus } from "../scan/path-scope.js";

assertKnownFlags(["--cache"] as const);
const cache = arg("--cache");

const totals = new Map(PATH_SCOPED_DETECTORS.map((d) => [d.detector, 0]));
const zeroTargets = new Map(PATH_SCOPED_DETECTORS.map((d) => [d.detector, [] as string[]]));

console.log(`Path-scoped detector census over ${EXTERNAL_CORPUS.length} pinned targets (${new Date().toISOString().slice(0, 10)})`);
console.log(`Detectors: ${PATH_SCOPED_DETECTORS.map((d) => d.detector).join(", ")}\n`);
console.log(`${"target".padEnd(26)}${"pin".padEnd(10)}${"source files".padEnd(14)}${PATH_SCOPED_DETECTORS.map((d) => d.detector.padEnd(20)).join("")}`);

for (const target of EXTERNAL_CORPUS) {
  const dir = mkdtempSync(join(tmpdir(), `harvey-pathscope-${target.slug}-`));
  try {
    cloneAtPinCached(target.repo, target.commit, dir, cache);
    const files = walkSourceFiles(dir);
    const census = pathScopeCensus(files);
    for (const row of census) {
      totals.set(row.detector, (totals.get(row.detector) ?? 0) + row.filesRead);
      if (row.filesRead === 0) zeroTargets.get(row.detector)?.push(target.slug);
    }
    console.log(`${target.slug.padEnd(26)}${target.commit.slice(0, 8).padEnd(10)}${String(files.length).padEnd(14)}${census.map((r) => String(r.filesRead).padEnd(20)).join("")}`);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

console.log("");
for (const d of PATH_SCOPED_DETECTORS) {
  const zero = zeroTargets.get(d.detector) ?? [];
  console.log(
    `${d.detector}: ${totals.get(d.detector)} file(s) read across the whole pinned corpus; ` +
      `${zero.length}/${EXTERNAL_CORPUS.length} targets gave it a population of ZERO${zero.length ? ` (${zero.join(", ")})` : ""}`,
  );
}
