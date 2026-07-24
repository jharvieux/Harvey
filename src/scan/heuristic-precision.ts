// M7/M8 heuristic precision gate (#823). The M1 mechanical corpus has a scored recall/precision
// gate (cli/validate-calibration.ts); the two noisiest HEURISTIC modules — M7 code tier
// (src/detectors/perf-code.ts) and M8 test intent (test-intent.ts + vitest-intent.ts) — had
// per-class fixture pairs but no aggregated precision NUMBER. This module scores the labeled
// fixture corpus (calibration/m7-code.entries.ts, calibration/m8-intent.entries.ts) against the
// live detectors and derives, per module:
//
//   recall    = positives caught / positives total
//   precision = positives caught / (positives caught + negatives that fired)
//
// These are CORPUS numbers, not field numbers: the corpus plants one instance per class and one
// benign lookalike per known FP shape, so "precision" here means "no catalogued noise shape
// fires", the #61 discipline — a field run's precision depends on how often each shape occurs
// in the wild. The negative rows encode the ATC-dogfood + 6-repo-triage FP catalog
// (docs/m7-performance.md §2a), so a guard regression shows up as a measured precision drop.
//
// Consumers: heuristic-precision.test.ts (the `pnpm verify` gate — the detectors are pure TS,
// no mechanical binaries needed), cli/validate-precision.ts (standalone report), and
// cli/validate-calibration.ts (summary block alongside the M1 matrix).

import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";
import type { SourceInput } from "../detectors/common.js";
import { detectPerfCodeFindings } from "../detectors/perf-code.js";
import { detectTestIntentFindings } from "../detectors/test-intent.js";
import { detectVitestIntentFindings } from "../detectors/vitest-intent.js";
import type { Finding } from "../findings.js";
import { detectionMetrics, type DetectionMetrics } from "./detection-metrics.js";
import { m7CodeEntries } from "./calibration/m7-code.entries.js";
import { m8IntentEntries } from "./calibration/m8-intent.entries.js";
import type { HeuristicEntry } from "./calibration/types.js";

export type { HeuristicEntry } from "./calibration/types.js";

export const HEURISTIC_CORPUS: HeuristicEntry[] = [...m7CodeEntries, ...m8IntentEntries];

const FIXTURES_ROOT = fileURLToPath(new URL("../detectors/__fixtures__/", import.meta.url));

// Same loader as perf-code.test.ts: fixtures are `<name>.txt` so tsc/knip/eslint don't compile
// them; strip the suffix to recover the logical source path.
function loadFixtureDir(relDir: string): SourceInput[] {
  const root = join(FIXTURES_ROOT, relDir);
  const files: SourceInput[] = [];
  const walk = (dir: string) => {
    for (const entry of readdirSync(dir)) {
      const full = join(dir, entry);
      if (statSync(full).isDirectory()) walk(full);
      else if (entry.endsWith(".txt")) {
        files.push({ path: relative(root, full).replace(/\.txt$/, "").split(sep).join("/"), text: readFileSync(full, "utf8") });
      }
    }
  };
  walk(root);
  return files;
}

// #248: the micro-render classes only emit when React Compiler is enabled — entries whose class
// is compiler-gated run with this config appended (same fixture as perf-code.test.ts).
const COMPILER_ON: SourceInput = {
  path: "next.config.mjs",
  text: "const nextConfig = { experimental: { reactCompiler: true } };\nexport default nextConfig;\n",
};

function runDetectors(entry: HeuristicEntry): Finding[] {
  const files = loadFixtureDir(entry.dir);
  if (entry.module === "M7") {
    return detectPerfCodeFindings(entry.compilerOn ? [...files, COMPILER_ON] : files, entry.framework);
  }
  return [...detectTestIntentFindings(files), ...detectVitestIntentFindings(files)];
}

export interface HeuristicRow {
  id: string;
  module: HeuristicEntry["module"];
  kind: HeuristicEntry["kind"];
  cls: string;
  fired: number; // relevant findings the entry's dir produced
  pass: boolean;
  detail: string;
}

function scoreHeuristicEntry(entry: HeuristicEntry): HeuristicRow {
  const findings = runDetectors(entry);
  const relevant = entry.taxonomy === undefined ? findings : findings.filter((f) => f.taxonomy === entry.taxonomy);
  const fired = relevant.length;
  const pass = entry.kind === "positive" ? fired > 0 : fired === 0;
  const detail =
    entry.kind === "positive"
      ? pass
        ? `caught (${fired} finding${fired === 1 ? "" : "s"})`
        : "NOT caught — the planted class did not fire"
      : pass
        ? "cleared — not flagged"
        : `FALSE POSITIVE — fired ${fired}×: ${relevant.map((f) => f.taxonomy).join(", ")}`;
  return { id: entry.id, module: entry.module, kind: entry.kind, cls: entry.cls, fired, pass, detail };
}

interface HeuristicModuleSummary {
  module: string;
  positivesTotal: number;
  positivesCaught: number;
  negativesTotal: number;
  negativesCleared: number;
  recall: number; // caught / total positives
  precision: number; // caught / (caught + negatives fired)
  // #881: the full OWASP-Benchmark metric set, PER MODULE. The point of computing it here as well
  // as for M1 is that M1's number must never be readable as the suite's: a per-module F1/Youden
  // next to it is what makes the difference between the modules legible instead of averaged.
  metrics: DetectionMetrics;
}

interface HeuristicMatrix {
  rows: HeuristicRow[];
  modules: HeuristicModuleSummary[];
  ok: boolean; // every positive caught AND every negative cleared
}

export function measureHeuristicPrecision(corpus: HeuristicEntry[] = HEURISTIC_CORPUS): HeuristicMatrix {
  const rows = corpus.map(scoreHeuristicEntry);
  const modules: HeuristicModuleSummary[] = [];
  for (const module of [...new Set(corpus.map((e) => e.module))]) {
    const mine = rows.filter((r) => r.module === module);
    const pos = mine.filter((r) => r.kind === "positive");
    const neg = mine.filter((r) => r.kind === "negative");
    const positivesCaught = pos.filter((r) => r.pass).length;
    const negativesFired = neg.filter((r) => !r.pass).length;
    const precisionDenom = positivesCaught + negativesFired;
    modules.push({
      module,
      positivesTotal: pos.length,
      positivesCaught,
      negativesTotal: neg.length,
      negativesCleared: neg.length - negativesFired,
      recall: pos.length === 0 ? 0 : positivesCaught / pos.length,
      precision: precisionDenom === 0 ? 0 : positivesCaught / precisionDenom,
      metrics: detectionMetrics({
        tp: positivesCaught,
        fn: pos.length - positivesCaught,
        fp: negativesFired,
        tn: neg.length - negativesFired,
      }),
    });
  }
  return { rows, modules, ok: rows.every((r) => r.pass) };
}
