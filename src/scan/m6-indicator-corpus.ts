// M6 indicator corpus scorer (#1371). The answer key lives in calibration/m6-handrolled.entries.ts;
// this is the consumer that makes it able to FAIL, which is the whole point of the issue.
//
// Why a dedicated scorer rather than a `module`-less row scored by validate-calibration: M6
// indicators are not in runMechanicalScan's default output at all (`handrolledIndicators` is
// opt-in, set only by quick-scan), and folding them into the M1 filter would report M6's recall as
// M1's. So this mirrors the M9 per-check corpus and the M7/M8 heuristic gate: load the detector's
// OWN committed fixtures, run the real detector, score with the SAME scoreEntry the rest of the
// corpus uses. Two consumers — m6-indicator-corpus.test.ts (`pnpm verify`; the detector is pure TS,
// no mechanical binaries) and cli/validate-calibration.ts (live gate).
//
// The two guards that stop this becoming another set of inert rows (#1428):
//   1. EXHAUSTIVENESS — the class list is re-derived from the `taxonomy:` literals in
//      handrolled.ts (the instrument `pnpm detector-census` uses), so a detector with no positive
//      row fails loud instead of landing uncovered. `uncovered` is reported, not silently zero.
//   2. THE FIXTURE WAS ACTUALLY READ — an entry whose directory yields no source file throws.
//      CLAUDE.md's rule (3): a fixture the scanner never read reports zero findings exactly like
//      one it scanned and cleared, and for a NEGATIVE that reads as a pass.

import { readFileSync } from "node:fs";
import { join, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { readEntriesSafe } from "../fs-walk.js";
import type { SourceInput } from "../detectors/common.js";
import { detectHandrolledFindings } from "../detectors/handrolled.js";
import { scoreEntry, type MatrixRow } from "./calibration.js";
import { m6HandrolledEntries } from "./calibration/m6-handrolled.entries.js";
import type { CorpusEntry } from "./calibration/types.js";

const FIXTURES_ROOT = fileURLToPath(new URL("../detectors/__fixtures__/handrolled/", import.meta.url));
const HANDROLLED_SOURCE = fileURLToPath(new URL("../detectors/handrolled.ts", import.meta.url));
const LOCATION_PREFIX = "m6-corpus/";
const TAX_PREFIX = "M6 — Indicator: ";

// Fixtures are `<name>.txt` so tsc/knip/eslint never compile them; strip the suffix to recover the
// logical source path, then prefix it with the entry's location so every fixture's findings carry a
// globally-unique location the shared matrix can attribute.
function loadPrefixed(relDir: string, prefix: string): SourceInput[] {
  const root = join(FIXTURES_ROOT, relDir);
  const files: SourceInput[] = [];
  const walk = (dir: string) => {
    for (const { name, path, isDirectory } of readEntriesSafe(dir).entries) {
      if (isDirectory) walk(path);
      else if (name.endsWith(".txt")) files.push({ path: `${prefix}/${relative(root, path).replace(/\.txt$/, "").split(sep).join("/")}`, text: readFileSync(path, "utf8") });
    }
  };
  walk(root);
  if (files.length === 0) throw new Error(`M6 corpus: fixture dir ${relDir} yielded no source files — a directory the detector never read scores identically to one it read and cleared`);
  return files;
}

/** Every indicator class handrolled.ts declares, read off the source the same way detector-census does. */
export function declaredIndicatorClasses(): string[] {
  const src = readFileSync(HANDROLLED_SOURCE, "utf8");
  const classes = new Set<string>();
  for (const m of src.matchAll(/taxonomy:\s*[`"']([^`"']+)/g)) {
    const tax = m[1]?.trim();
    if (tax?.startsWith(TAX_PREFIX)) classes.add(tax.slice(TAX_PREFIX.length));
  }
  return [...classes].sort();
}

interface M6CorpusResult {
  rows: MatrixRow[];
  /** Indicator classes handrolled.ts declares but no positive row scores. */
  uncovered: string[];
  /** Rows whose delivered severity missed the answer key (#1157) — M6's is the non-grading Info lock. */
  severityMismatches: MatrixRow[];
  positivesTotal: number;
  positivesCaught: number;
  negativesTotal: number;
  negativesCleared: number;
  classesDeclared: number;
  ok: boolean;
}

export function scoreM6IndicatorCorpus(corpus: CorpusEntry[] = m6HandrolledEntries): M6CorpusResult {
  const rows = corpus.map((entry) => {
    if (!entry.location.startsWith(LOCATION_PREFIX)) {
      throw new Error(`M6 corpus: entry ${entry.id} location "${entry.location}" must start with "${LOCATION_PREFIX}" — the location IS the fixture path`);
    }
    const relDir = entry.location.slice(LOCATION_PREFIX.length);
    return scoreEntry(entry, detectHandrolledFindings(loadPrefixed(relDir, entry.location)));
  });

  const declared = declaredIndicatorClasses();
  const covered = new Set(corpus.filter((e) => e.kind === "positive").map((e) => e.cls));
  const uncovered = declared.filter((c) => !covered.has(c));
  const positives = rows.filter((r) => r.kind === "positive");
  const negatives = rows.filter((r) => r.kind === "negative");
  const severityMismatches = rows.filter((r) => r.severityMismatch);
  const positivesCaught = positives.filter((r) => r.pass).length;
  const negativesCleared = negatives.filter((r) => r.pass).length;

  return {
    rows,
    uncovered,
    severityMismatches,
    positivesTotal: positives.length,
    positivesCaught,
    negativesTotal: negatives.length,
    negativesCleared,
    classesDeclared: declared.length,
    ok: uncovered.length === 0 && severityMismatches.length === 0 && positivesCaught === positives.length && negativesCleared === negatives.length,
  };
}
