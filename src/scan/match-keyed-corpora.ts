// #1560 — EVERY corpus that pins an answer-key row to a file location plus keywords, in one place.
//
// #1355's rule (a `match` key that is a substring of its own location is vacuous — it accepts any
// finding planted on that fixture, whatever defect the finding is for) was enforced over
// `CorpusEntry` and nothing else. `SemanticEntry` carries the identical `locations` + `match` pair
// and an identical matcher, and had never been swept: #1185 found 6 live vacuous keys across 4
// entries there, one of which scored a plpgsql dynamic-SQL-injection finding as a catch for an
// unrelated storage-bucket entry and moved a measured recall figure by a whole point.
//
// It was checked-by-coincidence after that: `free-recall-corpus.test.ts` swept FREE_RECALL_CORPUS,
// which happens to contain all four semantic targets. A semantic target that never joined the
// free-recall list would have been unswept again, and the check lived in a file that could not say
// so. #1560 moved it here, over the registry.
//
// WHY THIS FILE IS DISCOVERY-BACKED. A hand-maintained registry has exactly the failure it exists
// to fix: the third declaration of the shape joins the dark rather than the list. So
// `undeclaredMatchKeyedShapes()` reads the source tree for interfaces declaring a `match: string[]`
// field and fails when one is not accounted for here — the same posture #1330 took for conditional
// scan paths. Registering a new corpus is a two-line edit; NOT registering one is a test failure.

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { CORPUS, corpusMatchKeyedRows, selfMatchingKeys, type MatchKeyedRow, type SelfMatchingKeyRow } from "./calibration.js";
import { SEMANTIC_CORPUS } from "./semantic-corpus.js";
import { FREE_RECALL_CORPUS } from "./free-recall-corpus.js";
import { readRecursiveSafe } from "../fs-walk.js";

const srcRoot = join(dirname(fileURLToPath(import.meta.url)), "..");

export interface MatchKeyedCorpus {
  /** How the corpus is named in gate output. */
  label: string;
  /** Where a reader edits the rows. */
  source: string;
  rows: MatchKeyedRow[];
}

/**
 * The registry. Order is the order the gate prints; each row is flattened to `MatchKeyedRow` here so
 * a corpus's own entry type never has to change to be covered.
 */
export function matchKeyedCorpora(): MatchKeyedCorpus[] {
  return [
    {
      label: "CORPUS (calibration answer key)",
      source: "src/scan/calibration/*.entries.ts",
      rows: corpusMatchKeyedRows(CORPUS),
    },
    {
      label: "SEMANTIC_CORPUS (M1 semantic answer keys)",
      source: "src/scan/semantic-corpus.ts",
      rows: SEMANTIC_CORPUS.flatMap((t) => t.entries.map((e) => ({ id: `${t.slug}/${e.id}`, kind: e.kind, locations: e.locations, match: e.match, matchAll: e.matchAll }))),
    },
    {
      label: "FREE_RECALL_CORPUS (free-tier answer keys)",
      source: "src/scan/free-recall-corpus.ts",
      rows: FREE_RECALL_CORPUS.flatMap((t) => t.entries.map((e) => ({ id: `${t.slug}/${e.id}`, kind: e.kind, locations: e.locations, match: e.match, matchAll: e.matchAll }))),
    },
  ];
}

interface CorpusVacuity {
  label: string;
  source: string;
  scanned: number;
  rows: SelfMatchingKeyRow[];
}

/** Every registered corpus swept for #1355's shape. `scanned` travels with the verdict, so a corpus that quietly emptied reads differently from one that was read and found clean. */
export function allSelfMatchingKeys(corpora: MatchKeyedCorpus[] = matchKeyedCorpora()): CorpusVacuity[] {
  return corpora.map((c) => ({ label: c.label, source: c.source, scanned: c.rows.length, rows: selfMatchingKeys(c.rows) }));
}

// The files whose `match: string[]` declaration IS accounted for by the registry above. A path that
// appears in the tree scan and not here is a corpus nobody is sweeping.
//   calibration.ts        — declares MatchKeyedRow, the shape itself (the checker's own input type)
//   calibration/types.ts  — CorpusEntry,   registered as CORPUS
//   semantic-corpus.ts    — SemanticEntry, registered as SEMANTIC_CORPUS and, re-used, FREE_RECALL_CORPUS
const DECLARING_SOURCES = ["scan/calibration.ts", "scan/calibration/types.ts", "scan/semantic-corpus.ts"];

const MATCH_FIELD = /^\s+match(?:All)?\??: (readonly )?string\[\](?:\[\])?/m;

/**
 * Source files declaring the shape that the registry does not account for. Non-empty = a corpus is
 * carrying location+keyword rows that no gate sweeps, which is precisely how SemanticEntry spent
 * from #1355 to #1560 unswept while CLAUDE.md recorded "no suppression list, 0 vacuous keys".
 *
 * Test files are excluded: they PLANT the shape on purpose (every negative control below declares a
 * vacuous row), so scoring them would make the discovery check fire on its own proof.
 */
export function undeclaredMatchKeyedShapes(): string[] {
  return readRecursiveSafe(srcRoot)
    .filter((p) => p.endsWith(".ts") && !p.endsWith(".test.ts"))
    .filter((p) => MATCH_FIELD.test(readFileSync(join(srcRoot, p), "utf8")))
    .filter((p) => !DECLARING_SOURCES.includes(p))
    .sort();
}
