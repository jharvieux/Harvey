// Calibration validation gate (issue #61). Encodes the corpus answer key — every planted
// POSITIVE that must be caught and every benign NEGATIVE that must NOT be flagged in the free
// count — as data, then scores a Finding[] against it into a coverage matrix (positive recall +
// negative precision per rule/class). The mechanical layer earns the "free count" claim only
// when every high-tier rule fires on its positive and stays silent on its negative lookalike
// (docs/design/mechanical-toolchain.md §7; targets/calibration/GROUND-TRUTH.md).
//
// Two consumers:
//   - src/scan/calibration.test.ts — UNIT tests against RECORDED scanner output (no binaries),
//     so `pnpm verify` proves the scorecard logic in binary-less CI.
//   - src/cli/validate-calibration.ts — LIVE run (`pnpm validate:calibration`) that scans the
//     real targets/calibration with the installed binaries.

import type { Finding, PrecisionTier } from "../findings.js";
import { baseEntries } from "./calibration/base.entries.js";
import { m4m5Entries } from "./calibration/m4-m5.entries.js";
import { secretsEntries } from "./calibration/secrets.entries.js";
import type { CorpusEntry } from "./calibration/types.js";

export type { CorpusEntry } from "./calibration/types.js";

// Answer key, assembled from per-batch entry modules under ./calibration/. CONVENTION: each
// corpus batch (#71 fan-out) adds a `<batch>.entries.ts` file exporting a CorpusEntry[] and one
// spread below — this keeps parallel batches conflict-free (a new batch touches only its own
// file plus this single line). Positives extend GROUND-TRUTH.md's planted bugs; negatives are
// the benign lookalikes from the FP catalog (docs/fp-rules.txt).
export const CORPUS: CorpusEntry[] = [...baseEntries, ...secretsEntries, ...m4m5Entries];

function haystack(f: Finding): string {
  return `${f.id} ${f.title} ${f.taxonomy} ${f.evidence} ${f.location}`.toLowerCase();
}

// A finding is relevant to an entry when its location contains the entry's location substring
// and (if the entry lists keywords) at least one keyword appears anywhere in the finding text.
function relevantFindings(entry: CorpusEntry, findings: Finding[]): Finding[] {
  const loc = entry.location.toLowerCase();
  const keys = entry.match?.map((m) => m.toLowerCase());
  return findings.filter((f) => {
    if (!f.location.toLowerCase().includes(loc)) return false;
    if (!keys) return true;
    const hay = haystack(f);
    return keys.some((k) => hay.includes(k));
  });
}

function topTier(findings: Finding[]): PrecisionTier | undefined {
  if (findings.some((f) => f.precisionTier === "high")) return "high";
  if (findings.some((f) => f.precisionTier === "review")) return "review";
  return undefined;
}

export interface MatrixRow {
  id: string;
  kind: CorpusEntry["kind"];
  cls: string;
  expectedTier?: CorpusEntry["expectedTier"];
  caughtTier?: PrecisionTier; // best tier a relevant finding landed at (positives)
  highFlagged: boolean; // a relevant finding at HIGH (free-count) tier exists
  reviewFlagged: boolean; // a relevant finding at review tier exists
  pass: boolean;
  detail: string;
}

// Scoring:
//   positive (static): pass = caught at any tier. A "connected"-tier positive is N/A (never fails).
//   negative: pass = NO high-tier (free-count) finding is relevant. A review-tier hit is tolerated
//             (it gets triaged out of the count) but recorded. A "connected"-tier negative is N/A.
export function scoreEntry(entry: CorpusEntry, findings: Finding[]): MatrixRow {
  const relevant = relevantFindings(entry, findings);
  const highFlagged = relevant.some((f) => f.precisionTier === "high");
  const reviewFlagged = relevant.some((f) => f.precisionTier === "review");
  const caughtTier = topTier(relevant);

  if (entry.expectedTier === "connected") {
    return { id: entry.id, kind: entry.kind, cls: entry.cls, expectedTier: entry.expectedTier, caughtTier, highFlagged, reviewFlagged, pass: true, detail: "N/A — connected tier (live DB), not evaluated statically" };
  }

  if (entry.kind === "positive") {
    const pass = caughtTier !== undefined;
    const detail = pass
      ? `caught at ${caughtTier}${entry.expectedTier && entry.expectedTier !== caughtTier ? ` (expected ${entry.expectedTier})` : ""}`
      : "NOT caught by any rule";
    return { id: entry.id, kind: entry.kind, cls: entry.cls, expectedTier: entry.expectedTier, caughtTier, highFlagged, reviewFlagged, pass, detail };
  }

  // negative
  const pass = !highFlagged;
  const detail = highFlagged
    ? "FALSE POSITIVE in the free count"
    : reviewFlagged
      ? "cleared from the count (review-tier hit only, triaged out)"
      : "cleared — not flagged";
  return { id: entry.id, kind: entry.kind, cls: entry.cls, expectedTier: entry.expectedTier, caughtTier, highFlagged, reviewFlagged, pass, detail };
}

interface CoverageMatrix {
  rows: MatrixRow[];
  positivesTotal: number; // static positives (excludes connected tier)
  positivesCaught: number;
  positivesCaughtHigh: number;
  negativesTotal: number; // static negatives (excludes connected tier)
  negativesCleared: number;
  connectedNa: number;
  ok: boolean; // every static positive caught AND every static negative cleared
}

export function buildCoverageMatrix(findings: Finding[], corpus: CorpusEntry[] = CORPUS): CoverageMatrix {
  const rows = corpus.map((e) => scoreEntry(e, findings));
  const staticPos = rows.filter((r) => r.kind === "positive" && r.expectedTier !== "connected");
  const staticNeg = rows.filter((r) => r.kind === "negative" && r.expectedTier !== "connected");
  const positivesCaught = staticPos.filter((r) => r.pass).length;
  const negativesCleared = staticNeg.filter((r) => r.pass).length;
  return {
    rows,
    positivesTotal: staticPos.length,
    positivesCaught,
    positivesCaughtHigh: staticPos.filter((r) => r.highFlagged).length,
    negativesTotal: staticNeg.length,
    negativesCleared,
    connectedNa: rows.filter((r) => r.expectedTier === "connected").length,
    ok: positivesCaught === staticPos.length && negativesCleared === staticNeg.length,
  };
}
