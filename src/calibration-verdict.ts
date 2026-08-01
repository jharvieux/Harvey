// #1765. The scored recall gate decides its verdict on ONE list — `fatalRecallMisses(matrix.rows)` —
// and then reports through three SUBSETS of it: the high-tier misses, the review-tier misses, and
// the soundness (`mustCatch`) misses inside the review set. A miss belonging to none of the three
// therefore fails the gate and prints nothing, so `process.exit(1)` arrives with no row named. An
// exit 1 that names nothing reads like a crash, and the operator gets nothing to act on — this
// repo's fail-loud rule broken inside its own recall gate.
//
// `MEASURED 2026-07-31` on the corpus, correcting the population #1765 states: 0 of 522 positives
// carry no `expectedTier` (that half reproduces), but 21 carry a LIVE tier — 15 `local`, 4
// `hosted`, 2 `connected` — and a live tier is in no printed subset either. On this CLI they are
// `notScored` today because it passes no venue set, so today's live population really is 0; the 21
// are one wiring change away, and `pnpm validate:connected`, which does score them, prints a
// catch-all already. So this ships as the missing branch rather than as a backlog.
//
// The check is one line of set arithmetic on purpose: it takes the SAME list the verdict took, so a
// new tier-specific branch added above it shrinks this one automatically instead of racing it.

export function unnamedRecallMisses<T extends { id: string }>(
  fatal: readonly T[],
  named: readonly (readonly T[])[],
): T[] {
  const printed = new Set(named.flat().map((r) => r.id));
  return fatal.filter((r) => !printed.has(r.id));
}
