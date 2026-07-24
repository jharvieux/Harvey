// #881 — the detection-metric arithmetic the calibration gates report, in the vocabulary the
// OWASP Benchmark Project established: TP/FP/TN/FN → precision, recall, F1 and Youden's Index
// (TPR − FPR, which summarises sensitivity and specificity in one number). Its Java corpus is
// useless to us; its scoring model is free to adopt, and it is the unit a prospect's security lead
// already reads — unlike "198/201", which needs our whole corpus story to interpret.
//
// Shared by the M1 mechanical corpus (scan/calibration.ts) and the M7/M8 heuristic corpus
// (scan/heuristic-precision.ts) so both report the same arithmetic, per module, never blended.
//
// A zero denominator yields 0, not NaN: a corpus that reported nothing has a precision of zero to
// report, and NaN in a printed number is how a broken measurement gets mistaken for a missing one.

interface Confusion {
  tp: number; // planted positives the tier caught
  fp: number; // benign negatives the tier flagged
  tn: number; // benign negatives it left alone
  fn: number; // planted positives it missed
}

export interface DetectionMetrics extends Confusion {
  precision: number; // tp / (tp + fp)
  recall: number; // tp / (tp + fn) — the true-positive rate
  f1: number;
  fpr: number; // fp / (fp + tn) — the false-positive rate
  youden: number; // recall − fpr, in [-1, 1]
}

const ratio = (num: number, den: number): number => (den === 0 ? 0 : num / den);

export function detectionMetrics(c: Confusion): DetectionMetrics {
  const precision = ratio(c.tp, c.tp + c.fp);
  const recall = ratio(c.tp, c.tp + c.fn);
  const fpr = ratio(c.fp, c.fp + c.tn);
  return {
    ...c,
    precision,
    recall,
    f1: ratio(2 * precision * recall, precision + recall),
    fpr,
    youden: recall - fpr,
  };
}

const pct = (n: number): string => `${(n * 100).toFixed(1)}%`;

// One line, always carrying the counts the rates were derived from — a rate whose denominator is
// off-screen is exactly the blended number #881 exists to stop.
export function formatMetrics(m: DetectionMetrics): string {
  return (
    `TP ${m.tp} FN ${m.fn} FP ${m.fp} TN ${m.tn} | ` +
    `precision ${pct(m.precision)}, recall ${pct(m.recall)}, F1 ${pct(m.f1)}, FPR ${pct(m.fpr)}, Youden's J ${m.youden.toFixed(3)}`
  );
}
