// simplify/depdrop.ts — BENIGN (M6-N-DEPDROP): a small reimplementation that looks like
// M6-P-DEBOUNCE/group.ts's hand-rolled-primitive shape, but carries a `// WHY:` comment
// explaining a deliberate tradeoff. The rubric must NOT flag this one
// (quality-extras.txt "FALSE POSITIVES" — "a re-implementation chosen deliberately to drop a
// heavy dependency — note the tradeoff, don't flag as a defect").
//
// WHY: this project's only other use of lodash-es would be this one throttle call. Pulling in
// the whole dep (and its type package) for an 8-line function isn't worth the install/audit
// surface — reimplemented deliberately, revisit if a second lodash-es need shows up.
export function throttle<Args extends unknown[]>(
  fn: (...args: Args) => void,
  waitMs: number,
): (...args: Args) => void {
  let last = 0;
  return (...args: Args) => {
    const now = Date.now();
    if (now - last >= waitMs) {
      last = now;
      fn(...args);
    }
  };
}
