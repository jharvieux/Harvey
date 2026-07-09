// simplify/debounce.ts — PLANTED (M6-P-DEBOUNCE): a hand-rolled setTimeout-based debounce.
// The rubric expects /simplify to name a stdlib/existing-dep replacement (e.g. lodash-es
// `debounce`, or `useDebouncedCallback` if a hooks lib is already a dependency) instead of this
// bespoke reimplementation of a well-known primitive (quality-extras.txt M6 "HAND-ROLLED
// PRIMITIVES").
export function debounce<Args extends unknown[]>(
  fn: (...args: Args) => void,
  waitMs: number,
): (...args: Args) => void {
  let timer: ReturnType<typeof setTimeout> | undefined;
  return (...args: Args) => {
    if (timer) clearTimeout(timer);
    timer = setTimeout(() => fn(...args), waitMs);
  };
}
