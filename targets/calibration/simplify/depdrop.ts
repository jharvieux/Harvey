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
