// SAFE TWIN (N-LIB-EVAL-GUARD, #1631): the code-injection sibling carried no sanitizer block
// either, so this correct handler drew a Critical. The exported param is gated by an anchored,
// positive-class allowlist before it reaches eval.
export function calc(expr) {
  if (!/^[0-9+\-*\/ ]+$/.test(expr)) return null;
  return eval(expr);
}
