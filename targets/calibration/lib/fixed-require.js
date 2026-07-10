// NEGATIVE (N-REQUIRE-FIXED): require() with a fixed string literal — no request taint reaches it.
// harvey-dynamic-require needs a tainted argument — cleared.
const helper = require("./helper");

export function run() {
  return helper.run();
}
