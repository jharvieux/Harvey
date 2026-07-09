import { configDefaults, defineConfig } from "vitest/config";

// M8 (#72 §M8) added targets/calibration/test-quality/ — a real Stryker mutation-testing
// fixture with its own isolated npm project and, deliberately, one weak test
// (discount.tautological.test.ts, M8-P-TAUTOLOGICAL). Without this exclude, vitest's default
// include glob picks that up as if it were part of this repo's own suite (see eslint.config.mjs,
// which already ignores "targets" for the same reason). The Layer-1 gate for M8 is the recorded
// Stryker-capture assertions in src/mutation-scan.test.ts, not a live re-run of the target's
// own tests here. Extends (not replaces) vitest's own default excludes.
export default defineConfig({
  test: {
    exclude: [...configDefaults.exclude, "targets/**"],
  },
});
