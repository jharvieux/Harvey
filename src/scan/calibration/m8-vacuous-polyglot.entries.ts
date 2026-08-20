// M8 source-level vacuous-assertion corpus (#1931). These rows intentionally use files distinct
// from the Stryker corpus: the source classifier emits one finding per assertion statement/call,
// while mutation-scan.ts retains its separate file-level evidence identity.

import type { CorpusEntry } from "./types.js";

export const m8VacuousPolyglotEntries: CorpusEntry[] = [
  {
    module: "M8",
    id: "M8VAC-P-JS-FIXED",
    kind: "positive",
    cls: "Jest/Vitest fixed-literal assertion independent of production behavior",
    location: "m8-vacuous-assertion/vacuous.test.ts",
    match: ["production-independent assertion"],
    expectedTier: "review",
    expectedSeverity: "Medium",
    note: "expect(true).toBe(true) is a passing fixed-literal assertion. The source-level #1931 classifier must emit one review-tier finding at the assertion line even when the surrounding file contains useful tests.",
  },
  {
    module: "M8",
    id: "M8VAC-N-JS-OBSERVED",
    kind: "negative",
    cls: "Production-derived JS observation and rationale-bearing smoke check",
    location: "m8-vacuous-assertion/controls.test.ts",
    note: "calibrateDiscount(100) is production-derived, while the fixed assertion is immediately documented as a deliberate runner-wiring smoke check. Neither is #1931 noise.",
  },
  {
    module: "M8",
    id: "M8VAC-P-PYTHON-FIXED",
    kind: "positive",
    cls: "Python unconditional placeholder assertions",
    location: "m8-vacuous-assertion/test_vacuous.py",
    match: ["production-independent assertion"],
    expectedTier: "review",
    expectedSeverity: "Medium",
    note: "The explicit Python SourceInput contains assert True and assert 1 == 1. The bounded syntax recognizer must report both without claiming full Python parsing.",
  },
  {
    module: "M8",
    id: "M8VAC-N-PYTHON-OBSERVED",
    kind: "negative",
    cls: "Production-derived Python condition and rationale-bearing smoke check",
    location: "m8-vacuous-assertion/test_controls.py",
    note: "read_status() is production-derived, while the unconditional assertion is documented as a deliberate pytest-wiring smoke check. Comments, strings, and docstrings are lexically masked before syntax recognition.",
  },
];
