// M8 test-intent heuristic corpus (#823) — the labeled answer key for the static test-quality
// detectors (src/detectors/test-intent.ts #372/#384/#386, src/detectors/vitest-intent.ts #629),
// scored by src/scan/heuristic-precision.ts into the per-module precision/recall number the
// per-class fixture tests (test-intent.test.ts, vitest-intent.test.ts) never aggregated. Dirs
// are relative to src/detectors/__fixtures__/. Distinct from m8.entries.ts, which documents the
// Stryker mutation + stub-check corpus (executed verdicts, not static heuristics).

import type { HeuristicEntry } from "./types.js";

const M8 = "M8" as const;

export const m8IntentEntries: HeuristicEntry[] = [
  // --- POSITIVES (planted false-confidence tests — the class must fire) ---
  { module: M8, id: "M8INT-P-MOCK-SUBJECT", kind: "positive", cls: "Mock of the subject under test", taxonomy: "M8 — Mock of the subject under test", dir: "test-intent/mock-of-subject/positive", note: "vi.mock() of the very module the test exercises — basename match AND invoked-binding match (#372)." },
  { module: M8, id: "M8INT-P-ASSERTION-FREE", kind: "positive", cls: "Assertion-free test", taxonomy: "M8 — Assertion-free test", dir: "test-intent/assertion-free/positive", note: "Test bodies that call code but never assert — coverage padding (#372)." },
  { module: M8, id: "M8INT-P-TAUTOLOGICAL", kind: "positive", cls: "Tautological assertion", taxonomy: "M8 — Tautological assertion", dir: "test-intent/tautological/positive", note: "expect(x).toBe(x) — true by definition (#372)." },
  { module: M8, id: "M8INT-P-SNAPSHOT-ONLY", kind: "positive", cls: "Snapshot-only test", taxonomy: "M8 — Snapshot-only test", dir: "test-intent/snapshot-only/positive", note: "toMatchSnapshot as the only assertion — update-snapshots absorbs regressions (#372)." },
  { module: M8, id: "M8INT-P-CALL-COUNT", kind: "positive", cls: "Call-count-only test", taxonomy: "M8 — Call-count-only test", dir: "test-intent/call-count-only/positive", note: "toHaveBeenCalled as the only assertion — count stands in for behavior (#372)." },
  { module: M8, id: "M8INT-P-RLS-MOCKED", kind: "positive", cls: "Tenant-isolation test mocks the DB client", taxonomy: "M8 — Tenant-isolation test mocks the DB client", dir: "test-intent/rls-mocked-db/positive", note: "RLS-claiming tests over a mocked Supabase client — no query ever reaches Postgres (#384)." },
  { module: M8, id: "M8INT-P-HAPPY-PATH", kind: "positive", cls: "Happy-path-only tests on security-critical code", taxonomy: "M8 — Happy-path-only tests on security-critical code", dir: "test-intent/happy-path-only/positive", note: "auth/payment sources whose covering tests never name or assert a denial case (#386)." },
  { module: M8, id: "M8INT-P-UNRESTORED-SPY", kind: "positive", cls: "Unrestored vi.spyOn", taxonomy: "M8 — Unrestored vi.spyOn", dir: "vitest-intent/unrestored-spy/positive", note: "vi.spyOn with no restore — the replacement leaks into later tests (#629)." },
  { module: M8, id: "M8INT-P-IN-SOURCE", kind: "positive", cls: "In-source testing coverage-crediting", taxonomy: "M8 — In-source testing coverage-crediting", dir: "vitest-intent/in-source-test/positive", note: "import.meta.vitest block inside a product module inflating its own coverage (#629)." },
  { module: M8, id: "M8INT-P-HOISTED", kind: "positive", cls: "vi.hoisted misuse", taxonomy: "M8 — vi.hoisted misuse", dir: "vitest-intent/vi-hoisted-misuse/positive", note: "vi.hoisted factory referencing module-scope bindings that don't exist yet (#629)." },

  // --- NEGATIVES (benign lookalikes — the class must stay silent) ---
  { module: M8, id: "M8INT-N-MOCK-SUBJECT", kind: "negative", cls: "Dependency / partial / config-only mocks", taxonomy: "M8 — Mock of the subject under test", dir: "test-intent/mock-of-subject/negative", note: "A dependency mock, an importOriginal partial mock, and mock-config-only usage." },
  { module: M8, id: "M8INT-N-ASSERTION-FREE", kind: "negative", cls: "Helper-delegated / meta-asserted tests", taxonomy: "M8 — Assertion-free test", dir: "test-intent/assertion-free/negative", note: "expect, node:assert, local + page-object assertion helpers, hooks, it.todo, Playwright specs." },
  { module: M8, id: "M8INT-N-TAUTOLOGICAL", kind: "negative", cls: "Distinct-identifier / negated comparisons", taxonomy: "M8 — Tautological assertion", dir: "test-intent/tautological/negative", note: "Different expressions on the two sides, and .not chains." },
  { module: M8, id: "M8INT-N-SNAPSHOT-ONLY", kind: "negative", cls: "Snapshot plus a value assertion", taxonomy: "M8 — Snapshot-only test", dir: "test-intent/snapshot-only/negative", note: "A specific assertion alongside the snapshot clears the class." },
  { module: M8, id: "M8INT-N-CALL-COUNT", kind: "negative", cls: "toHaveBeenCalledWith arguments", taxonomy: "M8 — Call-count-only test", dir: "test-intent/call-count-only/negative", note: "Asserting call ARGUMENTS is a real behavioral claim." },
  { module: M8, id: "M8INT-N-RLS-MOCKED", kind: "negative", cls: "Real-client tenant tests / non-DB mocks", taxonomy: "M8 — Tenant-isolation test mocks the DB client", dir: "test-intent/rls-mocked-db/negative", note: "A real-client tenant test, a mocked-client non-tenant test, and a non-DB mock." },
  { module: M8, id: "M8INT-N-HAPPY-PATH", kind: "negative", cls: "Denial-named / denial-asserted suites", taxonomy: "M8 — Happy-path-only tests on security-critical code", dir: "test-intent/happy-path-only/negative", note: "Cleared by a denial name, a toThrow assertion, a non-critical word (author ≠ auth), or no covering tests." },
  { module: M8, id: "M8INT-N-UNRESTORED-SPY", kind: "negative", cls: "Restored spies", taxonomy: "M8 — Unrestored vi.spyOn", dir: "vitest-intent/unrestored-spy/negative", note: "mockRestore() handle and vi.restoreAllMocks() hook shapes." },
  { module: M8, id: "M8INT-N-IN-SOURCE", kind: "negative", cls: "Separate test file", taxonomy: "M8 — In-source testing coverage-crediting", dir: "vitest-intent/in-source-test/negative", note: "The same coverage lives in a real .test.ts — no in-source block in the product module." },
  { module: M8, id: "M8INT-N-HOISTED", kind: "negative", cls: "Self-contained vi.hoisted factories", taxonomy: "M8 — vi.hoisted misuse", dir: "vitest-intent/vi-hoisted-misuse/negative", note: "Factories that reference only their own locals/globals." },
];
