// Batch B25 — dependency-CVE VERSION PROVENANCE (#1471). No new detector: these rows score the
// three provenances checkNextVersionCVEs/checkKnownDependencyCVEs now distinguish, because the
// number a CVE row asserts had no provenance at all and "Installed next@14.2.5" was printed for a
// version nothing had installed.
//
// MEASURED 2026-07-31 on this repo's own calibration target: package.json declares next@^14.2.5,
// package-lock.json resolves next@14.2.35 (patched), and the scan reported "Installed next@14.2.5
// is below the fixed version 14.2.25" at Critical/Confirmed — while the OSV rows in the SAME report
// read `next@14.2.35`. Two rows in one deliverable disagreeing about the installed version.
//
// Fixture roots are scanned by validate-calibration.ts's scanManifestFixtures. Neither new root
// ships a lockfile, so each also draws SUP-NO-LOCKFILE — which is the scope control: a fixture the
// scanner never read reports zero exactly like one it scanned and missed (#1191 rule 3).

import type { CorpusEntry } from "./types.js";

const RANGE = "fixtures/b25-next-declared-range/package.json";

export const b25DepProvenanceEntries: CorpusEntry[] = [
  // --- The resolved-tree case, at the ROOT target: the false positive this batch removes. ---
  { id: "N-NEXT-29927-RESOLVED-PATCHED", kind: "negative", cls: "Declared range whose LOCKFILE resolves a patched version", location: "next", manifest: "package.json", match: ["29927"], note: "The root target declares next@^14.2.5 and its package-lock.json resolves next@14.2.35, which is at/above the 14.2.25 middleware-bypass fix. No CVE-2025-29927 row may be drawn here at all. This is the failing direction for #1471: preferring the manifest's range FLOOR over the resolved version reprints the Critical row and this negative fails as a free-count false positive. It cannot be satisfied by the co-firing WS-SSRF high on the same manifest — 14.2.35 genuinely is in that range (P-NEXT-CVE-WS-SSRF) — so the match key is the CVE number, exactly as N-NEXT-RSC-14X-UNAFFECTED isolates 55182." },

  // --- The declared-range case: raised, but as a conditional, and never in the free count. ---
  { id: "P-NEXT-RANGE-FLOOR", kind: "positive", cls: "Vulnerable range floor with no lockfile (conditional CVE)", location: RANGE, manifest: RANGE, match: ["29927"], expectedTier: "review", expectedSeverity: "Critical", note: "b25-next-declared-range declares next@^14.2.0 and ships no lockfile, so the floor 14.2.0 is below the 14.2.25 fix while the range equally admits a patched 14.2.x. The finding is still owed — the manifest permits a vulnerable install — so silence here is a miss. Severity stays Critical (the weakness's impact if present); the TIER and the wording carry the conditionality. The tier itself is asserted in src/scan/dependencies.test.ts (\"a declared RANGE with no lockfile\"), not by a paired negative here: a negative sharing this location and match key would be scored a false positive by calibration.test.ts's synthesized all-high matrix, which fabricates one high finding per static positive." },
  { id: "P-NEXT-RANGE-FLOOR-SCOPE", kind: "positive", cls: "Scope control — the declared-range fixture root was actually scanned", location: "fixtures/b25-next-declared-range", match: ["lockfile"], expectedTier: "high", note: "b25-next-declared-range ships no lockfile, so checkLockfilePresence emits SUP-NO-LOCKFILE (high) for it. Present because the two rows above are REVIEW tier, and a review-tier miss is reported but does not fail the gate — so a fixture root that stopped being scanned would go unnoticed. This row fails loud in that case. Location deliberately omits '/package.json' to keep it apart from the manifest findings in the same dir, the same construction P-MISSING-LOCKFILE uses." },
];
