// Corpus answer-key types, shared by the per-batch entry modules (base.entries.ts,
// secrets.entries.ts, …) and re-exported from ../calibration.ts for the two consumers
// (calibration.test.ts, cli/validate-calibration.ts). Kept in their own module so an entry
// file can import the types without a cycle through calibration.ts.

import type { PrecisionTier, Severity } from "../../findings.js";

type CorpusKind = "positive" | "negative";

// "high"/"review" mirror PrecisionTier; "connected" marks entries only detectable against a live
// database (Supabase Advisor) — out of scope for a static run, reported as N/A, never a failure.
// "none" marks a planted positive with NO mechanical rule BY DESIGN (a measured LLM-tier class —
// e.g. WEBHOOK-REPLAY, #353/#425): a static run scores it an INTENDED GAP, never a recall miss,
// and if ANY mechanical rule ever fires on its class the gate FAILS LOUD, so a by-design gap can't
// silently graduate into a claimed catch. Excluded from the recall denominator; still a real
// fixture for the parity census.
type ExpectedTier = PrecisionTier | "connected" | "none";

export interface CorpusEntry {
  id: string;
  kind: CorpusKind;
  cls: string;
  // Which audit module this entry belongs to. Omitted = "M1" (the original mechanical-scan
  // corpus, base+secrets — scored by validate-calibration.ts against runMechanicalScan output).
  // A module whose findings aren't produced by runMechanicalScan (e.g. "M10", a name/type
  // classifier with its own live pipeline) must be excluded from that scoring pass — see the
  // module filter in src/cli/validate-calibration.ts.
  module?: string;
  // Substring expected in a relevant finding's `location` (file path / lockfile coordinate).
  location: string;
  // Anchors a dependency entry to ONE manifest. Dependency findings encode location as
  // "<manifestPath> (<pkg>)", so a bare package-name `location` like "next" substring-matches
  // EVERY manifest that declares it — the root target's and every fixtures/*/package.json. That
  // let a positive score off the wrong fixture while the rule under test never fired on the
  // intended one, which is how #212's bad P-NEXT-CVE-RSC row appeared to pass (#253). When set,
  // a finding is relevant only if its manifest segment equals this exactly.
  manifest?: string;
  // Optional keywords; a finding is relevant only if one appears in its id/title/taxonomy/
  // evidence. Disambiguates fixtures that share a file (e.g. the anon key vs. the mis-prefixed
  // secret, both in .env.local).
  match?: string[];
  // Positives: the tier we expect the detection at. Negatives: omit.
  expectedTier?: ExpectedTier;
  // Only meaningful with expectedTier "none", which covers two DIFFERENT situations that must not
  // read alike in the gate output (#1190). "by-design" is the original meaning: a class no
  // mechanical rule is intended to reach, measured as LLM-tier remit. "measured-gap" is a real
  // coverage gap that was planted, scanned, and found uncaught — recorded here so it is scored as a
  // gap rather than a miss, with an issue tracking the fix. Both fail loud if a rule ever fires;
  // they differ only in whether the gap is an accepted boundary or outstanding work, and calling
  // the second one "by design" would misreport it. Defaults to "by-design" so existing rows keep
  // their meaning.
  gapKind?: "by-design" | "measured-gap";
  // Positives: the exact Severity the DELIVERED finding must carry (#1157). Presence is NOT
  // detection (that is expectedTier) — it is a scored assertion that a caught finding is RATED
  // right, so a real Critical shipped as Medium fails the gate the way a miss does (#1063/#1060).
  // Ground truth, not "whatever the code emits": set it from the advisory's CVSS band / the data
  // class, so the gate catches a live mis-rating, not merely a regression from a wrong baseline.
  // Only checked when the positive was caught; a not-caught positive already fails on the miss.
  // Omit where the expected severity is unstable or an entry legitimately matches findings of
  // several severities (e.g. a two-CVE cluster) — a silent omission there is fine, a wrong
  // assertion is not.
  expectedSeverity?: Severity;
  // #1344 — NEGATIVES ONLY. The review-tier taxonomies this benign fixture is MEASURED to draw and
  // that are accepted as triaged-out noise. A review-tier hit not on this list fails the gate.
  //
  // Why this exists: a negative used to pass on `!highFlagged` alone, so a widened rule that lit up
  // a planted negative at review tier scored "cleared (review-tier hit only)" and every gate stayed
  // green — #1251 hit exactly that (a taint-source widening made harvey-path-traversal fire on
  // N-STORAGE-DB-PATH; it surfaced only by hand-diffing dry-run/findings.json). The free count is
  // still what makes a negative FAIL LOUD as a false positive; this makes any MOVEMENT fail as a
  // regression, which is the thing no gate could previously see. Recording a taxonomy here is a
  // deliberate act with a reason in `note`, not a way to quiet a row.
  reviewTierHits?: readonly string[];
  note: string;
}

// Labeled corpus row for the M7/M8 heuristic precision gate (#823). Unlike CorpusEntry — scored
// against one shared Finding[] by location substring — a HeuristicEntry names a FIXTURE DIR that
// the gate scans itself (src/scan/heuristic-precision.ts), because the M7 code / M8 intent
// detectors are pure functions over SourceInput[] with per-class option axes (React Compiler
// on/off, Next vs Vite) that a single shared scan cannot express.
export interface HeuristicEntry {
  id: string;
  // #896 added "M1": the tenant-scope/BOLA detector's precision corpus, whose negatives are
  // distilled from third-party libraries whose PURPOSE is correct tenant isolation — code written
  // in idioms we did not anticipate, which is the case planted-clean fixtures cannot test.
  module: "M1" | "M7" | "M8";
  kind: CorpusKind;
  cls: string;
  // Fixture dir relative to src/detectors/__fixtures__/ (e.g. "perf/sort-in-jsx/positive").
  dir: string;
  // Exact Finding.taxonomy the class emits. Omitted on a negative = ANY finding from the
  // module's detectors counts as a false fire (e.g. the render-once dir must be fully silent).
  taxonomy?: string;
  // M7 axes: run with the Vite framework flag / with a React-Compiler-on next.config appended.
  framework?: "vite";
  compilerOn?: boolean;
  // #1344: a location substring naming a KNOWN-CAUGHT hit planted in the same negative fixture
  // directory. Its findings are excluded from the false-positive count, and the row FAILS if it
  // does not fire. Without it a negative dir the scanner never read scores identically to one it
  // scanned and correctly cleared — CLAUDE.md's rule (3), which until now had no way to be
  // enforced here, only followed by hand.
  scopeControl?: string;
  note: string;
}
