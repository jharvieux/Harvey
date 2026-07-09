// Corpus answer-key types, shared by the per-batch entry modules (base.entries.ts,
// secrets.entries.ts, …) and re-exported from ../calibration.ts for the two consumers
// (calibration.test.ts, cli/validate-calibration.ts). Kept in their own module so an entry
// file can import the types without a cycle through calibration.ts.

import type { PrecisionTier } from "../../findings.js";

type CorpusKind = "positive" | "negative";

// "high"/"review" mirror PrecisionTier; "connected" marks entries only detectable against a live
// database (Supabase Advisor) — out of scope for a static run, reported as N/A, never a failure.
type ExpectedTier = PrecisionTier | "connected";

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
  // Optional keywords; a finding is relevant only if one appears in its id/title/taxonomy/
  // evidence. Disambiguates fixtures that share a file (e.g. the anon key vs. the mis-prefixed
  // secret, both in .env.local).
  match?: string[];
  // Positives: the tier we expect the detection at. Negatives: omit.
  expectedTier?: ExpectedTier;
  note: string;
}
