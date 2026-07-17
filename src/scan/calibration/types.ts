// Corpus answer-key types, shared by the per-batch entry modules (base.entries.ts,
// secrets.entries.ts, …) and re-exported from ../calibration.ts for the two consumers
// (calibration.test.ts, cli/validate-calibration.ts). Kept in their own module so an entry
// file can import the types without a cycle through calibration.ts.

import type { PrecisionTier } from "../../findings.js";

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
  note: string;
}
