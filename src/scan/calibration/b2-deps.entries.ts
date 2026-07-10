// Batch B2 — framework-CVE + supply-chain manifest hygiene (#71, spec
// docs/design/spec-71-security-corpus.md §"Batch 4 — Framework CVEs" + §"Batch 5 — Supply
// chain / manifest hygiene"). Registers detections that already existed in src/scan/dependencies.ts
// (checkNextVersionCVEs, parseOsvFindings) and src/scan/supply-chain.ts but were unrepresented in
// the corpus, plus one new deterministic manifest check (checkNonRegistryDependencies) and its
// typosquat fixture. The already-registered base-batch dep rows (P-NEXT-CVE-29927, P-NEXT-CVE-RSC,
// P-DEP-CVE, P-SLOPSQUAT, P-POSTINSTALL, N-DEV-DEP) are NOT duplicated here. See GROUND-TRUTH.md §B2.
//
// Tiering: only the two deterministic-syntactic checks are `high` (free count) — an exact CVE
// version-range match (WS-SSRF) and the unpinned-range check. The OSV-backed cache-poisoning
// cluster, the offline edit-distance typosquat, and the non-registry-source check stay `review`
// (a version match / edit-distance / git-source presence isn't proof of exploitability).

import type { CorpusEntry } from "./types.js";

export const b2DepsEntries: CorpusEntry[] = [
  // --- POSITIVES ---
  { id: "P-NEXT-CVE-WS-SSRF", kind: "positive", cls: "Framework CVE — WebSocket-upgrade SSRF", location: "next", match: ["44578"], expectedTier: "high", note: "next@^14.2.5 falls in the CVE-2026-44578 range (>=13.4.13 <15.5.16, GHSA-c4j6-fc7j-m34r, CVSS 8.6). checkNextVersionCVEs (src/scan/dependencies.ts) — high. Match on the CVE number to disambiguate from the 29927/RSC entries sharing location 'next'." },
  { id: "P-UNPINNED-DEP", kind: "positive", cls: "Unpinned dependency version range", location: "package.json", match: ["unpinned"], expectedTier: "high", note: "The target's ^-ranged deps (next, react, pg, zod, @supabase/supabase-js, react-dom) trip checkUnpinnedDependencies (src/scan/supply-chain.ts) — a deterministic syntactic fact, high precision. Spec drafted this 'review'; the implemented check is ~100%-precise (an unpinned range IS unpinned), so it lands high, guarded by N-DEP-PINNED." },
  { id: "P-NEXT-CVE-CACHE", kind: "positive", cls: "Framework CVE — cache poisoning (May-2026 batch)", location: "next@14.2.35", match: ["cache poisoning"], expectedTier: "review", note: "OSV-Scanner over the committed lockfile (next resolved to 14.2.35) matches the May-2026 cache-poisoning advisories (e.g. GHSA-wfc6-r584-vfw7). parseOsvFindings tiers every non-curated OSV hit review — a version match isn't proof of exploitability." },
  { id: "P-TYPOSQUAT", kind: "positive", cls: "Typosquat — edit-distance-1 dependency name", location: "package.json", match: ["one edit"], expectedTier: "review", note: "'expres' (a real, published npm package — so checkSlopsquat's registry HEAD stays silent) is Levenshtein-1 from 'express'; checkTyposquat (src/scan/supply-chain.ts) flags it at review (offline corpus match, not a live-registry confirmation)." },
  { id: "P-NONREGISTRY-DEP", kind: "positive", cls: "Non-registry dependency source (git/url/file)", location: "package.json", match: ["non-registry"], expectedTier: "review", note: "'left-pad' pinned to a git+https URL (a real npm name, so checkSlopsquat stays silent) trips the new checkNonRegistryDependencies (src/scan/supply-chain.ts) — review (a git source can be intentional; presence isn't proof of a problem)." },

  // --- NEGATIVES ---
  { id: "N-DEP-PINNED", kind: "negative", cls: "Exactly-pinned registry dependency", location: "package.json", match: ["lodash"], note: "lodash@4.17.11 is exact-pinned and registry-sourced, so it never appears in the SUP-UNPINNED or SUP-NON-REGISTRY finding's evidence — the pinned-dep FP that a naive 'any dependency is unpinned' rule throws. Cleared (its OSV CVE finding lives at the lockfile location, not package.json, so it can't be mis-attributed here). Doubles as the registry-source negative for P-NONREGISTRY-DEP." },
  { id: "N-SLOPSQUAT-REAL", kind: "negative", cls: "Real popular dependency, similar name", location: "@supabase/supabase-js", note: "@supabase/supabase-js is a real, popular, scoped package (exact-match in checkTyposquat's popular set; a 200 from checkSlopsquat's registry HEAD) — the FP a name-shape heuristic throws on a legitimate scoped dep. Draws no slopsquat/typosquat finding — cleared." },
];
