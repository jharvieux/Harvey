// Batch M4+M5 (#72, spec §M4/§M5) — duplication (jscpd + the #360 diverged-clone pass) + dead
// code (knip). Fully self-contained, static: no live DB, no external service. Findings come from
// src/quality-scan.ts::jscpdToFindings / knipToFindings and src/diverged-clones.ts via
// `pnpm quality-scan targets/calibration`. See GROUND-TRUTH.md "Batch M4+M5 (#72)" for the
// fixtures. The M4 slice is measured live by src/quality-scan.test.ts (validate-calibration
// scores only mechanical-scan modules).
// Per the spec's locked precision-tier discipline, both are `high`: jscpd's text-match
// and knip's dead-export detection are ~100% precise once the FP class (generated code /
// framework magic / dynamic reference / public API) is configured — the negatives below
// are exactly that configuration.

import type { CorpusEntry } from "./types.js";

export const m4m5Entries: CorpusEntry[] = [
  // --- M4 duplication (jscpd) POSITIVES ---
  { module: "M4", id: "M4-P-CLONE-A", kind: "positive", cls: "Copy-pasted tax/rounding block", location: "invoice-total.ts", match: ["duplication"], expectedTier: "high", note: "dup/invoice-total.ts and dup/order-total.ts share a genuine 27-line copy-pasted tax/rounding block (299 tokens). jscpd clone cluster; jscpdToFindings emits an M4-* finding at Low severity (15-49 duplicated lines)." },
  { module: "M4", id: "M4-P-CLONE-B", kind: "positive", cls: "Copy-pasted report aggregation block", location: "report-a.ts", match: ["duplication"], expectedTier: "high", note: "dup/report-a.ts and dup/report-b.ts share a 52-line copy-pasted metric-aggregation block (658 tokens). jscpd clone cluster; jscpdToFindings' severityForClone -> Medium (>=50 lines)." },
  { module: "M4", id: "M4-P-CLONE-SEC", kind: "positive", cls: "Copy-pasted session/tenant validation block in an auth path", location: "auth/session-check-api.ts", match: ["duplication"], expectedTier: "high", note: "dup/auth/session-check-api.ts and dup/auth/session-check-action.ts share a genuine 25-line copy-pasted session/tenant validation block (246 tokens) under an auth/ path. jscpd clone cluster; touchesSecurityPath fires (#361) so jscpdToFindings elevates Low->Medium and appends the M1 cross-check note. Severity/note asserted in src/quality-scan.test.ts (the matrix scores caught-at-tier only)." },

  // #1095: the self-file band. #232 excluded it as inert repeated DATA; #1080 measured that false
  // (76% copy-pasted test setup, 7% JSX render blocks, ZERO SVG/enum clusters on a real 2755-file
  // target) and the operator ruled the band back into the SCORED findings on 2026-07-26.
  { module: "M4", id: "M4-P-CLONE-SELF", kind: "positive", cls: "Copy-pasted block repeated within one file", location: "self-file-shipping.ts", match: ["duplication"], expectedTier: "high", note: "dup/self-file-shipping.ts repeats a 16-line accumulate-and-format block between summariseDomesticShipment and summariseInternationalShipment IN THE SAME FILE. jscpd clone cluster with both refs on one path; since #1095 jscpdToFindings scores it like any other clone (Low, 15-49 lines) with in-file fix text, instead of dropping it into the M4-SELF-00 count." },

  // #1095: the same-file case of the near-miss pass. Both divergedCloneFindings and
  // wholeRepoDivergedCloneFindings used to `continue` on a.path === b.path, so two drifted copies
  // of one guard in ONE file — the case with the weakest discovery cues — were unreachable.
  { module: "M4", id: "M4-P-DIVERGED-SELF", kind: "positive", cls: "Diverged copy-pasted guard within one file", location: "workspace-guard.ts", match: ["diverged"], expectedTier: "review", note: "dup/auth/workspace-guard.ts holds assertWorkspaceMember and assertProjectMember 12 lines apart: structurally identical, disagreeing on the ownership column (row.owner_id vs row.id) with drifted error strings. No contiguous exact span reaches jscpd's floor, and before #1095 the near-miss pass skipped same-file pairs outright — so nothing saw this pair at all. divergedCloneFindings -> M4-DIV-* reviewFinding (High, review tier)." },

  // #360: the Type-3 shape jscpd structurally cannot see — a copy-pasted tenant guard whose
  // copies have DIVERGED (tenant_id vs owner_id scoping literal). Caught by the near-miss pass
  // (src/diverged-clones.ts), review tier: it is an adjudication request, not a verdict.
  { module: "M4", id: "M4-P-DIVERGED-TENANT", kind: "positive", cls: "Diverged copy-pasted tenant-scoping guard", location: "require-tenant-api.ts", match: ["diverged"], expectedTier: "review", note: "dup/auth/require-tenant-api.ts and require-tenant-admin.ts hold structurally-identical guards that disagree on the scoping literal ('tenant_id' vs 'owner_id') plus drifted error strings — jscpd's exact match sees only sub-threshold fragments, never the pair. divergedCloneFindings -> M4-DIV-* reviewFinding (High severity, review tier) naming the drifted literals." },

  // #399: the v2 widening — a per-entity store file whose PATH says nothing about security
  // (touchesSecurityPath is false) but whose BODY scopes a supabase query by a tenant key
  // (touchesTenantSupabasePath). Same diverged-guard shape as M4-P-DIVERGED-TENANT, just outside
  // the v1 path vocabulary — proves the widened file selection, not just the detector.
  { module: "M4", id: "M4-P-DIVERGED-TENANT-WIDENED", kind: "positive", cls: "Diverged tenant-scoped supabase query outside the security path vocabulary", location: "customer.store.ts", match: ["diverged"], expectedTier: "review", note: "dup/stores/customer.store.ts and order.store.ts hold structurally-identical supabase queries that disagree on the tenant-scoping literal ('organisation_id' vs 'org_id') — neither path matches touchesSecurityPath, so only touchesTenantSupabasePath's content-based admission (#399) puts them in front of divergedCloneFindings at all. divergedCloneFindings -> M4-DIV-* reviewFinding (High severity, review tier)." },

  // #809: the opt-in whole-repo extension (wholeRepoDivergedCloneFindings). A config builder
  // duplicated between two plain report-export files — neither auth/guard/security-path nor
  // tenant-scoped supabase query, so divergedCloneFindings' narrow admission (#360/#399) never
  // sees this pair; only the whole-repo pass does, at Medium severity and generic wording (never
  // the security framing) since it carries no security guarantee.
  { module: "M4", id: "M4-P-DIVERGED-WIDE", kind: "positive", cls: "Diverged config builder outside the security-path and tenant-supabase vocabulary", location: "export-config-a.ts", match: ["diverged"], expectedTier: "review", note: "dup/wide/export-config-a.ts and export-config-b.ts hold a structurally-identical buildExportJobConfig whose row-limit literal has drifted (500 vs 2000). wholeRepoDivergedCloneFindings -> M4-DIVW-* reviewFinding (Medium severity, review tier, M4_DIVERGED_WIDE_TAXONOMY)." },
  { module: "M4", id: "M4-N-DIVERGED-WIDE-DISTINCT", kind: "negative", cls: "Independently-written non-security function of similar size", location: "notification-format.ts", note: "dup/wide/notification-format.ts is a similar token mass to buildExportJobConfig but structurally distinct (loop + string building, not an object-literal config) — the whole-repo pass must not pair it with anything. Guards the near-miss detector's similarity floor against 'similar size' FPs outside the narrow pass's fixture set." },

  // #365: the "genuine small clone" boundary pair — one fixture, two contracts. The 9-line
  // pricing-tier ladder is real logic (not boilerplate) under MIN_SIGNIFICANT_LINES: it must NOT
  // become an individual finding (M4-N-SMALL-FLOOR) and MUST be counted by the aggregate M4-00
  // sub-threshold disclosure (M4-P-SMALL-DISCLOSED, matched via the example pair in its evidence).
  { module: "M4", id: "M4-P-SMALL-DISCLOSED", kind: "positive", cls: "Sub-threshold small-clone band disclosed in aggregate", location: "(repo-wide)", match: ["pricing-tier"], expectedTier: "high", note: "dup/pricing-tier-a.ts and dup/pricing-tier-b.ts share a genuine 9-line volume-discount ladder (129 tokens) — the AI-era small-block shape #365 measured at 30% of cross-file clones on the corpus's AI-authored target. jscpdToFindings' M4-00 disclosure finding must exist and name this pair in its evidence." },

  // --- M4 duplication NEGATIVES ---
  { module: "M4", id: "M4-N-GENERATED", kind: "negative", cls: "Generated file repeating a block found elsewhere", location: "schema.gen.ts", note: "dup/generated/schema.gen.ts repeats the invoice-total.ts tax block but is a generated file, not a hand-maintained duplicate. Excluded via the quality-scan CLI's jscpd --ignore glob (extended to **/generated/**, src/cli/quality-scan.ts) — jscpd never sees it." },
  { module: "M4", id: "M4-N-SMALL-FLOOR", kind: "negative", cls: "Genuine small clone stays below the individual-finding floor", location: "pricing-tier-a.ts", note: "The same 9-line pricing-tier ladder must not surface as its own M4-* finding (44 of these would triple an AI-authored target's M4 report — #365's measured basis for keeping MIN_SIGNIFICANT_LINES=10). Its visibility is the M4-00 aggregate, checked by M4-P-SMALL-DISCLOSED." },
  { module: "M4", id: "M4-N-DIV-DISTINCT", kind: "negative", cls: "Independently-written guard in the same auth path", location: "api-key-check.ts", note: "dup/auth/api-key-check.ts shares the domain (guard, early throws) but not the structure of the require-tenant pair — the #360 pass must not pair it with anything. Guards the near-miss detector's similarity floor against 'all guards look alike' FPs." },
  { module: "M4", id: "M4-N-BOILERPLATE", kind: "negative", cls: "Framework-mandated route boilerplate", location: "route-a.ts", note: "dup/route-a.ts and dup/route-b.ts share the Next.js API-route config+handler-signature boilerplate. The shared span stays under jscpd's 50-token minimum (.jscpd.json minTokens) — not a defect, not flagged." },

  // --- M5 dead code (knip) POSITIVES ---
  { module: "M5", id: "M5-P-DEAD-EXPORT", kind: "positive", cls: "Unused named export", location: "dead/orphan.ts", match: ["unusedhelper"], expectedTier: "high", note: "dead/orphan.ts exports unusedHelper(), imported nowhere (dead/consumer.ts only uses computeTotal). knip issues[].exports; knipToFindings -> M5-*." },
  { module: "M5", id: "M5-P-DEAD-FILE", kind: "positive", cls: "Unreferenced file", location: "dead/never-imported.ts", match: ["dead code"], expectedTier: "high", note: "dead/never-imported.ts is never imported by any entry point. knip top-level files[]; knipToFindings -> M5-* (measured line count)." },

  // --- M5 dead code NEGATIVES ---
  { module: "M5", id: "M5-N-NEXT-MAGIC", kind: "negative", cls: "Next.js framework-magic exports", location: "pages/dead-page.js", note: "pages/dead-page.js's default export + getServerSideProps are called by Next.js routing/build convention, never by import. knip's built-in Next.js plugin (auto-detected via the target's `next` dependency) treats pages/**/*.{js,jsx,ts,tsx} as entry points — not flagged." },
  { module: "M5", id: "M5-N-DYNAMIC-REF", kind: "negative", cls: "String-lookup dynamic export", location: "dead/registry.ts", note: "dead/registry.ts's handlerA is referenced only via dead/dispatch.ts's handlers[name] runtime lookup, invisible to static analysis. Tagged @lintignore; knip.json's tags:[\"-lintignore\"] silences it — not flagged." },
  { module: "M5", id: "M5-N-PUBLIC-API", kind: "negative", cls: "Package public-API entry point", location: "dead/index.ts", note: "dead/index.ts is the package's declared public entry (package.json exports['.']) for external consumers. targets/calibration/knip.json lists it under entry, so the file and its export stay silent instead of a false dead-file/dead-export report." },
];
