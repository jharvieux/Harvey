// FREE (mechanical, source-only) tier recall against the five INDEPENDENT answer keys (#1185).
//
// The sibling of semantic-corpus.ts. That module scores the paid semantic pass against keys other
// people wrote; this one scores the FREE mechanical tier against the SAME keys, so the two tiers
// are comparable and the free number stops being a doc line nobody can re-run. Before #1185 the
// only free-tier figures for these targets lived in docs/design/free-tier-recall-measurement.md §2
// marked `recorded — not re-run here`, dated 2026-07-18 and pre-dating the Vite/App-Router coverage
// campaigns — which is exactly the "a recorded number is a claim about the past" shape CLAUDE.md
// warns about. The CLI is cli/validate-free-recall.ts.
//
// WHAT THIS SCORES AND HOW IT DIFFERS FROM THE RECORDED NUMBERS
//   - The recorded per-target numbers in the measurement docs were HAND-scored by a human reading
//     each raw finding against the planted bug. This module scores by location + keyword, the same
//     generous matcher semantic-corpus.ts uses. The two are NOT the same instrument, so a delta
//     against `recordedMechanical` is evidence that something moved, never by itself proof that a
//     campaign raised recall. `recordedMechanical` is carried as a labelled baseline, not a target.
//   - Every entry is scored at TWO tiers, because a blended "caught" number is the one thing the
//     free tier must not report: HIGH (`precisionTier: "high"` — what the free scan actually counts
//     and grades) and ANY (high or review — surfaced to the reader as a lower-confidence indicator).
//     free-tier-scope.md sells indicators, not verdicts, so both numbers are real and they are very
//     different numbers.
//   - Negatives are scored too. A planted non-vulnerability reported at HIGH tier is a free-count
//     false positive — the failure mode that costs a free scan its credibility.

import type { Finding } from "../findings.js";
import { matchesSemanticEntry, SEMANTIC_CORPUS, type SemanticEntry } from "./semantic-corpus.js";

export interface FreeRecallTarget {
  slug: string;
  repo: string; // owner/name on GitHub
  ref: string; // the branch the answer key describes
  scope?: string; // subdirectory the key covers, when it covers only part of the repo
  source: string; // the measurement doc the key and the recorded baseline were transcribed from
  recordedMechanicalOn: string; // the date that doc recorded its mechanical tally
  // The free/source-only mechanical catch count that doc recorded, HAND-scored. A labelled claim
  // about the past — see the header note on why a delta against it is not self-evidently a gain.
  recordedMechanical: number;
  // The positive denominator in force when recordedMechanical was measured. Answer-key audits may
  // later change the live entries; retaining the original denominator prevents a historical 11/12
  // claim from being relabelled as 11/9 without a new mechanical measurement.
  recordedMechanicalTotal: number;
  entries: SemanticEntry[];
}

// vandyand is the one target with no semantic-corpus key: its measurement doc records the semantic
// tier only as "carried the union to 6/8+", which is not a scoreable tally, so semantic-corpus.ts
// correctly omits it. The MECHANICAL column is precise there (4/8 outright, +1 indicator, +1
// partial), so the free-tier gate can score it. Key transcribed from the doc's 8-row answer table.
//
// The match keys name the MECHANISM, per the semantic-corpus convention: a right-file/wrong-mechanism
// finding is what the doc calls a "partial" and it must not score as a catch. VD-5 is the live
// example — the doc records `Unauthenticated debug/admin route` firing on the exact file by a
// filename heuristic while the real bug is a missing `role` check, and the keys below keep that a
// miss rather than laundering it into the recall number.
const vandyand: FreeRecallTarget = {
  slug: "vandyand",
  repo: "vandyand/saas-security-teardown",
  ref: "main",
  source: "docs/design/vandyand-recall-measurement.md",
  recordedMechanicalOn: "2026-07-18",
  recordedMechanical: 4,
  recordedMechanicalTotal: 8,
  entries: [
    { id: "VD-1", kind: "positive", cls: "RLS never enabled on orgs (anon enumerates tenants)", locations: ["supabase/migrations"], match: ["orgs"], note: "" },
    { id: "VD-2", kind: "positive", cls: "line_items has no policy (side-door child-table leak)", locations: ["supabase/migrations"], match: ["line_items"], note: "" },
    { id: "VD-3", kind: "positive", cls: "profiles policy is using (true) — cross-tenant read", locations: ["supabase/migrations"], match: ["profiles"], note: "Recorded as a static INDICATOR, proven by M2 dynamic — so the any-tier column is where it should land, not the high-tier one." },
    { id: "VD-4", kind: "positive", cls: "service-role key shipped to the browser", locations: [".env.example", "lib/supabase/admin-browser.ts", "components/StatsWidget.tsx", "app/security/page.tsx"], match: ["service_role", "service-role", "service role"], note: "" },
    { id: "VD-5", kind: "positive", cls: "admin API has no server-side role check (broken function-level authz)", locations: ["app/api/admin/revenue/route.ts"], match: ["role check", "function-level", "bfla", "authorization"], note: "The doc's PARTIAL: right file, wrong mechanism. Keys name the mechanism so the filename heuristic cannot score it. Gap filed as #561." },
    { id: "VD-6", kind: "positive", cls: "server trusts client input on profile write (mass assignment)", locations: ["app/api/profile/route.ts"], match: ["mass assignment", "mass-assignment", "over-post", "overposting", "whitelist"], note: "Recorded as M2-dynamic-only; M1's harvey-route-noauth lands on the file on a FALSE premise, which is not this bug." },
    { id: "VD-7", kind: "positive", cls: "storage bucket created public by the seed script", locations: ["scripts/seed.mjs"], match: ["bucket"], note: "The doc's clean MISS — checkPublicBucketsWithNoPolicies is the connected/live tier and nothing models createBucket({public:true}) statically. Gap filed as #560." },
    { id: "VD-8", kind: "positive", cls: "PII over-exposure via select('*') in an API response", locations: ["app/api/team/route.ts"], match: ["select-star", "select(\"*\")", "select('*')", "excessive data", "pii"], note: "" },
  ],
};

// The four keys the semantic gate already carries, re-used verbatim so the free and paid columns
// are scored against the same rows. Their recorded MECHANICAL baselines come from
// free-tier-recall-measurement.md §2, which is a different column of the same measurement docs.
const MECHANICAL_BASELINES: Record<string, { recordedMechanical: number; recordedMechanicalTotal: number; recordedMechanicalOn: string }> = {
  supatest: { recordedMechanical: 0, recordedMechanicalTotal: 9, recordedMechanicalOn: "2026-07-18" },
  "nocode-rescue": { recordedMechanical: 3, recordedMechanicalTotal: 8, recordedMechanicalOn: "2026-07-18" },
  cipherx: { recordedMechanical: 7, recordedMechanicalTotal: 20, recordedMechanicalOn: "2026-07-18" },
  superredhat: { recordedMechanical: 11, recordedMechanicalTotal: 12, recordedMechanicalOn: "2026-07-18" },
};

export const FREE_RECALL_CORPUS: FreeRecallTarget[] = [
  ...SEMANTIC_CORPUS.map((t): FreeRecallTarget => {
    const baseline = MECHANICAL_BASELINES[t.slug];
    if (!baseline) {
      // Fail loud at module load rather than silently dropping a target from the denominator: a
      // semantic target with no recorded mechanical baseline leaves the free gate nothing to score.
      throw new Error(
        `free-recall corpus: semantic target "${t.slug}" has no recorded mechanical baseline in MECHANICAL_BASELINES. ` +
          `Add one from ${t.source} (the mechanical column) or the free tier silently loses a target.`,
      );
    }
    return { slug: t.slug, repo: t.repo, ref: t.ref, scope: t.scope, source: t.source, ...baseline, entries: t.entries };
  }),
  vandyand,
];

export interface FreeRecallRow {
  id: string;
  kind: SemanticEntry["kind"];
  cls: string;
  // The best tier any matching finding reached. "none" means nothing matched at all.
  tier: "high" | "review" | "none";
  matched: number;
  taxonomies: string[];
  detail: string;
}

export interface FreeRecallResult {
  slug: string;
  repo: string;
  scored: boolean;
  // Set ONLY when scored === false. Never replaced by a zero — an unscanned target and a scanned
  // target that caught nothing are the same number and must not be the same row (CLAUDE.md: "a
  // fixture the scanner never read reports zero findings, exactly like one it scanned and missed").
  reason?: string;
  rows: FreeRecallRow[];
  findingsScanned: number;
  positivesTotal: number;
  caughtHigh: number; // free-count tier — what the free scan grades
  caughtAnyTier: number; // high OR review — what the free scan surfaces as an indicator
  negativesTotal: number;
  negativesCleared: number; // no HIGH-tier match; a review-tier touch is recorded, not counted as an FP
  negativesFalsePositiveHigh: string[]; // entry ids a free-count finding landed on
  recordedMechanical: number;
  recordedMechanicalTotal: number;
  recordedMechanicalOn: string;
  source: string;
  // Findings satisfying more than one entry. Location+keyword matching is generous, so this says
  // how much of the recall rests on one broad finding covering two planted bugs.
  sharedFindings: number;
}

export function scoreFreeRecall(target: FreeRecallTarget, findings: Finding[]): FreeRecallResult {
  const hits = new Map<Finding, number>();
  const rows: FreeRecallRow[] = target.entries.map((entry) => {
    const relevant = findings.filter((f) => matchesSemanticEntry(entry, f));
    for (const f of relevant) hits.set(f, (hits.get(f) ?? 0) + 1);
    const tier: FreeRecallRow["tier"] = relevant.some((f) => f.precisionTier === "high")
      ? "high"
      : relevant.some((f) => f.precisionTier === "review")
        ? "review"
        : "none";
    const taxonomies = [...new Set(relevant.map((f) => f.taxonomy))];
    const detail =
      entry.kind === "positive"
        ? tier === "high"
          ? `caught at the free-count tier (${relevant.length} finding(s))`
          : tier === "review"
            ? `surfaced as a review-tier indicator only — not in the free count`
            : "NOT surfaced by the mechanical tier at any confidence"
        : tier === "high"
          ? `FREE-COUNT FALSE POSITIVE — ${relevant.length} graded finding(s) on a recorded non-vulnerability`
          : tier === "review"
            ? "cleared from the count (review-tier touch only)"
            : "cleared — not reported";
    return { id: entry.id, kind: entry.kind, cls: entry.cls, tier, matched: relevant.length, taxonomies, detail };
  });

  const pos = rows.filter((r) => r.kind === "positive");
  const neg = rows.filter((r) => r.kind === "negative");
  return {
    slug: target.slug,
    repo: target.repo,
    scored: true,
    rows,
    findingsScanned: findings.length,
    positivesTotal: pos.length,
    caughtHigh: pos.filter((r) => r.tier === "high").length,
    caughtAnyTier: pos.filter((r) => r.tier !== "none").length,
    negativesTotal: neg.length,
    negativesCleared: neg.filter((r) => r.tier !== "high").length,
    negativesFalsePositiveHigh: neg.filter((r) => r.tier === "high").map((r) => r.id),
    recordedMechanical: target.recordedMechanical,
    recordedMechanicalTotal: target.recordedMechanicalTotal,
    recordedMechanicalOn: target.recordedMechanicalOn,
    source: target.source,
    sharedFindings: [...hits.values()].filter((n) => n > 1).length,
  };
}

export function unscoredFreeTarget(target: FreeRecallTarget, reason: string): FreeRecallResult {
  const pos = target.entries.filter((e) => e.kind === "positive").length;
  return {
    slug: target.slug,
    repo: target.repo,
    scored: false,
    reason,
    rows: [],
    findingsScanned: 0,
    positivesTotal: pos,
    caughtHigh: 0,
    caughtAnyTier: 0,
    negativesTotal: target.entries.length - pos,
    negativesCleared: 0,
    negativesFalsePositiveHigh: [],
    recordedMechanical: target.recordedMechanical,
    recordedMechanicalTotal: target.recordedMechanicalTotal,
    recordedMechanicalOn: target.recordedMechanicalOn,
    source: target.source,
    sharedFindings: 0,
  };
}

interface FreeRecallMatrix {
  targets: FreeRecallResult[];
  scoredTargets: number;
  unscoredTargets: number;
  positivesTotal: number; // over SCORED targets only — the denominator of a number we measured
  caughtHigh: number;
  caughtAnyTier: number;
  negativesTotal: number;
  negativesCleared: number;
  ok: boolean;
}

// The verdict. This is a MEASUREMENT, not a regression gate: a low free-tier recall is the finding,
// not a failure (free-tier-recall-measurement.md §2 exists to say so). It fails on the two things
// that would make the printed number a lie — a free-count false positive on a recorded
// non-vulnerability, and NOTHING SCORED, because an unrun measurement must never exit 0 and read as
// a clean result.
export function summarizeFreeRecall(targets: FreeRecallResult[]): FreeRecallMatrix {
  const scored = targets.filter((t) => t.scored);
  const sum = (pick: (t: FreeRecallResult) => number) => scored.reduce((n, t) => n + pick(t), 0);
  const negativesTotal = sum((t) => t.negativesTotal);
  const negativesCleared = sum((t) => t.negativesCleared);
  return {
    targets,
    scoredTargets: scored.length,
    unscoredTargets: targets.length - scored.length,
    positivesTotal: sum((t) => t.positivesTotal),
    caughtHigh: sum((t) => t.caughtHigh),
    caughtAnyTier: sum((t) => t.caughtAnyTier),
    negativesTotal,
    negativesCleared,
    ok: scored.length > 0 && negativesCleared === negativesTotal,
  };
}
