// Calibration validation gate (issue #61). Encodes the corpus answer key — every planted
// POSITIVE that must be caught and every benign NEGATIVE that must NOT be flagged in the free
// count — as data, then scores a Finding[] against it into a coverage matrix (positive recall +
// negative precision per rule/class). The mechanical layer earns the "free count" claim only
// when every high-tier rule fires on its positive and stays silent on its negative lookalike
// (docs/design/mechanical-toolchain.md §7; targets/calibration/GROUND-TRUTH.md).
//
// Two consumers:
//   - src/scan/calibration.test.ts — UNIT tests against RECORDED scanner output (no binaries),
//     so `pnpm verify` proves the scorecard logic in binary-less CI.
//   - src/cli/validate-calibration.ts — LIVE run (`pnpm validate:calibration`) that scans the
//     real targets/calibration with the installed binaries.

import { detectionMetrics, type DetectionMetrics } from "./detection-metrics.js";
import { validateRecordedReason, type ParsedReason } from "../recorded-reasons.js";
import type { Cadence } from "../scored-gates.js";
import type { Finding, PrecisionTier, Severity } from "../findings.js";
import { baseEntries } from "./calibration/base.entries.js";
import { b2DepsEntries } from "./calibration/b2-deps.entries.js";
import { b3InjectionEntries } from "./calibration/b3-injection.entries.js";
import { b4XssEntries } from "./calibration/b4-xss.entries.js";
import { b5HeadersEntries } from "./calibration/b5-headers.entries.js";
import { b6CryptoEntries } from "./calibration/b6-crypto.entries.js";
import { b7AuthEntries } from "./calibration/b7-auth.entries.js";
import { b8SupaEntries } from "./calibration/b8-supa.entries.js";
import { b9SecretsEntries } from "./calibration/b9-secrets.entries.js";
import { b10DepsEntries } from "./calibration/b10-deps.entries.js";
import { b11CryptoEntries } from "./calibration/b11-crypto.entries.js";
import { b12NextconfigEntries } from "./calibration/b12-nextconfig.entries.js";
import { b13SupaEntries } from "./calibration/b13-supa.entries.js";
import { b14AppLogicEntries } from "./calibration/b14-applogic.entries.js";
import { b15NextjsAuthzEntries } from "./calibration/b15-nextjs-authz.entries.js";
import { b16StorageSecdefEntries } from "./calibration/b16-storage-secdef.entries.js";
import { b17RaceUnscopedEntries } from "./calibration/b17-race-unscoped.entries.js";
import { b18JobTenantScopeEntries } from "./calibration/b18-job-tenant-scope.entries.js";
import { b19PrismaTenantScopeEntries } from "./calibration/b19-prisma-tenant-scope.entries.js";
import { b20DrizzleTenantScopeEntries } from "./calibration/b20-drizzle-tenant-scope.entries.js";
import { b21SilentFailureEntries } from "./calibration/b21-silent-failure.entries.js";
import { b22GhaPermissionsEntries } from "./calibration/b22-gha-permissions.entries.js";
import { b23D091GapEntries } from "./calibration/b23-d091-gaps.entries.js";
import { b24ConnectedPostgrestRealtimeEntries } from "./calibration/b24-connected-postgrest-realtime.entries.js";
import { b25DepProvenanceEntries } from "./calibration/b25-dep-provenance.entries.js";
import { knownPublicCredsEntries } from "./calibration/known-public-creds.entries.js";
import { owaspMultiTenantEntries } from "./calibration/owasp-multitenant.entries.js";
import { owaspNodejsEntries } from "./calibration/owasp-nodejs.entries.js";
import { owaspReactEntries } from "./calibration/owasp-react.entries.js";
import { rlsStaticSemanticsEntries } from "./calibration/rls-static-semantics.entries.js";
import { m3Entries } from "./calibration/m3.entries.js";
import { m6HandrolledEntries } from "./calibration/m6-handrolled.entries.js";
import { m7Entries } from "./calibration/m7.entries.js";
import { m7InitplanStaticEntries } from "./calibration/m7-initplan-static.entries.js";
import { m8Entries } from "./calibration/m8.entries.js";
import { m9AuthzEntries } from "./calibration/m9-authz.entries.js";
import { m9CheckEntries } from "./calibration/m9-checks.entries.js";
import { m9PortEntries } from "./calibration/m9-ports.entries.js";
import { m10Entries } from "./calibration/m10.entries.js";
import { m4m5Entries } from "./calibration/m4-m5.entries.js";
import { secretsEntries } from "./calibration/secrets.entries.js";
import type { CorpusEntry, LiveTier } from "./calibration/types.js";

export type { CorpusEntry, LiveTier } from "./calibration/types.js";

// Answer key, assembled from per-batch entry modules under ./calibration/. CONVENTION: each
// corpus batch (#71/#72 fan-out) adds a `<batch>.entries.ts` file exporting a CorpusEntry[] and
// one spread below — this keeps parallel batches conflict-free (a new batch touches only its own
// file plus this single line). Positives extend GROUND-TRUTH.md's planted bugs; negatives are
// the benign lookalikes from the FP catalog (briefs/fp-rules.txt).
export const CORPUS: CorpusEntry[] = [
  ...baseEntries,
  ...secretsEntries,
  ...b2DepsEntries,
  ...b3InjectionEntries,
  ...b4XssEntries,
  ...b5HeadersEntries,
  ...b6CryptoEntries,
  ...b7AuthEntries,
  ...b8SupaEntries,
  ...b9SecretsEntries,
  ...b10DepsEntries,
  ...b11CryptoEntries,
  ...b12NextconfigEntries,
  ...b13SupaEntries,
  ...b14AppLogicEntries,
  ...b15NextjsAuthzEntries,
  ...b16StorageSecdefEntries,
  ...b17RaceUnscopedEntries,
  ...b18JobTenantScopeEntries,
  ...b19PrismaTenantScopeEntries,
  ...b20DrizzleTenantScopeEntries,
  ...b21SilentFailureEntries,
  ...b22GhaPermissionsEntries,
  ...b23D091GapEntries,
  ...b24ConnectedPostgrestRealtimeEntries,
  ...b25DepProvenanceEntries,
  ...knownPublicCredsEntries,
  ...owaspMultiTenantEntries,
  ...owaspNodejsEntries,
  ...owaspReactEntries,
  ...rlsStaticSemanticsEntries,
  ...m9AuthzEntries,
  ...m9CheckEntries,
  ...m9PortEntries,
  ...m10Entries,
  ...m4m5Entries,
  ...m8Entries,
  ...m7Entries,
  ...m7InitplanStaticEntries,
  ...m3Entries,
  ...m6HandrolledEntries,
];

// `location` may be an absolute path rooted in the environment-dependent checkout (e.g. a tool
// invoked against an absolute target dir), so it can carry arbitrary text — like a worktree
// directory name — that has nothing to do with the finding. Strip that prefix before the location
// enters the keyword-matching haystack, so a corpus `match` keyword can't spuriously match the
// checkout path instead of the finding (issue #86).
function normalizeLocation(location: string): string {
  const cwdPrefix = `${process.cwd()}/`;
  if (location.startsWith(cwdPrefix)) return location.slice(cwdPrefix.length);
  const anchorIndex = location.lastIndexOf("targets/");
  const atSegmentStart = anchorIndex === 0 || location[anchorIndex - 1] === "/" || location[anchorIndex - 1] === "\\";
  return anchorIndex !== -1 && atSegmentStart ? location.slice(anchorIndex) : location;
}

function haystack(f: Finding): string {
  return `${f.id} ${f.title} ${f.taxonomy} ${f.evidence} ${normalizeLocation(f.location)}`.toLowerCase();
}

// Dependency findings label their location "<manifestPath> (<pkg>)" — see checkNextVersionCVEs.
// Pull the manifest segment back out so an entry can be pinned to one manifest.
function manifestOf(location: string): string | undefined {
  const m = /^(.*?)\s*\([^()]*\)\s*$/.exec(normalizeLocation(location));
  return m?.[1]?.toLowerCase();
}

// A finding is relevant to an entry when its location contains the entry's location substring
// and (if the entry lists keywords) at least one keyword appears anywhere in the finding text.
// An entry that declares a `manifest` additionally requires an EXACT manifest match, so a bare
// package name can't cross-match another fixture's manifest (#253).
function relevantFindings(entry: CorpusEntry, findings: Finding[]): Finding[] {
  const loc = entry.location.toLowerCase();
  const keys = entry.match?.map((m) => m.toLowerCase());
  const manifest = entry.manifest?.toLowerCase();
  return findings.filter((f) => {
    if (!f.location.toLowerCase().includes(loc)) return false;
    if (manifest !== undefined && manifestOf(f.location) !== manifest) return false;
    if (!keys) return true;
    const hay = haystack(f);
    return keys.some((k) => hay.includes(k));
  });
}

// #1355: a `match` keyword that is a substring of the entry's OWN location is vacuous. Every
// finding that survives the location filter carries that location in the haystack (directly, and
// again inside the path-derived ids the AST detectors mint), so such a key is satisfied by ANY
// finding on the fixture — including one for an entirely different defect. On a POSITIVE that is
// the #1062 masking shape: the detection the row exists to score can go silent while the row stays
// green (MEASURED on P-OWASP-MT-CLIENT-TENANT, whose `["tenant"]` key on client-supplied-tenant.ts
// scored an unrelated XSS finding as a full pass). MEASURED 2026-07-28 over the whole corpus: 59
// such keys on 58 entries, 39 of them positives.
//
// Both shapes are reported: the raw location, and the location with every non-alphanumeric run
// collapsed to "-", which is how a detector-minted id embeds the path (e.g.
// AUTH-client-supplied-tenant-tenantId-src-owasp-mt-client-supplied-tenant-ts-2).
//
// On a NEGATIVE the vacuity runs the safe way — a wider relevant set can only make the row fail —
// but the key is still a lie about what the entry discriminates, and the honest spelling is no
// `match` at all. Both kinds are reported so the corpus stays free of the shape.
interface SelfMatchingKeyRow {
  id: string;
  kind: CorpusEntry["kind"];
  location: string;
  keys: string[];
}

export function selfMatchingMatchKeys(corpus: CorpusEntry[] = CORPUS): SelfMatchingKeyRow[] {
  const rows: SelfMatchingKeyRow[] = [];
  for (const e of corpus) {
    if (!e.match) continue;
    const raw = e.location.toLowerCase();
    const hyphenated = raw.replace(/[^a-z0-9]+/g, "-");
    const keys = e.match.filter((k) => raw.includes(k.toLowerCase()) || hyphenated.includes(k.toLowerCase()));
    if (keys.length) rows.push({ id: e.id, kind: e.kind, location: e.location, keys });
  }
  return rows;
}

export function formatSelfMatchingKeys(rows: SelfMatchingKeyRow[]): string {
  return rows
    .map(
      (r) =>
        `${r.id} (${r.kind}) — key(s) ${r.keys.map((k) => JSON.stringify(k)).join(", ")} are a substring of its own location "${r.location}", ` +
        `so every finding on that fixture satisfies the entry. ` +
        (r.kind === "positive"
          ? "Re-scope the key to vocabulary from the taxonomy/message of the finding this row exists to score."
          : "Delete the `match` list — for a negative the entry already means 'any finding here is a false positive'."),
    )
    .join("\n");
}

function topTier(findings: Finding[]): PrecisionTier | undefined {
  if (findings.some((f) => f.precisionTier === "high")) return "high";
  if (findings.some((f) => f.precisionTier === "review")) return "review";
  return undefined;
}

// A mechanical finding reaching the corpus scorer MUST declare its precisionTier. An untiered
// finding scores as "no tier" in BOTH directions silently: a detector true-positive registers as
// an outright MISS, and a negative's untiered false-positive is indistinguishable from a clean
// clear (it never counts against precision). Detectors set an explicit conservative default, but
// a finding that still arrives untiered is a bug in whatever produced it — fail loud here rather
// than let it corrupt the numbers unseen (#327).
function assertTiered(entry: CorpusEntry, relevant: Finding[]): void {
  const untiered = relevant.filter((f) => f.precisionTier === undefined);
  if (untiered.length === 0) return;
  throw new Error(
    `Corpus entry ${entry.id} matched ${untiered.length} finding(s) with no precisionTier ` +
      `(${untiered.map((f) => `${f.id} @ ${f.location}`).join(", ")}). A mechanical finding reaching ` +
      `the calibration scorer must set precisionTier — an untiered finding silently mis-scores. ` +
      `Set it on the detector that produced it.`,
  );
}

export interface MatrixRow {
  id: string;
  kind: CorpusEntry["kind"];
  cls: string;
  expectedTier?: CorpusEntry["expectedTier"];
  caughtTier?: PrecisionTier; // best tier a relevant finding landed at (positives)
  highFlagged: boolean; // a relevant finding at HIGH (free-count) tier exists
  reviewFlagged: boolean; // a relevant finding at review tier exists
  pass: boolean;
  detail: string;
  // #1157: severity-correctness scoring. `expectedSeverity` echoes the entry's answer key;
  // `deliveredSeverities` is the distinct set the caught findings actually carried; `severityMismatch`
  // is true only for a CAUGHT positive whose expectedSeverity is set and NO relevant finding delivered
  // it. A miss never sets it (the miss already fails); a negative/live/none row never does.
  expectedSeverity?: CorpusEntry["expectedSeverity"];
  deliveredSeverities?: Severity[];
  severityMismatch: boolean;
  // #1428: this row was NOT scored — its live venue was not available on this run. `pass: true` on
  // such a row is bookkeeping, not evidence, and a consumer blind to the difference is how
  // three gutted detectors produced a byte-identical GATE PASS. Anything that reports a pass rate
  // must report this count beside it.
  notScored: boolean;
}

// The two venues a corpus row can need a running stack for. See LiveTier in calibration/types.ts
// for what each one can answer.
export const LIVE_TIERS: readonly LiveTier[] = ["local", "connected", "hosted"];

export function isLiveTier(tier: CorpusEntry["expectedTier"]): tier is LiveTier {
  return tier === "local" || tier === "connected" || tier === "hosted";
}

const NO_LIVE_VENUE: ReadonlySet<LiveTier> = new Set();

/** What a run must have to score a row of each live tier — printed in the NOT SCORED detail. */
const LIVE_VENUE_NEEDS: Record<LiveTier, string> = {
  local: "a Postgres connection to a `supabase start` stack",
  connected: "the project's own REST/GraphQL surface",
  hosted: "a hosted project and a Management API token",
};

// Scoring:
//   positive (static): pass = caught at any tier.
//   negative: pass = NO high-tier (free-count) finding is relevant. A review-tier hit is tolerated
//             (it gets triaged out of the count) but recorded.
//   live tier ("local"/"connected"): scored EXACTLY like the above when `scoredVenues` says this run
//             has that venue — the whole point of #1428. Otherwise the row is NOT SCORED: still
//             `pass: true` so an offline gate's arithmetic is unchanged, but flagged `notScored` so
//             no caller can read it as a result.
export function scoreEntry(entry: CorpusEntry, findings: Finding[], scoredVenues: ReadonlySet<LiveTier> = NO_LIVE_VENUE): MatrixRow {
  const relevant = relevantFindings(entry, findings);
  assertTiered(entry, relevant);
  const highFlagged = relevant.some((f) => f.precisionTier === "high");
  const reviewFlagged = relevant.some((f) => f.precisionTier === "review");
  const caughtTier = topTier(relevant);
  // A caught-and-clean severity default for every non-scored path; the positive branch overrides it.
  const noSev = { expectedSeverity: entry.expectedSeverity, severityMismatch: false, notScored: false };

  if (isLiveTier(entry.expectedTier) && !scoredVenues.has(entry.expectedTier)) {
    const detail = `NOT SCORED — needs the "${entry.expectedTier}" live venue (${LIVE_VENUE_NEEDS[entry.expectedTier]}), which this run does not have. Scored by \`pnpm validate:connected\`, never by a static run.`;
    return { id: entry.id, kind: entry.kind, cls: entry.cls, expectedTier: entry.expectedTier, caughtTier, highFlagged, reviewFlagged, pass: true, detail, ...noSev, notScored: true };
  }

  // "none": no mechanical rule by design (a measured LLM-tier class). The intended gap holds only
  // while NOTHING of the class fires; a relevant finding means a rule graduated, so it flips loud
  // (pass=false) rather than letting a by-design gap silently become a claimed catch (#425).
  if (entry.expectedTier === "none") {
    const held = relevant.length === 0;
    const measured = entry.gapKind === "measured-gap";
    const detail = held
      ? measured
        ? "MEASURED GAP — planted, scanned, nothing fired; outstanding work, not a boundary (see entry note for the tracking issue)"
        : "intended gap — no mechanical rule by design (measured LLM-tier); nothing fired"
      : `REGRESSION: a mechanical rule now reaches this ${measured ? "recorded gap — close the entry out and re-tier it" : "by-design gap — re-tier this entry"}. Fired: ${relevant.map((f) => f.taxonomy).join(", ")}`;
    return { id: entry.id, kind: entry.kind, cls: entry.cls, expectedTier: entry.expectedTier, caughtTier, highFlagged, reviewFlagged, pass: held, detail, ...noSev };
  }

  if (entry.kind === "positive") {
    const pass = caughtTier !== undefined;
    // #1157: a caught positive with an answer-keyed severity must DELIVER that severity. Scored only
    // when caught — a miss already fails on the tier. `some(===)` not "all", because an entry may
    // legitimately match a sibling finding of another severity; the assertion is that the expected
    // rating is present, which is exactly the #1063 "everything defaulted to Medium" failure mode.
    const deliveredSeverities = [...new Set(relevant.map((f) => f.severity))];
    const severityMismatch = pass && entry.expectedSeverity !== undefined && !relevant.some((f) => f.severity === entry.expectedSeverity);
    const sevDetail = entry.expectedSeverity === undefined ? "" : severityMismatch ? ` — SEVERITY MISRATED: expected ${entry.expectedSeverity}, delivered ${deliveredSeverities.join("/") || "none"}` : ` [severity ${entry.expectedSeverity} ✓]`;
    const detail = pass
      ? `caught at ${caughtTier}${entry.expectedTier && entry.expectedTier !== caughtTier ? ` (expected ${entry.expectedTier})` : ""}${sevDetail}`
      : "NOT caught by any rule";
    return { id: entry.id, kind: entry.kind, cls: entry.cls, expectedTier: entry.expectedTier, caughtTier, highFlagged, reviewFlagged, pass, detail, expectedSeverity: entry.expectedSeverity, deliveredSeverities, severityMismatch, notScored: false };
  }

  // negative. #1344: `!highFlagged` alone let a widened rule light up a planted negative at review
  // tier while every gate stayed green (#1251). The free count still decides FALSE POSITIVE; a
  // review-tier taxonomy the entry has not recorded now decides REGRESSION.
  const accepted = new Set(entry.reviewTierHits ?? []);
  const unexpectedReview = [...new Set(relevant.filter((f) => f.precisionTier === "review" && !accepted.has(f.taxonomy)).map((f) => f.taxonomy))];
  const pass = !highFlagged && unexpectedReview.length === 0;
  const detail = highFlagged
    ? "FALSE POSITIVE in the free count"
    : unexpectedReview.length > 0
      ? `REVIEW-TIER REGRESSION: a rule newly fires on this benign fixture — ${unexpectedReview.join(", ")}. Narrow the rule, or record the taxonomy in this entry's reviewTierHits with the reason it is acceptable noise.`
      : reviewFlagged
        ? `cleared from the count (recorded review-tier hit only, triaged out: ${[...new Set(relevant.filter((f) => f.precisionTier === "review").map((f) => f.taxonomy))].join(", ")})`
        : "cleared — not flagged";
  return { id: entry.id, kind: entry.kind, cls: entry.cls, expectedTier: entry.expectedTier, caughtTier, highFlagged, reviewFlagged, pass, detail, ...noSev };
}

export interface CoverageMatrix {
  rows: MatrixRow[];
  positivesTotal: number; // static positives that MUST be caught (excludes the live AND none tiers)
  positivesCaught: number;
  positivesCaughtHigh: number;
  negativesTotal: number; // static negatives (excludes the live tiers)
  negativesCleared: number;
  // #1428: rows this run did not score because it had no live venue for them. Reported beside the
  // pass rate, never folded into it — the count IS the disclosure.
  liveNotScored: number;
  noRuleTotal: number; // positives with no mechanical rule by design ("none" tier)
  noRuleHeld: number; // ...of those, the intended gap still holds (nothing of the class fired)
  // #881: the same two counts in the OWASP-Benchmark vocabulary. Scored on the basis this gate
  // already enforces — a positive is a TP when some rule caught it, a negative is an FP when a
  // FREE-COUNT (high-tier) finding lands on it — so the metrics and the pass/fail verdict can
  // never disagree. This is the M1 MECHANICAL corpus's number and nothing else's (#341).
  metrics: DetectionMetrics;
  ok: boolean; // every static positive caught, every negative cleared, every no-rule gap still held
}

// A module whose entries omit `module` is the original M1 mechanical-scan corpus (base+secrets+
// b2–b16+…). Everything else carries an explicit M3/M4/M5/M7/M8/M9/M10 label.
function moduleOf(entry: CorpusEntry): string {
  return entry.module ?? "M1";
}

interface ModuleCensusRow {
  module: string;
  positivesStatic: number; // static positives (excludes the live tiers)
  positivesConnected: number; // live-tier positives (local/connected — scored by validate-connected)
  negatives: number;
}

// The ten modules the deliverable is sold on. The census is seeded from this list, not from what
// the corpus happens to contain (#1314): a module with zero entries used to emit no row at all, so
// the parity minimum computed over the census could not see it — M2 and M6 had zero fixtures each
// while the gate printed "all modules meet it". An absent row never appears in a tally.
export const AUDIT_MODULES = ["M1", "M2", "M3", "M4", "M5", "M6", "M7", "M8", "M9", "M10"] as const;

// Per-module fixture census over the corpus, so a blended recall count can never imply uniform
// coverage: a module standing on 1 positive is visibly thin here rather than averaged into the
// M1-dominated total (#341). Purely counts the answer key — says nothing about what any gate runs.
export function moduleCensus(corpus: CorpusEntry[] = CORPUS): ModuleCensusRow[] {
  const rows = new Map<string, ModuleCensusRow>(
    AUDIT_MODULES.map((m) => [m, { module: m, positivesStatic: 0, positivesConnected: 0, negatives: 0 }]),
  );
  for (const e of corpus) {
    const m = moduleOf(e);
    const row = rows.get(m) ?? { module: m, positivesStatic: 0, positivesConnected: 0, negatives: 0 };
    if (e.kind === "negative") row.negatives++;
    else if (isLiveTier(e.expectedTier)) row.positivesConnected++;
    else row.positivesStatic++;
    rows.set(m, row);
  }
  const numOf = (m: string) => Number(m.replace(/^M/, "")) || 0;
  return [...rows.values()].sort((a, b) => numOf(a.module) - numOf(b.module));
}

// PARITY MINIMUM (#427, made exhaustive by #1314). Every module carries >= MIN_POSITIVES_PER_MODULE
// positive fixtures (static + connected) and >= MIN_NEGATIVES_PER_MODULE boundary negative.
// Rationale: a single positive fails only on a TOTAL outage (its module's recall drops to 0); two
// positives exercising DISTINCT rule surfaces let a PARTIAL regression — one shape breaks while
// another still fires — show up as a drop. 2 is the floor at which partial and total become
// distinguishable. This enforces the fixtures EXIST; the partial-regression detection itself lives
// in each module's own suite.
//
// #1314 also enforces the negative half. #427's comment claimed every module's positives were "each
// paired with >= 1 boundary negative" and only ever counted positives; the per-positive pairing it
// describes is not representable in the answer key, so what is ENFORCED is the per-module floor
// below — stated in the enforced form rather than the aspirational one.
export const MIN_POSITIVES_PER_MODULE = 2;
export const MIN_NEGATIVES_PER_MODULE = 1;

// A module may sit below the minimum only with a NAMED substitute gate — the "disclosed exemption"
// half of #1314.
//
// #1454 — AN EXEMPTION IS A RECORDED REASON, AND UNTIL NOW IT WAS THE ONLY KIND NOTHING GATED. The
// shape used to be `{ module, reason }`: a free-text sentence with no KIND, no PROVENANCE, no OWNER,
// no FALSIFIER. Every `REASON:` block in this repo is held to exactly those fields by
// `pnpm validate-reasons`; the one structure whose whole job is to CLOSE A COVERAGE QUESTION was
// held to none of them, and `validate-calibration` printed all three possible provenances — a
// measured fact, an operator ruling, and one executor's untested guess — as the same `EXEMPT M6:`
// line. The operator read a product decision they had never made off that line.
//
// The M6 row is why. Its stated ground, written the same day by the executor of #1314, held that
// M6's indicators are whole-repo shape counts a planted single-file fixture could not express
// — impossibility's vocabulary on an untested claim. MEASURED 2026-07-28 by running
// detectHandrolledFindings over ONE planted file carrying three hand-rolled shapes: 3 of 3 fire, at
// their own line numbers. The claim was false when written.
//
// THAT ROW IS GONE, and its deletion is the point rather than a tidy-up. #1454 re-expressed it as
// decisional — OWNER operator, DECISION #1371 — and wrote the hand-off into the row itself: "when
// its entries land, M6 stops being thin and this row must be deleted". #1453 landed them (33 of 33
// indicator classes scored, src/scan/calibration/m6-handrolled.entries.ts, run by
// src/scan/m6-indicator-corpus.ts), so M6 now stands on its own fixtures and the `stale` check
// below is what would have fired had the row stayed. M6's two substitute gates still exist and
// still run; they are simply no longer what the module stands on.
//
// So an exemption now carries the registry's own fields and is validated by the registry's own
// function (validateRecordedReason), which buys three things at once: an ASSUMED provenance can no
// longer wear impossibility's vocabulary (#1319), an empirical exemption must carry the command that
// would falsify it (#1033), and a decisional one must name the OWNER and the venue where the
// operator was actually asked (#1319's relay rule). `substituteGate` is the exemption-specific
// field: the gate standing in for the missing fixtures, whose path tokens must EXIST in the
// checkout — a renamed or deleted gate is otherwise indistinguishable from a live one.
//
// An exemption for a module that is NOT thin is itself a failure (the `stale` list) — a substitute gate
// that has been overtaken by real fixtures must not keep standing in for them.
/**
 * #1483 — one gate standing in for a module's missing fixtures. Naming it is not enough: a path that
 * EXISTS and a gate that RUNS are different claims, and re-validating M2 for #1454 found the two
 * apart. `pnpm exec tsx src/cli/pentest.ts --mode=coverage` works — it exits 1 naming a real
 * untested target and 0 when that target is listed — and appears in no workflow and no
 * package.json script, so nothing runs it unless a human remembers. That is the exact state #1288
 * found for the scored gates, one level over, and an exemption was free to cite it.
 *
 * So a substitute gate declares its `cadence` in the same checkable vocabulary #1288 built, and
 * `none` is a legitimate answer that must carry the issue tracking it — disclosed, never silent.
 */
export interface SubstituteGate {
  /** What it covers, in a reader's words. Every path token must exist in the checkout. */
  what: string;
  /** The token a venue has to invoke for this gate to have run — normally the CLI's own path. */
  invokes: string;
  cadence: Cadence;
}

export interface ParityExemption {
  module: string;
  /** The gate(s) covering this module instead of corpus fixtures. */
  substituteGates: readonly SubstituteGate[];
  /**
   * The registry's fields (#1033/#1072/#1319), validated by validateRecordedReason. Lowercase keys
   * deliberately: recorded-reasons.ts's own file walk reads `REASON:` at the start of any line as a
   * block opener, so uppercase keys here would make this interface and these literals parse as five
   * malformed reason blocks. They are mapped to the registry's keys in parityExemptionReasons.
   */
  reason: {
    claim: string;
    kind: "empirical" | "decisional";
    provenance: string;
    falsifier?: string;
    owner?: string;
    decision?: string;
  };
}

const PARITY_EXEMPTIONS: readonly ParityExemption[] = [
  {
    module: "M2",
    substituteGates: [
      {
        what: "`src/cli/pentest.ts --mode=coverage` reaches assertComplete (src/pentest/targets.ts) and fails loud on any enumerated target `--tested` did not list (#352)",
        invokes: "src/cli/pentest.ts",
        // MEASURED 2026-07-28: `grep -rn "mode=coverage" .github/workflows/ package.json` returns
        // nothing, and no workflow names pentest at all. The check works in both directions; it just
        // runs only when a human remembers. Wiring it into a venue is a supervised
        // .github/workflows/ edit, so it is DISCLOSED here and relayed on #1483 rather than done.
        cadence: { kind: "none", issue: 1483 },
      },
      {
        what: "the M2 conservation plant in src/audit-conservation.ts, asserted by src/cli/validate-conservation.ts (#1155)",
        invokes: "src/cli/validate-conservation.ts",
        cadence: { kind: "workflow", file: ".github/workflows/conservation.yml", job: "conservation", when: "every PR + daily schedule (a required status check since #1205)" },
      },
    ],
    reason: {
      claim:
        "M2's findings are produced only by HTTP probes against a running two-tenant stack, so the offline scan of a planted source tree emits no M2 finding for a CorpusEntry to score — the corpus scores findings against planted file locations, and M2 never produces one",
      kind: "empirical",
      // Re-measured for #1454 rather than inherited from the row this replaces. The falsifier's
      // bound is stated here because the registry has no field for it: it reads the COMMITTED
      // offline-scan artifact, so an offline M2 detector that targets/calibration plants no defect
      // for would not turn it green.
      provenance:
        "MEASURED 2026-07-28 — `grep -c '\"taxonomy\": \"M2' dry-run/findings.json` (the committed offline scan of targets/calibration) is 0; the substitute gate fires in BOTH directions: `tsx src/cli/pentest.ts --mode=coverage --repo targets/vuln-seam-app --tested bogus-id` exits 1 naming the real gap `app:root`, and `--tested app:root` exits 0; CALIBRATION_PLANTS carries the M2 row (src/audit-conservation.ts). The falsifier below was exercised in all three directions the same day: 1 as committed (blocker holds), 0 against a copy of the artifact carrying an M2 taxonomy (blocker gone), 127 when the artifact is absent — a bare `grep` exits 2 there, which would read as \"still blocked\"",
      falsifier: `test -f dry-run/findings.json || exit 127; grep -q '"taxonomy": "M2' dry-run/findings.json`,
    },
  },
];

// Mapped rather than written inline, for the same reason the keys above are lowercase: a literal
// `REASON:` at the start of a line in this file is read by recorded-reasons.ts's own walk as a
// malformed reason block. Keeping the uppercase names on the RIGHT of a lowercase key keeps them out
// of column zero. (`pnpm validate-reasons` catches a regression here loudly, which is how this was
// found — twice.)
const REGISTRY_KEY = { claim: "REASON", kind: "KIND", provenance: "PROVENANCE", falsifier: "FALSIFIER", owner: "OWNER", decision: "DECISION" } as const;

/**
 * An exemption rendered as the registry's own block shape, so it is held to `validateRecordedReason`
 * and re-tested by `validate-reasons --revalidate` exactly like a `REASON:` block in a source
 * comment. `line: 0` marks it as data rather than a text span — no comment line owns it.
 */
export function parityExemptionReasons(exemptions: readonly ParityExemption[] = PARITY_EXEMPTIONS): ParsedReason[] {
  return exemptions.map((e) => ({
    file: `src/scan/calibration.ts (PARITY_EXEMPTIONS ${e.module})`,
    line: 0,
    endLine: 0,
    fields: Object.fromEntries(
      Object.entries(e.reason)
        .filter(([, value]) => value !== undefined)
        .map(([key, value]) => [REGISTRY_KEY[key as keyof ParityExemption["reason"]], value]),
    ),
    parseErrors: [],
  }));
}

// A path-shaped token, matching recorded-reasons.ts's own derivation: a `/`-bearing token is a path
// claim, and a claim that names a path which is not in the checkout is watching nothing.
// A trailing `.` is sentence punctuation, not part of the path — `handrolled.test.ts.` would be
// reported missing forever, which is the false-alarm half of the same disease.
const GATE_PATH_TOKEN = /[\w.@-]+\/[\w.@/-]*[\w@/-]/g;

interface ExemptionErrors {
  module: string;
  errors: string[];
}

/**
 * The venues a substitute gate's cadence can be checked against: `package.json` scripts and the
 * workflow texts. Same inputs #1288's gate takes, because it is the same question one level over.
 */
export interface CadenceVenues {
  readonly scripts: Readonly<Record<string, string>>;
  readonly workflows: Readonly<Record<string, string>>;
}

// #1483 — "the gate exists" and "the gate runs" are different claims. This checks the second, and
// only ever against a venue the caller actually supplied: an absent `venues` is stated in the
// output by the caller (validate-calibration), never silently treated as a pass.
function cadenceErrors(gate: SubstituteGate, venues: CadenceVenues): string[] {
  const { cadence } = gate;
  if (cadence.kind === "verify") {
    const chain = venues.scripts["verify"] ?? "";
    const runs = venues.scripts["test"] ?? "";
    return chain.includes(gate.invokes) || runs.includes(gate.invokes) || chain.split("&&").some((p) => p.trim().endsWith(gate.invokes))
      ? []
      : [`substituteGates: "${gate.what.slice(0, 60)}…" declares the \`verify\` cadence, but the verify chain (\`${chain}\`) never reaches \`${gate.invokes}\``];
  }
  if (cadence.kind === "workflow") {
    const text = venues.workflows[cadence.file];
    if (text === undefined) return [`substituteGates: declares a cadence in ${cadence.file}, which does not exist — the venue was renamed or deleted and this module now stands on nothing`];
    return text.includes(gate.invokes)
      ? []
      : [`substituteGates: declares a cadence in ${cadence.file} (${cadence.job}) but that workflow never invokes \`${gate.invokes}\` — the cadence was removed, or never landed`];
  }
  return cadence.issue > 0
    ? []
    : ["substituteGates: has no cadence and names no tracking issue. A substitute gate that runs only when someone remembers is a legitimate state; an undisclosed one never appears in a tally"];
}

/**
 * Every committed exemption, held to the recorded-reasons registry plus the substitute-gate rules.
 * `exists` answers "is this a path in the checkout"; it defaults to accepting everything so a caller
 * with no filesystem still gets the structural half (same contract as validateRecordedReason).
 * `venues` adds the #1483 cadence check; omitted, the cadence half is not scored.
 */
export function validateParityExemptions(
  exemptions: readonly ParityExemption[] = PARITY_EXEMPTIONS,
  exists: (path: string) => boolean = () => true,
  venues?: CadenceVenues,
): ExemptionErrors[] {
  const reasons = parityExemptionReasons(exemptions);
  return exemptions
    .map((e, i) => {
      const errors = validateRecordedReason(reasons[i] as ParsedReason, exists);
      if (!AUDIT_MODULES.includes(e.module as (typeof AUDIT_MODULES)[number])) {
        errors.push(`module: "${e.module}" is not one of the ten audited modules (${AUDIT_MODULES.join(", ")}) — an exemption for a module the census never renders exempts nothing and is invisible`);
      }
      if (e.substituteGates.length === 0) {
        errors.push("substituteGates: empty — an exemption's whole content is the gate standing in for the missing fixtures");
      }
      for (const gate of e.substituteGates) {
        const paths = [...new Set([...gate.what.matchAll(GATE_PATH_TOKEN)].map((m) => m[0] as string))];
        const missing = [...paths, gate.invokes].filter((p) => p.includes("/") && !exists(p));
        if (paths.length === 0) {
          errors.push(`substituteGates: "${gate.what.slice(0, 60)}…" names no path in this checkout — a gate nobody can open is a sentence, not a substitute`);
        }
        if (missing.length > 0) {
          errors.push(`substituteGates: names path(s) that do not exist here — ${[...new Set(missing)].join(", ")}. A renamed or deleted substitute gate reads exactly like a live one, so this module would stand on nothing while the census printed EXEMPT`);
        }
        if (venues) errors.push(...cadenceErrors(gate, venues));
      }
      return { module: e.module, errors };
    })
    .filter((x) => x.errors.length > 0);
}

interface ParityVerdict {
  thin: { module: string; positives: number; negatives: number; missing: string }[];
  exempt: { module: string; positives: number; negatives: number; exemption: ParityExemption }[];
  stale: string[]; // modules carrying an exemption they no longer need
}

export function parityVerdict(corpus: CorpusEntry[] = CORPUS, exemptions: readonly ParityExemption[] = PARITY_EXEMPTIONS): ParityVerdict {
  const byModule = new Map(exemptions.map((e) => [e.module, e]));
  const verdict: ParityVerdict = { thin: [], exempt: [], stale: [] };
  for (const c of moduleCensus(corpus)) {
    const positives = c.positivesStatic + c.positivesConnected;
    const missing = [
      positives < MIN_POSITIVES_PER_MODULE ? `${positives}/${MIN_POSITIVES_PER_MODULE} positives` : undefined,
      c.negatives < MIN_NEGATIVES_PER_MODULE ? `${c.negatives}/${MIN_NEGATIVES_PER_MODULE} negatives` : undefined,
    ].filter((s) => s !== undefined).join(" and ");
    const exemption = byModule.get(c.module);
    if (exemption === undefined) {
      if (missing) verdict.thin.push({ module: c.module, positives, negatives: c.negatives, missing });
    } else if (missing) {
      verdict.exempt.push({ module: c.module, positives, negatives: c.negatives, exemption });
    } else {
      verdict.stale.push(c.module);
    }
  }
  return verdict;
}

// The M1-only slice validate-calibration.ts scores against runMechanicalScan output (#341,
// #398): every entry that omits `module` (moduleOf() => "M1"). A module-tagged entry has its own
// live pipeline outside runMechanicalScan (see each *.entries.ts file's header) and is gated by
// its own suite instead — moduleCensus() is what keeps that exclusion visible rather than silent.
// Centralized here (not re-filtered inline in the CLI script) so the exclusion rule has exactly
// one implementation for calibration.test.ts to hold accountable.
export function mechanicalCorpus(corpus: CorpusEntry[] = CORPUS): CorpusEntry[] {
  return corpus.filter((e) => e.module === undefined);
}

// `scoredVenues` names the live venues THIS run has (empty for every static run). A live row in a
// venue this run has is scored — and counted — exactly like a static one; a live row in a venue it
// does not have is `notScored` and excluded from every denominator, so it can neither inflate a
// recall number nor hide inside one.
export function buildCoverageMatrix(findings: Finding[], corpus: CorpusEntry[] = CORPUS, scoredVenues: ReadonlySet<LiveTier> = NO_LIVE_VENUE): CoverageMatrix {
  const rows = corpus.map((e) => scoreEntry(e, findings, scoredVenues));
  const staticPos = rows.filter((r) => r.kind === "positive" && !r.notScored && r.expectedTier !== "none");
  const staticNeg = rows.filter((r) => r.kind === "negative" && !r.notScored);
  const noRule = rows.filter((r) => r.kind === "positive" && r.expectedTier === "none");
  const positivesCaught = staticPos.filter((r) => r.pass).length;
  const negativesCleared = staticNeg.filter((r) => r.pass).length;
  const noRuleHeld = noRule.filter((r) => r.pass).length;
  return {
    rows,
    positivesTotal: staticPos.length,
    positivesCaught,
    positivesCaughtHigh: staticPos.filter((r) => r.highFlagged).length,
    negativesTotal: staticNeg.length,
    negativesCleared,
    liveNotScored: rows.filter((r) => r.notScored).length,
    noRuleTotal: noRule.length,
    noRuleHeld,
    metrics: detectionMetrics({
      tp: positivesCaught,
      fn: staticPos.length - positivesCaught,
      fp: staticNeg.length - negativesCleared,
      tn: negativesCleared,
    }),
    ok: positivesCaught === staticPos.length && negativesCleared === staticNeg.length && noRuleHeld === noRule.length,
  };
}
