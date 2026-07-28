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
import { knownPublicCredsEntries } from "./calibration/known-public-creds.entries.js";
import { owaspMultiTenantEntries } from "./calibration/owasp-multitenant.entries.js";
import { owaspNodejsEntries } from "./calibration/owasp-nodejs.entries.js";
import { owaspReactEntries } from "./calibration/owasp-react.entries.js";
import { rlsStaticSemanticsEntries } from "./calibration/rls-static-semantics.entries.js";
import { m3Entries } from "./calibration/m3.entries.js";
import { m7Entries } from "./calibration/m7.entries.js";
import { m7InitplanStaticEntries } from "./calibration/m7-initplan-static.entries.js";
import { m8Entries } from "./calibration/m8.entries.js";
import { m9AuthzEntries } from "./calibration/m9-authz.entries.js";
import { m9CheckEntries } from "./calibration/m9-checks.entries.js";
import { m9PortEntries } from "./calibration/m9-ports.entries.js";
import { m10Entries } from "./calibration/m10.entries.js";
import { m4m5Entries } from "./calibration/m4-m5.entries.js";
import { secretsEntries } from "./calibration/secrets.entries.js";
import type { CorpusEntry } from "./calibration/types.js";

export type { CorpusEntry } from "./calibration/types.js";

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
  // it. A miss never sets it (the miss already fails); a negative/connected/none row never does.
  expectedSeverity?: CorpusEntry["expectedSeverity"];
  deliveredSeverities?: Severity[];
  severityMismatch: boolean;
}

// Scoring:
//   positive (static): pass = caught at any tier. A "connected"-tier positive is N/A (never fails).
//   negative: pass = NO high-tier (free-count) finding is relevant. A review-tier hit is tolerated
//             (it gets triaged out of the count) but recorded. A "connected"-tier negative is N/A.
export function scoreEntry(entry: CorpusEntry, findings: Finding[]): MatrixRow {
  const relevant = relevantFindings(entry, findings);
  assertTiered(entry, relevant);
  const highFlagged = relevant.some((f) => f.precisionTier === "high");
  const reviewFlagged = relevant.some((f) => f.precisionTier === "review");
  const caughtTier = topTier(relevant);
  // A caught-and-clean severity default for every non-scored path; the positive branch overrides it.
  const noSev = { expectedSeverity: entry.expectedSeverity, severityMismatch: false };

  if (entry.expectedTier === "connected") {
    return { id: entry.id, kind: entry.kind, cls: entry.cls, expectedTier: entry.expectedTier, caughtTier, highFlagged, reviewFlagged, pass: true, detail: "N/A — connected tier (live DB), not evaluated statically", ...noSev };
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
    return { id: entry.id, kind: entry.kind, cls: entry.cls, expectedTier: entry.expectedTier, caughtTier, highFlagged, reviewFlagged, pass, detail, expectedSeverity: entry.expectedSeverity, deliveredSeverities, severityMismatch };
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
  positivesTotal: number; // static positives that MUST be caught (excludes connected AND none tiers)
  positivesCaught: number;
  positivesCaughtHigh: number;
  negativesTotal: number; // static negatives (excludes connected tier)
  negativesCleared: number;
  connectedNa: number;
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
  positivesStatic: number; // static positives (excludes connected tier)
  positivesConnected: number; // connected-tier positives (live-DB only, N/A statically)
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
    else if (e.expectedTier === "connected") row.positivesConnected++;
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
// half of #1314. Both entries below were verified 2026-07-28 before being written here, per the
// rule that a disclosure is earned by an attempt:
//   M2 — `pnpm exec tsx src/cli/pentest.ts --mode=coverage` reaches assertComplete
//        (src/pentest/targets.ts:161), and CALIBRATION_PLANTS carries an M2 row
//        (src/audit-conservation.ts:59) since #1155.
//   M6 — src/scan/external-corpus.ts carries an "M6-indicator" baseline on six external targets
//        (#483), re-run by `pnpm corpus-drift`.
// An exemption for a module that is NOT thin is itself a failure (the `stale` list) — a substitute gate
// that has been overtaken by real fixtures must not keep standing in for them.
interface ParityExemption {
  module: string;
  reason: string;
}

const PARITY_EXEMPTIONS: readonly ParityExemption[] = [
  { module: "M2", reason: "no static corpus by construction — M2 is the dynamic tier, and its findings come from a live two-tenant stack, not a planted file. Covered instead by `pnpm exec tsx src/cli/pentest.ts --mode=coverage` (#352 assertComplete, which fails loud on any enumerated target `--tested` did not list) and by the M2 conservation plant (#1155)." },
  { module: "M6", reason: "no static corpus — M6's indicators are whole-repo shape counts, which a planted single-file fixture cannot express. Covered instead by the #483 `M6-indicator` baselines over six external targets in src/scan/external-corpus.ts, re-run by `pnpm corpus-drift`." },
];

interface ParityVerdict {
  thin: { module: string; positives: number; negatives: number; missing: string }[];
  exempt: { module: string; positives: number; negatives: number; reason: string }[];
  stale: string[]; // modules carrying an exemption they no longer need
}

export function parityVerdict(corpus: CorpusEntry[] = CORPUS): ParityVerdict {
  const exemptions = new Map(PARITY_EXEMPTIONS.map((e) => [e.module, e.reason]));
  const verdict: ParityVerdict = { thin: [], exempt: [], stale: [] };
  for (const c of moduleCensus(corpus)) {
    const positives = c.positivesStatic + c.positivesConnected;
    const missing = [
      positives < MIN_POSITIVES_PER_MODULE ? `${positives}/${MIN_POSITIVES_PER_MODULE} positives` : undefined,
      c.negatives < MIN_NEGATIVES_PER_MODULE ? `${c.negatives}/${MIN_NEGATIVES_PER_MODULE} negatives` : undefined,
    ].filter((s) => s !== undefined).join(" and ");
    const reason = exemptions.get(c.module);
    if (reason === undefined) {
      if (missing) verdict.thin.push({ module: c.module, positives, negatives: c.negatives, missing });
    } else if (missing) {
      verdict.exempt.push({ module: c.module, positives, negatives: c.negatives, reason });
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

export function buildCoverageMatrix(findings: Finding[], corpus: CorpusEntry[] = CORPUS): CoverageMatrix {
  const rows = corpus.map((e) => scoreEntry(e, findings));
  const staticPos = rows.filter((r) => r.kind === "positive" && r.expectedTier !== "connected" && r.expectedTier !== "none");
  const staticNeg = rows.filter((r) => r.kind === "negative" && r.expectedTier !== "connected");
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
    connectedNa: rows.filter((r) => r.expectedTier === "connected").length,
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
