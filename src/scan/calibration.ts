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
import { knownPublicCredsEntries } from "./calibration/known-public-creds.entries.js";
import { owaspMultiTenantEntries } from "./calibration/owasp-multitenant.entries.js";
import { owaspNodejsEntries } from "./calibration/owasp-nodejs.entries.js";
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
  ...knownPublicCredsEntries,
  ...owaspMultiTenantEntries,
  ...owaspNodejsEntries,
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

  // negative
  const pass = !highFlagged;
  const detail = highFlagged
    ? "FALSE POSITIVE in the free count"
    : reviewFlagged
      ? "cleared from the count (review-tier hit only, triaged out)"
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

// Per-module fixture census over the corpus, so a blended recall count can never imply uniform
// coverage: a module standing on 1 positive is visibly thin here rather than averaged into the
// M1-dominated total (#341). Purely counts the answer key — says nothing about what any gate runs.
export function moduleCensus(corpus: CorpusEntry[] = CORPUS): ModuleCensusRow[] {
  const rows = new Map<string, ModuleCensusRow>();
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
