// Coverage scorecard for the calibration dry run (issue #34): maps each planted bug in
// targets/calibration/GROUND-TRUTH.md to the SINGLE gated answer key and reports caught / missed /
// requires-live-run against dry-run/findings.json (src/cli/dry-run.ts's real output — this script
// does not invent results, it classifies what the corpus says about what's already there).
//
// #425 — ONE answer key, no second hand-maintained matcher. A static bug names the calibration
// corpus entry (corpusId) whose rule verdict IS its verdict; DETECTION is scored by the gated
// corpus (src/scan/calibration.ts's scoreEntry), never a per-bug `matches` kept here that could
// drift. A dynamic (M2) bug names the pen-test replay (replayId) a static pass never runs, so it
// is requires-live-run with its reason — deferred, never absent. The drift class is structural:
// a corpusId that doesn't resolve throws, and a corpus rule that stops firing fails `pnpm verify`.
//
// A catch is split by the corpus finding's precision tier — an "asserted" verdict (high) vs a
// "surfaced-for-review" shape a human must adjudicate — so the summary never launders review-tier
// surfacing into autonomous detection (#342). The "none"-tier corpus entry (WEBHOOK-REPLAY) makes
// its accepted no-mechanical-rule gap first-class: it scores "missed" while the gap holds, and if a
// rule ever fires on the class the corpus gate fails loud (src/scan/calibration.ts).
//
//   pnpm exec tsx src/cli/dry-run.ts --out dry-run   # produces dry-run/findings.json first
//   pnpm exec tsx src/cli/dry-run-scorecard.ts --findings dry-run/findings.json --out dry-run

import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { type BugDetection, type GroundTruthBug, scoreCoverage, statusFromDynamicProbe, summarizeCoverage } from "../coverage-scorecard.js";
import type { Finding } from "../findings.js";
import type { DynamicScorecard } from "../pentest/scorecard.js";
import { CORPUS, scoreEntry } from "../scan/calibration.js";

// The engagement-rehearsal record for one GROUND-TRUTH.md planted bug. DETECTION is not decided
// here: exactly one of corpusId (static — the gated corpus entry that answers detection) or
// replayId (dynamic M2 — the pen-test replay a static pass never runs). #425 DECISION: `moduleRan`
// is gone — "did the detecting module run" is now the corpusId-vs-replayId split, and #229's
// execution log owns runtime provenance. severity + exploitability stay here as the rehearsal
// record (the corpus has no severity concept); expectedModule is the human-readable provenance and
// exploit path, preserved so per-module coverage is never dropped.
interface PlantedBug {
  id: string;
  severity: string;
  location: string;
  expectedModule: string;
  corpusId?: string;
  replayId?: string;
}

// A dynamic (M2) bug: a live-BEHAVIOR class only a request replayed against a running app confirms
// (GROUND-TRUTH rows 9–12, #145–#148). A static pass runs no M2 phase, so it stays requires-live-run
// WITH its reason — an unlisted bug can't appear in a tally. replayId is the replay registered in
// src/pentest/verify.ts; dry-run-scorecard.test.ts falsifies a dangling id.
const m2 = (replayId: string, proves: string): Pick<PlantedBug, "expectedModule" | "replayId"> => ({
  replayId,
  expectedModule:
    `${replayId} (src/pentest/verify.ts) — M2 dynamic pen-test replay: ${proves}. Requires a running app plus a local ` +
    "`supabase start` stack seeded with two tenants (`pnpm exec tsx src/cli/pentest.ts`); this dry run is static and executed no M2 phase.",
});

export const GROUND_TRUTH_BUGS: PlantedBug[] = [
  { id: "RLS-USING-TRUE", severity: "Critical", location: "supabase/migrations/20260708000002_rls.sql:31-32", corpusId: "P-RLS-USING-TRUE-STATIC", expectedModule: "usingTrueReview (src/rls-policy-review.ts, #337) via checkMigrationPolicySemantics — reviews documents_select_all's USING (true), surfaced for adjudication at review tier." },
  { id: "RLS-AUTH-ROLE", severity: "Critical", location: "supabase/migrations/20260708000002_rls.sql:38-39", corpusId: "P-RLS-AUTH-ROLE-STATIC", expectedModule: "checkMigrationPolicySemantics (src/scan/supabase-static.ts, #220) — reviews invoices_select_authenticated's predicate at review tier." },
  { id: "RLS-DISABLED", severity: "High", location: "supabase/migrations/20260708000002_rls.sql:41-43", corpusId: "P-RLS-MISSING-STATIC", expectedModule: "checkMigrationRlsStatic (src/scan/supabase-static.ts) — proves audit_logs never gets RLS enabled in any migration, at high tier." },
  { id: "SQLI-SERVICE", severity: "Critical", location: "pages/api/search.js:9", corpusId: "P-SQLI-CONCAT", expectedModule: "Semgrep harvey-sql-injection-template matched the raw-SQL-concat in search.js, at high tier." },
  { id: "WEBHOOK-REPLAY", severity: "Medium", location: "pages/api/webhook.js:20-24", corpusId: "P-WEBHOOK-REPLAY-NO-RULE", expectedModule: "No mechanical rule by design (measured LLM-tier, #353): proving a replay guard's absence is whole-handler+callee reasoning no FP-safe grep/AST can do — corpus P-WEBHOOK-REPLAY-NO-RULE ('none' tier)." },
  { id: "COUNTER-RACE", severity: "Medium", location: "pages/api/counter/increment.js:11-31", corpusId: "P-COUNTER-RACE", expectedModule: "detectCounterRaceFindings (src/scan/counter-race.ts, #353) matched the non-atomic read-modify-write on counters, at review tier." },
  { id: "UPDATE-UNSCOPED", severity: "High", location: "pages/api/profile/update.js:11-14", corpusId: "P-UPDATE-UNSCOPED", expectedModule: "scanLeftoverAuth (src/scan/leftover-auth.ts, #353) matched the raw UPDATE with no WHERE in this route handler, at review tier." },
  { id: "OPEN-REDIRECT", severity: "Low", location: "pages/api/redirect.js:9", corpusId: "P-OPEN-REDIRECT", expectedModule: "Semgrep harvey-open-redirect (src/scan/rules/semgrep/base.yml) matched at redirect.js, at review tier." },
  {
    id: "SHADOW-API-VERSION",
    severity: "High",
    location: "pages/api/v1/export.js",
    ...m2("SHADOW-API-VERSION", "GETs each discovered versioned route as anon and proves the bug only when the deprecated route answers 200 with rows the current route gates"),
  },
  {
    id: "NO-RATE-LIMIT",
    severity: "High",
    location: "pages/api/coupon/redeem.js",
    ...m2("NO-RATE-LIMIT", "POSTs the same coupon 5× and proves the bug only when all 5 are accepted (side-effecting, so it additionally needs allowDestructive)"),
  },
  {
    id: "CACHE-CROSS-USER",
    severity: "High",
    location: "pages/api/me/summary.js",
    ...m2("CACHE-CROSS-USER", "warms the route as Tenant A then re-reads it as anon, proving the bug only when anon is served A's tenant_id from a public/s-maxage cache"),
  },
  {
    id: "ANON-PRIVILEGED-RPC",
    severity: "Critical",
    location: "supabase/migrations/20260710000002_dynamic_probes.sql",
    ...m2("ANON-PRIVILEGED-RPC", "POSTs each DB-derived privileged RPC with only the anon key and proves the bug only when the body EXECUTED — a 2xx, or an engine-raised SQLSTATE (class 22/23) from a statement the body issued. A plpgsql P0001 the function RAISED itself is a self-guarding function refusing the caller, so it is reported and never asserted (side-effecting, so it additionally needs allowDestructive)"),
  },
];

// Resolve a planted bug's detection from the single gated answer key. Static bugs are scored by the
// gated corpus entry — a missing corpusId throws (the FK-integrity guard that makes drift
// structurally impossible), and the "none" tier maps its accepted no-mechanical-rule gap to a
// "missed" (gap held) that flips to caught only if the corpus gate is already failing on a
// graduated rule.
//
// #1310 — a DYNAMIC (M2) bug resolves against a committed pen-test scorecard when one is supplied,
// which is the whole point of #347: the `requires-live-run` deferral points at a real recorded
// outcome instead of a memory. `statusFromDynamicProbe` owns that mapping (it is the module that
// knows a `cleared` probe is a MISS, not a deferral) and had no production caller until this. With
// no scorecard, or a scorecard that recorded no verdict for this replay, the row stays
// requires-live-run — never a guess that something ran.
export function resolveDetection(bug: PlantedBug, findings: Finding[], dynamic?: DynamicScorecard): BugDetection | null {
  if (bug.replayId) {
    const probe = dynamic?.probes.find((p) => p.findingId === bug.replayId);
    if (!probe) return null;
    const status = statusFromDynamicProbe(probe.status);
    if (status === "requires-live-run") return null;
    return {
      caught: status === "caught",
      // A live replay either exhibited the bug against a running stack or it did not — that is an
      // asserted verdict, not a shape surfaced for a human to adjudicate.
      ...(status === "caught" ? { tier: "high" as const } : {}),
      note:
        `M2 replay ${bug.replayId} scored "${probe.status}" against ${dynamic!.target} in the pen-test scorecard ` +
        `generated ${dynamic!.generatedAt}: ${probe.evidence}`,
    };
  }
  const entry = CORPUS.find((e) => e.id === bug.corpusId);
  if (!entry) {
    throw new Error(
      `Planted bug ${bug.id} references corpus entry "${bug.corpusId}", which is not in the gated corpus ` +
        "(src/scan/calibration.ts). The single answer-key link is broken — fix the corpusId or restore the entry.",
    );
  }
  const row = scoreEntry(entry, findings);
  if (entry.expectedTier === "none") {
    return {
      caught: !row.pass,
      tier: row.caughtTier,
      note: row.pass
        ? `Accepted gap — no mechanical rule reaches this class by design (measured LLM-tier); gated corpus ${entry.id} scores it an intended gap.`
        : `A mechanical rule now fires on this by-design gap — re-tier gated corpus ${entry.id}. ${row.detail}`,
    };
  }
  return {
    caught: row.pass,
    tier: row.caughtTier,
    note: row.pass
      ? `Detected via gated corpus ${entry.id} at ${row.caughtTier ?? "?"} tier (${row.detail}).`
      : `Gated corpus ${entry.id} no longer fires on the committed findings — the detecting rule regressed.`,
  };
}

function arg(flag: string, fallback: string): string {
  const i = process.argv.indexOf(flag);
  return i >= 0 && process.argv[i + 1] ? process.argv[i + 1]! : fallback;
}

// #1310 — the committed M2 record the dynamic rows resolve against. Default path so a regeneration
// picks it up with no extra flag once a live run has deposited one; an explicitly-named file that
// is missing is a hard error, because silently falling back to requires-live-run is exactly the
// "unstated limitation reads as a clean bill of health" failure.
function loadDynamicScorecard(): DynamicScorecard | undefined {
  const explicit = process.argv.includes("--dynamic-scorecard");
  const path = arg("--dynamic-scorecard", "dry-run/dynamic-scorecard.json");
  if (!existsSync(path)) {
    if (explicit) throw new Error(`--dynamic-scorecard ${path} does not exist; produce it with \`pentest.ts --mode=verify … --scorecard ${path}\``);
    return undefined;
  }
  return JSON.parse(readFileSync(path, "utf8")) as DynamicScorecard;
}

function main(): void {
  const findingsPath = arg("--findings", "dry-run/findings.json");
  const outDir = arg("--out", "dry-run");

  const findings = JSON.parse(readFileSync(findingsPath, "utf8")) as Finding[];
  const dynamic = loadDynamicScorecard();

  const bugs: GroundTruthBug[] = GROUND_TRUTH_BUGS.map((b) => ({
    id: b.id,
    severity: b.severity,
    location: b.location,
    expectedModule: b.expectedModule,
    detection: resolveDetection(b, findings, dynamic),
  }));
  const scored = scoreCoverage(bugs);
  const summary = summarizeCoverage(scored);

  writeFileSync(join(outDir, "scorecard.json"), JSON.stringify({ summary, bugs: scored }, null, 2));

  console.log(
    `Coverage scorecard: ${summary.asserted} asserted, ${summary["surfaced-for-review"]} surfaced for review, ` +
      `${summary.missed} missed, ${summary["requires-live-run"]} require a live run (of ${scored.length} planted bugs)`,
  );
  // Where the M2 rows' verdicts came from. Silence here would make "no live record" and "a live
  // record that resolved them" print identically — the exact ambiguity #347/#1310 exist to end.
  console.log(
    dynamic
      ? `  M2 dynamic rows resolved against ${dynamic.probes.length} probe(s) recorded on ${dynamic.generatedAt} against ${dynamic.target}`
      : "  M2 dynamic rows: no pen-test scorecard supplied — every replay stays requires-live-run (produce one with `pentest.ts --mode=verify … --scorecard dry-run/dynamic-scorecard.json`)",
  );
  // A caught bug prints its tier so a review-tier surfacing is never read as an asserted verdict.
  for (const b of scored) {
    const label = b.status === "caught" ? (b.tier === "high" ? "asserted" : "surfaced-for-review") : b.status;
    console.log(`  [${label.padEnd(19)}] ${b.id.padEnd(16)} (${b.severity})`);
  }
}

// Guarded so dry-run-scorecard.test.ts can import GROUND_TRUTH_BUGS without writing scorecard.json.
if (process.argv[1] === fileURLToPath(import.meta.url)) main();
