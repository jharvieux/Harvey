// Coverage scorecard for the calibration dry run (issue #34): maps the planted bugs in
// targets/calibration/GROUND-TRUTH.md's §"Planted bugs" to the module expected to catch each, and
// scores each against dry-run/findings.json (src/cli/dry-run.ts's real output — this script does
// not invent results, it only classifies what's already there). A catch is split by the matching
// finding's precision tier: an "asserted" verdict (high-precision rule) vs a "surfaced-for-review"
// shape a human must still adjudicate — so the summary never launders review-tier surfacing into
// autonomous detection (#342).
//
// SCOPE, per GROUND-TRUTH's own split: the 8 statically-reachable bugs are this scorecard's
// semantic/RLS ground truth and the only ones a static dry run can return a verdict on. The other
// two populations are scored by the tier that can actually reach them, NOT re-scored here: the
// mechanical precision corpus (`pnpm validate:calibration` / src/scan/calibration.test.ts) and the
// M2 dynamic replays (src/pentest/verify.ts). Rows 9–12 are still LISTED below — as
// requires-live-run with their reason — because a bug this pass cannot judge must be visible as
// awaiting a live run, never absent (see NOT_RUN_M2_REPLAY).
//
//   pnpm exec tsx src/cli/dry-run.ts --out dry-run   # produces dry-run/findings.json first
//   pnpm exec tsx src/cli/dry-run-scorecard.ts --findings dry-run/findings.json --out dry-run
//
// moduleRan is set here by hand from what this dry-run pass actually executed (see
// docs/runbooks/dry-run-calibration.md) — not derived automatically, so a bug's status can't
// silently flip if a module's behavior changes without this file being reviewed too.

import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { type GroundTruthBug, scoreCoverage, type ScorableFinding, summarizeCoverage } from "../coverage-scorecard.js";

// A catch must be the right RULE at the right FILE. `location` is an absolute path into a scratch
// scan copy, so anchor on the target-relative file suffix; `taxonomy` must name a rule that
// actually reasons about this bug's class, not merely fire somewhere in the same file.
const at = (file: RegExp, rule: RegExp) => (f: ScorableFinding) => file.test(f.location) && rule.test(f.taxonomy);

// A KNOWN, ACCEPTED coverage gap — not a regression. The mechanical tier scans the file and no
// rule has ever claimed this bug's class, so the bug scores `missed` by design: this is the
// scorecard measuring the mechanical tier's real ceiling, which is what it exists to do. Verified
// for all three users of this text (#286): `missed` in EVERY committed scorecard.json back to the
// original #34 baseline, and `git log -S` finds no rule for any of these classes in any semgrep
// rule file, ever. These bugs are the paid semantic tier's job (docs/free-tier-scope.md).
// A `caught` here would mean a NEW rule genuinely fires — never relax a `matches` to manufacture it.
const RAN_SEMGREP_NO_RULE = (why: string) => `Semgrep ran (src/scan/semgrep.ts) but ${why}`;

// GROUND-TRUTH rows 9–12 (§"Dynamic-tier probes", #145–#148) are live-BEHAVIOR classes: only a
// request replayed against a running app confirms them, which is why GROUND-TRUTH itself puts them
// outside the mechanical count. A static pass genuinely cannot judge them — that part was never in
// dispute. What was wrong is that they were absent rather than deferred: the scorecard reported
// `requires-live-run: 0`, asserting nothing awaits a live run, while four bugs did. Deferring a bug
// silently is the one thing the coverage guard forbids outright, so they are listed here with the
// reason instead.
// `matches: () => false` is the honest matcher: a static pass cannot produce a finding that proves a
// live-behavior class, and any matcher that COULD fire here would manufacture a catch the tier never
// earned. Do not add mechanical rules for these — the M2 probes are the detection.
const NOT_RUN_M2_REPLAY = (probe: string, proves: string) =>
  `${probe} (src/pentest/verify.ts) — M2 dynamic pen-test replay: ${probe} ${proves}. Requires a running app plus a local \`supabase start\` stack seeded with two tenants (\`pnpm exec tsx src/cli/pentest.ts\`); this dry run is static and executed no M2 phase`;

export const GROUND_TRUTH_BUGS: GroundTruthBug[] = [
  {
    id: "RLS-USING-TRUE",
    severity: "Critical",
    location: "supabase/migrations/20260708000002_rls.sql:31-32",
    expectedModule:
      "usingTrueReview (src/rls-policy-review.ts, #337) ran inside runMechanicalScan via checkMigrationPolicySemantics and reviewed documents_select_all's USING (true) at the planted line — review tier, so the tier surfaces it for adjudication rather than asserting the verdict",
    moduleRan: true,
    // `rls.sql:31` is the planted policy's own line, and documents_select_all is the only policy
    // the semantic review reports there — its siblings are located at their own lines (:6, :38).
    matches: at(/rls\.sql:31 /, /Multi-tenant security/),
  },
  {
    id: "RLS-AUTH-ROLE",
    severity: "Critical",
    location: "supabase/migrations/20260708000002_rls.sql:38-39",
    expectedModule:
      "checkMigrationPolicySemantics (src/scan/supabase-static.ts, #220) ran inside runMechanicalScan and reviewed invoices_select_authenticated's predicate at the planted line",
    moduleRan: true,
    // `rls.sql:38` is the planted policy's own line, and the only policy the semantic review
    // reports there — the sibling policies in this file are located at their own lines.
    matches: at(/rls\.sql:38 /, /Multi-tenant security/),
  },
  {
    id: "RLS-DISABLED",
    severity: "High",
    location: "supabase/migrations/20260708000002_rls.sql:41-43",
    expectedModule:
      "checkMigrationRlsStatic (src/scan/supabase-static.ts) ran inside runMechanicalScan and proved audit_logs never gets RLS enabled in ANY migration",
    moduleRan: true,
    // GROUND-TRUTH addresses this bug at its ABSENCE site (rls.sql:41-43, where the missing
    // `enable row level security` belongs); the static check reports the CREATE site
    // (schema.sql:35) because the absence it proves is file-wide — it asserts no migration
    // anywhere enables RLS on this table, so it can only anchor on the one line that does exist.
    // Accepting the create site is honest, not convenient: the rule reasons about exactly this
    // bug's class for exactly this table, and audit_logs is the only table this rule reports in
    // schema.sql, so the match cannot be earned by a finding about some other table.
    matches: at(/schema\.sql:35/, /Migration table without RLS/),
  },
  {
    id: "SQLI-SERVICE",
    severity: "Critical",
    location: "pages/api/search.js:9",
    expectedModule: "Semgrep ran (src/scan/semgrep.ts) and harvey-sql-injection-template matched the raw-SQL-concat pattern in search.js",
    moduleRan: true,
    matches: at(/search\.js/, /sql.?injection/i),
  },
  {
    id: "WEBHOOK-REPLAY",
    severity: "Medium",
    location: "pages/api/webhook.js:20-24",
    expectedModule: RAN_SEMGREP_NO_RULE("no rule targets missing replay/nonce protection"),
    moduleRan: true,
    matches: at(/webhook\.js/, /replay|nonce/i),
  },
  {
    id: "COUNTER-RACE",
    severity: "Medium",
    location: "pages/api/counter/increment.js:11-31",
    expectedModule: RAN_SEMGREP_NO_RULE("no rule targets non-atomic read-modify-write races"),
    moduleRan: true,
    matches: at(/increment\.js/, /race|atomic/i),
  },
  {
    id: "UPDATE-UNSCOPED",
    severity: "High",
    location: "pages/api/profile/update.js:11-14",
    expectedModule: RAN_SEMGREP_NO_RULE("no rule targets an unscoped service-role .update() call"),
    moduleRan: true,
    matches: at(/profile.(\/|\\)?update\.js/, /unscoped|service.?role/i),
  },
  {
    id: "OPEN-REDIRECT",
    severity: "Low",
    location: "pages/api/redirect.js:9",
    expectedModule: "Semgrep ran (src/scan/semgrep.ts) and the harvey-open-redirect custom rule (src/scan/rules/semgrep/base.yml) matched at redirect.js",
    moduleRan: true,
    matches: at(/redirect\.js/, /open.?redirect/i),
  },
  {
    id: "SHADOW-API-VERSION",
    severity: "High",
    location: "pages/api/v1/export.js",
    expectedModule: NOT_RUN_M2_REPLAY(
      "replayShadowApiVersion",
      "GETs each discovered versioned route as anon and proves the bug only when the deprecated route answers 200 with rows the current route gates",
    ),
    moduleRan: false,
    matches: () => false,
  },
  {
    id: "NO-RATE-LIMIT",
    severity: "High",
    location: "pages/api/coupon/redeem.js",
    expectedModule: NOT_RUN_M2_REPLAY(
      "replayNoRateLimit",
      "POSTs the same coupon 5× and proves the bug only when all 5 are accepted (side-effecting, so it additionally needs allowDestructive)",
    ),
    moduleRan: false,
    matches: () => false,
  },
  {
    id: "CACHE-CROSS-USER",
    severity: "High",
    location: "pages/api/me/summary.js",
    expectedModule: NOT_RUN_M2_REPLAY(
      "replayCacheCrossUser",
      "warms the route as Tenant A then re-reads it as anon, proving the bug only when anon is served A's tenant_id from a public/s-maxage cache",
    ),
    moduleRan: false,
    matches: () => false,
  },
  {
    id: "ANON-PRIVILEGED-RPC",
    severity: "Critical",
    location: "supabase/migrations/20260710000002_dynamic_probes.sql",
    expectedModule: NOT_RUN_M2_REPLAY(
      "replayAnonPrivilegedRpc",
      "POSTs /rest/v1/rpc/issue_refund with only the anon key and proves the bug only on a 2xx (side-effecting, so it additionally needs allowDestructive)",
    ),
    moduleRan: false,
    matches: () => false,
  },
];

function arg(flag: string, fallback: string): string {
  const i = process.argv.indexOf(flag);
  return i >= 0 && process.argv[i + 1] ? process.argv[i + 1]! : fallback;
}

function main(): void {
  const findingsPath = arg("--findings", "dry-run/findings.json");
  const outDir = arg("--out", "dry-run");

  const rawFindings = JSON.parse(readFileSync(findingsPath, "utf8")) as { taxonomy: string; location: string; precisionTier?: ScorableFinding["precisionTier"] }[];
  const findings: ScorableFinding[] = rawFindings.map((f) => ({ taxonomy: f.taxonomy, location: f.location, precisionTier: f.precisionTier }));

  const scored = scoreCoverage(GROUND_TRUTH_BUGS, findings);
  const summary = summarizeCoverage(scored);

  writeFileSync(join(outDir, "scorecard.json"), JSON.stringify({ summary, bugs: scored }, null, 2));

  console.log(
    `Coverage scorecard: ${summary.asserted} asserted, ${summary["surfaced-for-review"]} surfaced for review, ` +
      `${summary.missed} missed, ${summary["requires-live-run"]} require a live run (of ${scored.length} planted bugs)`,
  );
  // A caught bug prints its tier so a review-tier surfacing is never read as an asserted verdict.
  for (const b of scored) {
    const label = b.status === "caught" ? (b.tier === "high" ? "asserted" : "surfaced-for-review") : b.status;
    console.log(`  [${label.padEnd(19)}] ${b.id.padEnd(16)} (${b.severity})`);
  }
}

// Guarded so dry-run-scorecard.test.ts can import GROUND_TRUTH_BUGS without writing scorecard.json.
if (process.argv[1] === fileURLToPath(import.meta.url)) main();
