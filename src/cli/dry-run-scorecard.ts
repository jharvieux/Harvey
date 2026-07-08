// Coverage scorecard for the calibration dry run (issue #34): maps every planted bug in
// targets/calibration/GROUND-TRUTH.md to the module expected to catch it, and scores each
// caught/missed/requires-live-run against dry-run/findings.json (src/cli/dry-run.ts's real
// output — this script does not invent results, it only classifies what's already there).
//
//   pnpm exec tsx src/cli/dry-run.ts --out dry-run   # produces dry-run/findings.json first
//   pnpm exec tsx src/cli/dry-run-scorecard.ts --findings dry-run/findings.json --out dry-run
//
// moduleRan is set here by hand from what this dry-run pass actually executed (see
// docs/runbooks/dry-run-calibration.md) — not derived automatically, so a bug's status can't
// silently flip if a module's behavior changes without this file being reviewed too.

import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { type GroundTruthBug, scoreCoverage, type ScorableFinding, summarizeCoverage } from "../coverage-scorecard.js";

const NOT_RUN_SEMANTIC_RLS_READ =
  "Semantic RLS-policy predicate read (tier1-runbook.md step 1 LLM /vuln-scan + /triage pass, or manual hand-verify at step 6) — no mechanical module in src/ evaluates policy semantics";
const NOT_RUN_SUPABASE_ADVISOR =
  "Supabase Advisor lint rls_disabled_in_public (src/scan/supabase-advisors.ts) — requires a live DB via `supabase start` (Docker) or the hosted Management API";
const RAN_SEMGREP_NO_RULE = (why: string) => `Semgrep ran (src/scan/semgrep.ts) but ${why}`;

export const GROUND_TRUTH_BUGS: GroundTruthBug[] = [
  {
    id: "RLS-USING-TRUE",
    severity: "Critical",
    location: "supabase/migrations/20260708000002_rls.sql:31-32",
    expectedModule: NOT_RUN_SEMANTIC_RLS_READ,
    moduleRan: false,
    matches: () => false,
  },
  {
    id: "RLS-AUTH-ROLE",
    severity: "Critical",
    location: "supabase/migrations/20260708000002_rls.sql:38-39",
    expectedModule: NOT_RUN_SEMANTIC_RLS_READ,
    moduleRan: false,
    matches: () => false,
  },
  {
    id: "RLS-DISABLED",
    severity: "High",
    location: "supabase/migrations/20260708000002_rls.sql:41-43",
    expectedModule: NOT_RUN_SUPABASE_ADVISOR,
    moduleRan: false,
    matches: () => false,
  },
  {
    id: "SQLI-SERVICE",
    severity: "Critical",
    location: "pages/api/search.js:9",
    expectedModule: RAN_SEMGREP_NO_RULE("no registry/custom rule matched the raw-SQL-concat pattern in search.js"),
    moduleRan: true,
    matches: (s) => /search\.js/.test(s) || /sql.?injection/i.test(s),
  },
  {
    id: "WEBHOOK-REPLAY",
    severity: "Medium",
    location: "pages/api/webhook.js:20-24",
    expectedModule: RAN_SEMGREP_NO_RULE("no rule targets missing replay/nonce protection"),
    moduleRan: true,
    matches: (s) => /webhook\.js/.test(s) || /replay/i.test(s),
  },
  {
    id: "COUNTER-RACE",
    severity: "Medium",
    location: "pages/api/counter/increment.js:11-31",
    expectedModule: RAN_SEMGREP_NO_RULE("no rule targets non-atomic read-modify-write races"),
    moduleRan: true,
    matches: (s) => /increment\.js/.test(s) || /race/i.test(s),
  },
  {
    id: "UPDATE-UNSCOPED",
    severity: "High",
    location: "pages/api/profile/update.js:11-14",
    expectedModule: RAN_SEMGREP_NO_RULE("no rule targets an unscoped service-role .update() call"),
    moduleRan: true,
    matches: (s) => /profile.(\/|\\)?update\.js/.test(s) || /unscoped/i.test(s),
  },
  {
    id: "OPEN-REDIRECT",
    severity: "Low",
    location: "pages/api/redirect.js:9",
    expectedModule: RAN_SEMGREP_NO_RULE(
      "the harvey-open-redirect custom rule (src/scan/rules/semgrep-nextjs-supabase.yml) is written for the App-Router shape ($REQ.nextUrl.searchParams.get) — it doesn't match this Pages-Router zod-validated-URL shape",
    ),
    moduleRan: true,
    matches: (s) => /redirect\.js/.test(s) || /open.?redirect/i.test(s),
  },
];

function arg(flag: string, fallback: string): string {
  const i = process.argv.indexOf(flag);
  return i >= 0 && process.argv[i + 1] ? process.argv[i + 1]! : fallback;
}

function main(): void {
  const findingsPath = arg("--findings", "dry-run/findings.json");
  const outDir = arg("--out", "dry-run");

  const rawFindings = JSON.parse(readFileSync(findingsPath, "utf8")) as { taxonomy: string; location: string }[];
  const findings: ScorableFinding[] = rawFindings.map((f) => ({ taxonomy: f.taxonomy, location: f.location }));

  const scored = scoreCoverage(GROUND_TRUTH_BUGS, findings);
  const summary = summarizeCoverage(scored);

  writeFileSync(join(outDir, "scorecard.json"), JSON.stringify({ summary, bugs: scored }, null, 2));

  console.log(`Coverage scorecard: ${summary.caught} caught, ${summary.missed} missed, ${summary["requires-live-run"]} require a live run (of ${scored.length} planted bugs)`);
  for (const b of scored) console.log(`  [${b.status.padEnd(17)}] ${b.id.padEnd(16)} (${b.severity})`);
}

main();
