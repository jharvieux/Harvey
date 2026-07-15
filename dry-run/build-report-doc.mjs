// Wraps dry-run/findings.json (a raw Finding[] from src/cli/dry-run.ts) in the meta envelope
// report-template/render.mjs expects, so the real dry-run output can be pushed through the
// actual render pipeline (issue #34 deliverable 5). Not a general tool — a one-off glue script
// for this dry run; the meta fields are deliberately honest about this being a partial,
// mechanical-only pass, not a scored client audit.
import { readFileSync, writeFileSync } from "node:fs";

const findings = JSON.parse(readFileSync("dry-run/findings.json", "utf8"));

// Read the caught/missed tally off the scorecard rather than restating it by hand — a hardcoded
// headline silently went stale ("0 of 8") when the run was regenerated (#246). Run
// src/cli/dry-run-scorecard.ts before this script.
const { summary } = JSON.parse(readFileSync("dry-run/scorecard.json", "utf8"));
const plantedTotal = summary.caught + summary.missed + summary["requires-live-run"];

const doc = {
  meta: {
    client: "Calibration target (internal dry run — issue #34)",
    subtitle: "PARTIAL — mechanical scan + M1 detect-deeper only; no live DB/Docker in this pass",
    date: new Date().toISOString().slice(0, 10),
    commit: "dry-run scratch snapshot (git-initialized copy of targets/calibration, see docs/runbooks/dry-run-calibration.md)",
    auditor: "Harvey dry-run harness (src/cli/dry-run.ts)",
    confidential: false,
    overallHealth: 0,
    tenantIsolation: "NOT ASSESSED IN THIS PASS — the 3 planted RLS bugs (GROUND-TRUTH.md #1-#3) require either a live Supabase Advisor run or a manual/LLM policy-semantics read, neither of which ran here; see docs/runbooks/dry-run-calibration.md.",
    authModel: "N/A — not evaluated in this pass.",
    headline: `This is NOT a scored audit. It demonstrates the findings.json -> report render pipeline using REAL output from a real (partial) scan run. ${summary.caught} of ${plantedTotal} GROUND-TRUTH.md planted bugs were caught by the modules that ran in this sandbox (${summary.missed} missed, ${summary["requires-live-run"]} require a live run); see the coverage scorecard (dry-run/scorecard.json) for why.`,
    scope: "targets/calibration (mechanical scan: secrets/deps/semgrep/supply-chain/leftover-auth; M1 detect-deeper grant/definer classifiers fed from migration SQL; M10 PII data map).",
    methodology: "src/cli/dry-run.ts — see docs/runbooks/dry-run-calibration.md for exactly what ran and what didn't.",
    outOfScope: "Everything requiring Docker/a live DB or the LLM /threat-model+/vuln-scan+/triage pass — not available in this sandbox.",
  },
  findings,
};

writeFileSync("dry-run/findings-report.json", JSON.stringify(doc, null, 2));
console.log(`Wrote dry-run/findings-report.json (${findings.length} findings)`);
