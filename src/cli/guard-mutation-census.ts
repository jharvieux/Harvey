import "./sync-stdio.js";
// #1738 — run mutation testing against Harvey's OWN guards and print the surviving-mutant census.
//
// Two modes, because the two things this has to prove are different:
//   (default)          run Stryker over stryker.guards.config.json and census the fresh report.
//   --report <path>    census a report that already exists. This is how the reporter's own failing
//                      direction is exercised, against the committed REAL Stryker capture of the
//                      planted vacuous fixture (src/scan/__fixtures__/stryker/) — a census that
//                      blind to the thing it exists to count would be the joke #1738 is about.
//
// REPORT ONLY: always exits 0. Operator ruling 2026-07-31. Promotion to blocking is a separate,
// later decision — see src/guard-mutation-census.ts.

import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { arg, assertKnownFlags } from "./args.js";
import { formatGuardCensus, guardMutationCensus, guardSetIsFullyAccounted } from "../guard-mutation-census.js";
import type { StrykerReport } from "../mutation-scan.js";

assertKnownFlags(["--report", "--config"]);

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const CONFIG = arg("--config") ?? "stryker.guards.config.json";
const DEFAULT_REPORT = join(REPO_ROOT, "reports", "guard-mutation", "mutation.json");

// Checked before anything runs, and loudly, because this is the one failure the census itself would
// report as good news: a guard dropped from `mutate` leaves the table entirely, and a table with a
// missing row reads exactly like a table with a healthy one.
const accounting = guardSetIsFullyAccounted((JSON.parse(readFileSync(join(REPO_ROOT, CONFIG), "utf8")) as { mutate: string[] }).mutate);
if (accounting.missing.length > 0 || accounting.doubleBooked.length > 0) {
  console.error(
    `✗ ${CONFIG} and GUARD_SET disagree — ${accounting.missing.length} declared guard(s) neither mutated nor disclosed (${accounting.missing.join(", ") || "none"}), ` +
      `${accounting.doubleBooked.length} both (${accounting.doubleBooked.join(", ") || "none"}). The census below would be silently short a row.`,
  );
  process.exit(1);
}

const supplied = arg("--report");
if (!supplied) {
  console.log(`Running Stryker over ${CONFIG} — this mutates the guard set, not the repo. See the config for the target list and why.`);
  execFileSync("node_modules/.bin/stryker", ["run", CONFIG], { cwd: REPO_ROOT, stdio: "inherit" });
}

const reportPath = supplied ? resolve(supplied) : DEFAULT_REPORT;
if (!existsSync(reportPath)) {
  // Fail loud rather than printing an empty census: "no guards with zero kills" and "the run
  // produced nothing" are the same sentence otherwise, and only one of them is good news.
  console.error(`✗ no Stryker report at ${reportPath} — nothing was measured, so nothing is reported. Re-run without --report to produce one.`);
  process.exit(1);
}

const census = guardMutationCensus(JSON.parse(readFileSync(reportPath, "utf8")) as StrykerReport);
console.log(formatGuardCensus(census));
console.log(`\nreport: ${reportPath}`);
