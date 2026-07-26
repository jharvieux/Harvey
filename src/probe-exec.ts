// The ONE real implementation of RunContext.exec — how a probe shells out to its module's CLI.
//
// #1109: it lived twice, copy-pasted into src/cli/run-audit.ts and src/cli/validate-conservation.ts,
// and the copies drifted the moment one of them learned to keep stderr: the orchestrator handed M4
// and M5 their scope counts while the conservation gate — running the same probes over the same
// fixture — did not, so the gate failed on a difference between two spellings of "run the tool".
// A probe's view of the outside world has to be identical in both, so there is one of these.
//
// spawnSync, not execFileSync, because execFileSync RETURNS stdout only: a successful tool's stderr
// was discarded, and that is where quality-scan prints the jscpd/knip scope counts M4 and M5 need to
// say what they examined. stderr is kept SEPARATE from `output` — M4/M5's non-capturing path parses
// stdout as a bare Finding[] JSON, so merging the streams would break it.

import { spawnSync } from "node:child_process";
import type { RunContext } from "./audit-runner.js";

export const probeExec: RunContext["exec"] = (command, argv, opts) => {
  const r = spawnSync(command, argv, {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
    // #520: overlay a per-child env (e.g. a per-project SUPABASE_DB_URL for M10's live tier) onto
    // the inherited environment; absent ⇒ inherit unchanged.
    ...(opts?.env ? { env: { ...process.env, ...opts.env } } : {}),
  });
  const stdout = r.stdout ?? "";
  const stderr = r.stderr ?? "";
  // A tool that exits non-zero or is not installed is a real outcome the probe must judge, not an
  // orchestrator crash — hand it back and let the module's probe describe it.
  if (r.status !== 0) return { ok: false, output: stderr || stdout || r.error?.message || "", stderr };
  return { ok: true, output: stdout, stderr };
};
