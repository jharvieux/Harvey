// Fix-verification gate (#883) — closes the findings → tickets → re-audit loop. Takes the
// engagement's delivered findings.json as the ONLY scope (it never speaks about code we did not
// already report on), re-runs each finding's own detector against the client's current checkout,
// and classifies every finding:
//
//   resolved     — the detector that produced the finding no longer fires at its location.
//   persistent   — it still fires. The ticket stays open; nothing is written back.
//   regressed    — a prior gate run verified it resolved and it fires again (reintroduced).
//   unverifiable — the detector could not be re-run (no resolver for its taxonomy, engine
//                  unavailable). NEVER treated as resolved: an unrun detector is not a clean
//                  detector (src/fix/verify.ts computeGreen), and a ticket is never closed on
//                  faith — the row is disclosed with its reason instead (coverage doctrine:
//                  silent omission is worse than a wrong status).
//
// The accumulated report IS the self-serve re-audit: each run carries the prior run via --prior,
// matched on the #457 stable finding identity (taxonomy+location — positional ids reshuffle), so
// "this change resolves F-07" and "this change reintroduces F-12" fall out of the status deltas.
// Ticket write-back lives in src/trackers/verify-writeback.ts, keyed on the same marker
// findings-to-tickets stamped when it filed the ticket.

import { execFileSync } from "node:child_process";
import type { Finding } from "../findings.js";
import type { SourceInput } from "../detectors/common.js";
import { loadSources } from "../detectors/load-sources.js";
import { findingIdentity } from "../audit-diff.js";
import { findingMarker } from "../trackers/findings-to-tickets.js";
import { rerunDetector } from "./detector-rerun.js";
import type { DetectorRun } from "./verify.js";

export type GateStatus = "resolved" | "persistent" | "regressed" | "unverifiable";

export interface GateResult {
  findingId: string;
  identity: string; // #457 stable key — how this finding is matched across gate runs
  marker: string; // the dedup marker findings-to-tickets stamped into the filed ticket
  title: string;
  taxonomy: string;
  location: string;
  status: GateStatus;
  detail: string; // detector output, or the notRun reason for an unverifiable row
  previousStatus?: GateStatus; // from the prior gate run, when one was supplied
}

export interface GateReport {
  engagement: string;
  targetDir: string;
  commit: string; // HEAD of the verified checkout, or a stated reason it has none
  generatedAt: string;
  results: GateResult[];
  counts: Record<GateStatus, number>;
}

interface GateOptions {
  // Marker namespace — must match the --engagement the tickets were filed under, or write-back
  // lookups will miss. Default "harvey", same as findings-to-tickets.
  engagement?: string;
  prior?: GateReport; // previous gate run; enables regressed detection
  // Injection points for tests. rerun defaults to the real detector re-run (src/fix/detector-rerun);
  // sources defaults to one loadSources walk shared across all findings.
  rerun?: (finding: Finding, targetDir: string, sources?: SourceInput[]) => DetectorRun | Promise<DetectorRun>;
  sources?: SourceInput[];
}

function targetCommit(targetDir: string): string {
  try {
    return execFileSync("git", ["-C", targetDir, "rev-parse", "HEAD"], { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim();
  } catch {
    return "unknown (target is not a git checkout)";
  }
}

export async function runGate(findings: Finding[], targetDir: string, opts: GateOptions = {}): Promise<GateReport> {
  const engagement = opts.engagement ?? "harvey";
  const rerun = opts.rerun ?? rerunDetector;
  const sources = opts.sources ?? loadSources(targetDir);
  const priorByIdentity = new Map<string, GateStatus>();
  for (const r of opts.prior?.results ?? []) priorByIdentity.set(r.identity, r.status);

  const results: GateResult[] = [];
  const counts: Record<GateStatus, number> = { resolved: 0, persistent: 0, regressed: 0, unverifiable: 0 };

  for (const f of findings) {
    const identity = findingIdentity(f);
    const previousStatus = priorByIdentity.get(identity);
    const run = await rerun(f, targetDir, sources);

    let status: GateStatus;
    if (run.notRun !== undefined) status = "unverifiable";
    else if (run.fired) status = previousStatus === "resolved" ? "regressed" : "persistent";
    else status = "resolved";

    counts[status]++;
    results.push({
      findingId: f.id,
      identity,
      marker: findingMarker(f, engagement),
      title: f.title,
      taxonomy: f.taxonomy,
      location: f.location,
      status,
      detail: run.notRun ?? run.output,
      ...(previousStatus !== undefined ? { previousStatus } : {}),
    });
  }

  return {
    engagement,
    targetDir,
    commit: targetCommit(targetDir),
    generatedAt: new Date().toISOString(),
    results,
    counts,
  };
}
