// The assembler half of #312. run-audit derives the coverage ledger and captures each emitting
// module's findings; this turns those into the single engagement findings.json that
// report-template/ and `pnpm validate:findings` consume. It is what removes the manual "collect
// every module's output by hand" step — a step the operator could do incompletely, leaving a
// module's findings silently out of the deliverable.
//
// The coverage ledger travels WITH the findings so a module that produced no findings because it
// never ran (a requires-live-run row, with its reason) stays distinguishable from a module that ran
// and found nothing (a "ran" row) — those are different claims and the report must not collapse
// them into the same silence (#349).

import { buildAuditCoverage, type EngagementEnv, type ModuleCoverage } from "./audit-coverage.js";
import type { CoverageRow, Finding, FindingsDocument, ReportMeta } from "./findings.js";
import { enrichFindingsWithHotspots } from "./hotspot-scan.js";

// The derived coverage report's rows, projected onto the report schema's CoverageRow.
export function coverageLedger(recorded: ModuleCoverage[], env?: EngagementEnv): CoverageRow[] {
  return buildAuditCoverage(recorded, env).rows.map((r) => ({
    module: r.module,
    name: r.name,
    status: r.status,
    ...(r.instance ? { instance: r.instance } : {}),
    ...(r.reason ? { reason: r.reason } : {}),
    ...(r.detail ? { detail: r.detail } : {}),
    ...(r.subStatus ? { subStatus: r.subStatus } : {}),
  }));
}

// Drops byte-identical duplicates (same id AND same content) — the shared-CLI capture case, where
// quality-scan is captured under both M4 and M5, and detect-static under both M7 and M9, yields the
// same Finding[] twice. A same-id-but-different-content collision is deliberately left in place so
// validateFindings flags it loudly rather than letting one variant silently win.
export function dedupeFindings(findings: Finding[]): Finding[] {
  const seen = new Set<string>();
  const out: Finding[] = [];
  for (const f of findings) {
    const key = JSON.stringify(f);
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(f);
  }
  return out;
}

// #515: when the run captured an M3 hotspot ranking, tag every module's findings on a ranked hotspot
// (onHotspot/hotspotRank) so the report up-ranks them across modules — one mechanism, every module.
// Absent hotspots ⇒ findings pass through untagged, unchanged.
export function assembleEngagementDocument(recorded: ModuleCoverage[], env: EngagementEnv, findings: Finding[], meta: ReportMeta, hotspots?: string[]): FindingsDocument {
  const deduped = dedupeFindings(findings);
  const enriched = hotspots?.length ? enrichFindingsWithHotspots(deduped, hotspots) : deduped;
  return { meta, coverage: coverageLedger(recorded, env), findings: enriched };
}
