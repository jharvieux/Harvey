// Ticket write-back for the fix-verification gate (#883). Consumes a GateReport (src/fix/gate.ts)
// and closes the loop on the tickets findings-to-tickets filed: a verified-resolved finding's
// ticket gets a verification comment and is closed; a regressed finding's ticket is reopened with
// a reintroduction comment. Everything else is a disclosed no-op — in particular an `unverifiable`
// row NEVER closes a ticket (an unrun detector is not a clean detector), and a `persistent` row
// leaves its ticket open without spamming a comment per run.
//
// Structure mirrors findings-to-tickets: planWriteback is PURE (no tracker), so a dry-run provably
// cannot touch the network; writeBackVerification is the only path that writes, goes through the
// same pacer, and records a per-finding outcome — a tracker failure on one ticket is captured and
// disclosed, never silently swallowed and never allowed to abort the rest of the batch unseen.

import type { GateReport, GateResult } from "../fix/gate.js";
import { makePacer, type Pacer } from "./rate-limit.js";
import type { CreatedRef, TicketState, TicketWriteback } from "./types.js";

type WritebackIntent = TicketState | "none";

interface PlannedWriteback {
  findingId: string;
  marker: string;
  intent: WritebackIntent;
  reason: string;
  comment?: string; // the verification note, present iff intent !== "none"
}

interface WritebackRecord {
  findingId: string;
  marker: string;
  action: WritebackIntent;
  reason: string;
  ticket?: CreatedRef;
  error?: string; // the tracker call failed; the batch continued, the failure is disclosed here
}

interface WritebackResult {
  records: WritebackRecord[];
  closed: number;
  reopened: number;
  failed: number;
}

function resolvedComment(r: GateResult, report: GateReport): string {
  return [
    `**Harvey fix-verification: resolved** (${r.findingId})`,
    "",
    `The detector that produced this finding (\`${r.taxonomy}\`) no longer fires at \`${r.location}\` — verified against commit \`${report.commit}\`.`,
    "",
    `Detector re-run: ${r.detail}`,
  ].join("\n");
}

function regressedComment(r: GateResult, report: GateReport): string {
  return [
    `**Harvey fix-verification: reintroduced** (${r.findingId})`,
    "",
    `A prior run verified this finding resolved, but its detector (\`${r.taxonomy}\`) fires again at \`${r.location}\` as of commit \`${report.commit}\`. Reopening.`,
    "",
    `Detector re-run: ${r.detail}`,
  ].join("\n");
}

// Pure: what the gate report implies for each ticket, with a reason for every no-op. Write-back
// acts only on TRANSITIONS — a finding already verified resolved by the prior run is not re-closed,
// so repeated gate runs don't churn tickets.
export function planWriteback(report: GateReport): PlannedWriteback[] {
  return report.results.map((r): PlannedWriteback => {
    const base = { findingId: r.findingId, marker: r.marker };
    switch (r.status) {
      case "resolved":
        return r.previousStatus === "resolved"
          ? { ...base, intent: "none", reason: "already verified resolved by the prior gate run" }
          : { ...base, intent: "closed", reason: "detector no longer fires — verified resolved", comment: resolvedComment(r, report) };
      case "regressed":
        return { ...base, intent: "reopened", reason: "previously verified resolved; detector fires again", comment: regressedComment(r, report) };
      case "persistent":
        return { ...base, intent: "none", reason: "still detected — ticket stays open" };
      case "unverifiable":
        return { ...base, intent: "none", reason: `cannot be mechanically verified, never closed on faith: ${r.detail}` };
    }
  });
}

export async function writeBackVerification(
  tracker: TicketWriteback,
  report: GateReport,
  opts: { pacer?: Pacer } = {},
): Promise<WritebackResult> {
  const pacer = opts.pacer ?? makePacer();
  const call = <T>(fn: () => Promise<T>) => pacer.run(fn);
  const result: WritebackResult = { records: [], closed: 0, reopened: 0, failed: 0 };

  for (const planned of planWriteback(report)) {
    if (planned.intent === "none") {
      result.records.push({ findingId: planned.findingId, marker: planned.marker, action: "none", reason: planned.reason });
      continue;
    }
    try {
      const ticket = await call(() => tracker.findByMarker(planned.marker));
      if (!ticket) {
        // No ticket carries this finding's marker — it was never filed (or filed under a different
        // --engagement namespace). Disclosed, not an error: the gate report still records the
        // verification even when there is no ticket to write it to.
        result.records.push({
          findingId: planned.findingId,
          marker: planned.marker,
          action: "none",
          reason: `${planned.reason} — but no ticket found for its marker (not filed, or a different --engagement namespace)`,
        });
        continue;
      }
      await call(() => tracker.addComment(ticket.id, planned.comment as string));
      await call(() => tracker.transitionState(ticket.id, planned.intent as TicketState));
      result.records.push({ findingId: planned.findingId, marker: planned.marker, action: planned.intent, reason: planned.reason, ticket });
      if (planned.intent === "closed") result.closed++;
      else result.reopened++;
    } catch (err) {
      result.failed++;
      result.records.push({
        findingId: planned.findingId,
        marker: planned.marker,
        action: "none",
        reason: planned.reason,
        error: err instanceof Error ? err.message : String(err),
      });
    }
  }

  return result;
}
