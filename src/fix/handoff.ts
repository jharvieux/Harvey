// Client handoff section (design §1.5). The engagement report's fix summary: every approved finding as
// a row — PR'd, delivered-inert-pending-transport, awaiting an implementer, downgraded, blocked, or
// aborted — never an omission. A downgraded fix is a ROW WITH A REASON, not a silent drop (CLAUDE.md:
// silent omission is worse than a wrong status). It carries the merge-order advisory (§4) alongside, so
// the client gets finding id → status → PR link → verification → recommended merge order in one place.

import type { Severity } from "../findings.js";
import { emitMergeOrder, scheduleFixes, type MergeOrder, type ScheduleNode } from "./schedule.js";

// The delivery/decision state of one approved fix. The first three become PRs (they carry a merge
// rank); the rest are the "why not automated" half of the deliverable (§3.2).
export type HandoffStatus =
  | "pr-opened" // draft PR is open, awaiting the operator gate → client merge
  | "verified-inert" // diff verified against a disposable worktree; no PR yet (transport is a later gate)
  | "awaiting-implementer" // screened auto, but no implementer diff was produced
  | "manual" // ease/safety below the automated threshold — an operator drafts it
  | "recommend-only" // downgraded: needs DB/secret/contract/product judgment (§3.2)
  | "rails-blocked" // a diff that would touch a denylisted/out-of-allowlist/over-cap path
  | "verify-failed" // a diff that did not apply clean / did not verify
  | "aborted" // rail-violation or stale-location abort
  | "not-approved"; // present in the findings doc but not client-approved for this engagement

// Statuses that will become a PR — the ones the merge order sequences.
const DELIVERABLE: ReadonlySet<HandoffStatus> = new Set(["pr-opened", "verified-inert", "awaiting-implementer"]);

interface HandoffRow {
  findingId: string;
  status: HandoffStatus;
  severity?: Severity;
  prUrl?: string;
  verification?: string; // how it was verified (or why not), verbatim
  reason?: string; // downgrade / block / abort / not-approved reason
  mergeRank?: number; // 1-based position in the merge order, deliverable rows only
}

interface FixHandoff {
  client: string;
  baselineCommit: string;
  rows: HandoffRow[];
  mergeOrder: MergeOrder;
}

// One approved finding's outcome, as the caller (the CLI, or a future transport-integrated runner)
// resolved it. `files` feeds the merge scheduler; it is only read for DELIVERABLE statuses.
export interface FixOutcomeSummary {
  findingId: string;
  severity: Severity;
  bftb: number;
  files: string[];
  status: HandoffStatus;
  prUrl?: string;
  verification?: string;
  reason?: string;
}

interface HandoffInputs {
  client: string;
  baselineCommit: string;
  outcomes: FixOutcomeSummary[]; // every approved finding, each already resolved to a status
  notApproved?: string[]; // findings present but not client-approved — listed for transparency
}

export function assembleHandoff(input: HandoffInputs): FixHandoff {
  const deliverable = input.outcomes.filter((o) => DELIVERABLE.has(o.status) && o.files.length > 0);
  const nodes: ScheduleNode[] = deliverable.map((o) => ({ findingId: o.findingId, severity: o.severity, bftb: o.bftb, files: o.files }));
  const mergeOrder = emitMergeOrder(scheduleFixes(nodes), nodes);
  const rankOf = new Map(mergeOrder.order.map((id, i) => [id, i + 1]));

  const rows: HandoffRow[] = input.outcomes.map((o) => ({
    findingId: o.findingId,
    status: o.status,
    severity: o.severity,
    prUrl: o.prUrl,
    verification: o.verification,
    reason: o.reason,
    mergeRank: rankOf.get(o.findingId),
  }));
  for (const id of input.notApproved ?? []) {
    rows.push({ findingId: id, status: "not-approved", reason: "present in findings but not client-approved for this engagement" });
  }
  return { client: input.client, baselineCommit: input.baselineCommit, rows, mergeOrder };
}
