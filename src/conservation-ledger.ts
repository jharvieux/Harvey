// #1096 invariant (1) — the conservation LEDGER. Sibling of src/audit-conservation.ts's invariants
// (4) and (5), and deliberately a different question.
//
//   (4)/(5) ask: did the ONE finding we planted for module Mn survive probe → deliverable?
//   (1) asks:   did ALL of them? — arithmetic over the whole set, no fixture and no plant required,
//               so it holds on a real client engagement where nothing is planted.
//
// The equation, asserted at the produce→assemble seam:
//
//   produced == delivered_from_produced + deduped + suppressed + capped + notApplicable
//   delivered == delivered_from_produced + synthesized
//
// Every produced finding must land in exactly one column. A finding in none of them is
// `unaccounted` — it was produced, it is not in the deliverable, and nothing in the pipeline says
// why. That is #1040 (385 findings discarded), #1050, #1061 and #1062 in one number, and it is a
// LOUD failure: an unaccounted delta is exactly the silence the coverage doctrine forbids.
//
// Independent by construction. This does NOT read the assembler's own bookkeeping — it recounts
// produced against delivered from the two arrays. So if dedupeFindings is ever changed to drop
// something that is not a byte-identical duplicate, the drop shows up here as unaccounted rather
// than being blessed by the very code that made it. Two implementations agreeing is the evidence;
// one implementation grading its own homework is not.
//
// Scope of the seam: probes → assembleEngagementDocument. The baseline diff (#457, applyBaseline)
// runs AFTER this and legitimately tags (never drops) the current set while carrying resolved rows
// in from a prior engagement, so it sits outside THIS ledger. It is not unmeasured, though: its own
// arithmetic is `baselineLedger` below, asserted across applyBaseline on the same discipline (#1146).
// Stated rather than assumed: see docs/design/conservation-of-findings.md.

import { contentIdentity } from "../report-template/dispositions.mjs";
import type { AuditModule } from "./audit-coverage.js";
import type { Finding } from "./findings.js";

// A finding the ASSEMBLER adds that no probe produced. Declared, so a gain is a deliberate act by a
// named piece of code rather than an unexplained row in the client's report. Anything delivered
// that is neither produced nor on this list fails the gate the same way a loss does — a report that
// grows findings out of nowhere is as wrong as one that loses them.
// M10-ESCALATION-00: with no M10 data map, EVERY severity in the report is un-escalated, and an
// un-escalated severity is indistinguishable from one checked against the map and left alone — so
// the assembler states that absence as its own row (#1049).
const SYNTHESIZERS: { id: string; by: string }[] = [{ id: "M10-ESCALATION-00", by: "dataClassJoinNotAssessed (src/data-class-escalation.ts)" }];

/** Why a produced finding is not in the deliverable. `unaccounted` is the failure. */
type Disposition = "delivered" | "deduped" | "suppressed" | "capped" | "not-applicable" | "unaccounted";

// A finding a pipeline transform DELIBERATELY dropped between produce and assemble, naming the column
// it belongs in and the code that dropped it. This is the producer for the suppressed/capped/
// not-applicable columns: without it the arithmetic has no way to tell a legitimate suppression from
// the #1040 silent loss, so a legitimate drop would surface as `unaccounted` and a false failure.
//
// There is NO such transform in the produce→assemble seam today, so run-audit passes none and the
// three columns read zero. But the slot is now LIVE and VALIDATED, not a hardcoded literal: a
// declared drop must correspond to a finding that was PRODUCED and is ABSENT from the deliverable —
// claiming to have suppressed a finding that still ships, or one no probe produced, is itself a
// LEDGER FAIL (`misdeclaredDispositions`). The nearest real cap is #935's >N-per-shape rollup, which
// runs at RENDER (report-template/rollup.mjs), downstream of this seam, and carries its own
// conservation test; if that rollup is ever moved into assembly it declares its withheld rows here.
export interface DeclaredDrop {
  id: string;
  /** Required when one producer ID names multiple different observations. */
  contentKey?: string;
  disposition: "suppressed" | "capped" | "not-applicable";
  reason: string;
  /** The pipeline code that performed the drop — so a nonzero column names who filled it. */
  by: string;
}

interface LedgerRow {
  id: string;
  contentKey?: string;
  disposition: Disposition;
  /** Why this finding is not delivered. Empty ONLY for `delivered`; `unaccounted` means nobody said. */
  reason: string;
  /** The probe(s) that produced it, when attribution is available — so a loss names its module. */
  modules: AuditModule[];
}

interface ConservationLedger {
  produced: number;
  delivered: number;
  /** The columns of the equation. suppressed/capped/notApplicable are fed by DeclaredDrop entries
   * (see the type) — no transform declares any today, so they read zero, but a nonzero one now can
   * only come from a declared drop this ledger verified was really produced and really absent. */
  deliveredFromProduced: number;
  deduped: number;
  suppressed: number;
  capped: number;
  notApplicable: number;
  unaccounted: number;
  /** Delivered rows no probe produced: declared synthesizers, plus any undeclared gain (a failure). */
  synthesized: number;
  undeclaredGains: string[];
  /** Declared drops that did not correspond to a real loss — a finding claimed suppressed/capped/
   * not-applicable that still ships, or that no probe produced. A bookkeeping lie is a failure. */
  misdeclaredDispositions: string[];
  /** Every non-delivered produced finding, with its reason. Delivered rows are not listed. */
  rows: LedgerRow[];
  ok: boolean;
}

const bodyKey = (f: Finding): string => JSON.stringify(f);

// Attribution for a finding id, from runAudit's per-probe map. Ids can be produced by two probes
// (the shared-CLI captures), so this is a list, and it is empty when the caller has no map.
const attribute = (byModule: Partial<Record<AuditModule, Finding[]>>): Map<string, AuditModule[]> => {
  const out = new Map<string, AuditModule[]>();
  for (const [module, findings] of Object.entries(byModule) as [AuditModule, Finding[]][]) {
    for (const f of findings) out.set(f.id, [...new Set([...(out.get(f.id) ?? []), module])]);
  }
  return out;
};

/**
 * @param produced  every finding the probes emitted, before assembly — runAudit's `findings`.
 * @param delivered the assembled document's findings.
 * @param byModule  runAudit's per-probe attribution, so a loss names the module that produced it.
 * @param declared  drops a transform DELIBERATELY made (suppressed/capped/not-applicable), each
 *                  verified real — the producer for those three columns. Empty in the pipeline today.
 */
export function conservationLedger(produced: Finding[], delivered: Finding[], byModule: Partial<Record<AuditModule, Finding[]>> = {}, declared: DeclaredDrop[] = []): ConservationLedger {
  const owners = attribute(byModule);
  const unique = new Map<string, { finding: Finding; copies: number }>();
  for (const f of produced) {
    const key = bodyKey(f);
    const entry = unique.get(key);
    if (entry) entry.copies++;
    else unique.set(key, { finding: f, copies: 1 });
  }
  const rows: LedgerRow[] = [];
  const consumed = new Set<number>();
  const credited = new Set<DeclaredDrop>();
  let deliveredFromProduced = 0;
  let deduped = 0;
  let suppressed = 0;
  let capped = 0;
  let notApplicable = 0;
  let unaccounted = 0;
  for (const { finding: f, copies } of unique.values()) {
    const contentKey = contentIdentity(f);
    const modules = owners.get(f.id) ?? [];
    if (copies > 1) {
      deduped += copies - 1;
      rows.push({ id: f.id, contentKey, modules, disposition: "deduped", reason: `${copies - 1} byte-identical duplicate capture(s) collapsed; content ${contentKey}` });
    }
    const index = delivered.findIndex((d, i) => !consumed.has(i) && contentIdentity(d) === contentKey);
    if (index >= 0) { consumed.add(index); deliveredFromProduced++; continue; }
    const sameId = [...unique.values()].filter((x) => x.finding.id === f.id).length;
    const drops = declared.filter((d) => !credited.has(d) && d.id === f.id && (d.contentKey === contentKey || (!d.contentKey && sameId === 1)) && d.reason.trim() && d.by.trim());
    if (drops.length === 1) {
      const drop = drops[0]!;
      credited.add(drop);
      if (drop.disposition === "suppressed") suppressed++;
      else if (drop.disposition === "capped") capped++;
      else notApplicable++;
      rows.push({ id: f.id, contentKey, modules, disposition: drop.disposition, reason: `${drop.reason} — dropped by ${drop.by}` });
    } else {
      unaccounted++;
      rows.push({ id: f.id, contentKey, modules, disposition: "unaccounted", reason: "" });
    }
  }
  const misdeclaredDispositions = declared.filter((d) => !credited.has(d)).map((d) => d.id);
  const gains = delivered.filter((_f, i) => !consumed.has(i));
  const synthesizerIds = new Set(SYNTHESIZERS.map((s) => s.id));
  const undeclaredGains = gains.filter((f) => !synthesizerIds.has(f.id) || produced.some((p) => p.id === f.id)).map((f) => f.id);
  return { produced: produced.length, delivered: delivered.length, deliveredFromProduced, deduped, suppressed, capped, notApplicable, unaccounted,
    synthesized: gains.length, undeclaredGains, misdeclaredDispositions, rows,
    ok: unaccounted === 0 && undeclaredGains.length === 0 && misdeclaredDispositions.length === 0 };
}

export function formatLedger(ledger: ConservationLedger): string {
  const lines = [
    "Conservation ledger — produced → delivered (#1096, invariant 1)",
    "",
    `  produced   ${ledger.produced}`,
    `  = delivered_from_produced ${ledger.deliveredFromProduced} + deduped ${ledger.deduped} + suppressed ${ledger.suppressed} + capped ${ledger.capped} + not-applicable ${ledger.notApplicable} + UNACCOUNTED ${ledger.unaccounted}`,
    `  delivered  ${ledger.delivered} = delivered_from_produced ${ledger.deliveredFromProduced} + synthesized ${ledger.synthesized}`,
  ];
  const lost = ledger.rows.filter((r) => r.disposition === "unaccounted");
  if (lost.length) {
    lines.push(
      "",
      `LEDGER FAIL — ${ledger.unaccounted} finding(s) were PRODUCED and are not in the deliverable, and nothing in the pipeline says why. This is the #1040/#1050/#1061/#1062 class: the detector worked and the row was dropped at a producer→consumer seam.`,
      ...lost.map((r) => `  LOST  ${r.id}${r.modules.length ? ` (produced by ${r.modules.join(", ")})` : " (no module attribution supplied)"}`),
    );
  }
  if (ledger.undeclaredGains.length) {
    lines.push(
      "",
      `LEDGER FAIL — ${ledger.undeclaredGains.length} finding(s) are in the deliverable that NO probe produced and no synthesizer declares: ${ledger.undeclaredGains.join(", ")}. A report that grows rows from nowhere is as wrong as one that loses them; declare the synthesizer in src/conservation-ledger.ts (today: ${SYNTHESIZERS.map((s) => `${s.id} by ${s.by}`).join("; ")}) or find where the row came from.`,
    );
  }
  if (ledger.misdeclaredDispositions.length) {
    lines.push(
      "",
      `LEDGER FAIL — ${ledger.misdeclaredDispositions.length} finding(s) were declared suppressed/capped/not-applicable but did not actually go missing (they still ship, or no probe produced them): ${ledger.misdeclaredDispositions.join(", ")}. A disposition column may only be credited against a finding that was produced and is absent from the deliverable.`,
    );
  }
  if (ledger.ok) lines.push("", "LEDGER PASS — every produced finding is delivered or accounted for, and every delivered finding was produced or declared.");
  return lines.join("\n");
}

// #1146 invariant across the baseline seam. The ledger above stops at assembleEngagementDocument;
// applyBaseline (#457, src/audit-diff.ts) runs AFTER it and was unmeasured — a finding could be
// dropped there with no ledger row. This closes that gap with the same arithmetic, one seam later:
//
//   entered == retained + removed        (findings that went into applyBaseline)
//   exited  == retained + gained         (findings that came out)
//
// applyBaseline TAGS the current set (baselineStatus) and never drops or adds a member of it — the
// resolved rows it surfaces come from the PRIOR engagement and live in doc.baseline, not
// doc.findings. So the honest invariant today is removed == 0 AND gained == 0: any finding that
// entered and did not exit was silently deleted by a baseline-application bug (the NEW finding the
// task guards), and any row that exited without entering was invented. Matching is by finding id,
// which applyBaseline preserves (it spreads `{ ...current, baselineStatus }`). If a future baseline
// design legitimately withholds accepted/persistent findings, it must ACCOUNT each removal — declare
// it, don't drop it — exactly as the disposition columns above require.
interface BaselineLedger {
  entered: number;
  exited: number;
  retained: number;
  /** Findings that entered applyBaseline and did not exit — a silent deletion. Empty is the pass. */
  removed: { id: string; modules: AuditModule[] }[];
  /** Ids that exited applyBaseline without entering — a row invented by the baseline diff. */
  gained: string[];
  ok: boolean;
}

export function baselineLedger(before: Finding[], after: Finding[], byModule: Partial<Record<AuditModule, Finding[]>> = {}): BaselineLedger {
  const owners = attribute(byModule);
  const consumed = new Set<number>();
  const removed: { id: string; modules: AuditModule[] }[] = [];
  for (const f of before) {
    const index = after.findIndex((x, i) => !consumed.has(i) && contentIdentity(x) === contentIdentity(f));
    if (index >= 0) consumed.add(index);
    else removed.push({ id: f.id, modules: owners.get(f.id) ?? [] });
  }
  const gained = after.filter((_f, i) => !consumed.has(i)).map((f) => f.id);
  return { entered: before.length, exited: after.length, retained: consumed.size, removed, gained, ok: removed.length === 0 && gained.length === 0 };
}

export function formatBaselineLedger(ledger: BaselineLedger): string {
  const lines = [
    "Baseline ledger — across applyBaseline (#457/#1146)",
    "",
    `  entered ${ledger.entered} = retained ${ledger.retained} + removed ${ledger.removed.length}`,
    `  exited  ${ledger.exited} = retained ${ledger.retained} + gained ${ledger.gained.length}`,
  ];
  if (ledger.removed.length) {
    lines.push(
      "",
      `BASELINE LEDGER FAIL — ${ledger.removed.length} finding(s) entered the baseline diff and did not come out: the baseline application silently deleted them. A resolved/persistent tag must never drop a current finding.`,
      ...ledger.removed.map((r) => `  DELETED  ${r.id}${r.modules.length ? ` (produced by ${r.modules.join(", ")})` : " (no module attribution supplied)"}`),
    );
  }
  if (ledger.gained.length) {
    lines.push("", `BASELINE LEDGER FAIL — ${ledger.gained.length} row(s) came out of the baseline diff that did not go in: ${ledger.gained.join(", ")}. The baseline diff tags the current set; it may not invent or duplicate a member of it.`);
  }
  if (ledger.ok) lines.push("", "BASELINE LEDGER PASS — the baseline diff tagged the current set and neither dropped nor invented a finding.");
  return lines.join("\n");
}
