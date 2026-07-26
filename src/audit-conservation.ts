// #1064, invariants (4) and (5) — the end-to-end plant-and-assert, and zero-is-suspicious.
//
// The coverage guard proves a module was ACCOUNTED FOR. It does not prove that module's findings
// REACHED THE DELIVERABLE, and every defect of the #1040/#1045/#1050/#1043/#1061/#1062 class lives
// in that gap: the detector worked, the finding never arrived, the ledger read clean and the run
// exited 0. Unit tests could not see it — each of those breaks was at a producer→consumer seam that
// no unit test spans.
//
// So this gate spans it. For each module it asks two questions, in order:
//
//   1. PRODUCED — did THIS module's own probe emit the finding planted for it in the fixture?
//      Zero is a legitimate answer in the field. It is never legitimate on a fixture that carries a
//      planted defect for the module, so zero here is a failure (invariant 5).
//   2. DELIVERED — did that finding survive into the ASSEMBLED deliverable? A produced-but-absent
//      row is the conservation break itself (invariant 4).
//
// The two are separate on purpose. Asking only about the deliverable is not enough: on a
// single-target run M9's probe captures detect-static UNFILTERED, so it re-collects M6/M7/M8 rows,
// and an M7 capture that broke entirely would still show M7 taxonomies in the document. That is
// precisely how #1062 hid — hence question 1 reads findingsByModule (the per-probe attribution),
// not the merged set.
//
// A module that genuinely cannot be exercised offline is recorded in UNEXERCISED with a tagged
// reason and a falsifier, never quietly dropped: a gate that silently omits a module is the very
// shape this file exists to catch.

import { AUDIT_MODULES, type AuditModule, type ModuleCoverage, type ModuleStatus } from "./audit-coverage.js";
import type { Finding } from "./findings.js";

// A defect planted in the fixture, and the signature that identifies its finding. Anchored on
// taxonomy AND location so the row names an actual planted bug: a taxonomy-only match would be
// satisfied by any other finding of the same class, which is how a shrinking scan passes a gate.
interface ModulePlant {
  module: AuditModule;
  /** The planted defect in one line — printed on FAIL so the row says what went missing. */
  plant: string;
  /** Prefix match on Finding.taxonomy. */
  taxonomy: string;
  /** Substring match on Finding.location. */
  location: string;
}

// The plants in targets/calibration. Each was confirmed present by running the gate — a plant
// nobody has watched fire is a claim, not a control.
export const CALIBRATION_PLANTS: ModulePlant[] = [
  { module: "M1", plant: "an RLS SELECT policy with a USING (true) tautology on public.documents", taxonomy: "M1 — Multi-tenant security", location: "documents_select_all" },
  // M3's signal is git-derived, so its "plant" is the fixture's own authorship history rather than
  // anything written into a file — the only shape a hotspot ranking can be planted in.
  // It asserts M3's FULL tier: knowledge-risk (truck-factor) comes from the `vitals` plugin, and the
  // reduced tier (#807, vitals absent) computes a churn×complexity ranking with no knowledge-risk at
  // all. So a run without vitals reports GONE M3 — correctly, since M3 really did not run in full.
  // That is a toolchain prerequisite to install, never a plant to weaken: the runner installs vitals
  // at a pinned commit (.github/workflows/conservation.yml).
  //
  // #1112 asked whether this plant DECAYS — it does, but on a two-year clock, not the 90-day churn
  // window the issue was filed on. MEASURED 2026-07-26 against a throwaway repo with a fully
  // backdated history: at 200 days (churn window exhausted, hotspot table 0 rows) both truck-factor
  // rows still fire, because vitals falls back to all tracked source files when nothing clears the
  // churn gate (vitals_cli.py:131); at 800 days they are gone, because the authorship log is scoped
  // `--since=2.years.ago` (git_analysis.py:260). So the decay is real and slow, and the failure it
  // would cause is now DIAGNOSABLE rather than silent: with no truck-factor row, M3 emits
  // M3-KNOWLEDGE-00 (src/hotspot-scan.ts) naming which of "analysed N files, none sole-authored" and
  // "no authorship history to analyse" happened.
  { module: "M3", plant: "a truck-factor-1 file (one author in the fixture's git history) in the hotspot ranking", taxonomy: "Knowledge risk (truck-factor-1)", location: "targets/calibration" },
  { module: "M4", plant: "a copy-pasted report builder duplicated across dup/report-a.ts and dup/report-b.ts", taxonomy: "M4 — Duplication", location: "dup/report-a.ts" },
  { module: "M5", plant: "a module nothing imports (dead/never-imported.ts)", taxonomy: "M5 — Slop / dead code", location: "dead/never-imported.ts" },
  { module: "M6", plant: "a hand-rolled random-string id generator in lib/token.js", taxonomy: "M6 — Indicator: random-string id", location: "lib/token.js" },
  { module: "M7", plant: "a raw <img> where next/image belongs, in components/ImgAttr.jsx", taxonomy: "M7 — Raw <img> instead of next/image", location: "components/ImgAttr.jsx" },
  { module: "M8", plant: "an assertion-free test in test-quality/audit-log.deletion-surviving.test.ts", taxonomy: "M8 — Assertion-free test", location: "test-quality/audit-log.deletion-surviving.test.ts" },
  { module: "M9", plant: "a server→client data leak in app/documents/detail-page.tsx", taxonomy: "M9 — Server→client data leak", location: "app/documents/detail-page.tsx" },
  { module: "M10", plant: "a table of regulated columns (public.profiles) in the migration schema", taxonomy: "M10 — Data classification (PII/PHI/PCI)", location: "profiles" },
];

// REASON: M2 cannot be plant-and-asserted offline — its probes drive a stood-up two-tenant Supabase stack over HTTP, which this gate does not and must not provision, so targets/calibration carries no M2 plant to assert
// KIND: empirical
// PROVENANCE: MEASURED 2026-07-26 (ran the gate on targets/calibration: M2's probe reports requires-live-run with 0 findings while all nine other modules produced and delivered their plant)
// FALSIFIER: pnpm exec tsx src/cli/validate-conservation.ts --require M2
// TOUCHES: src/audit-runners.ts src/cli/pentest.ts
export const UNEXERCISED: { module: AuditModule; reason: string }[] = [
  {
    module: "M2",
    reason:
      "M2 probes a running two-tenant stack (pnpm exec tsx src/cli/pentest.ts against a stood-up local Supabase, docs/runbooks/m2-pentest-ops.md). This gate is offline, so there is no M2 plant in targets/calibration to assert. Falsifier: `pnpm exec tsx src/cli/validate-conservation.ts --require M2` — it exits 0 the day M2 delivers findings from this fixture.",
  },
];

// A module in NEITHER list would be silently outside the gate — the omission this whole file
// exists to make impossible. Checked at module load so the failure arrives before any run does.
{
  const covered = new Set<AuditModule>([...CALIBRATION_PLANTS.map((p) => p.module), ...UNEXERCISED.map((u) => u.module)]);
  const missing = AUDIT_MODULES.filter((m) => !covered.has(m));
  if (missing.length) {
    throw new Error(
      `Conservation gate does not account for ${missing.join(", ")} — every module of M1–M10 needs either a plant in CALIBRATION_PLANTS or an entry in UNEXERCISED with its reason (#1064). A module in neither is one the gate cannot know it skipped.`,
    );
  }
  const both = CALIBRATION_PLANTS.map((p) => p.module).filter((m) => UNEXERCISED.some((u) => u.module === m));
  if (both.length) throw new Error(`Conservation gate both plants and excuses ${both.join(", ")} — two answers to "is this module exercised".`);
}

type ConservationVerdict = "delivered" | "lost-in-assembly" | "not-produced" | "unexercised";

interface ConservationRow {
  module: AuditModule;
  verdict: ConservationVerdict;
  /** The planted defect, or the reason the module is unexercised. */
  detail: string;
  /** Findings matching the plant that the module's OWN probe emitted. */
  produced: number;
  /** Findings matching the plant present in the assembled deliverable. */
  delivered: number;
  /** The probe's own ledger status and reason, quoted so a not-produced row says why. */
  probeStatus?: ModuleStatus;
  probeReason?: string;
}

interface ConservationReport {
  rows: ConservationRow[];
  ok: boolean;
}

interface ConservationInput {
  /** Per-probe findings from runAudit — the attribution the merged array loses. */
  findingsByModule: Partial<Record<AuditModule, Finding[]>>;
  /** The derived coverage ledger, for quoting a not-produced module's own reason. */
  recorded: ModuleCoverage[];
  /** The findings of the ASSEMBLED deliverable, post-dedupe/enrichment. */
  delivered: Finding[];
  /**
   * Modules from UNEXERCISED to hold to the full standard anyway. This is the falsifier path: a
   * recorded "cannot run offline" is a claim about the world, and `--require M2` is the command
   * that exits 0 the day it stops being true. A required-but-unplanted module is judged on ANY
   * finding, since there is no plant to name.
   */
  required?: AuditModule[];
}

export function checkConservation(input: ConservationInput): ConservationReport {
  const required = new Set(input.required ?? []);
  const rows: ConservationRow[] = [];

  for (const module of AUDIT_MODULES) {
    const probeRow = input.recorded.find((r) => r.module === module);
    const probeStatus = probeRow ? { probeStatus: probeRow.status, ...(probeRow.reason ? { probeReason: probeRow.reason } : {}) } : {};
    const plant = CALIBRATION_PLANTS.find((p) => p.module === module);
    const unexercised = UNEXERCISED.find((u) => u.module === module);

    if (unexercised && !required.has(module)) {
      rows.push({ module, verdict: "unexercised", detail: unexercised.reason, produced: 0, delivered: 0, ...probeStatus });
      continue;
    }
    // A required-but-unplanted module has no signature to match, so any finding counts: the
    // question `--require` asks is whether the module produces anything at all here.
    const hit = plant ? (f: Finding) => f.taxonomy.startsWith(plant.taxonomy) && f.location.includes(plant.location) : () => true;
    const detail = plant ? plant.plant : "no plant defined — judged on any finding this module produced (--require)";
    const producedFindings = (input.findingsByModule[module] ?? []).filter(hit);
    // With a plant, the delivered side is counted by the SAME signature — so a module that produced
    // nothing while another probe's unfiltered capture delivered the identical row shows up as
    // produced=0 delivered=1, which names the #1062 defect exactly. Without a plant there is no
    // signature, so the question narrows to "of what this module produced, how much arrived".
    const producedIds = new Set(producedFindings.map((f) => f.id));
    const delivered = plant ? input.delivered.filter(hit).length : input.delivered.filter((f) => producedIds.has(f.id)).length;
    const verdict: ConservationVerdict = producedFindings.length === 0 ? "not-produced" : delivered === 0 ? "lost-in-assembly" : "delivered";
    rows.push({ module, verdict, detail, produced: producedFindings.length, delivered, ...probeStatus });
  }

  return { rows, ok: rows.every((r) => r.verdict === "delivered" || r.verdict === "unexercised") };
}

const MARK: Record<ConservationVerdict, string> = {
  delivered: "PASS",
  "lost-in-assembly": "LOST",
  "not-produced": "GONE",
  unexercised: "SKIP",
};

export function formatConservation(report: ConservationReport): string {
  const table = report.rows.map(
    (r) => `  ${MARK[r.verdict]}  ${r.module.padEnd(4)} produced=${String(r.produced).padEnd(4)} delivered=${String(r.delivered).padEnd(4)} ${r.detail}`,
  );
  const notes = report.rows.map((r) => {
    if (r.verdict === "not-produced") {
      return `GATE FAIL — ${r.module} produced NOTHING here: ${r.detail}. Zero findings is a legitimate field answer and never a legitimate fixture answer — either the detector regressed or the probe stopped capturing. The probe recorded ${r.probeStatus ?? "no row"}${r.probeReason ? `: ${r.probeReason}` : ""}`;
    }
    if (r.verdict === "lost-in-assembly") {
      return `GATE FAIL — ${r.module} produced ${r.produced} finding(s) for its planted defect (${r.detail}) and the assembled deliverable carries NONE. This is a producer→consumer break — the #1040/#1061/#1062 class — not a detection gap.`;
    }
    if (r.verdict === "unexercised") return `NOT EXERCISED — ${r.module}: ${r.detail}`;
    return "";
  });
  if (report.ok) notes.push("CONSERVATION PASS — every exercised module's planted finding reached the deliverable.");
  return ["Conservation of findings — per-module plant → deliverable (#1064)", "", ...table, "", ...notes.filter(Boolean)].join("\n");
}
