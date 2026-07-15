// Audit module-coverage gate. The audit is a 9-module product (M1–M9); a delivery is only
// "complete" when EVERY module is accounted for — either run, or explicitly marked not-applicable
// with a reason. This is the same completeness discipline as the target gate (src/pentest/
// targets.ts): the RAG-backend and the M8/test-health omissions both happened because nothing
// mechanically checked that everything ran. assertModuleCoverage fails loud on any module left in
// an unaccounted (skipped/missing) state, so a module can't be silently dropped from an engagement.

type ModuleNeed = "source" | "connected" | "dynamic" | "llm";

interface AuditModule {
  id: string; // M1..M9
  name: string;
  tools: string; // what runs it
  needs: ModuleNeed; // the minimum environment it requires
  freeTier: boolean; // contributes to the free quick-scan (vs paid-only)
}

// The canonical 9 modules (docs/audit-modules.md / epic #2). `needs` lets the gate tell a
// legitimate environment-gated skip (e.g. M2 with no running app in scope) from a silent
// omission — but even a legitimate skip must be RECORDED as "na" with a reason, never just
// left out. `needs` is the MINIMUM environment: M7 runs its code-level detectors on source
// alone (#170); without a live DB its advisor layer is missing, so it records "partial",
// not "na".
export const AUDIT_MODULES: AuditModule[] = [
  { id: "M1", name: "Multi-tenant security", tools: "D-091 guards + scan-extras + Supabase security advisor + Semgrep", needs: "source", freeTier: true },
  { id: "M2", name: "Local pen test (dynamic)", tools: "seeded target + probe kit (src/pentest)", needs: "dynamic", freeTier: false },
  { id: "M3", name: "Hotspots", tools: "vitals (churn × complexity)", needs: "source", freeTier: false },
  { id: "M4", name: "Duplication", tools: "jscpd", needs: "source", freeTier: true },
  { id: "M5", name: "Slop / dead code", tools: "knip", needs: "source", freeTier: false },
  { id: "M6", name: "Simplification / reuse", tools: "pnpm simplify-scan (assembles the quality-extras M6 brief + target source for a review pass)", needs: "llm", freeTier: false },
  { id: "M7", name: "Performance", tools: "code-level perf detectors (src/detectors/perf-code.ts) + Supabase performance advisor (connected)", needs: "source", freeTier: true },
  { id: "M8", name: "Test quality", tools: "Stryker mutation testing", needs: "source", freeTier: true },
  { id: "M9", name: "Next.js App Router", tools: "scan-extras M9 + detectors", needs: "source", freeTier: true },
];

// Modules with no execution record in ANY engagement, ever. This is a repo-level ledger, not a
// per-engagement one: `na` answers "did this run THIS time," and for a module whose environment is
// absent by default every time (M6 needs the paid LLM tier), the answer is legitimately "no" at
// every individual moment while the module has never executed once. Each `na` was correct; the
// series was a permanent silence. That is the quietest possible failure of "fail loud", so a
// never-executed module is surfaced regardless of tier and blocks `complete` — an engagement
// cannot claim full module coverage on the strength of a module that has never produced output.
//
// Remove an id here the first time that module actually runs against a target. This is a hand-kept
// ledger because nothing yet observes what ran — #229's orchestrator half is what would derive it;
// until then assessModuleCoverage takes its records from the caller and cannot tell on its own.
export const MODULES_NEVER_EXECUTED = new Set<string>([
  // M6: defined 2026-07-09 (#72), still zero output as of 2026-07-15. It now has a runner
  // (`pnpm simplify-scan`, #266); this entry comes out when it is first run against a real target.
  // The #265 eval run was against our own calibration fixtures, not an engagement target, and its
  // result was contaminated (docs/design/m6-simplification-eval.md §3.1) — that is not an execution
  // record.
  "M6",
]);

type ModuleStatus = "ran" | "partial" | "na" | "skipped";

export interface ModuleRecord {
  // "ran" = ALL of the module's in-scope classes executed (even if a result was "no tests exist");
  // "partial" = some classes ran but others didn't (e.g. M2's DB-level RLS ran but the app-route /
  //   seam probes couldn't — no deployed test app) — REQUIRES a note listing what's missing and why;
  // "na" = deliberately not applicable (requires a note); "skipped" = left undone.
  status: ModuleStatus;
  note?: string; // required for "na" AND "partial"
}

// Which environments the engagement actually has. A module whose `needs` isn't available is only
// allowed to be "na", and still must carry a reason — this is what turns "we didn't have a live
// DB" into a recorded decision instead of a silent gap.
interface EngagementEnv {
  connected: boolean; // a live/read-only database was provided
  dynamic: boolean; // a running app / self-hosted clone is available for probing
  llm: boolean; // the paid LLM tier is in scope
}

interface ModuleCoverage {
  complete: boolean; // true only when EVERY module is fully "ran" or "na" — a partial does NOT count
  ran: string[];
  partial: { id: string; note: string }[]; // ran, but not all classes — a disclosed (not silent) gap
  na: { id: string; note: string }[];
  gaps: string[]; // modules neither run nor validly accounted — the fail-loud set
  // Modules that have never executed in any engagement and didn't execute here either. Distinct
  // from `na`: `na` is a defensible per-engagement skip, this is a module with zero output ever.
  // Not folded into `gaps` — a gap is a reasonless omission this engagement, which the caller can
  // fix by recording a reason. This can't be fixed by a note; only by running the module.
  neverRun: string[];
}

export function assessModuleCoverage(records: Record<string, ModuleRecord>, env?: EngagementEnv): ModuleCoverage {
  const ran: string[] = [];
  const partial: { id: string; note: string }[] = [];
  const na: { id: string; note: string }[] = [];
  const gaps: string[] = [];
  for (const mod of AUDIT_MODULES) {
    const rec = records[mod.id];
    if (rec?.status === "ran") {
      ran.push(mod.id);
    } else if (rec?.status === "partial" && rec.note?.trim()) {
      partial.push({ id: mod.id, note: rec.note.trim() });
    } else if (rec?.status === "na" && rec.note?.trim()) {
      na.push({ id: mod.id, note: rec.note.trim() });
    } else {
      // Missing, "skipped", or partial/na without a reason → a gap. Annotate the likely cause.
      const envGated = env && ((mod.needs === "connected" && !env.connected) || (mod.needs === "dynamic" && !env.dynamic) || (mod.needs === "llm" && !env.llm));
      gaps.push(envGated ? `${mod.id} (needs ${mod.needs}: mark na with a reason)` : mod.id);
    }
  }
  // A module in the never-executed ledger that also didn't run here stays loud no matter how well
  // reasoned its `na` note is — that note is exactly what has kept it invisible every time before.
  const neverRun = [...MODULES_NEVER_EXECUTED].filter((id) => !ran.includes(id));

  // A partial is disclosed, so it's not a silent gap — but the audit is NOT fully complete while any
  // module is only partially run. "complete" means every module fully ran or is a reasoned na.
  return { complete: gaps.length === 0 && partial.length === 0 && neverRun.length === 0, ran, partial, na, gaps, neverRun };
}

// Throws on GAPS (silent omission / reasonless skip) and on NEVER-RUN modules. A "partial" is an
// acknowledged, disclosed incompleteness — it does not block delivery, but assess().complete is
// false so the report cannot claim full coverage. Read the returned coverage to surface partials
// honestly.
//
// Why never-run throws rather than warns (#266): a warning is what M6 has effectively had for a
// year — every engagement recorded a correct, well-reasoned `na` and nobody noticed the module had
// never produced a single finding while docs/audit-modules.md sold it as a product wedge. A status
// that doesn't stop anything is the same silence with better paperwork. This is deliberately
// unsatisfiable by note-writing: the only way to clear it is to run the module once and drop it
// from MODULES_NEVER_EXECUTED. Throwing is safe today because the ledger is empty apart from M6 and
// the guard has no callers outside its tests; if that changes and this proves too blunt for a
// scoped engagement, the dial to turn is an explicit opt-out on EngagementEnv, not a downgrade to a
// warning.
export function assertModuleCoverage(records: Record<string, ModuleRecord>, env?: EngagementEnv): void {
  const { gaps, neverRun } = assessModuleCoverage(records, env);
  if (gaps.length) {
    throw new Error(`Incomplete audit-module coverage — ${gaps.length} module(s) unaccounted: ${gaps.join(", ")}. Every module must be run, marked partial (with what's missing), or na (with a reason) before delivery.`);
  }
  if (neverRun.length) {
    throw new Error(`Module(s) ${neverRun.join(", ")} have NEVER executed in any engagement — no output, ever. This is not a per-engagement 'na': no reason clears it, only running the module does (see MODULES_NEVER_EXECUTED). Run it (M6: \`pnpm simplify-scan <target>\`) or remove the product claim.`);
  }
}
