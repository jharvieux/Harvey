// The audit-level coverage gate (issue #229). Harvey's deliverable is all TEN modules (M1–M10),
// not a security subset — an engagement that quietly runs M1/M4/M7/M9 and drops the rest is a
// coverage FAILURE, not a scan. That has happened; this module is the guard.
//
// It lifts the discipline that already existed one level down — assertComplete (src/pentest/
// targets.ts) fails loud on an enumerated-but-untested M2 target, and coverage-scorecard.ts's
// moduleRan never guesses that a module executed — from "every target within M2" up to "every
// module of the audit".
//
// The rule it enforces: a module that cannot run is recorded `partial`/`requires-live-run` WITH
// THE REASON. Never silently omitted, never assumed to have run. An unaccounted-for module is an
// error, and a reason-less excuse is itself unaccounted for.
//
// This is the pure ledger + gate. Executing the ten runners is the caller's job (they span
// separate CLIs, tiers, and prereqs — see CLAUDE.md's module table); the caller records what it
// actually did here, and assertAuditComplete decides whether that constitutes an audit.
//
// #288: this was one of TWO coverage guards. src/audit/module-coverage.ts enumerated nine modules
// while this one enumerated ten, and nothing reconciled them — which is how #275 ("M10 is
// invisible") was possible. Two answers to "did every module run?" makes the guarantee
// unenforceable, so the dead guard was deleted and its distinctive parts merged here: the
// MODULES_NEVER_EXECUTED ledger, the needs/freeTier metadata, and env-gated gap annotation.

import { neverExecutedModules, readExecutionLog } from "./audit-execution-log.js";

// The ten modules of the audit. Authoritative scope: briefs/audit-modules.md — audit-coverage.test.ts
// reads that file and asserts this list matches it, so the doc cannot drift from the code (#275).
export const AUDIT_MODULES = ["M1", "M2", "M3", "M4", "M5", "M6", "M7", "M8", "M9", "M10"] as const;

export type AuditModule = (typeof AUDIT_MODULES)[number];

// The minimum environment a module requires. Lets the gate tell a legitimate environment-gated
// skip (e.g. M2 with no running app in scope) from a silent omission — it annotates the gap with
// what was missing rather than excusing it. This is the MINIMUM: M7 runs its code-level detectors
// on source alone (#170) and M10 classifies columns straight out of migration SQL (#250); without
// a live DB each loses a layer, so each records "partial", not a skip.
type ModuleNeed = "source" | "connected" | "dynamic" | "llm";

// `freeTier`: contributes to the free quick-scan (vs paid-only). Per-module split:
// docs/free-tier-scope.md.
export const MODULES: Record<AuditModule, { name: string; needs: ModuleNeed; freeTier: boolean }> = {
  M1: { name: "Multi-tenant security", needs: "source", freeTier: true },
  M2: { name: "Local pen-test (dynamic)", needs: "dynamic", freeTier: false },
  M3: { name: "Hotspot analysis", needs: "source", freeTier: false },
  M4: { name: "Duplication", needs: "source", freeTier: true },
  M5: { name: "Slop / dead code", needs: "source", freeTier: false },
  M6: { name: "Simplification / maintainability", needs: "llm", freeTier: false },
  M7: { name: "Performance", needs: "source", freeTier: true },
  M8: { name: "Test quality", needs: "source", freeTier: true },
  M9: { name: "App Router boundary/rendering", needs: "source", freeTier: true },
  M10: { name: "Data classification (PII/PHI/PCI)", needs: "source", freeTier: true },
};

// Modules with no execution record in ANY engagement, ever. This is a repo-level ledger, not a
// per-engagement one: a reason answers "why not THIS time," and for a module whose environment is
// absent by default every time (M6 needs the paid LLM tier), the answer is legitimately "no" at
// every individual moment while the module has never executed once. Each reason was correct; the
// series was a permanent silence. That is the quietest possible failure of "fail loud", so a
// never-executed module is surfaced regardless of tier and blocks `complete` — an engagement
// cannot claim full module coverage on the strength of a module that has never produced output.
//
// #284: this was a hand-kept Set — someone had to remember to delete "M6" the first time M6 ran,
// and (the worse half) to ADD any future module that had never run, or it would silently never get
// the loud treatment M6 got. It is now DERIVED: the complement of audit-execution-log.json, which
// #229's orchestrator appends to when a probe reports a module actually ran. A module is never-run
// because no execution record claims it ran — not because a human curated it. The default for an
// unknown module is never-run, which is the fail-loud direction.
//
// M6 is the one module absent from the log: defined 2026-07-09 (#72), still zero output. It has a
// runner (`pnpm simplify-scan`, #266); its entry appears the first time it runs against a real
// target. The #265 eval was against our own calibration fixtures and was contaminated
// (docs/design/m6-simplification-eval.md §3.1) — not an execution record.
export const MODULES_NEVER_EXECUTED: ReadonlySet<AuditModule> = neverExecutedModules(AUDIT_MODULES, readExecutionLog());

// "ran": the module executed against the target.
// "partial": it executed but couldn't cover its full scope (e.g. M7 code tier without the DB
//   advisors) — the audit still ships, with the shortfall named.
// "requires-live-run": a prereq was absent, so it could not execute (no live DB, no test suite,
//   no local stack). Mirrors coverage-scorecard.ts's status of the same name.
export type ModuleStatus = "ran" | "partial" | "requires-live-run";

// #682: distinguishes a `partial` caused by a BLOCKED sub-step (crashed/could not run) whose
// sibling sub-step still ran and surfaced findings, from a partial that produced nothing. Mirrors
// findings.ts's SubStatus (the report schema keeps its own copy, as CoverageStatus already does).
export type ModuleSubStatus = "sub-step-blocked";

export interface ModuleCoverage {
  module: AuditModule;
  status: ModuleStatus;
  // Why the module fell short. Required for anything but a clean "ran": an unexplained gap is
  // indistinguishable from a silent skip, which is the failure this gate exists to catch.
  reason?: string;
  // What actually executed (command, tier). Free-text provenance for the report's coverage line.
  detail?: string;
  // #506: on a monorepo, a per-app/per-DB tier records one row per enumerated instance; this labels
  // WHICH app or Supabase project the row covers. Absent ⇒ a single-instance (whole-target) row.
  instance?: string;
  // #682: on a `partial` row, marks that a sub-step was blocked while a sibling sub-step ran and
  // surfaced findings — the deliverable badges it apart from a partial that produced nothing.
  subStatus?: ModuleSubStatus;
}

// Which environments the engagement actually has. Optional: when supplied, a gap is annotated with
// the environment it was missing, which turns "we didn't have a live DB" into a recorded decision
// instead of an unexplained hole. It never excuses the gap — the caller still must record a reason.
export interface EngagementEnv {
  connected: boolean; // a live/read-only database was provided
  dynamic: boolean; // a running app / self-hosted clone is available for probing
  llm: boolean; // the paid LLM tier is in scope
}

const isPlaceholder = (reason: string | undefined): boolean => /^todo\b/i.test(reason ?? "");

const envGated = (module: AuditModule, env: EngagementEnv | undefined): boolean => {
  if (!env) return false;
  const needs = MODULES[module].needs;
  return (needs === "connected" && !env.connected) || (needs === "dynamic" && !env.dynamic) || (needs === "llm" && !env.llm);
};

interface AuditCoverageGap {
  module: AuditModule;
  problem: string;
}

interface AuditCoverageReport {
  rows: (ModuleCoverage & { name: string })[];
  gaps: AuditCoverageGap[];
  // Modules that have never executed in ANY engagement and didn't execute here either. Distinct
  // from a gap: a gap is a reasonless omission this engagement, which the caller can fix by
  // recording a reason. This cannot be fixed by a reason; only by running the module.
  neverRun: AuditModule[];
  complete: boolean;
  ranCount: number;
}

// Builds the coverage matrix over ALL ten modules from what the caller recorded. A module absent
// from `recorded` is a gap — the point of the gate: we never infer that an unmentioned module ran.
// #506: a per-app/per-DB tier records ONE entry per enumerated instance, so a module may legitimately
// appear more than once — keyed by (module, instance). Two entries with the SAME (module, instance),
// though, are still the broken-bookkeeping case they always were.
// `neverExecuted` defaults to the live ledger derived from audit-execution-log.json. It is a
// parameter, not a hard reference, so the fail-loud wiring (never-run ⇒ not a gap ⇒ blocks
// `complete` ⇒ throws) can be exercised with a synthetic set once every real module has executed and
// the live ledger is empty (#283 cleared M6, the last holdout) — the behavior must stay tested even
// when no module currently triggers it.
export function buildAuditCoverage(recorded: ModuleCoverage[], env?: EngagementEnv, neverExecuted: ReadonlySet<AuditModule> = MODULES_NEVER_EXECUTED): AuditCoverageReport {
  const byModule = new Map<AuditModule, ModuleCoverage[]>();
  const gaps: AuditCoverageGap[] = [];

  for (const entry of recorded) {
    const list = byModule.get(entry.module) ?? [];
    if (list.some((e) => (e.instance ?? "") === (entry.instance ?? ""))) {
      // Two conflicting verdicts for one (module, instance) means the caller's bookkeeping is broken;
      // we can't know which is true, so refuse to pick rather than let a "ran" mask a gap.
      const where = entry.instance ? `${entry.module} (instance ${entry.instance})` : entry.module;
      gaps.push({ module: entry.module, problem: `recorded twice — ambiguous coverage for ${where}` });
      continue;
    }
    list.push(entry);
    byModule.set(entry.module, list);
  }

  const rows: (ModuleCoverage & { name: string })[] = [];
  for (const module of AUDIT_MODULES) {
    const entries = byModule.get(module);
    if (!entries || !entries.length) {
      const gated = envGated(module, env) ? ` (needs ${MODULES[module].needs}: record it requires-live-run with that reason)` : "";
      gaps.push({ module, problem: `never accounted for — no run, and no reason given for skipping it${gated}` });
      rows.push({ module, name: MODULES[module].name, status: "requires-live-run", reason: "not accounted for in this engagement" });
      continue;
    }
    for (const entry of entries) {
      const reason = entry.reason?.trim();
      const at = entry.instance ? `${module} (${entry.instance})` : module;
      if (entry.status !== "ran" && !reason) {
        gaps.push({ module, problem: `${at} recorded "${entry.status}" with no reason — a gap without a reason is a silent skip` });
      } else if (entry.status !== "ran" && isPlaceholder(reason)) {
        // An unfilled --template row. The gate can't judge whether a reason is TRUE, but it can
        // refuse the one reason that is definitionally not an accounting: the prompt to write one.
        gaps.push({ module, problem: `${at} reason is still the "${reason}" placeholder — record why it could not run` });
      }
      rows.push({ ...entry, name: MODULES[module].name });
    }
  }

  // A module in the never-executed ledger that also didn't run here (on ANY instance) stays loud no
  // matter how well reasoned its excuse — that reason is exactly what has kept it invisible before.
  const ranAny = new Set(rows.filter((r) => r.status === "ran").map((r) => r.module));
  const neverRun = [...neverExecuted].filter((module) => !ranAny.has(module));
  // "ran in full" is stricter than "ran on some instance": a module counts only when EVERY one of
  // its recorded instances ran — a monorepo where one app ran and another is partial has not.
  const ranCount = AUDIT_MODULES.filter((m) => {
    const es = byModule.get(m);
    return !!es && es.length > 0 && es.every((e) => e.status === "ran");
  }).length;

  return {
    rows,
    gaps,
    neverRun,
    complete: gaps.length === 0 && neverRun.length === 0,
    ranCount,
  };
}

// The fail-loud half, mirroring assertComplete's contract: throw, naming every unaccounted-for
// module, so a partial audit can never be reported as a complete one.
//
// Why never-run throws rather than warns (#266): a warning is what M6 has effectively had — every
// engagement recorded a correct, well-reasoned excuse and nobody noticed the module had never
// produced a single finding while briefs/audit-modules.md sold it as a product wedge. A status that
// doesn't stop anything is the same silence with better paperwork. It is deliberately unsatisfiable
// by reason-writing: the only way to clear it is to run the module once and drop it from
// MODULES_NEVER_EXECUTED.
export function assertAuditComplete(recorded: ModuleCoverage[], env?: EngagementEnv, neverExecuted: ReadonlySet<AuditModule> = MODULES_NEVER_EXECUTED): void {
  const { gaps, neverRun } = buildAuditCoverage(recorded, env, neverExecuted);
  if (gaps.length) {
    const detail = gaps.map((g) => `${g.module} (${MODULES[g.module].name}): ${g.problem}`).join("; ");
    throw new Error(`Incomplete audit coverage — ${gaps.length} of ${AUDIT_MODULES.length} module(s) unaccounted for: ${detail}`);
  }
  if (neverRun.length) {
    throw new Error(
      `Module(s) ${neverRun.join(", ")} have NEVER executed in any engagement — no output, ever. This is not a per-engagement excuse: no reason clears it, only running the module does (see MODULES_NEVER_EXECUTED). Run it (M6: \`pnpm simplify-scan <target>\`) or remove the product claim.`,
    );
  }
}

// The coverage matrix as report/console lines: one per module, every gap visible.
export function formatAuditCoverage(report: AuditCoverageReport): string {
  const mark = (r: AuditCoverageReport["rows"][number]): string =>
    r.status === "ran" ? "RAN " : r.status === "partial" ? "PART" : "LIVE";
  const lines = report.rows.map((r) => {
    const suffix = r.reason ? ` — ${r.reason}` : r.detail ? ` — ${r.detail}` : "";
    const label = r.instance ? `${r.name} [${r.instance}]` : r.name;
    return `  ${mark(r)}  ${r.module.padEnd(3)} ${label.padEnd(34)}${suffix}`;
  });
  lines.push("", `${report.ranCount}/${AUDIT_MODULES.length} modules ran in full.`);
  if (report.gaps.length) {
    lines.push("", `COVERAGE FAIL — ${report.gaps.length} module(s) unaccounted for:`);
    for (const g of report.gaps) lines.push(`  ${g.module}: ${g.problem}`);
  }
  if (report.neverRun.length) {
    lines.push("", `COVERAGE FAIL — module(s) that have NEVER executed in any engagement: ${report.neverRun.join(", ")}`);
  }
  return lines.join("\n");
}
