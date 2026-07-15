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

// The ten modules of the audit. Authoritative scope: docs/audit-modules.md.
export const AUDIT_MODULES = ["M1", "M2", "M3", "M4", "M5", "M6", "M7", "M8", "M9", "M10"] as const;

export type AuditModule = (typeof AUDIT_MODULES)[number];

export const MODULE_NAMES: Record<AuditModule, string> = {
  M1: "Multi-tenant security",
  M2: "Local pen-test (dynamic)",
  M3: "Hotspot analysis",
  M4: "Duplication",
  M5: "Slop / dead code",
  M6: "Simplification / maintainability",
  M7: "Performance",
  M8: "Test quality",
  M9: "App Router boundary/rendering",
  M10: "Data classification (PII/PHI/PCI)",
};

// "ran": the module executed against the target.
// "partial": it executed but couldn't cover its full scope (e.g. M7 code tier without the DB
//   advisors) — the audit still ships, with the shortfall named.
// "requires-live-run": a prereq was absent, so it could not execute (no live DB, no test suite,
//   no local stack). Mirrors coverage-scorecard.ts's status of the same name.
export type ModuleStatus = "ran" | "partial" | "requires-live-run";

export interface ModuleCoverage {
  module: AuditModule;
  status: ModuleStatus;
  // Why the module fell short. Required for anything but a clean "ran": an unexplained gap is
  // indistinguishable from a silent skip, which is the failure this gate exists to catch.
  reason?: string;
  // What actually executed (command, tier). Free-text provenance for the report's coverage line.
  detail?: string;
}

const isPlaceholder = (reason: string | undefined): boolean => /^todo\b/i.test(reason ?? "");

interface AuditCoverageGap {
  module: AuditModule;
  problem: string;
}

interface AuditCoverageReport {
  rows: (ModuleCoverage & { name: string })[];
  gaps: AuditCoverageGap[];
  complete: boolean;
  ranCount: number;
}

// Builds the coverage matrix over ALL ten modules from what the caller recorded. A module absent
// from `recorded` is a gap — the point of the gate: we never infer that an unmentioned module ran.
export function buildAuditCoverage(recorded: ModuleCoverage[]): AuditCoverageReport {
  const byModule = new Map<AuditModule, ModuleCoverage>();
  const gaps: AuditCoverageGap[] = [];

  for (const entry of recorded) {
    if (byModule.has(entry.module)) {
      // Two conflicting verdicts for one module means the caller's bookkeeping is broken; we
      // can't know which is true, so refuse to pick rather than let a "ran" mask a gap.
      gaps.push({ module: entry.module, problem: `recorded twice — ambiguous coverage for ${entry.module}` });
      continue;
    }
    byModule.set(entry.module, entry);
  }

  const rows = AUDIT_MODULES.map((module) => {
    const entry = byModule.get(module);
    if (!entry) {
      gaps.push({ module, problem: `never accounted for — no run, and no reason given for skipping it` });
      return { module, name: MODULE_NAMES[module], status: "requires-live-run" as const, reason: "not accounted for in this engagement" };
    }
    const reason = entry.reason?.trim();
    if (entry.status !== "ran" && !reason) {
      gaps.push({ module, problem: `recorded "${entry.status}" with no reason — a gap without a reason is a silent skip` });
    } else if (entry.status !== "ran" && isPlaceholder(reason)) {
      // An unfilled --template row. The gate can't judge whether a reason is TRUE, but it can
      // refuse the one reason that is definitionally not an accounting: the prompt to write one.
      gaps.push({ module, problem: `reason is still the "${reason}" placeholder — record why ${module} could not run` });
    }
    return { ...entry, name: MODULE_NAMES[module] };
  });

  return {
    rows,
    gaps,
    complete: gaps.length === 0,
    ranCount: rows.filter((r) => r.status === "ran").length,
  };
}

// The fail-loud half, mirroring assertComplete's contract: throw, naming every unaccounted-for
// module, so a partial audit can never be reported as a complete one.
export function assertAuditComplete(recorded: ModuleCoverage[]): void {
  const { gaps } = buildAuditCoverage(recorded);
  if (gaps.length === 0) return;
  const detail = gaps.map((g) => `${g.module} (${MODULE_NAMES[g.module]}): ${g.problem}`).join("; ");
  throw new Error(`Incomplete audit coverage — ${gaps.length} of ${AUDIT_MODULES.length} module(s) unaccounted for: ${detail}`);
}

// The coverage matrix as report/console lines: one per module, every gap visible.
export function formatAuditCoverage(report: AuditCoverageReport): string {
  const mark = (r: AuditCoverageReport["rows"][number]): string =>
    r.status === "ran" ? "RAN " : r.status === "partial" ? "PART" : "LIVE";
  const lines = report.rows.map((r) => {
    const suffix = r.reason ? ` — ${r.reason}` : r.detail ? ` — ${r.detail}` : "";
    return `  ${mark(r)}  ${r.module.padEnd(3)} ${r.name.padEnd(34)}${suffix}`;
  });
  lines.push("", `${report.ranCount}/${AUDIT_MODULES.length} modules ran in full.`);
  if (report.gaps.length) {
    lines.push("", `COVERAGE FAIL — ${report.gaps.length} module(s) unaccounted for:`);
    for (const g of report.gaps) lines.push(`  ${g.module}: ${g.problem}`);
  }
  return lines.join("\n");
}
