// The orchestrator half of #229 — the piece the gate has been missing.
//
// src/audit-coverage.ts answers "does this ledger constitute an audit?" but takes the ledger from
// the CALLER, so it cannot tell that you skipped M5: a caller that never mentions a module and a
// caller that lies about it are indistinguishable to a gate reading only what it was handed. This
// module removes the caller from the loop. Every row it produces is the RETURN VALUE of a probe
// that actually ran; there is no parameter through which a caller can assert "M5 ran".
//
// The three properties that make the ledger derived rather than asserted:
//   1. runAudit takes runners + context, never a ModuleCoverage[]. Nothing to forge.
//   2. A module with no registered runner is a hard throw (assertRegistryComplete) — the "silently
//      skipped" case of #229 becomes structurally impossible rather than merely discouraged.
//   3. A probe that throws is NOT recorded as an environment gap. A crashed scanner produced no
//      output for a reason that is a bug, not a tier — laundering it into "requires-live-run" would
//      hand back the exact silent pass the gate exists to prevent. It goes in `failures`, which
//      fails loud on its own.

import { AUDIT_MODULES, type AuditModule, type EngagementEnv, type ModuleCoverage, MODULES } from "./audit-coverage.js";
import type { Finding } from "./findings.js";

// What a probe reports about its OWN execution. It is deliberately not ModuleCoverage: a probe may
// only describe what it did, and cannot claim a status for a module it isn't registered under.
// `findings` (#312): the report-schema Finding[] the module's CLI emitted, when the probe captured
// it. A requires-live-run probe produced no output, so it carries none.
export type ProbeOutcome =
  | { status: "ran"; detail: string; findings?: Finding[] }
  | { status: "partial"; detail: string; reason: string; findings?: Finding[] }
  | { status: "requires-live-run"; reason: string };

// The seam that keeps this engine testable and offline: probes reach the outside world only through
// ctx, so a test drives real orchestration logic against fake tooling rather than a mocked runAudit.
export interface RunContext {
  targetDir: string;
  env: EngagementEnv;
  // Runs a module's CLI. `ok` is the exit status; the engine never parses `output` — a module's
  // own runner decides what its output means.
  exec: (command: string, args: string[]) => { ok: boolean; output: string };
  // Prereq probing (target node_modules, a test suite, migrations). Injected for the same reason.
  exists: (path: string) => boolean;
  // #312 findings assembly. When both are set, an emitter probe writes its Finding[] to a file in
  // captureDir and reads it back, so run-audit can assemble one engagement findings.json. Absent
  // (the default) means no capture — coverage-only runs keep their prior behaviour.
  captureDir?: string;
  readFindings?: (path: string) => Finding[];
  // #420: some module CLIs write an OBJECT artifact to --out (M3's { findings, ... }, M8's
  // { finding, moduleRecord } | { summary, ... }) rather than the bare Finding[] readFindings
  // demands. readArtifact parses that object without the array assertion so the probe can pull the
  // report-schema Finding[] it embeds — and, for M8, read the verdict --out diverts off stdout.
  readArtifact?: (path: string) => unknown;
}

export interface ModuleRunner {
  module: AuditModule;
  run: (ctx: RunContext) => ProbeOutcome;
}

interface ModuleFailure {
  module: AuditModule;
  error: string;
}

interface AuditRunResult {
  // Derived, not supplied: one row per module, each the outcome of that module's probe.
  recorded: ModuleCoverage[];
  failures: ModuleFailure[];
  // Report-schema findings captured from the module CLIs that emit them (#312). Raw and possibly
  // overlapping (shared CLIs feed two probes); assembleEngagementDocument de-duplicates.
  findings: Finding[];
}

// A registry missing a module is the #229 defect at the source — an audit that never even tries M5
// cannot discover that it skipped M5. Checked before anything runs, so the failure arrives before
// a partial ledger exists to be mistaken for a whole one.
export function assertRegistryComplete(runners: ModuleRunner[]): void {
  const registered = new Set(runners.map((r) => r.module));
  const missing = AUDIT_MODULES.filter((module) => !registered.has(module));
  if (missing.length) {
    const detail = missing.map((m) => `${m} (${MODULES[m].name})`).join(", ");
    throw new Error(
      `Audit runner registry is incomplete — no runner for ${missing.length} module(s): ${detail}. Every module of M1–M10 needs a runner, even one that only reports why it cannot execute; a module with no runner is a module the audit cannot know it skipped (#229).`,
    );
  }
  const duplicated = runners.map((r) => r.module).filter((m, i, all) => all.indexOf(m) !== i);
  if (duplicated.length) {
    throw new Error(`Audit runner registry registers ${[...new Set(duplicated)].join(", ")} more than once — two probes for one module means two answers to "did it run".`);
  }
}

// Runs every module and derives the coverage ledger from what each probe actually reported.
export function runAudit(runners: ModuleRunner[], ctx: RunContext): AuditRunResult {
  assertRegistryComplete(runners);

  const byModule = new Map(runners.map((r) => [r.module, r]));
  const recorded: ModuleCoverage[] = [];
  const failures: ModuleFailure[] = [];
  const findings: Finding[] = [];

  // Iterate AUDIT_MODULES, not `runners`: the ledger's shape is owned by the module enumeration,
  // so a registry can never shorten the audit by reordering or under-listing itself.
  for (const module of AUDIT_MODULES) {
    const runner = byModule.get(module);
    if (!runner) continue; // unreachable — assertRegistryComplete has already thrown.
    let outcome: ProbeOutcome;
    try {
      outcome = runner.run(ctx);
    } catch (err) {
      // Recorded requires-live-run because that is the honest description of the OUTPUT (there is
      // none). The reason names the crash rather than a tier, and `failures` — not this row — is
      // what stops the run: see the header, property 3.
      const message = err instanceof Error ? err.message : String(err);
      failures.push({ module, error: message });
      recorded.push({ module, status: "requires-live-run", reason: `runner failed: ${message}` });
      continue;
    }
    recorded.push(
      outcome.status === "requires-live-run"
        ? { module, status: "requires-live-run", reason: outcome.reason }
        : { module, status: outcome.status, detail: outcome.detail, ...(outcome.status === "partial" ? { reason: outcome.reason } : {}) },
    );
    if (outcome.status !== "requires-live-run" && outcome.findings) findings.push(...outcome.findings);
  }

  return { recorded, failures, findings };
}

export function formatFailures(failures: ModuleFailure[]): string {
  return [
    `AUDIT FAIL — ${failures.length} module runner(s) crashed. A crashed runner is a bug, not a tier:`,
    ...failures.map((f) => `  ${f.module} (${MODULES[f.module].name}): ${f.error}`),
  ].join("\n");
}
