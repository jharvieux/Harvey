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

import { AUDIT_MODULES, type AuditModule, type EngagementEnv, type ModuleCoverage, type ModuleSubStatus, MODULES } from "./audit-coverage.js";
import type { Finding } from "./findings.js";

// What a probe reports about its OWN execution. It is deliberately not ModuleCoverage: a probe may
// only describe what it did, and cannot claim a status for a module it isn't registered under.
// `findings` (#312): the report-schema Finding[] the module's CLI emitted, when the probe captured
// it. A requires-live-run probe produced no output, so it carries none.
// `instance` (#506): on a monorepo, a per-app/per-DB tier runs once per enumerated app or Supabase
// project; the label names WHICH instance this outcome covers so the ledger records one row per
// (module × instance). Absent ⇒ a single-instance target (the common case) — unchanged.
// `hotspots` (#515): M3's worst-first top-K hotspot file list, surfaced so the assembler can enrich
// EVERY module's findings with an onHotspot/hotspotRank tag. Only the M3 probe sets it.
// #682: `subStatus: "sub-step-blocked"` on a partial says a sub-step was BLOCKED while a sibling
// sub-step ran and surfaced `findings` — so a blocked Stryker run never discards the test-intent
// tier's findings by degrading to requires-live-run (which carries none).
export type ProbeOutcome =
  | { status: "ran"; detail: string; findings?: Finding[]; instance?: string; hotspots?: string[] }
  | { status: "partial"; detail: string; reason: string; findings?: Finding[]; instance?: string; hotspots?: string[]; subStatus?: ModuleSubStatus }
  | { status: "requires-live-run"; reason: string; instance?: string };

// The seam that keeps this engine testable and offline: probes reach the outside world only through
// ctx, so a test drives real orchestration logic against fake tooling rather than a mocked runAudit.
export interface RunContext {
  targetDir: string;
  env: EngagementEnv;
  // Runs a module's CLI. `ok` is the exit status; the engine never parses `output` — a module's
  // own runner decides what its output means. `opts.env` (#520) overlays extra variables onto the
  // child's inherited environment, so the M10 live tier can point pii-classify at a different
  // SUPABASE_DB_URL per enumerated project; absent ⇒ the child inherits the parent env unchanged.
  exec: (command: string, args: string[], opts?: { env?: Record<string, string> }) => { ok: boolean; output: string };
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
  // #416: where the out-of-orchestrator passes (M1 semantic/live, M2 dynamic, M3 vitals, M6 verdict)
  // leave their durable results artifact. When set, a probe checks for a fresh, target-matching
  // artifact and DERIVES `ran` from it (src/audit-pass-artifact.ts). Absent ⇒ those probes keep
  // their honest partial/requires-live-run — no artifacts dir, no way to prove the pass ran.
  artifactsDir?: string;
  // #416: injected clock (epoch ms) for pass-artifact freshness. Injected so tests can pin "now";
  // the real driver sets Date.now(). Absent ⇒ findFreshPass falls back to Date.now().
  now?: number;
  // #434: the connected Supabase project ref for M7's DB advisor tier (`pnpm perf-scan <ref>`).
  // SUPABASE_ACCESS_TOKEN travels via the inherited process env, not this context — perf-scan reads
  // it itself. Absent ⇒ the advisor tier has no ref to call with, so M7 stays partial even when
  // --connected is set (a flag alone was never evidence — same rule #311/#356 apply to the ref).
  supabaseRef?: string;
  // #506: the enumerated apps and Supabase projects of a monorepo target. `apps` (>1 entry) makes
  // the per-app tiers (M4/M5/M9, M10 schema) fan out — one probe run per app dir, one ledger row
  // per app. `supabaseRefs` (>1 entry) makes M7's advisor tier fan out per project. Absent or a
  // single entry ⇒ single-instance behaviour, exactly as before. An enumerated instance that is
  // never covered must surface as an explicit partial/requires-live-run row — never absent (#506).
  apps?: { name: string; path: string }[];
  supabaseRefs?: string[];
  // #529: an operator-supplied schema location for M10's schema tier (run-audit --schema <path>),
  // tried ahead of the conventional-location probe (supabase/migrations, prisma/migrations,
  // drizzle, …), on a SINGLE-target run. Absent ⇒ probe the conventional locations only.
  schemaHint?: string;
  // #538: per-app schema locations for a MONOREPO, keyed by the app name in `apps` below (run-audit
  // --schema <app>=<path>, repeatable — one pair per app whose layout the conventional-location
  // probe would not find). schemaHint (above) is a single path and only ever applies to a
  // single-target run; on a monorepo fan-out, each app's hint (if any) comes from this map instead,
  // so an app with an unconventional layout still gets real M10 schema classification instead of
  // being limited to the conventional-location probe alone. Absent ⇒ no per-app hints supplied.
  schemaHints?: Record<string, string>;
  // #520: per-Supabase-project DB connection URLs for M10's live tier, keyed by project ref. On a
  // multi-project connected run the M10 probe classifies each ref whose URL is present here and
  // records requires-live-run for any ref without one — so each enumerated project is either
  // live-classified or carries its own honest not-run row. Built by run-audit from
  // SUPABASE_DB_URL_<ref> env vars (the first ref also falling back to plain SUPABASE_DB_URL).
  // Absent ⇒ no per-DB URLs supplied.
  supabaseDbUrls?: Record<string, string>;
  // #523: operator consent for the M8 mutation tier to provision missing Stryker packages into the
  // target via `npm install --no-save` (which executes the target's npm lifecycle scripts — a real
  // trust-boundary decision). When set, the M8 probe passes `--install` to mutation-scan so the
  // scaffolded full-mutation rung is reachable under the orchestrator; absent (the default) it stays
  // off and a cold target degrades to the loud "re-run with --install" partial. Consent unlocks the
  // attempt; the status is still derived from what actually ran.
  allowTargetInstall?: boolean;
  // #537: whether ctx.targetDir is a git repository ROOT — the same signal quick-scan's mechanical
  // scan uses internally (src/scan/secrets.ts's isGitRepoRoot, exported in #533) to decide whether
  // the git-history secrets tier can run at all. Checking it directly lets the M1 probe disclose that
  // sub-gap on every run, not only a capturing one with a raw findings feed to read back (#528's
  // original fix only fired when ctx.captureDir was set). Absent ⇒ the probe cannot tell and stays
  // silent on this sub-gap.
  isGitRepoRoot?: (dir: string) => boolean;
}

export interface ModuleRunner {
  module: AuditModule;
  // #506: a per-app/per-DB probe returns ONE outcome per instance (an array). A single-instance
  // probe returns one outcome. runAudit records one ledger row per returned outcome — so a fan-out
  // that enumerated N instances produces N rows, and an empty array is treated as a crash (a
  // fan-out with zero instances would be a silent skip, the one thing the gate exists to catch).
  run: (ctx: RunContext) => ProbeOutcome | ProbeOutcome[];
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
  // #515: M3's top-K hotspot ranking, when the M3 probe captured one. Fed to the assembler so every
  // module's findings get the shared hotspot enrichment. Absent ⇒ M3 produced no ranking this run.
  hotspots?: string[];
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
  let hotspots: string[] | undefined;

  // Iterate AUDIT_MODULES, not `runners`: the ledger's shape is owned by the module enumeration,
  // so a registry can never shorten the audit by reordering or under-listing itself.
  for (const module of AUDIT_MODULES) {
    const runner = byModule.get(module);
    if (!runner) continue; // unreachable — assertRegistryComplete has already thrown.
    let outcomes: ProbeOutcome[];
    try {
      const result = runner.run(ctx);
      outcomes = Array.isArray(result) ? result : [result];
    } catch (err) {
      // Recorded requires-live-run because that is the honest description of the OUTPUT (there is
      // none). The reason names the crash rather than a tier, and `failures` — not this row — is
      // what stops the run: see the header, property 3.
      const message = err instanceof Error ? err.message : String(err);
      failures.push({ module, error: message });
      recorded.push({ module, status: "requires-live-run", reason: `runner failed: ${message}` });
      continue;
    }
    // #506: a fan-out that produced no outcome would drop the module from the ledger silently — the
    // exact omission the gate exists to prevent. Treat it as a crash, not an absence.
    if (!outcomes.length) {
      failures.push({ module, error: "runner returned no outcomes — a per-instance fan-out that enumerated nothing is a silent skip" });
      recorded.push({ module, status: "requires-live-run", reason: "runner produced no outcome for any instance" });
      continue;
    }
    for (const outcome of outcomes) {
      const instance = outcome.instance ? { instance: outcome.instance } : {};
      recorded.push(
        outcome.status === "requires-live-run"
          ? { module, status: "requires-live-run", reason: outcome.reason, ...instance }
          : { module, status: outcome.status, detail: outcome.detail, ...(outcome.status === "partial" ? { reason: outcome.reason, ...(outcome.subStatus ? { subStatus: outcome.subStatus } : {}) } : {}), ...instance },
      );
      // #620: on a monorepo fan-out each app's probe emits the SAME finding ids (SLOP-01, M9-01, …),
      // so the assembled document had duplicate ids and --findings-out failed schema validation —
      // the deliverable was never written. Namespace ids by the instance they belong to so each
      // app's finding is distinct (and the location/instance still says which app it is). Only when
      // an instance is set: a single-target run keeps its ids unchanged.
      if (outcome.status !== "requires-live-run" && outcome.findings) {
        findings.push(
          ...(outcome.instance ? outcome.findings.map((f) => ({ ...f, id: `${f.id}@${outcome.instance}` })) : outcome.findings),
        );
      }
      if (outcome.status !== "requires-live-run" && outcome.hotspots?.length) hotspots = outcome.hotspots;
    }
  }

  return { recorded, failures, findings, ...(hotspots ? { hotspots } : {}) };
}

export function formatFailures(failures: ModuleFailure[]): string {
  return [
    `AUDIT FAIL — ${failures.length} module runner(s) crashed. A crashed runner is a bug, not a tier:`,
    ...failures.map((f) => `  ${f.module} (${MODULES[f.module].name}): ${f.error}`),
  ].join("\n");
}
