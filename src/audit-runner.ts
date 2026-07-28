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
import type { DataClassMap } from "./data-class-escalation.js";
import type { Finding, TestQuality } from "./findings.js";

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
// `dataMap` (#1049): M10's table→PII/PHI/PCI classification, surfaced so the assembler can weight
// EVERY module's severities by the sensitivity of the data they touch. Only the M10 probe sets it.
// `testQuality` (#1045): M8's per-module §3b measurement is a module-level TABLE, not findings, so
// it needs its own channel out of the probe — without one the orchestrator dropped it, and the
// renderer's test-quality section was unreachable for its whole life.
export type ProbeOutcome =
  | { status: "ran"; detail: string; findings?: Finding[]; instance?: string; hotspots?: string[]; dataMap?: DataClassMap; testQuality?: TestQuality }
  | { status: "partial"; detail: string; reason: string; findings?: Finding[]; instance?: string; hotspots?: string[]; dataMap?: DataClassMap; subStatus?: ModuleSubStatus; testQuality?: TestQuality }
  | { status: "requires-live-run"; reason: string; instance?: string };

// ---- #1096 invariant (2): the typed non-empty result ----
//
// The bad state ProbeOutcome permits, and permitted for its whole life: `{ status: "ran", detail,
// findings: [] }` — "the module ran and found nothing", with no statement of what was looked at.
// That sentence is indistinguishable from "the probe passed no --out and captured nothing" (#1062),
// "the scan loaded 0 product source files and exited 0" (#1065) and "the tool ran clean". Three
// different claims, one silence, and the report ships the reassuring one.
//
// Examined makes the reassuring reading unrepresentable: a probe that says it examined something
// must say HOW MUCH and OF WHAT, in the same object as the findings. `unitsExamined: 0` is rejected
// at normalization — a probe that examined nothing did not run, and must say so as NotAssessed.
//
// NotAssessed carries the #1033 reason contract at the TYPE level: a not-run reason without a
// provenance tag and a falsifier is the shape four blockers were written in on 2026-07-24, all four
// false. Here it will not compile.
export interface Examined {
  kind: "examined";
  /** The count that makes "0 findings" checkable: source files read, tables classified, tests parsed. */
  unitsExamined: number;
  /** The units, named — "product source files", "database tables", "recorded pass artifacts". */
  scope: string;
  /** The command/tier that ran, for the ledger row. */
  detail: string;
  /** Required, and may be empty — but only in the company of unitsExamined and scope. */
  findings: Finding[];
  /** Present ⇒ the module ran PARTIALLY and this is why. Absent ⇒ a full `ran`. */
  reason?: string;
  subStatus?: ModuleSubStatus;
  instance?: string;
  hotspots?: string[];
  dataMap?: DataClassMap;
  testQuality?: TestQuality;
}

export interface NotAssessed {
  kind: "not-assessed";
  reason: string;
  /** MEASURED = a command was run and this is what it did. TRIED = attempted, this happened.
   *  ASSUMED = inferred, never tested. The four blockers falsified on 2026-07-24 were ASSUMED
   *  written in MEASURED's register; the tag is what makes that distinguishable in the ledger. */
  provenance: "MEASURED" | "TRIED" | "ASSUMED";
  /** The command that exits 0 the day this reason stops being true. A reason with no falsifier is
   *  unfalsifiable and therefore permanent. */
  falsifier: string;
  instance?: string;
}

export type ProbeResult = Examined | NotAssessed;
/** What a probe may hand back mid-migration: the typed union, or the legacy shape. */
export type ProbeReport = ProbeOutcome | ProbeResult;

const isTyped = (r: ProbeReport): r is ProbeResult => "kind" in r;

// The migration ledger for invariant (2). A module is in exactly one list, checked at module load,
// for the same reason CALIBRATION_PLANTS/UNEXERCISED are: a half-migration nobody wrote down is
// indistinguishable from a finished one, and "which probes are typed?" would become a grep instead
// of a fact. Moving a module from UNTYPED to TYPED is the whole of the remaining work.
// #1109 completed the migration: all ten probes return Examined | NotAssessed. UNTYPED_PROBES stays
// (empty, and asserted empty-or-explained by the exhaustiveness check below) because it is the slot a
// NEW module's probe lands in — an eleventh module added to AUDIT_MODULES without a typed probe has
// to be written down here rather than quietly rejoining the untyped shape.
export const TYPED_PROBES: AuditModule[] = ["M1", "M2", "M3", "M4", "M5", "M6", "M7", "M8", "M9", "M10"];

export const UNTYPED_PROBES: { module: AuditModule; reason: string }[] = [];

{
  const covered = new Set<AuditModule>([...TYPED_PROBES, ...UNTYPED_PROBES.map((u) => u.module)]);
  const missing = AUDIT_MODULES.filter((m) => !covered.has(m));
  if (missing.length) {
    throw new Error(
      `The typed-result migration ledger does not account for ${missing.join(", ")} — every module of M1–M10 belongs in TYPED_PROBES or UNTYPED_PROBES with the reason it is not migrated yet (#1096). A module in neither is a half-migration nobody can see.`,
    );
  }
  const both = TYPED_PROBES.filter((m) => UNTYPED_PROBES.some((u) => u.module === m));
  if (both.length) throw new Error(`The typed-result migration ledger both types and excuses ${both.join(", ")} — two answers to "is this probe migrated".`);
}

// Normalizes a typed result onto the transport the ledger and assembler already speak. The two
// assertions are where the type's promise becomes a runtime one:
//   - an Examined that examined nothing is a contradiction, not a clean scan (#1065's exact shape);
//   - a module declared TYPED that hands back a legacy outcome has been laundered by a helper
//     somewhere, and the compile-time guarantee is worthless if that passes silently.
export function toOutcome(result: ProbeResult): ProbeOutcome {
  const instance = result.instance ? { instance: result.instance } : {};
  if (result.kind === "not-assessed") {
    return { status: "requires-live-run", reason: `${result.reason} [${result.provenance}; falsifier: ${result.falsifier}]`, ...instance };
  }
  if (result.unitsExamined <= 0) {
    throw new Error(
      `A probe reported Examined with unitsExamined=${result.unitsExamined} (${result.scope}) — examining nothing is not a clean scan, it is a NotAssessed with a reason (#1065/#1096). Detail: ${result.detail}`,
    );
  }
  const carried = {
    findings: result.findings,
    ...instance,
    ...(result.hotspots ? { hotspots: result.hotspots } : {}),
    ...(result.dataMap ? { dataMap: result.dataMap } : {}),
    ...(result.testQuality ? { testQuality: result.testQuality } : {}),
  };
  // The unit count rides on the ledger's own detail string, so the deliverable's coverage row says
  // what was looked at — a "ran, 0 findings" row that names 0 units read is no longer possible, and
  // one that names 412 files is a claim the client can check.
  const detail = `${result.detail} [examined ${result.unitsExamined} ${result.scope}]`;
  return result.reason
    ? { status: "partial", detail, reason: result.reason, ...(result.subStatus ? { subStatus: result.subStatus } : {}), ...carried }
    : { status: "ran", detail, ...carried };
}

// The seam that keeps this engine testable and offline: probes reach the outside world only through
// ctx, so a test drives real orchestration logic against fake tooling rather than a mocked runAudit.
export interface RunContext {
  targetDir: string;
  env: EngagementEnv;
  // Runs a module's CLI. `ok` is the exit status; the engine never parses `output` — a module's
  // own runner decides what its output means. `opts.env` (#520) overlays extra variables onto the
  // child's inherited environment, so the M10 live tier can point pii-classify at a different
  // SUPABASE_DB_URL per enumerated project; absent ⇒ the child inherits the parent env unchanged.
  // `stderr` (#1109): the child's error stream, kept SEPARATE from `output` because several probes
  // parse stdout as JSON. It is where quality-scan reports the jscpd/knip scope counts M4 and M5
  // need to state what they examined — the real runner always supplies it; a test double that does
  // not is telling those probes their tool printed no scope summary, which they report as such.
  exec: (command: string, args: string[], opts?: { env?: Record<string, string> }) => { ok: boolean; output: string; stderr?: string };
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
  // #770: real-filesystem discovery for the schema tier, tried after the hint and the conventional-
  // location probe both miss — a bounded, CREATE-TABLE-filtered search for schema DDL living
  // somewhere neither recognizes (a root-level or nested schema.sql under an unconventional name,
  // e.g. launch-mvp's `initial_supabase_table_schema.sql`, nocode-rescue's `before/schema.sql`).
  // Wired to dynamic-validate.ts's discoverSchemaFiles (already built and tested for M2's stand-up
  // probe) in the real driver. Absent ⇒ the probe keeps its prior conventional-location-only
  // behaviour — no regression for a caller (or test double) that hasn't wired it.
  discoverSchemaFiles?: (dir: string) => { files: string[]; probed: string[] };
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
  // #1096: a migrated probe returns ProbeResult (Examined | NotAssessed) instead; runAudit
  // normalizes. The union is the migration seam, and `typed` is what stops it being a hole — a
  // runner that declares itself migrated is HELD to it at runtime, so a helper cannot quietly
  // launder the result back into the untyped shape while the compile-time guarantee reads as kept.
  typed?: true;
  run: (ctx: RunContext) => ProbeReport | ProbeReport[];
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
  // #1064: the same findings before the merge above erases who produced them. Module attribution is
  // exactly what `findings` loses, and its loss is why #1062 was invisible from the deliverable —
  // the M7 probe captured nothing while M9's unfiltered sweep re-collected the same rows, so the
  // assembled document looked complete. The conservation gate asks "did M7 ITSELF produce its
  // planted finding", which only this map can answer.
  findingsByModule: Partial<Record<AuditModule, Finding[]>>;
  // #515: M3's top-K hotspot ranking, when the M3 probe captured one. Fed to the assembler so every
  // module's findings get the shared hotspot enrichment. Absent ⇒ M3 produced no ranking this run.
  hotspots?: string[];
  // #1049: M10's table→data-class map, when the M10 probe captured one. Fed to the assembler so
  // every module's severities are weighted by data sensitivity. Absent ⇒ M10 classified nothing this
  // run, and the assembler records that the join could not run rather than leaving it unstated.
  dataMap?: DataClassMap;
  // #1045: M8's §3b test-quality measurement, when the mutation tier produced one. Absent ⇒ no
  // mutation measurement this engagement, and M8's ledger row states why.
  testQuality?: TestQuality;
  // #1470: id families that collided this run and were disambiguated. Empty on a clean run; a
  // non-empty list is printed loudly by the caller, because it names a detector minting an id that
  // is not unique per finding — a real defect, just no longer one that costs the client the report.
  idCollisions: IdCollision[];
}

/** One finding id that arrived on two or more DIFFERENT findings, and what they were renamed to. */
interface IdCollision {
  id: string;
  /** How many distinct findings shared it (≥2). */
  count: number;
  /** The ids the 2nd..nth were given — the 1st keeps `id`. */
  renamedTo: string[];
  modules: AuditModule[];
}

// #1470 — the general guard behind the two id families proposit tripped over.
//
// MEASURED 2026-07-28 on JakeLeoDev/proposit @ 82838cef: ten modules ran, 589 findings were
// produced, the conservation ledger printed LEDGER PASS, and `--findings-out`/`--sarif-out` wrote
// NOTHING — the assembled document failed report-schema validation on two duplicate ids
// (`SB-DEFINER-AUTHZ-public.handle_new_user()`, minted from a function name that two migrations
// declare; `M4-97`, the 97th positional jscpd cluster colliding with the fixed diverged-clone scope
// sentinel of the same id). #620 and #1175 are the same class on two earlier families.
//
// Both root causes are fixed at their detectors in this change. This is the guard for the NEXT one:
// a duplicate id must never again be able to cost a client the whole deliverable. Of the three
// available dispositions —
//
//   de-duplicate  — collapses two DIFFERENT findings into one. That is the #1040 loss class, and
//                   the conservation ledger would (correctly) report it as UNACCOUNTED.
//   block         — what happens today: every finding is assembled and none is delivered.
//   disambiguate  — every finding ships, under an id that is unique.
//
// only the third keeps the two properties the audit sells: nothing is lost, and nothing is silent.
// So the 2nd..nth finding sharing an id is renamed `<id>#2`, `<id>#3`, … in stable order, and the
// collision is reported to the caller to print. Byte-identical repeats are NOT touched — those are
// the shared-CLI double captures assembleEngagementDocument collapses and the ledger counts as
// `deduped`.
//
// It runs at the PRODUCE boundary (here, beside #620's per-app namespacing, which does the same job
// for a monorepo) rather than at assembly, so `findings` and `findingsByModule` carry the renamed
// rows and the conservation ledger's produced/delivered arithmetic still matches finding-for-finding.
function disambiguateFindingIds(
  findings: Finding[],
  byModule: Partial<Record<AuditModule, Finding[]>>,
): { findings: Finding[]; byModule: Partial<Record<AuditModule, Finding[]>>; collisions: IdCollision[] } {
  const distinctBodies = new Map<string, Set<string>>();
  for (const f of findings) {
    const bodies = distinctBodies.get(f.id) ?? new Set<string>();
    bodies.add(JSON.stringify(f));
    distinctBodies.set(f.id, bodies);
  }
  const collided = new Set([...distinctBodies].filter(([, bodies]) => bodies.size > 1).map(([id]) => id));
  if (!collided.size) return { findings, byModule, collisions: [] };

  // Keyed on the ORIGINAL object so both views get the same replacement — `findingsByModule` holds
  // the very objects `findings` does, and a rename applied to only one of them would make the
  // conservation gate's produced/delivered comparison disagree with itself.
  const renamed = new Map<Finding, Finding>();
  const seenBodies = new Map<string, Map<string, string>>();
  const collisions = new Map<string, IdCollision>();
  for (const f of findings) {
    if (!collided.has(f.id)) continue;
    const bodies = seenBodies.get(f.id) ?? new Map<string, string>();
    seenBodies.set(f.id, bodies);
    const body = JSON.stringify(f);
    const already = bodies.get(body);
    if (already !== undefined) {
      // A byte-identical repeat of a finding whose id ALSO has a genuine collision: it keeps
      // whatever id its first copy took, so dedupe still collapses the pair at assembly.
      if (already !== f.id) renamed.set(f, { ...f, id: already });
      continue;
    }
    const ordinal = bodies.size + 1;
    const id = ordinal === 1 ? f.id : `${f.id}#${ordinal}`;
    bodies.set(body, id);
    if (ordinal > 1) renamed.set(f, { ...f, id });
  }
  for (const [id, bodies] of seenBodies) {
    collisions.set(id, { id, count: bodies.size, renamedTo: [...bodies.values()].slice(1), modules: [] });
  }

  const remap = (list: Finding[]): Finding[] => list.map((f) => renamed.get(f) ?? f);
  const nextByModule: Partial<Record<AuditModule, Finding[]>> = {};
  for (const [module, list] of Object.entries(byModule) as [AuditModule, Finding[]][]) {
    nextByModule[module] = remap(list);
    for (const f of list) {
      const c = collisions.get(f.id);
      if (c && !c.modules.includes(module)) c.modules.push(module);
    }
  }
  return { findings: remap(findings), byModule: nextByModule, collisions: [...collisions.values()] };
}

export function formatIdCollisions(collisions: IdCollision[]): string {
  return [
    `⚠ ${collisions.length} finding id(s) were minted more than once this run and were disambiguated so the deliverable could still ship (#1470). A detector is deriving an id from something that is not unique per finding — fix it at the detector; the rename below is a safety net, not the answer:`,
    ...collisions.map((c) => `  ${c.id} — ${c.count} distinct findings${c.modules.length ? ` (produced by ${c.modules.join(", ")})` : ""}; renamed: ${c.renamedTo.join(", ")}`),
  ].join("\n");
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
  const findingsByModule: Partial<Record<AuditModule, Finding[]>> = {};
  let hotspots: string[] | undefined;
  // #1049: merged across a monorepo's per-app M10 rows — one engagement, one table→data-class view.
  // Two apps declaring the same table name collapse to the later app's classification; the join is a
  // severity weight, and both entries classify the same name, so the merge cannot invent sensitivity.
  let dataMap: DataClassMap | undefined;
  let testQuality: TestQuality | undefined;

  // Iterate AUDIT_MODULES, not `runners`: the ledger's shape is owned by the module enumeration,
  // so a registry can never shorten the audit by reordering or under-listing itself.
  for (const module of AUDIT_MODULES) {
    const runner = byModule.get(module);
    if (!runner) continue; // unreachable — assertRegistryComplete has already thrown.
    let outcomes: ProbeOutcome[];
    try {
      const result = runner.run(ctx);
      const reports = Array.isArray(result) ? result : [result];
      // #1096: a runner that declares itself migrated and hands back a legacy outcome means a
      // helper somewhere laundered the typed result back into the untyped shape — the compile-time
      // guarantee would still read as kept while the runtime one was gone. Fail loud instead.
      if (runner.typed) {
        const legacy = reports.filter((r) => !isTyped(r));
        if (legacy.length) {
          throw new Error(
            `${module} declares itself migrated (typed: true) but returned ${legacy.length} legacy ProbeOutcome(s) — a migrated probe must return Examined | NotAssessed all the way out, or the typed contract is only decorative (#1096).`,
          );
        }
      }
      outcomes = reports.map((r) => (isTyped(r) ? toOutcome(r) : r));
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
        const produced = outcome.instance ? outcome.findings.map((f) => ({ ...f, id: `${f.id}@${outcome.instance}` })) : outcome.findings;
        findings.push(...produced);
        findingsByModule[module] = [...(findingsByModule[module] ?? []), ...produced];
      }
      if (outcome.status !== "requires-live-run" && outcome.hotspots?.length) hotspots = outcome.hotspots;
      if (outcome.status !== "requires-live-run" && outcome.dataMap) dataMap = { ...dataMap, ...outcome.dataMap };
      if (outcome.status !== "requires-live-run" && outcome.testQuality) testQuality = outcome.testQuality;
    }
  }

  const unique = disambiguateFindingIds(findings, findingsByModule);
  return { recorded, failures, findings: unique.findings, findingsByModule: unique.byModule, idCollisions: unique.collisions, ...(hotspots ? { hotspots } : {}), ...(dataMap ? { dataMap } : {}), ...(testQuality ? { testQuality } : {}) };
}

export function formatFailures(failures: ModuleFailure[]): string {
  return [
    `AUDIT FAIL — ${failures.length} module runner(s) crashed. A crashed runner is a bug, not a tier:`,
    ...failures.map((f) => `  ${f.module} (${MODULES[f.module].name}): ${f.error}`),
  ].join("\n");
}
