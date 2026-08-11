// Layer 2 for the external-repo corpus (#263): clones each pinned commit, re-runs the source-tier
// modules against it, and scores the result against the recorded baselines (#222) and #227's
// free-tier calibration invariant (#261). Layer 1 (src/scan/external-corpus.test.ts) proves the
// scorers in `pnpm verify` with no network; this is the pass that actually re-measures real repos.
//
//   pnpm corpus-drift [--target <slug>] [--keep] [--json <path>] [--baseline-findings <path>] [--install] [--m8]
//
// --install (#251) installs each clone's own dependency tree before the scanners — with the package
// manager that clone's lockfile implies, since #1268 — which is what lets knip resolve the target's
// config (CLAUDE.md's M5 prereq). --m8 (#300) additionally installs Stryker +
// the target's runner plugin and scores the mutation baseline of every target carrying an `m8`
// config. Both are opt-in and both are minutes per target — the scheduled jobs pass them
// (corpus-drift.yml --install; corpus-m8.yml --install --m8), a local run stays fast by default.
//
// NOT part of `pnpm verify`: it clones every pinned repo over the network and shells out to
// jscpd/knip and the mechanical binaries. It runs on a daily schedule AND on every pull request
// (.github/workflows/corpus-drift.yml, which short-circuits in-job when the diff touches nothing
// the scanners read) — `verify` stays deterministic and offline, which is what makes it usable as
// the required per-PR check.
//
// Exits non-zero naming the module and target that drifted. A drift is EITHER a precision fix
// (update that target's baseline in the same PR, with the measured note) OR a regression (fix the
// scanner) — the run does not guess which, it just refuses to be quiet about the movement, and
// (#1564) it no longer stops at the count: every DRIFT line is immediately followed by
// the ADDED/REMOVED rows that moved (file:line, taxonomy, severity), on by default because the data
// costs nothing extra to print — it's the same finding list this run already computed. The true
// added/removed split needs a prior run's row-level output, via --baseline-findings <path> (this
// run's own --json output already writes one, so tomorrow's run can read today's); without it, the
// run discloses that and names the module's CURRENT findings instead of guessing or staying silent.
//
// Modules scored here are the source-only tier: M4/M5 (quality-scan), M7/M8-intent/M9
// (detect-static), M8 (mutation-scan --detect-only: only where the absence of a suite IS the
// finding — #470: this pass NEVER invokes Stryker; real mutation scoring is corpus-m8.yml's job,
// and a target whose M8 is a mutation baseline gets an explicit deferred row here rather than a
// crash or a silent skip), M10 (classifyMigrationSql over the target's own cloned SQL migrations,
// or #758's Prisma classifier when the manifest's schemaPath names a `schema.prisma` — #894,
// #279 — a target with no schemaPath in the manifest is skipped here and stays not-run. #299
// closed the one target that used to hit this: boxyhq's Prisma migrations parse fine now that
// parseColumns/parseTableNames read quoted identifiers.).
// Anything a target can't run is recorded not-run WITH THE REASON in the manifest and skipped by
// the scorer — never scored 0.
//
// #322: a target may carry per-module scan roots (today: mvp-boilerplate's M5-knip at nextjs/,
// the only place its Next app's package.json lives). The scoped module measures a DIFFERENT tree
// than the whole-repo modules, so every scored row for such a target states its scanned scope —
// the disagreement is recorded in the output, never silent, and cross-module comparisons on such
// a target are scope-invalid by construction.

import "./sync-stdio.js";
import { execFileSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { recordMeasured } from "../ci-liveness.js";
import { readRecursiveSafe } from "../fs-walk.js";
import { fileURLToPath } from "node:url";
import type { Finding } from "../findings.js";
import { detectPackageManager, installAllCommand, installExtraCommand, npmOnlyFlags, withRestoredManifest } from "../package-manager.js";
import { buildQuickScanReport } from "../quick-scan.js";
import { cloneAtPinCached } from "../scan/corpus-clone.js";
import { runMechanicalScanDetailed } from "../scan/mechanical.js";
import { buildMechanicalPhaseCache } from "../scan/mechanical-phase-identity.js";
import { resolveGitTree } from "../scan/mechanical-phase-cache.js";
import {
  EXTERNAL_CORPUS,
  driftExplanationLines,
  FLOOR_CLAIM_TRIAGE,
  floorClaimingNotes,
  fpFloorViolations,
  FREE_TIER_EXPECTATIONS,
  isMutationBaseline,
  isNotRun,
  m10FindingsFromPrismaSchema,
  m10FindingsFromSchema,
  moduleMatches,
  revalidateNotRunReasons,
  scoreExternalBaseline,
  scoreFreeTierExpectation,
  scoreMutationBaseline,
} from "../scan/external-corpus.js";
import { mutationRunFromArtifact } from "../mutation-scan.js";
import { shardTargets } from "../scan/corpus-shards.js";
import { materializeM8Config, type M8CorpusConfig } from "../scan/m8-corpus.js";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const args = process.argv.slice(2);
const flag = (name: string): string | undefined => {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : undefined;
};

const onlySlug = flag("--target");
const jsonOut = flag("--json");
const keep = args.includes("--keep");
// #1564: a prior run's OWN --json output (this run's shape also now writes one — see
// `findingsBySlug` below), so a drift can be EXPLAINED — which rows moved, not just how many —
// without a second scan. Optional: absent on a target's first-ever run, or a local ad-hoc
// invocation; driftExplanationLines then falls back to naming the module's current findings instead
// of a true added/removed split, disclosed as exactly that rather than silently saying nothing.
const baselineFindingsPath = flag("--baseline-findings");
// #251/#300: both opt-in because both cost real minutes of install per target. The scheduled jobs
// pass them (corpus-drift.yml --install, corpus-m8.yml --install --m8); a local run stays fast and
// scores the source-tier modules exactly as before.
const install = args.includes("--install");
const m8 = args.includes("--m8");
const forceColdCache = args.includes("--force-cold-cache");
const phaseCacheDir = process.env.HARVEY_CORPUS_PHASE_CACHE_DIR;
if (forceColdCache && !phaseCacheDir) {
  console.error("--force-cold-cache requires HARVEY_CORPUS_PHASE_CACHE_DIR; a cold equivalence run with nowhere to read/write artifacts proves nothing");
  process.exit(2);
}

// #1586: `--shard i/n` selects this runner's slice of the corpus so corpus-drift.yml can score the
// targets in parallel across n machines. Deterministic and coordination-free — every runner computes
// the same partition and takes its own index. `--target` addresses ONE target for a local run; the
// two are different addressing modes and combining them is a mistake worth failing on rather than
// silently letting one win.
const shardSpec = flag("--shard");
if (shardSpec && onlySlug) {
  console.error("--shard and --target are different addressing modes — pass one or the other, not both");
  process.exit(2);
}

let targets = onlySlug ? EXTERNAL_CORPUS.filter((t) => t.slug === onlySlug) : EXTERNAL_CORPUS;
if (targets.length === 0) {
  console.error(`no corpus target "${onlySlug}" — known: ${EXTERNAL_CORPUS.map((t) => t.slug).join(", ")}`);
  process.exit(2);
}

if (shardSpec) {
  const [rawIndex, rawCount] = shardSpec.split("/");
  const shardIndex = Number(rawIndex);
  const shardCount = Number(rawCount);
  if (!Number.isInteger(shardIndex) || !Number.isInteger(shardCount)) {
    console.error(`--shard expects <index>/<count>, e.g. --shard 1/3 — got "${shardSpec}"`);
    process.exit(2);
  }
  // shardTargets asserts the partition is exhaustive and disjoint before returning this slice: a
  // target silently dropped from the split stops being scored while every shard still exits 0,
  // which is a coverage change wearing a green tick.
  let mine: Set<string>;
  try {
    mine = new Set(shardTargets(EXTERNAL_CORPUS.map((t) => t.slug), shardIndex, shardCount));
  } catch (e) {
    console.error(e instanceof Error ? e.message : String(e));
    process.exit(2);
  }
  targets = targets.filter((t) => mine.has(t.slug));
  console.error(
    `shard ${shardIndex}/${shardCount} — scoring ${targets.length} of ${EXTERNAL_CORPUS.length} target(s): ${targets.map((t) => t.slug).join(", ")}`,
  );
  // A shard that draws no targets is a partition or shard-count bug, not a fast pass. Failing here
  // keeps it from reporting green having measured nothing.
  if (targets.length === 0) {
    console.error(`shard ${shardIndex}/${shardCount} drew no targets — the partition or the shard count is wrong`);
    process.exit(2);
  }
}

let priorFindingsBySlug: Record<string, Finding[]> | undefined;
if (baselineFindingsPath) {
  if (!existsSync(baselineFindingsPath)) {
    console.error(`--baseline-findings ${baselineFindingsPath} not found — proceeding without a prior snapshot (a drift will name its current findings, not a true added/removed split)`);
  } else {
    const parsed = JSON.parse(readFileSync(baselineFindingsPath, "utf8")) as { findings?: Record<string, Finding[]> };
    priorFindingsBySlug = parsed.findings ?? {};
  }
}

// #251: knip resolves a target's config imports only when the target's own deps are present
// (CLAUDE.md's M5 prereq) — without this, M5-knip was unrun on 4 of 6 targets. Off by default and
// on in the scheduled job (--install): a clone-and-install of six real repos is minutes and a lot
// of network, which a local `pnpm corpus-drift --target X` shouldn't pay unless it's asking about
// M5. Measured 2026-07-15: installing is inert for the other modules (M4 and both already-scored
// M5-knip baselines reproduced byte-identically with deps present).
//
// Failure is NOT fatal to the target: quality-scan degrades to its M5-00 "did not run" finding
// (#223), the M5-knip baseline then drifts, and the job says so — which is the loud failure this
// job exists for. Swallowing the install error to keep other modules scoring is the same call
// runScanner already makes.
//
// #1268: `npm install` at a pnpm-workspace root resolves only the ROOT packages — MEASURED against
// inbox-zero/rallly (external-corpus.ts's recorded M8 not-run reasons: apps/web/node_modules simply
// does not exist afterward) and fails outright on carbon (a pnpm-catalog `catalog:` dependency,
// EUNSUPPORTEDPROTOCOL). The target's own lockfile says which package manager actually resolves it.
//
// A second, narrower #1268 finding, MEASURED against the real inbox-zero clone: its own
// `pnpm-workspace.yaml` opts into `enableGlobalVirtualStore: true`, which stores the resolved
// package graph OUTSIDE the project (under pnpm's global home dir,
// `~/Library/pnpm/store/v11/links/...` on macOS) rather than in
// the project's own node_modules/.pnpm. pnpm's own dependency resolution is unaffected, but any
// tool that dynamically resolves a SIBLING package via Node's own node_modules directory walk
// relative to ITS OWN real (globally-stored) file path can no longer find it — Stryker does exactly
// this for both its runner plugins and its own `import("typescript")` (src/mutation-scan.ts's
// scaffoldStrykerConfig `plugins` fix, #1284, does not help here: the walk never reaches the
// project's node_modules at all). Disabling it for the disposable corpus clone (never the target's
// own repo) reproduced a real 76.00% Stryker run against inbox-zero's apps/web (this PR).
const GLOBAL_VIRTUAL_STORE_TRUE = /^(\s*enableGlobalVirtualStore\s*:\s*)true\s*$/m;

function disableGlobalVirtualStoreIfSet(dir: string): void {
  const path = join(dir, "pnpm-workspace.yaml");
  if (!existsSync(path)) return;
  const text = readFileSync(path, "utf8");
  if (!GLOBAL_VIRTUAL_STORE_TRUE.test(text)) return;
  writeFileSync(path, text.replace(GLOBAL_VIRTUAL_STORE_TRUE, "$1false"));
  console.error(`  #1268: ${path} opts into enableGlobalVirtualStore — disabled for this clone (Stryker's own plugin/typescript resolution cannot reach a globally-stored package graph)`);
}

function installTargetDeps(dir: string, flags: readonly string[]): void {
  const pm = detectPackageManager(dir);
  if (pm === "pnpm") disableGlobalVirtualStoreIfSet(dir);
  const { bin, args } = installAllCommand(pm, npmOnlyFlags(pm, flags));
  try {
    execFileSync(bin, args, { cwd: dir, stdio: ["ignore", "ignore", "inherit"], env: { ...process.env, CI: "true" } });
  } catch {
    console.error(`  ⚠ ${bin} install failed — M5-knip will report its #223 did-not-run finding and drift against the baseline`);
  }
}

// #1574: PER-PHASE cost, per target. #1586 measured each target's TOTAL from banner intervals and
// used it to partition the shards; that is the right input for a partition and the wrong one for an
// optimisation, because it leaves open whether a target's minutes went to the clone, the install
// or one scanner. #1574's own table asserted ~79% scanning from a single 2026-07-28 run and could not
// break that down further. Every phase below is timed at its own call site, so any run — CI or
// local — re-derives the split instead of quoting that table.
//
// stderr, not the --json scorecard: #1564 makes that file a FUTURE run's --baseline-findings input,
// and a timing key would travel into a comparison it has no business in.
//
// WHAT IT MEASURED, and it moves the answer #1574 was filed with.
// PROVENANCE: MEASURED 2026-07-31 on a 10-core darwin box, `pnpm corpus-drift --install` over the
// whole corpus (17 targets, 854s timed), n=1 for the run and n=2 for the three heaviest targets
// (`--install --target <slug>`, second pass in close agreement: carbon 343s/331s, proposit 93s/90s,
// saas-lite 91s/92s). Per-repeat numbers are in this PR's body; the run prints its own every time,
// so nothing here has to be believed.
//
//   free-tier quick-scan  447.9s  52.5%     clone            61.9s   7.3%
//   quality-scan          138.6s  16.2%     detect-static    61.7s   7.2%
//   install               134.2s  15.7%     mutation-scan     9.4s   1.1%
//
// #1574's table split this as "~79% scanning / ~21% clone+install" and named the scanners as
// "semgrep / detect-static / jscpd / knip". Both halves reconcile — 77.0% vs 23.0% here (scanning
// 657.6s of 853.7s, setup 196.1s of 853.7s) — but the
// DOMINANT phase is one that table does not name at all: the FREE-TIER quick-scan, the full
// `runMechanicalScan` the #261 invariant needs, which runs for the 6 targets carrying a
// FREE_TIER_EXPECTATIONS entry and is 52.5% of the corpus on its own (247s of carbon's 343s). An
// optimisation aimed at "the scanners" as the table describes them would have gone after
// detect-static, which is 7.2%.
//
// WHAT IS NOT DONE HERE, each with the cost this run measured (#1574 criterion 3):
//   * Caching the --install tree, #1574's option 1. Ceiling 134.2s (15.7%), and only on a cache
//     HIT — the key would be the target's lockfile, so the first run after any pin bump pays it in
//     full. The largest single install is documenso's 23.2s.
//   * Caching scan results per (target sha, scanner version, rule set), option 2. Ceiling 657.6s
//     (77%) and the only one with real headroom, which is what #1574 already suspected. Every input
//     is pinned; the work is deriving a key that a semgrep rule edit invalidates. #1710's original
//     blocker here — semgrep returned 47/62/70 findings across three identical carbon runs, so a
//     cache would have pinned one draw from a distribution — is CLOSED: runSemgrep now pins
//     `--x-parmap --timeout 0` (measured byte-identical across 7/7 carbon repeats, 2026-07-31,
//     semgrep 1.164.0; docs/design/semgrep-determinism.md), so a cache key is sound again.
//   * Bounding the per-target scan, option 3. carbon is 343s of 854s; bounding it to the corpus
//     mean would buy ~290s and cost the corpus its only large target, which is the one that finds
//     things the others do not. It would also need a counted not-assessed row naming what it
//     skipped, per the disclosure family.
// Option 4, sharding, IS done — #1586 — and is measured before/after (single-job CI runs
// `30584074986` 22m12s, `30588890377` 22m51s, `30346918870` 21m10s, n=3 mean 22m04s; three-shard
// PR runs `30658181231` 11m35s, `30657876311` 10m55s, `30651453802` 11m18s, `30640448533` 10m52s,
// `30630790646` 10m15s, n=5 max-shard mean 11m00s) — a 50% cut in the wall clock on the merge path.
const phaseSeconds: Record<string, Record<string, number>> = {};
let phaseTarget = "";

function timed<T>(phase: string, fn: () => T): T {
  const at = Date.now();
  try {
    return fn();
  } finally {
    const bucket = (phaseSeconds[phaseTarget] ??= {});
    bucket[phase] = (bucket[phase] ?? 0) + (Date.now() - at) / 1000;
  }
}

function runScanner(script: string, scriptArgs: string[]): Finding[] {
  const out = join(mkdtempSync(join(tmpdir(), "harvey-corpus-")), "findings.json");
  try {
    execFileSync("pnpm", [script, ...scriptArgs, "--out", out], { cwd: repoRoot, stdio: ["ignore", "ignore", "inherit"] });
  } catch {
    // The scanner CLIs already print their own diagnosis to stderr. A module that could not run
    // contributes no findings, which the scorer then reports as drift against its baseline —
    // the loud failure this job exists for, not something to swallow into a pass.
    return [];
  }
  const parsed = JSON.parse(readFileSync(out, "utf8")) as Finding[] | { finding: Finding };
  return Array.isArray(parsed) ? parsed : [parsed.finding];
}

// #300: installs Stryker + the target's runner plugin, writes the vendored config, and runs the M8
// wrapper — the setup m8-corpus.ts explains why is per-target data rather than something a generic
// wrapper infers. --no-save keeps the target's own manifest untouched, and node_modules/.bin is
// prepended so mutation-scan's `stryker` lookup finds THIS target's binary rather than a stray one.
//
// An install/run failure throws: unlike the source-tier modules, there is no partial M8 result to
// salvage, and a target listed as m8-scoreable that silently produced no score is exactly the
// silent skip the coverage guard forbids.
//
// #1268: same fix as installTargetDeps above, for the EXTRA Stryker packages this needs on top of
// whatever the target already declares — npm's --no-save is native, pnpm/yarn have no equivalent
// (see src/package-manager.ts), so withRestoredManifest snapshots+restores package.json/lockfile
// around a pnpm/yarn install. Harmless either way here (dir is a disposable temp clone), but keeps
// this path's behavior consistent with mutation-scan.ts's own --install rung against a live target.
// `appDir` is where the config, the Stryker install, and mutation-scan itself all point — the
// clone root for a single-package target (proposit/boxyhq, cfg.appPath undefined), or the
// workspace MEMBER that actually carries the suite (inbox-zero's apps/web) when set. The package
// manager is still detected from the clone ROOT: that is where the workspace's lockfile lives.
function runMutationScan(slug: string, dir: string, cfg: M8CorpusConfig): { mutationScore: number; killed: number; valid: number } {
  const pm = detectPackageManager(dir);
  const appDir = cfg.appPath ? join(dir, cfg.appPath) : dir;
  const { bin, args } = installExtraCommand(pm, [...cfg.strykerPackages]);
  // withRestoredManifest(dir, ...) restores the WORKSPACE lockfile (shared, lives at the clone
  // root); a `pnpm add` run with cwd: appDir writes the extra packages into appDir's OWN
  // package.json, which this does not restore — a no-op gap here since `dir` is a disposable temp
  // clone discarded after this run, not the client's real repo (see mutation-scan.ts's --install
  // rung, which DOES need the full restore and runs at a single directory, never a sub-app).
  withRestoredManifest(dir, pm, () => execFileSync(bin, [...args, ...npmOnlyFlags(pm, cfg.installFlags)], { cwd: appDir, stdio: ["ignore", "ignore", "inherit"] }));

  // #1496/#1693: the vendored Stryker config, plus (for a target whose own suite is unscoreable —
  // multi-tenant-starter's Docker-per-mutant cost) the DB-free suite that config points at, written
  // in before Stryker's dry run reads either. `appDir` is inside the disposable temp clone the rest
  // of this function already writes into. Lives in m8-corpus.ts so it has a test.
  materializeM8Config(appDir, cfg);

  const out = join(mkdtempSync(join(tmpdir(), "harvey-m8-")), "m8.json");
  execFileSync("pnpm", ["mutation-scan", appDir, "--out", out], {
    cwd: repoRoot,
    stdio: ["ignore", "ignore", "inherit"],
    env: { ...process.env, PATH: `${join(appDir, "node_modules", ".bin")}:${process.env.PATH ?? ""}` },
  });

  // #1419: read through mutationRunFromArtifact, which names the target and the degradation instead
  // of dying on `summary.overall` with a TypeError that reads as a crash in this harness.
  return mutationRunFromArtifact(slug, JSON.parse(readFileSync(out, "utf8")));
}

// #279: every *.sql file under `dir`, sorted so migrations apply in filename order — the same
// shape tools/pii-classify.mjs's own (private) readSchemaSql uses for its --schema CLI path.
// Recursive (#299): a Prisma schemaPath (prisma/migrations/<name>/migration.sql) is one directory
// deeper than a Supabase one (supabase/migrations/<timestamp>.sql flat) — see readSchemaSql's note.
function readMigrationSql(dir: string): string {
  return readRecursiveSafe(dir)
    .filter((f) => f.endsWith(".sql"))
    .sort()
    .map((f) => readFileSync(join(dir, f), "utf8"))
    .join("\n\n");
}

interface Row {
  slug: string;
  check: string;
  pass: boolean;
  detail: string;
  // Set only on a count-baseline row (scoreExternalBaseline's output) — the module name, so a
  // failed row can be explained (driftExplanationLines) against this run's own current findings without
  // re-parsing it out of `check`. Absent on every other row kind (free tier, M8 mutation, a stale
  // not-run reason): those aren't a finding-count drift and driftExplanationLines has nothing to say about
  // them.
  module?: string;
}

const rows: Row[] = [];
// #1564: the current findings this run computed per target, keyed by slug — captured so
// a drift can be explained from data already in memory, and so THIS run's --json output can serve
// as a FUTURE run's --baseline-findings input (see the JSON write at the bottom of this file).
const findingsBySlug: Record<string, Finding[]> = {};

for (const target of targets) {
  const dir = mkdtempSync(join(tmpdir(), `harvey-${target.slug}-`));
  console.error(`\n=== ${target.slug} (${target.repo} @ ${target.commit.slice(0, 8)}) ===`);
  // #1586: the shard weights in corpus-shards.ts are an estimate derived once, from banner
  // intervals in one run's log. Printing each target's real elapsed time means any run re-measures
  // them directly, so a weight that has gone stale is visible rather than inferred.
  const startedAt = Date.now();
  phaseTarget = target.slug;
  phaseSeconds[target.slug] = {};
  try {
    // #1571: a per-run copy from $HARVEY_CORPUS_CACHE_DIR's pristine checkout when CI has one
    // (set by .github/actions/corpus-clone-cache) — a bare network clone otherwise, exactly as
    // before. `dir` stays a disposable mkdtemp copy either way, so --install/scanning below can
    // still mutate or delete it freely.
    timed("clone", () => cloneAtPinCached(target.repo, target.commit, dir, process.env.HARVEY_CORPUS_CACHE_DIR, true));

    // #1524: strip any vendored reference subtree BEFORE any scanner or install sees this disposable
    // clone — schemaPath/installTargetDeps below still resolve against `dir` itself, which this
    // never touches, only named subdirectories under it.
    for (const sub of target.vendoredSubtrees ?? []) {
      const subDir = join(dir, sub);
      if (!existsSync(subDir)) throw new Error(`${target.slug}: vendoredSubtrees names "${sub}", not found in the cloned tree — the manifest entry is stale`);
      console.error(`  #1524: removing vendored subtree ${sub}/ before scanning (not this target's own code)`);
      rmSync(subDir, { recursive: true, force: true });
    }

    // #251: before any scanner — knip needs these present to resolve the target's config.
    if (install) timed("install", () => installTargetDeps(dir, target.m8?.installFlags ?? []));

    // #300: M8 is scored as a mutation percentage, not a finding count, and only where the manifest
    // carries both a vendored config and a MutationBaseline. --m8 is an M8-ONLY pass: its job
    // (corpus-m8.yml) exists because mutation testing is minutes per target, and it deliberately
    // doesn't install the mechanical binaries the free-tier check below shells out to. Re-scoring
    // the source tier here would either duplicate corpus-drift.yml's work or fail on a missing
    // binary. Targets whose M8 is not-run keep their recorded reason; the zero-test targets are
    // scored by the source-tier pass below, where #224's finding IS the count.
    if (m8) {
      if (target.m8) {
        const baseline = target.modules.M8;
        if (!isMutationBaseline(baseline)) {
          throw new Error(`${target.slug}: has an m8 config but its M8 baseline is not a MutationBaseline — the manifest disagrees with itself about whether this target is scoreable`);
        }
        const row = scoreMutationBaseline(target.slug, baseline, runMutationScan(target.slug, dir, target.m8));
        rows.push({ slug: row.slug, check: "M8 mutation baseline", pass: row.pass, detail: row.detail });
      } else {
        // Asked to mutation-score a target the manifest says isn't scoreable. Not a silent no-op:
        // the reason is recorded, so print it and fail rather than exiting 0 having measured
        // nothing (the coverage guard — a job that scores nothing must not look green).
        const baseline = target.modules.M8;
        rows.push({
          slug: target.slug,
          check: "M8 mutation baseline",
          pass: false,
          detail: `NOT SCOREABLE: ${isNotRun(baseline) ? baseline.reason : "this target's M8 is scored by the source-tier pass (#224's zero-coverage finding), not by mutation testing — run it without --m8"}`,
        });
      }
      continue;
    }

    // Two scanners emit `M5 —` findings and they measure DIFFERENT things: quality-scan's knip
    // pass is dead code (unused files/exports), detect-static's slop pass is style (else-after-
    // return, single-call wrappers). #278 split the manifest's single M5 into M5-knip and
    // M5-slop, each with its own baseline, and scoreExternalBaseline's moduleMatches tells them
    // apart by taxonomy — so both scanners' output is scored now instead of filtering one out.
    // mutation-scan runs --detect-only (#470): this job provisions no Stryker, so it must only
    // ever contribute the suite-absent finding (#224/#252), never attempt a mutation run that
    // dies on a missing binary mid-corpus.
    let findings = [
      ...timed("detect-static", () => runScanner("detect-static", [dir])),
      ...timed("quality-scan", () => runScanner("quality-scan", [dir])),
      ...timed("mutation-scan", () => runScanner("mutation-scan", [dir, "--detect-only"])),
    ];

    // #322: a per-module scan root — the module measures the subtree it needs (knip requires the
    // tree with the package.json), while every other module keeps the whole repo. The scoped
    // measurement REPLACES the whole-tree pass's M5-knip output (which for such a target is only
    // ever the #223 "did not run" sentinel from the root-level knip failure); the scored rows for
    // this target then carry the per-module scope so the difference is explicit.
    const m5Root = target.scanRoots?.["M5-knip"];
    if (m5Root) {
      const rootDir = join(dir, m5Root);
      if (!existsSync(rootDir)) {
        throw new Error(`${target.slug}: M5-knip scan root "${m5Root}" not found in the cloned tree — the manifest's scan root is stale`);
      }
      if (install) timed("install", () => installTargetDeps(rootDir, []));
      const scoped = timed("quality-scan", () => runScanner("quality-scan", [rootDir])).filter((f) => moduleMatches(f.taxonomy, "M5-knip"));
      findings = [...findings.filter((f) => !moduleMatches(f.taxonomy, "M5-knip")), ...scoped];
    }

    // #279: M10 over the target's own cloned migrations. A target with no schemaPath (boxyhq —
    // Prisma migrations this parser can't read) is skipped here and stays not-run in the manifest,
    // per the coverage guard. A schemaPath that doesn't resolve in the cloned tree is a stale
    // manifest entry, not an absent module — that throws rather than silently scoring 0.
    if (target.schemaPath) {
      const schemaPath = join(dir, target.schemaPath);
      if (!existsSync(schemaPath)) {
        throw new Error(`${target.slug}: schemaPath "${target.schemaPath}" not found in the cloned tree — the manifest's path is stale`);
      }
      // #894: a Prisma-path target declares a `schema.prisma` FILE, not a migrations dir — those
      // targets have no CREATE TABLE SQL for classifyMigrationSql to read, so they route through
      // #758's Prisma model/field classifier instead. Routed on the extension rather than a new
      // manifest field: the path already says which input it is.
      findings.push(...(target.schemaPath.endsWith(".prisma")
        ? m10FindingsFromPrismaSchema(readFileSync(schemaPath, "utf8"))
        : m10FindingsFromSchema(readMigrationSql(schemaPath))));
    }

    findingsBySlug[target.slug] = findings;

    for (const row of scoreExternalBaseline(target, findings)) {
      rows.push({ slug: row.slug, check: `${row.module} baseline`, pass: row.pass, detail: row.detail, module: row.module });
    }

    // #470: this pass runs no Stryker, so a target whose M8 is a mutation baseline is not
    // scoreable here — that is a DEFERRAL to corpus-m8.yml, and it gets a row saying so. A
    // passing-but-explicit row, not a failure: the module's absence from the tally is the
    // silent-skip failure mode this job exists to prevent, and before this row the M8 step
    // crashed on "stryker binary not found" instead (issue #470).
    if (isMutationBaseline(target.modules.M8)) {
      rows.push({
        slug: target.slug,
        check: "M8 mutation baseline",
        pass: true,
        detail: "deferred — mutation scoring needs a provisioned Stryker install and is corpus-m8.yml's job (pnpm corpus-drift --m8); recorded here so the M8 mutation tier is never silently absent from this scorecard",
      });
    }

    // #321: the standard pass already re-attempted every source-tier module above. If a module the
    // manifest records as not-run nonetheless produced real findings, its reason has decayed — fail
    // loud so the stale excuse gets replaced by a baseline rather than silently costing coverage.
    for (const row of revalidateNotRunReasons(target, findings)) {
      rows.push({ slug: row.slug, check: `${row.module} not-run reason still valid`, pass: row.pass, detail: row.detail });
    }

    // #261: the free-tier invariant, scored against a REAL quick-scan of this pinned tree rather
    // than the synthetic findings #244 could only assert over.
    const expectation = FREE_TIER_EXPECTATIONS.find((e) => e.slug === target.slug);
    if (expectation) {
      // Timed around the SCAN, not just the report build: the scan is the whole cost (proposit's
      // free-tier pass measured 84s of its 96s), and timing the cheap half would have left it in
      // the untimed `other` bucket — a phase table whose largest row is "other" answers nothing.
      const mechanicalRun = await runMechanicalScanDetailed({
        dir,
        phaseCache: phaseCacheDir ? buildMechanicalPhaseCache({
          repoRoot,
          cacheDir: phaseCacheDir,
          mode: forceColdCache ? "verify" : "read-write",
          targetRevision: target.commit,
          targetTree: `${resolveGitTree(dir)}:${JSON.stringify(target.vendoredSubtrees ?? [])}`,
          optionIdentity: JSON.stringify({ bundleDir: null, skipBundleScan: false, skipNetworkChecks: false, handrolledIndicators: false, authGuards: [] }),
          onEvent: (message) => console.error(`  ${target.slug}: ${message}`),
        }) : undefined,
      });
      const mechanical = mechanicalRun.findings;
      for (const phase of mechanicalRun.phases) {
        const name = `mechanical:${phase.phase}`;
        (phaseSeconds[phaseTarget] ??= {})[name] = ((phaseSeconds[phaseTarget] ??= {})[name] ?? 0) + phase.durationMs / 1000;
        console.error(`  ${target.slug}: PHASE ${phase.phase} ${(phase.durationMs / 1000).toFixed(1)}s — ${phase.cache}; ${phase.scope.unitsExamined} unit(s); ${phase.reason}`);
      }
      const reportAt = Date.now();
      const report = buildQuickScanReport(mechanical);
      (phaseSeconds[phaseTarget] ??= {})["free-tier report"] = (Date.now() - reportAt) / 1000;
      rows.push(...scoreFreeTierExpectation(expectation, report).map((r) => ({ slug: r.slug, check: `free tier: ${r.check}`, pass: r.pass, detail: r.detail })));
    }
  } finally {
    const total = (Date.now() - startedAt) / 1000;
    const phases = phaseSeconds[target.slug] ?? {};
    const timedTotal = Object.values(phases).reduce((a, b) => a + b, 0);
    // "other" is every un-timed second inside the target's block — the M10 schema pass, the
    // scorers, the temp-dir teardown. Printed rather than dropped: a phase table whose parts do not
    // reconcile with the total is how "~79% scanning" becomes unfalsifiable.
    const parts = [...Object.entries(phases), ["other", total - timedTotal] as [string, number]]
      .filter(([, v]) => v >= 0.05)
      .sort((a, b) => b[1] - a[1])
      .map(([k, v]) => `${k} ${v.toFixed(1)}s`);
    console.error(`  ${target.slug}: ${Math.round(total)}s — ${parts.join(", ")}`);
    if (keep) console.error(`  (kept clone: ${dir})`);
    else rmSync(dir, { recursive: true, force: true });
  }
}

// A target in FREE_TIER_EXPECTATIONS that never got scored (e.g. --target skipped it) must not
// read as a pass — the invariant is the product promise, so an unrun check is a failure. Keyed on
// the free-tier rows specifically, not on the slug: an M8 row for the same target is not evidence
// the free-tier check ran. --m8 is exempt because it is an M8-only pass that never claims to score
// the invariant; the weekly corpus-drift.yml is what holds that promise.
const freeTierScored = new Set(rows.filter((r) => r.check.startsWith("free tier: ")).map((r) => r.slug));
// #1586: scoped to the targets THIS run was asked to score, rather than to `--target` specifically.
// A `--shard` run owns a subset, and the targets it does not own are another shard's responsibility,
// not an unrun check — MEASURED on run 30591262412, where shards 2 and 3 correctly scored their own
// slices and then failed on the free-tier expectations belonging to shard 1. The guard is not
// weakened: the partition is asserted exhaustive, so every expectation is still checked by exactly
// one shard, and a target this run DID own but failed to score is still caught below.
// Scoping by slug is only safe because every free-tier expectation is guaranteed to name a real
// corpus target — one that did not would silently vanish under this rule instead of being flagged
// forever as unscored. external-corpus.ts throws at module load if that ever stops holding, so an
// orphaned expectation fails at import, before this line runs and before anything is cloned.
const scopedSlugs = new Set(targets.map((t) => t.slug));
const unscored = m8 ? [] : FREE_TIER_EXPECTATIONS.filter((e) => !freeTierScored.has(e.slug) && scopedSlugs.has(e.slug));

// #1574 criterion 1: the run's OWN per-phase split, rolled up across every target it scored. The
// figures #1574 was filed from ("~79% scanning", "clone ~4%") came from one 2026-07-28 run and were
// stated in the issue body, which is exactly the shape this repo treats as a claim about the past.
// This prints the current one every time, so the next optimisation argues with a number the run in
// front of it produced.
const rollup: Record<string, number> = {};
for (const phases of Object.values(phaseSeconds)) {
  for (const [phase, secs] of Object.entries(phases)) rollup[phase] = (rollup[phase] ?? 0) + secs;
}
const timedAll = Object.values(rollup).reduce((a, b) => a + b, 0);
if (timedAll > 0) {
  console.error(`\n──── where the time went (${targets.length} target(s), ${timedAll.toFixed(0)}s timed) ────`);
  for (const [phase, secs] of Object.entries(rollup).sort((a, b) => b[1] - a[1])) {
    console.error(`  ${phase.padEnd(22)} ${secs.toFixed(1).padStart(8)}s  ${((secs / timedAll) * 100).toFixed(1).padStart(5)}%`);
  }
  console.error("  (per-target lines above carry each target's own split, including its untimed `other`)");
}

console.error("\n──── corpus drift ────");
for (const r of rows) console.error(`  ${r.pass ? "✓" : "✗"} ${r.slug.padEnd(23)} ${r.check.padEnd(46)} ${r.detail}`);

// #1509's second-order defect: this job died in SETUP for days and read no differently from "ran and
// found no drift". Emitted HERE, after scoring, so only a run that got this far writes the receipt —
// and `rows.length === 0` throws rather than printing "✓ 0 checks pass" below.
recordMeasured("corpus-drift", rows.length, `baseline checks over ${targets.length} pinned target(s)`);

// #1564: `findings` alongside `rows` so THIS run's own --json output can serve as a
// FUTURE run's --baseline-findings — no separate artifact, no second scan, just the same data this
// run already computed, kept instead of discarded.
if (jsonOut) writeFileSync(jsonOut, `${JSON.stringify({ rows, findings: findingsBySlug }, null, 2)}\n`);

// #1485 — the manifest's declared false-positive FLOORS, checked here as well as in the unit suite,
// because this is the job that watches the baselines move. A floor that starts producing graded rows
// is a negative control that has saturated: it can no longer fail in the direction it exists to fail
// in, and the drift row alone does not say so. The claim census is printed even on a pass — its net
// is a hand-written vocabulary (`FLOOR_CLAIM_PHRASES`), so it is a ratchet over the phrasings this
// repo has used, never a census of every floor a note might intend.
const floorClaims = floorClaimingNotes();
const floorBreaches = fpFloorViolations();
console.error(
  `\nFP-FLOOR CENSUS (#1485): ${floorClaims.length} note(s) claim a floor role — ` +
    `${floorClaims.length - FLOOR_CLAIM_TRIAGE.length} declared \`fpFloor\`, ${FLOOR_CLAIM_TRIAGE.length} triaged as something else. ` +
    `Vocabulary-bounded: a note inventing a new way to say "floor" is invisible to it.`,
);
for (const b of floorBreaches) console.error(`✗ SATURATED FLOOR ${b.slug} / ${b.module} — declared fpFloor, baseline carries ${b.counted} graded row(s)`);

const failed = rows.filter((r) => !r.pass);
if (failed.length === 0 && unscored.length === 0 && floorBreaches.length === 0) {
  console.error(`\n✓ ${rows.length} checks pass — every module reproduces its baseline and the free-tier invariant holds.`);
  process.exit(0);
}
// On by default, not behind a flag: the data is already in memory from this same run (`current`),
// costs nothing extra to print, and the reader who most needs the exact rows that moved is the one
// who did not know to ask for them (both 2026-07-30 incidents this exists for were resolved only by
// someone cloning the target and diffing by hand — 20+ minutes each).
//
// #1580: the lines come from driftExplanationLines() rather than being printed here, because the
// case that mattered — a standing drift whose row diff is empty — used to print nothing at all, and
// a `void` printer inside a CLI is reachable by no test. The loop below is now thin enough that what
// it prints is what that function returns.
for (const r of failed) {
  console.error(`\n✗ DRIFT ${r.slug} / ${r.check}\n    ${r.detail}`);
  // Not a count-baseline row (free tier / M8 mutation / stale not-run reason) — explainDrift has
  // nothing to add.
  if (!r.module) continue;
  for (const line of driftExplanationLines(r.module, r.slug, findingsBySlug[r.slug] ?? [], priorFindingsBySlug?.[r.slug], baselineFindingsPath)) console.error(line);
}
for (const e of unscored) console.error(`\n✗ NOT SCORED ${e.slug} / free-tier invariant — the check never ran, which is not a pass.`);
process.exit(1);
