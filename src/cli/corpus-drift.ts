// Layer 2 for the external-repo corpus (#263): clones each pinned commit, re-runs the source-tier
// modules against it, and scores the result against the recorded baselines (#222) and #227's
// free-tier calibration invariant (#261). Layer 1 (src/scan/external-corpus.test.ts) proves the
// scorers in `pnpm verify` with no network; this is the pass that actually re-measures real repos.
//
//   pnpm corpus-drift [--target <slug>] [--keep] [--json <path>] [--install] [--m8]
//
// --install (#251) runs `npm install` in each clone before the scanners, which is what lets knip
// resolve the target's config (CLAUDE.md's M5 prereq). --m8 (#300) additionally installs Stryker +
// the target's runner plugin and scores the mutation baseline of every target carrying an `m8`
// config. Both are opt-in and both are minutes per target — the scheduled jobs pass them
// (corpus-drift.yml --install; corpus-m8.yml --install --m8), a local run stays fast by default.
//
// NOT part of `pnpm verify`: it clones six repos over the network and shells out to jscpd/knip and
// the mechanical binaries. It runs on a schedule (.github/workflows/corpus-drift.yml) — `verify`
// stays deterministic and offline, which is what makes it usable as the required per-PR check.
//
// Exits non-zero naming the module and target that drifted. A drift is EITHER a precision fix
// (update that target's baseline in the same PR, with the measured note) OR a regression (fix the
// scanner) — the run does not guess which, it just refuses to be quiet about the movement.
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

import { execFileSync } from "node:child_process";
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { Finding } from "../findings.js";
import { detectPackageManager, installAllCommand, installExtraCommand, withRestoredManifest } from "../package-manager.js";
import { buildQuickScanReport } from "../quick-scan.js";
import { cloneAtPin } from "../scan/corpus-clone.js";
import { runMechanicalScan } from "../scan/mechanical.js";
import {
  EXTERNAL_CORPUS,
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
import type { M8CorpusConfig } from "../scan/m8-corpus.js";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const args = process.argv.slice(2);
const flag = (name: string): string | undefined => {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : undefined;
};

const onlySlug = flag("--target");
const jsonOut = flag("--json");
const keep = args.includes("--keep");
// #251/#300: both opt-in because both cost real minutes of install per target. The scheduled jobs
// pass them (corpus-drift.yml --install, corpus-m8.yml --install --m8); a local run stays fast and
// scores the source-tier modules exactly as before.
const install = args.includes("--install");
const m8 = args.includes("--m8");

const targets = onlySlug ? EXTERNAL_CORPUS.filter((t) => t.slug === onlySlug) : EXTERNAL_CORPUS;
if (targets.length === 0) {
  console.error(`no corpus target "${onlySlug}" — known: ${EXTERNAL_CORPUS.map((t) => t.slug).join(", ")}`);
  process.exit(2);
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
  const { bin, args } = installAllCommand(pm, flags);
  try {
    execFileSync(bin, args, { cwd: dir, stdio: ["ignore", "ignore", "inherit"], env: { ...process.env, CI: "true" } });
  } catch {
    console.error(`  ⚠ ${bin} install failed — M5-knip will report its #223 did-not-run finding and drift against the baseline`);
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
function runMutationScan(dir: string, cfg: M8CorpusConfig): { mutationScore: number; killed: number; valid: number } {
  const pm = detectPackageManager(dir);
  const appDir = cfg.appPath ? join(dir, cfg.appPath) : dir;
  const { bin, args } = installExtraCommand(pm, [...cfg.strykerPackages]);
  // withRestoredManifest(dir, ...) restores the WORKSPACE lockfile (shared, lives at the clone
  // root); a `pnpm add` run with cwd: appDir writes the extra packages into appDir's OWN
  // package.json, which this does not restore — a no-op gap here since `dir` is a disposable temp
  // clone discarded after this run, not the client's real repo (see mutation-scan.ts's --install
  // rung, which DOES need the full restore and runs at a single directory, never a sub-app).
  withRestoredManifest(dir, pm, () => execFileSync(bin, [...args, ...cfg.installFlags], { cwd: appDir, stdio: ["ignore", "ignore", "inherit"] }));
  writeFileSync(join(appDir, "stryker.conf.json"), `${JSON.stringify(cfg.config, null, 2)}\n`);

  const out = join(mkdtempSync(join(tmpdir(), "harvey-m8-")), "m8.json");
  execFileSync("pnpm", ["mutation-scan", appDir, "--out", out], {
    cwd: repoRoot,
    stdio: ["ignore", "ignore", "inherit"],
    env: { ...process.env, PATH: `${join(appDir, "node_modules", ".bin")}:${process.env.PATH ?? ""}` },
  });

  const { summary } = JSON.parse(readFileSync(out, "utf8")) as {
    summary: { overall: { mutationScore: number; killed: number; totalMutants: number; ignored: number; compileErrors: number } };
  };
  const o = summary.overall;
  // "valid" is Stryker's own denominator for the score: everything it could actually judge.
  return { mutationScore: o.mutationScore, killed: o.killed, valid: o.totalMutants - o.ignored - o.compileErrors };
}

// #279: every *.sql file under `dir`, sorted so migrations apply in filename order — the same
// shape tools/pii-classify.mjs's own (private) readSchemaSql uses for its --schema CLI path.
// Recursive (#299): a Prisma schemaPath (prisma/migrations/<name>/migration.sql) is one directory
// deeper than a Supabase one (supabase/migrations/<timestamp>.sql flat) — see readSchemaSql's note.
function readMigrationSql(dir: string): string {
  return readdirSync(dir, { recursive: true, encoding: "utf8" })
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
}

const rows: Row[] = [];

for (const target of targets) {
  const dir = mkdtempSync(join(tmpdir(), `harvey-${target.slug}-`));
  console.error(`\n=== ${target.slug} (${target.repo} @ ${target.commit.slice(0, 8)}) ===`);
  try {
    cloneAtPin(target.repo, target.commit, dir);

    // #251: before any scanner — knip needs these present to resolve the target's config.
    if (install) installTargetDeps(dir, target.m8?.installFlags ?? []);

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
        const row = scoreMutationBaseline(target.slug, baseline, runMutationScan(dir, target.m8));
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
      ...runScanner("detect-static", [dir]),
      ...runScanner("quality-scan", [dir]),
      ...runScanner("mutation-scan", [dir, "--detect-only"]),
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
      if (install) installTargetDeps(rootDir, []);
      const scoped = runScanner("quality-scan", [rootDir]).filter((f) => moduleMatches(f.taxonomy, "M5-knip"));
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

    for (const row of scoreExternalBaseline(target, findings)) {
      rows.push({ slug: row.slug, check: `${row.module} baseline`, pass: row.pass, detail: row.detail });
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
      const report = buildQuickScanReport(await runMechanicalScan({ dir }));
      rows.push(...scoreFreeTierExpectation(expectation, report).map((r) => ({ slug: r.slug, check: `free tier: ${r.check}`, pass: r.pass, detail: r.detail })));
    }
  } finally {
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
const unscored = m8 ? [] : FREE_TIER_EXPECTATIONS.filter((e) => !freeTierScored.has(e.slug) && (!onlySlug || onlySlug === e.slug));

console.error("\n──── corpus drift ────");
for (const r of rows) console.error(`  ${r.pass ? "✓" : "✗"} ${r.slug.padEnd(23)} ${r.check.padEnd(46)} ${r.detail}`);

if (jsonOut) writeFileSync(jsonOut, `${JSON.stringify(rows, null, 2)}\n`);

const failed = rows.filter((r) => !r.pass);
if (failed.length === 0 && unscored.length === 0) {
  console.error(`\n✓ ${rows.length} checks pass — every module reproduces its baseline and the free-tier invariant holds.`);
  process.exit(0);
}
for (const r of failed) console.error(`\n✗ DRIFT ${r.slug} / ${r.check}\n    ${r.detail}`);
for (const e of unscored) console.error(`\n✗ NOT SCORED ${e.slug} / free-tier invariant — the check never ran, which is not a pass.`);
process.exit(1);
