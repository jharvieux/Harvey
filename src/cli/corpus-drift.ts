// Layer 2 for the external-repo corpus (#263): clones each pinned commit, re-runs the source-tier
// modules against it, and scores the result against the recorded baselines (#222) and #227's
// free-tier calibration invariant (#261). Layer 1 (src/scan/external-corpus.test.ts) proves the
// scorers in `pnpm verify` with no network; this is the pass that actually re-measures real repos.
//
//   pnpm corpus-drift [--target <slug>] [--keep] [--json <path>]
//
// NOT part of `pnpm verify`: it clones six repos over the network and shells out to jscpd/knip and
// the mechanical binaries. It runs on a schedule (.github/workflows/corpus-drift.yml) — `verify`
// stays deterministic and offline, which is what makes it usable as the required per-PR check.
//
// Exits non-zero naming the module and target that drifted. A drift is EITHER a precision fix
// (update that target's baseline in the same PR, with the measured note) OR a regression (fix the
// scanner) — the run does not guess which, it just refuses to be quiet about the movement.
//
// Modules scored here are the source-only tier: M4/M5 (quality-scan), M7/M9 (detect-static), M8
// (mutation-scan, only where the absence of a suite IS the finding), M10 (classifyMigrationSql
// over the target's own cloned SQL migrations, #279 — a target with no schemaPath in the manifest
// is skipped here and stays not-run. #299 closed the one target that used to hit this: boxyhq's
// Prisma migrations parse fine now that parseColumns/parseTableNames read quoted identifiers.).
// Anything a target can't run is recorded not-run WITH THE REASON in the manifest and skipped by
// the scorer — never scored 0.

import { execFileSync } from "node:child_process";
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { Finding } from "../findings.js";
import { buildQuickScanReport } from "../quick-scan.js";
import { runMechanicalScan } from "../scan/mechanical.js";
import {
  EXTERNAL_CORPUS,
  FREE_TIER_EXPECTATIONS,
  m10FindingsFromSchema,
  scoreExternalBaseline,
  scoreFreeTierExpectation,
  type ExternalTarget,
} from "../scan/external-corpus.js";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const args = process.argv.slice(2);
const flag = (name: string): string | undefined => {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : undefined;
};

const onlySlug = flag("--target");
const jsonOut = flag("--json");
const keep = args.includes("--keep");

const targets = onlySlug ? EXTERNAL_CORPUS.filter((t) => t.slug === onlySlug) : EXTERNAL_CORPUS;
if (targets.length === 0) {
  console.error(`no corpus target "${onlySlug}" — known: ${EXTERNAL_CORPUS.map((t) => t.slug).join(", ")}`);
  process.exit(2);
}

// Fetch by exact commit rather than clone + checkout: the baselines are only meaningful against
// the pinned tree, and `fetch --depth 1 <sha>` refuses rather than silently landing on HEAD if the
// pin ever disappears upstream (a force-push or a deleted repo must fail loudly, not re-baseline).
function cloneAtPin(target: ExternalTarget, into: string): void {
  const git = (...a: string[]): void => void execFileSync("git", ["-C", into, ...a], { stdio: ["ignore", "ignore", "pipe"] });
  execFileSync("git", ["init", "-q", into], { stdio: "inherit" });
  git("remote", "add", "origin", `https://github.com/${target.repo}`);
  git("fetch", "-q", "--depth", "1", "origin", target.commit);
  git("checkout", "-q", "FETCH_HEAD");
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
    cloneAtPin(target, dir);

    // Two scanners emit `M5 —` findings and they measure DIFFERENT things: quality-scan's knip
    // pass is dead code (unused files/exports), detect-static's slop pass is style (else-after-
    // return, single-call wrappers). #278 split the manifest's single M5 into M5-knip and
    // M5-slop, each with its own baseline, and scoreExternalBaseline's moduleMatches tells them
    // apart by taxonomy — so both scanners' output is scored now instead of filtering one out.
    const findings = [
      ...runScanner("detect-static", [dir]),
      ...runScanner("quality-scan", [dir]),
      ...runScanner("mutation-scan", [dir]),
    ];

    // #279: M10 over the target's own cloned migrations. A target with no schemaPath (boxyhq —
    // Prisma migrations this parser can't read) is skipped here and stays not-run in the manifest,
    // per the coverage guard. A schemaPath that doesn't resolve in the cloned tree is a stale
    // manifest entry, not an absent module — that throws rather than silently scoring 0.
    if (target.schemaPath) {
      const schemaDir = join(dir, target.schemaPath);
      if (!existsSync(schemaDir)) {
        throw new Error(`${target.slug}: schemaPath "${target.schemaPath}" not found in the cloned tree — the manifest's path is stale`);
      }
      findings.push(...m10FindingsFromSchema(readMigrationSql(schemaDir)));
    }

    for (const row of scoreExternalBaseline(target, findings)) {
      rows.push({ slug: row.slug, check: `${row.module} baseline`, pass: row.pass, detail: row.detail });
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
// read as a pass — the invariant is the product promise, so an unrun check is a failure.
const scoredSlugs = new Set(rows.map((r) => r.slug));
const unscored = FREE_TIER_EXPECTATIONS.filter((e) => !scoredSlugs.has(e.slug) && (!onlySlug || onlySlug === e.slug));

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
