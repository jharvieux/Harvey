// Ungraded breadth-sweep runner (#899, mechanical half) — clones each BREADTH_SWEEP pin, runs the
// SOURCE-tier mechanical scanners over it, times each, and writes RAW UNGRADED artifacts.
//
//   pnpm exec tsx src/cli/breadth-sweep.ts [--target <slug>] [--out-dir <dir>]
//       [--clones-dir <dir>] [--timeout <seconds>] [--keep]
//
// This is NOT corpus-drift. corpus-drift scores six pinned repos against MEASURED baselines and
// fails a check on drift. This job has no baselines and asserts nothing about counts — its output
// is a CLAIM, not a fact (#900 owns the triage that turns claims into facts). What it CAN surface,
// and what six curated targets never stress, is the failure class breadth is uniquely good at:
// a scanner that CRASHES on an unseen repo shape, one that TIMES OUT, one that goes SILENT (runs
// clean but emits nothing where something is expected), or one that OVER-FIRES (hundreds of hits on
// one idiom). Every per-scanner row below records exactly that: seconds, status, and finding count.
//
// Every artifact is stamped `graded: false`. The reader must never mistake a row here for a scored
// baseline — that distinction is the crux of #899/#900. src/scan/breadth-sweep.test.ts asserts it.
//
// Tiers NOT run here (recorded in every artifact's `notRunTiers`, never silently omitted — the
// coverage doctrine): M1 semantic/live, M2 dynamic, M3 hotspot, M6 verdict, M7 advisors/Lighthouse,
// M8 mutation, M10 live. This is the source/mechanical tier ONLY, by design.

import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { gzipSync } from "node:zlib";
import { tmpdir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { cloneAtPin } from "../scan/corpus-clone.js";
import { BREADTH_SWEEP } from "../scan/breadth-sweep.js";
import type { Finding } from "../findings.js";
// The same two classifiers the graded corpus's M10 adapter uses — SQL migrations and schema.prisma.
import { classifyMigrationSql, classifyPrismaSchema } from "../../tools/pii-classify.mjs";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const args = process.argv.slice(2);
const flag = (name: string): string | undefined => {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : undefined;
};

const onlySlug = flag("--target");
const outDir = resolve(flag("--out-dir") ?? join(repoRoot, "breadth-sweep", "ungraded"));
const clonesDir = flag("--clones-dir");
const timeoutSec = Number(flag("--timeout") ?? "1500");
const keep = args.includes("--keep");

const targets = onlySlug ? BREADTH_SWEEP.filter((t) => t.slug === onlySlug) : BREADTH_SWEEP;
if (targets.length === 0) {
  console.error(`no breadth target "${onlySlug}" — known: ${BREADTH_SWEEP.map((t) => t.slug).join(", ")}`);
  process.exit(2);
}

// The source/mechanical-tier scanners that emit Finding[] — the source-tier set, minus the graded
// scoring. Each is timed and its status judged independently. quick-scan is the M1 mechanical pass
// (semgrep + gitleaks/trufflehog secrets + OSV deps + static RLS) and uses --dir/--findings-out
// rather than a positional dir + --out, so it carries its own arg builder.
const SCANNERS: { name: string; script: string; scriptArgs: (dir: string, out: string) => string[]; modules: string }[] = [
  { name: "quick-scan", script: "quick-scan", scriptArgs: (dir, out) => ["--dir", dir, "--findings-out", out], modules: "M1 mechanical (semgrep, secrets, deps, static RLS)" },
  { name: "detect-static", script: "detect-static", scriptArgs: (dir, out) => [dir, "--out", out], modules: "M1-static, M5-slop, M6-indicator, M7-code, M8-intent, M9" },
  { name: "quality-scan", script: "quality-scan", scriptArgs: (dir, out) => [dir, "--out", out], modules: "M4, M5-knip" },
  { name: "mutation-scan", script: "mutation-scan", scriptArgs: (dir, out) => [dir, "--detect-only", "--out", out], modules: "M8 (suite-absent only)" },
];

type ScannerStatus = "ok" | "empty" | "error" | "timeout";
interface ScannerRow {
  name: string;
  modules: string;
  seconds: number;
  status: ScannerStatus;
  findingCount: number;
  detail?: string;
}

// #470/#279 shape: one M10 Finding per table with ≥1 classified column — the same mapping the
// graded corpus's m10FindingsFromSchema uses, generalized to accept either classifier's dataMap.
function dataMapToFindings(dataMap: Record<string, { infotypes: string[]; columns: { column: string }[]; categories: string[]; severity: string }>, source: string): Finding[] {
  return Object.entries(dataMap).map(([table, t], i) => ({
    id: `M10-SCHEMA-${String(i + 1).padStart(2, "0")}`,
    title: `${table}: ${t.infotypes.join(", ")}`,
    severity: t.severity as Finding["severity"],
    confidence: "Confirmed",
    category: "Data classification",
    taxonomy: "M10 — Data classification",
    location: `${source}:${table}`,
    status: "Open",
    evidence: `${t.columns.length} column(s) classified: ${t.columns.map((c) => c.column).join(", ")}.`,
    impact: `${t.categories.join("/")} data on this table.`,
    fix: "Confirm this data is encrypted at rest or scoped behind RLS before it reaches an exposed schema/view.",
    value: 3,
    ease: 2,
    safety: 4,
    mechanical: true,
  }));
}

const SKIP_WALK = new Set(["node_modules", ".git", ".next", "dist", "build", ".turbo", "coverage", ".vercel"]);

// M10 schema tier, in-process. Collects every .sql DDL file (migrations included — unlike
// dynamic-validate's discoverSchemaFiles, which excludes migrations/ because M2 applies those
// separately; M10 CLASSIFIES them) AND every .prisma file (schema.prisma or a multi-file schema/
// dir), then classifies each with the same two
// classifiers the graded corpus's M10 adapter uses. Prisma uses the CLI-independent fallback parser
// — no target install, which is correct for a source-tier breadth run. Returns findings + the
// source it read (or the reason nothing was found — never a silent zero).
function runM10(dir: string): { findings: Finding[]; source: string; seconds: number } {
  const started = Date.now();
  const findings: Finding[] = [];
  const sources: string[] = [];

  const { sql, prisma } = collectSchemaFiles(dir);
  if (sql.length) {
    const concatenated = sql.sort().map((f) => readFileSync(f, "utf8")).join("\n\n");
    const { dataMap } = classifyMigrationSql(concatenated);
    findings.push(...dataMapToFindings(dataMap, "sql"));
    sources.push(`${sql.length} .sql file(s)`);
  }
  for (const p of prisma) {
    const { dataMap } = classifyPrismaSchema(readFileSync(p, "utf8"));
    findings.push(...dataMapToFindings(dataMap, `prisma:${basename(dirname(p))}`));
  }
  if (prisma.length) sources.push(`${prisma.length} schema.prisma`);

  const seconds = (Date.now() - started) / 1000;
  return { findings, source: sources.join(" + ") || "no schema found (probed *.sql + schema.prisma)", seconds };
}

function collectSchemaFiles(dir: string, depth = 0, acc: { sql: string[]; prisma: string[] } = { sql: [], prisma: [] }): { sql: string[]; prisma: string[] } {
  if (depth > 6) return acc;
  let entries: import("node:fs").Dirent[];
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    return acc;
  }
  for (const e of entries) {
    const p = join(dir, e.name);
    if (e.isDirectory()) {
      if (!SKIP_WALK.has(e.name)) collectSchemaFiles(p, depth + 1, acc);
    } else if (e.name.endsWith(".prisma")) {
      // Any .prisma file, not just schema.prisma — Prisma's multi-file schema feature puts the
      // models in a schema/ dir of arbitrarily-named .prisma files (e.g. documenso), which an
      // exact schema.prisma match silently misses.
      acc.prisma.push(p);
    } else if (e.name.endsWith(".sql")) {
      acc.sql.push(p);
    }
  }
  return acc;
}

// Volume: total non-ignored files + TS/TSX subset, so a wall-clock reading can be read against
// repo size ("module X is unusable above N files" — #899 deliverable 2).
function countFiles(dir: string): { files: number; tsFiles: number } {
  let files = 0;
  let tsFiles = 0;
  const walk = (d: string): void => {
    let entries: import("node:fs").Dirent[];
    try {
      entries = readdirSync(d, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of entries) {
      if (e.isDirectory()) {
        if (!SKIP_WALK.has(e.name)) walk(join(d, e.name));
      } else {
        files++;
        if (/\.tsx?$/.test(e.name)) tsFiles++;
      }
    }
  };
  walk(dir);
  return { files, tsFiles };
}

// The module a finding rolls up to. An explicit "M<n> — …" taxonomy always wins — quick-scan emits
// M6 hand-rolled indicators and M7 static-RLS findings with proper taxonomy, and those stay in
// their modules. Only quick-scan's UN-prefixed findings (semgrep security rules, secrets, dependency
// CVEs, dangerous-config) fall back to M1, the mechanical tier quick-scan leads.
function moduleOf(taxonomy: string, scanner: string): string {
  const m = /^M(\d+)/.exec(taxonomy ?? "");
  if (m) return `M${m[1]}`;
  return scanner === "quick-scan" ? "M1" : "unknown";
}

function runScanner(scanner: (typeof SCANNERS)[number], dir: string): { row: ScannerRow; findings: Finding[] } {
  const out = join(mkdtempSync(join(tmpdir(), "harvey-breadth-")), "findings.json");
  const started = Date.now();
  let status: ScannerStatus = "ok";
  let detail: string | undefined;
  try {
    execFileSync("pnpm", [scanner.script, ...scanner.scriptArgs(dir, out)], {
      cwd: repoRoot,
      stdio: ["ignore", "ignore", "pipe"],
      timeout: timeoutSec * 1000,
      maxBuffer: 64 * 1024 * 1024,
    });
  } catch (err) {
    const e = err as { signal?: string; killed?: boolean; stderr?: Buffer | string; message?: string };
    if (e.killed && (e.signal === "SIGTERM" || e.signal === "SIGKILL")) {
      status = "timeout";
      detail = `killed after ${timeoutSec}s`;
    } else {
      status = "error";
      const stderr = typeof e.stderr === "string" ? e.stderr : e.stderr?.toString() ?? "";
      detail = (stderr.trim().split("\n").pop() || e.message || "non-zero exit").slice(0, 300);
    }
  }
  const seconds = (Date.now() - started) / 1000;

  let findings: Finding[] = [];
  if (existsSync(out)) {
    const parsed = JSON.parse(readFileSync(out, "utf8")) as Finding[] | { finding: Finding };
    findings = Array.isArray(parsed) ? parsed : [parsed.finding];
  }
  // A scanner that ran clean but emitted nothing is the SILENT failure class breadth exists to
  // surface — flag it distinctly from a real error, never as a plain success.
  if (status === "ok" && findings.length === 0) status = "empty";
  return { row: { name: scanner.name, modules: scanner.modules, seconds: round(seconds), status, findingCount: findings.length, detail }, findings };
}

const round = (n: number): number => Math.round(n * 10) / 10;

interface TargetResult {
  slug: string;
  repo: string;
  commit: string;
  status: "scanned" | "dropped";
  reason?: string;
  files?: number;
  tsFiles?: number;
  wallclockSec?: number;
  scanners?: ScannerRow[];
  findingsByModule?: Record<string, number>;
  findingsBySeverity?: Record<string, number>;
  totalFindings?: number;
}

// The tiers this mechanical run does NOT cover — stamped into every artifact so an absent module
// reads as "not run here", never as "clean". (CLAUDE.md: an unstated limitation reads as a clean
// bill of health.)
const NOT_RUN_TIERS = [
  "M1 semantic/live (paid-LLM + connected)",
  "M2 dynamic pen-test (live stack)",
  "M3 hotspot analysis (vitals plugin)",
  "M6 paid verdict (human/LLM pass over the review packet)",
  "M7 DB advisors + Lighthouse (connected + local-run)",
  "M8 mutation scoring (Stryker; only suite-absent detection runs here)",
  "M10 live DB classification (connected)",
];

mkdirSync(outDir, { recursive: true });
const index: TargetResult[] = [];

for (const target of targets) {
  console.error(`\n=== ${target.slug} (${target.repo} @ ${target.commit.slice(0, 8)}) [${target.bucket}] ===`);
  const dir = clonesDir ? join(clonesDir, target.slug) : mkdtempSync(join(tmpdir(), `harvey-breadth-${target.slug}-`));
  const started = Date.now();
  try {
    if (clonesDir && existsSync(join(dir, ".git"))) {
      console.error(`  reusing clone at ${dir}`);
    } else {
      if (clonesDir) mkdirSync(dir, { recursive: true });
      cloneAtPin(target.repo, target.commit, dir);
    }

    const { files, tsFiles } = countFiles(dir);
    console.error(`  ${files} files (${tsFiles} .ts/.tsx)`);

    const scanners: ScannerRow[] = [];
    const findings: Finding[] = [];
    for (const scanner of SCANNERS) {
      const { row, findings: got } = runScanner(scanner, dir);
      console.error(`  ${row.name.padEnd(16)} ${row.status.padEnd(8)} ${String(row.findingCount).padStart(5)} findings  ${row.seconds}s${row.detail ? `  — ${row.detail}` : ""}`);
      scanners.push(row);
      for (const f of got) findings.push({ ...f, sweepScanner: row.name } as Finding & { sweepScanner: string });
    }

    const m10 = runM10(dir);
    console.error(`  ${"pii-classify".padEnd(16)} ${(m10.findings.length ? "ok" : "empty").padEnd(8)} ${String(m10.findings.length).padStart(5)} findings  ${round(m10.seconds)}s  — ${m10.source}`);
    scanners.push({ name: "pii-classify", modules: "M10 (schema)", seconds: round(m10.seconds), status: m10.findings.length ? "ok" : "empty", findingCount: m10.findings.length, detail: m10.source });
    for (const f of m10.findings) findings.push({ ...f, sweepScanner: "pii-classify" } as Finding & { sweepScanner: string });

    const byModule: Record<string, number> = {};
    const bySeverity: Record<string, number> = {};
    for (const f of findings) {
      const mod = moduleOf(f.taxonomy, (f as Finding & { sweepScanner: string }).sweepScanner);
      byModule[mod] = (byModule[mod] ?? 0) + 1;
      bySeverity[f.severity] = (bySeverity[f.severity] ?? 0) + 1;
    }

    const wallclockSec = round((Date.now() - started) / 1000);
    // The RAW UNGRADED artifact. `graded: false` is first and load-bearing — see the header and
    // the test invariant. Full findings included: this is the raw output #899 asks to land. Written
    // GZIPPED (<slug>.json.gz) — the full per-target dumps total ~46 MB pretty (cal-diy alone is
    // 8.7k findings); gzip lands the complete raw output at a fraction of that. INDEX.json stays
    // plaintext for the human-readable measurement. `gunzip -c <slug>.json.gz` reads one.
    const artifact = {
      graded: false as const,
      warning: "UNGRADED — these findings are unverified CLAIMS from a volume sweep (#899), NOT scored capability. No baseline, no triage. Do not quote a count here as recall/precision. #900 owns the triage that turns these into facts.",
      target: { slug: target.slug, repo: target.repo, commit: target.commit, defaultBranch: target.defaultBranch, license: target.license, bucket: target.bucket, what: target.what },
      scannedAt: new Date().toISOString(),
      volume: { files, tsFiles },
      wallclockSec,
      scanners,
      notRunTiers: NOT_RUN_TIERS,
      findingsByModule: byModule,
      findingsBySeverity: bySeverity,
      totalFindings: findings.length,
      findings,
    };
    writeFileSync(join(outDir, `${target.slug}.json.gz`), gzipSync(`${JSON.stringify(artifact, null, 2)}\n`));

    index.push({
      slug: target.slug, repo: target.repo, commit: target.commit, status: "scanned",
      files, tsFiles, wallclockSec, scanners, findingsByModule: byModule, findingsBySeverity: bySeverity, totalFindings: findings.length,
    });
  } catch (err) {
    const reason = (err as Error).message.slice(0, 400);
    console.error(`  ✗ DROPPED: ${reason}`);
    index.push({ slug: target.slug, repo: target.repo, commit: target.commit, status: "dropped", reason });
    // A dropped target is a RESULT, not an omission — write a stub artifact so it appears on disk.
    writeFileSync(join(outDir, `${target.slug}.json.gz`), gzipSync(`${JSON.stringify({ graded: false as const, target: { slug: target.slug, repo: target.repo, commit: target.commit }, status: "dropped", reason }, null, 2)}\n`));
  } finally {
    if (!clonesDir) {
      if (keep) console.error(`  (kept clone: ${dir})`);
      else rmSync(dir, { recursive: true, force: true });
    }
  }
}

const scanned = index.filter((r) => r.status === "scanned");
const dropped = index.filter((r) => r.status === "dropped");
writeFileSync(join(outDir, "INDEX.json"), `${JSON.stringify({
  graded: false as const,
  warning: "UNGRADED breadth sweep (#899, mechanical half). Counts are unverified claims, not scored capability. Triage/grading is #900.",
  generatedAt: new Date().toISOString(),
  targetsScanned: scanned.length,
  targetsDropped: dropped.length,
  rows: index,
}, null, 2)}\n`);

console.error(`\n──── breadth sweep (UNGRADED) ────`);
console.error(`  scanned: ${scanned.length}   dropped: ${dropped.length}`);
for (const r of index) {
  if (r.status === "dropped") console.error(`  ✗ ${r.slug.padEnd(18)} DROPPED — ${r.reason}`);
  else console.error(`  • ${r.slug.padEnd(18)} ${String(r.totalFindings).padStart(5)} ungraded findings  ${r.wallclockSec}s  (${r.files} files)`);
}
console.error(`\nArtifacts → ${outDir}`);
