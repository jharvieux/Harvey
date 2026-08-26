import "./sync-stdio.js";

// #1689 / #1800 — provenance-bound target×class path-scope census over the pinned corpus.
//
//   pnpm exec tsx src/cli/path-scope-census.ts [--cache <dir>] [--json]
//
// Network + minutes per run, like corpus-drift: not part of `pnpm verify`. A zero is a measured
// fact, not a failing exit; the delivered NotAssessed row is owned by pathScopeNotAssessedRows.

import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { loadSourceInventory, loadSources } from "../detectors/load-sources.js";
import { cloneAtPinCached } from "../scan/corpus-clone.js";
import { EXTERNAL_CORPUS } from "../scan/external-corpus.js";
import { detectTargetFramework, type TargetFramework } from "../scan/framework-detect.js";
import {
  PATH_SCOPE_CLASS_GROUPS,
  PATH_SCOPED_DETECTORS,
  pathScopeCensus,
  type PathScopeCensusRow,
} from "../scan/path-scope.js";
import { arg, assertKnownFlags } from "./args.js";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");

function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function git(args: string[]): string {
  return execFileSync("git", args, { cwd: REPO_ROOT, encoding: "utf8" }).trim();
}

function toolVersion(): string {
  const pkg = JSON.parse(readFileSync(join(REPO_ROOT, "package.json"), "utf8")) as { version?: unknown };
  return typeof pkg.version === "string" ? pkg.version : "unversioned";
}

const corpusPins = EXTERNAL_CORPUS.map((target) => ({
  slug: target.slug,
  repo: target.repo,
  commit: target.commit,
}));

const registryReceipt = PATH_SCOPE_CLASS_GROUPS.map((group) => ({
  ownerFile: group.ownerFile,
  exportName: group.exportName,
  rows: group.classes.map((row) => ({
    rowId: row.rowId,
    detector: row.detector,
    classId: row.classId,
    ownerFile: row.ownerFile,
    selectorSymbol: row.selectorSymbol,
    inventory: row.inventory ?? "loaded-sources",
    convention: row.convention,
    hasApplicabilityGate: row.applicable !== undefined,
  })),
}));

export interface PathScopeTargetClassRow extends PathScopeCensusRow {
  target: string;
  repo: string;
  pin: string;
  framework: TargetFramework;
  loadedFiles: number;
}

export interface PathScopeCensusReport {
  schemaVersion: 1;
  generatedAt: string;
  date: string;
  tool: {
    name: "harvey-path-scope-census";
    version: string;
    entrypoint: "src/cli/path-scope-census.ts";
    node: string;
  };
  source: {
    revision: string;
    workingTreeClean: boolean;
  };
  corpus: {
    targetCount: number;
    pinDigestSha256: string;
    pins: typeof corpusPins;
  };
  registry: {
    classCount: number;
    selectorCount: number;
    receiptDigestSha256: string;
    groups: typeof registryReceipt;
  };
  completeness: {
    expectedTargetClassRows: number;
    observedTargetClassRows: number;
  };
  rows: PathScopeTargetClassRow[];
}

export function runPathScopeCensus(cache?: string): PathScopeCensusReport {
  const generatedAt = new Date().toISOString();
  const rows: PathScopeTargetClassRow[] = [];

  for (const target of EXTERNAL_CORPUS) {
    const dir = mkdtempSync(join(tmpdir(), `harvey-pathscope-${target.slug}-`));
    try {
      cloneAtPinCached(target.repo, target.commit, dir, cache);
      // loadSources is the production inventory: source, package/config, generated-file, and
      // exclusion semantics must match the real detector inputs rather than a parallel walker.
      const files = loadSources(dir);
      const identifiedSourceFiles = loadSourceInventory(dir);
      const framework = detectTargetFramework(dir);
      for (const row of pathScopeCensus(files, { framework, identifiedSourceFiles })) {
        rows.push({
          target: target.slug,
          repo: target.repo,
          pin: target.commit,
          framework,
          loadedFiles: files.length,
          ...row,
        });
      }
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }

  const expectedTargetClassRows = EXTERNAL_CORPUS.length * PATH_SCOPED_DETECTORS.length;
  if (rows.length !== expectedTargetClassRows) {
    throw new Error(`Path-scope census incomplete: expected ${expectedTargetClassRows} target×class rows, observed ${rows.length}`);
  }

  return {
    schemaVersion: 1,
    generatedAt,
    date: generatedAt.slice(0, 10),
    tool: {
      name: "harvey-path-scope-census",
      version: toolVersion(),
      entrypoint: "src/cli/path-scope-census.ts",
      node: process.version,
    },
    source: {
      revision: git(["rev-parse", "HEAD"]),
      workingTreeClean: git(["status", "--porcelain", "--untracked-files=no"]) === "",
    },
    corpus: {
      targetCount: EXTERNAL_CORPUS.length,
      pinDigestSha256: sha256(JSON.stringify(corpusPins)),
      pins: corpusPins,
    },
    registry: {
      classCount: PATH_SCOPED_DETECTORS.length,
      selectorCount: new Set(PATH_SCOPED_DETECTORS.map((row) => row.select)).size,
      receiptDigestSha256: sha256(JSON.stringify(registryReceipt)),
      groups: registryReceipt,
    },
    completeness: {
      expectedTargetClassRows,
      observedTargetClassRows: rows.length,
    },
    rows,
  };
}

function markdownCell(value: string): string {
  return value.replace(/\|/g, "\\|").replace(/\n/g, " ");
}

function printHuman(report: PathScopeCensusReport): void {
  console.log(`Path-scoped class census — ${report.date}`);
  console.log(`Tool: ${report.tool.name}@${report.tool.version} (${report.tool.entrypoint}; ${report.tool.node})`);
  console.log(`Source revision: ${report.source.revision}${report.source.workingTreeClean ? " (clean)" : " (DIRTY — registry digest retained below)"}`);
  console.log(`Corpus: ${report.corpus.targetCount} pinned targets; SHA-256 ${report.corpus.pinDigestSha256}`);
  console.log(
    `Registry: ${report.registry.classCount} classes / ${report.registry.selectorCount} distinct production selectors; ` +
      `SHA-256 ${report.registry.receiptDigestSha256}`,
  );
  console.log(
    `Completeness: ${report.completeness.observedTargetClassRows}/${report.completeness.expectedTargetClassRows} target×class rows\n`,
  );
  console.log("| Target | Pin | Framework | Loaded files | Row ID | Applicable | Files read | Class |");
  console.log("| --- | --- | --- | ---: | --- | --- | ---: | --- |");
  for (const row of report.rows) {
    console.log(
      `| ${markdownCell(row.target)} | \`${row.pin}\` | ${row.framework} | ${row.loadedFiles} | \`${row.rowId}\` | ` +
        `${row.applicable ? "yes" : "no"} | ${row.filesRead} | ${markdownCell(row.classId)} |`,
    );
  }
}

export function main(argv: string[] = process.argv): void {
  assertKnownFlags(["--cache", "--json"] as const, argv.slice(2));
  const report = runPathScopeCensus(arg("--cache", argv));
  if (argv.includes("--json")) console.log(JSON.stringify(report, null, 2));
  else printHuman(report);
}

if (process.argv[1] !== undefined && fileURLToPath(import.meta.url) === resolve(process.argv[1])) main();
