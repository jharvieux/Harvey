// Runs the static AST detector modules — M9 App Router (src/detectors/app-router.ts) and
// M7 code-level performance (src/detectors/perf-code.ts) — over a target repo and writes
// the merged Finding[]. This is the engagement entry point for both detector sets (they
// take in-memory sources, so tests never needed a CLI; audits do).
//
//   pnpm detect-static <target-dir> [--out findings.static.json]
//
// Thin untested I/O wrapper per the repo convention — the detectors themselves are the
// tested pure transforms. Test/story/fixture files are excluded: perf and boundary findings
// in test code aren't audit findings.

import { readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { join, relative, resolve, sep } from "node:path";
import type { Finding } from "../findings.js";
import { detectAppRouterFindings } from "../detectors/app-router.js";
import { detectPerfCodeFindings } from "../detectors/perf-code.js";
import type { SourceInput } from "../detectors/common.js";
import { resolveScanScope } from "../scan/scan-scope.js";

const args = process.argv.slice(2);
const targetArg = args.find((a) => !a.startsWith("--"));
const outIdx = args.indexOf("--out");
const outPath = outIdx >= 0 ? args[outIdx + 1] : undefined;

if (!targetArg) {
  console.error("usage: pnpm detect-static <target-dir> [--out findings.static.json]");
  process.exit(2);
}

const SOURCE_FILE = /\.(ts|tsx|jsx|mjs)$/;
const CONFIG_FILE = /^(next\.config\.(js|mjs|cjs|ts)|\.babelrc|\.babelrc\.json|babel\.config\.(js|json|mjs|cjs))$/;
const EXCLUDED_DIR = /^(node_modules|\.next|\.git|dist|build|coverage|out)$/;
const NON_PRODUCT = /\.(test|spec)\.[cm]?[jt]sx?$|(^|\/)(__tests__|__mocks__|__fixtures__|__snapshots__)\/|\.stories\./;

function loadSources(root: string): SourceInput[] {
  const files: SourceInput[] = [];
  const walk = (dir: string) => {
    for (const entry of readdirSync(dir)) {
      const full = join(dir, entry);
      const stat = statSync(full);
      if (stat.isDirectory()) {
        if (!EXCLUDED_DIR.test(entry)) walk(full);
      } else if (SOURCE_FILE.test(entry) || CONFIG_FILE.test(entry)) {
        const path = relative(root, full).split(sep).join("/");
        if (NON_PRODUCT.test(path)) continue;
        files.push({ path, text: readFileSync(full, "utf8") });
      }
    }
  };
  walk(root);
  return files;
}

const targetDir = resolve(targetArg);
const { scanDir, cleanup } = resolveScanScope(targetDir);
try {
  const sources = loadSources(scanDir);
  console.log(`loaded ${sources.length} source files from ${targetDir}`);

  const findings: Finding[] = [...detectAppRouterFindings(sources), ...detectPerfCodeFindings(sources)];

  const byTaxonomy = new Map<string, number>();
  for (const f of findings) byTaxonomy.set(f.taxonomy, (byTaxonomy.get(f.taxonomy) ?? 0) + 1);
  console.log(`\n${findings.length} findings across ${byTaxonomy.size} classes:`);
  for (const [tax, count] of [...byTaxonomy.entries()].sort((a, b) => b[1] - a[1])) {
    console.log(`  ${String(count).padStart(4)}  ${tax}`);
  }

  if (outPath) {
    writeFileSync(outPath, `${JSON.stringify(findings, null, 2)}\n`);
    console.log(`\nwritten to ${outPath} — merge into the engagement findings.json and \`pnpm validate:findings\``);
  }
} finally {
  cleanup();
}
