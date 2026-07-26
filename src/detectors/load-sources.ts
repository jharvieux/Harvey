// Shared source-file loader for the static AST detector passes: walks a target tree and
// returns SourceInput[] for the detector modules. Extracted from src/cli/static-detect.ts
// when the M6 free-tier indicator pass (#267) made runMechanicalScan a second consumer.

import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative, sep } from "node:path";
import type { SourceInput } from "./common.js";

// #1065: plain .js/.cjs (and .mts/.cts) were absent here until 2026-07-25, so every
// loadSources-based detector — M5 slop, M6 hand-rolled indicators, M7 code-tier perf, M8
// test-intent, M9 App Router, the M1 AST passes — read nothing at all on a JavaScript codebase
// (measured: targets/vuln-seam-app loaded 2 files and reported 0 findings). src/detectors/common.ts
// parses everything through ts.ScriptKind.TS/TSX, which handles plain JS, so widening the filter
// is all that was needed.
export const SOURCE_FILE = /\.(ts|tsx|jsx|js|mjs|cjs|mts|cts)$/;
// Bundler output committed into a repo (public/ vendor scripts, prebuilt chunks) is machine-
// generated, not fixable in place, and would swamp the M5/M6 indicator detectors now that .js is
// read at all. Name check plus a content check, because minified filenames are not standardised:
// no hand-authored source has a 1000-character line. Excluded deliberately, and counted in the
// M1-EXT-00 disclosure (src/scan/ext-coverage.ts) so the exclusion is stated rather than silent.
const GENERATED_NAME = /\.min\.[cm]?jsx?$/;
export const isGeneratedSource = (name: string, text: string): boolean =>
  GENERATED_NAME.test(name) || text.split("\n").some((line) => line.length > 1000);
// tsconfig/jsconfig are loaded so the M9 App Router pass can resolve `paths` aliases
// (`@/…` imports) — without the file that defines what `@/` maps to, aliased imports are
// invisible to the server→client-leak and server-only-guard cross-file resolution (#380).
export const CONFIG_FILE = /^(next\.config\.(js|mjs|cjs|ts)|\.babelrc|\.babelrc\.json|babel\.config\.(js|json|mjs|cjs)|package\.json|tsconfig\.json|jsconfig\.json)$/;
export const EXCLUDED_DIR = /^(node_modules|\.next|\.git|dist|build|coverage|out|\.turbo|\.vercel|\.svelte-kit|\.nuxt|\.output)$/;

// Test/story/fixture files — excluded from the product-code detectors (perf, boundary, and
// indicator findings in test code aren't audit findings); the M8 test-intent pass loads the
// full set instead, because test files are its subject matter.
export const NON_PRODUCT = /\.(test|spec)\.[cm]?[jt]sx?$|(^|\/)(__tests__|__mocks__|__fixtures__|__snapshots__)\/|\.stories\./;

export function loadSources(root: string): SourceInput[] {
  const files: SourceInput[] = [];
  const walk = (dir: string) => {
    for (const entry of readdirSync(dir)) {
      const full = join(dir, entry);
      const stat = statSync(full);
      if (stat.isDirectory()) {
        if (!EXCLUDED_DIR.test(entry)) walk(full);
      } else if (SOURCE_FILE.test(entry) || CONFIG_FILE.test(entry)) {
        const path = relative(root, full).split(sep).join("/");
        const text = readFileSync(full, "utf8");
        if (!CONFIG_FILE.test(entry) && isGeneratedSource(entry, text)) continue;
        files.push({ path, text });
      }
    }
  };
  walk(root);
  return files;
}
