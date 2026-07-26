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
// read at all. Name check plus a content check, because minified filenames are not standardised.
// #1136: "any single line over 1000 chars" false-excluded real, hand-authored source that merely
// carries ONE long string literal (an LLM tool-description prompt, a SQL/GraphQL query) — dropping
// the whole file, and every finding in it, for an unrelated line. MEASURED (inbox-zero's
// apps/web/utils/ai/assistant/tools/rules/update-rule-tool.ts, pinned commit 2b78f2b3): 605 lines,
// one 1081-char line, that line is 5.7% of the file's bytes — real source, wrongly excluded pre-fix.
// A minified/generated file isn't "has a long line", it's "IS, almost entirely, long lines", so the
// check is now relative to the file: an outlier line over LONG_OUTLIER must exist (unchanged
// trigger) AND lines over LONG_LINE must account for at least LONG_LINE_FRACTION of the file's
// total bytes (the file's bulk, not an aside, is packed onto long lines). MEASURED on carbon's
// SVG-icon-path-data config files (packages/ee/src/{onshape,paperless-parts}/config.tsx, pinned
// commit 92e19c04), the case #1088 originally added this check for: 65% and 54% of file bytes
// respectively — both stay excluded, comfortably clear of inbox-zero's 5.7% on the other side of
// the threshold. Counted in the M1-EXT-00 disclosure (src/scan/ext-coverage.ts) so the exclusion
// is stated rather than silent.
const GENERATED_NAME = /\.min\.[cm]?jsx?$/;
const LONG_OUTLIER = 1000;
const LONG_LINE = 500;
const LONG_LINE_FRACTION = 0.3;
export const isGeneratedSource = (name: string, text: string): boolean => {
  if (GENERATED_NAME.test(name)) return true;
  const lines = text.split("\n");
  if (!lines.some((line) => line.length > LONG_OUTLIER)) return false;
  const longLineChars = lines.reduce((sum, line) => (line.length > LONG_LINE ? sum + line.length : sum), 0);
  return longLineChars / text.length >= LONG_LINE_FRACTION;
};
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
