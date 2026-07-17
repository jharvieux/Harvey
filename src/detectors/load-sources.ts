// Shared source-file loader for the static AST detector passes: walks a target tree and
// returns SourceInput[] for the detector modules. Extracted from src/cli/static-detect.ts
// when the M6 free-tier indicator pass (#267) made runMechanicalScan a second consumer.

import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative, sep } from "node:path";
import type { SourceInput } from "./common.js";

const SOURCE_FILE = /\.(ts|tsx|jsx|mjs)$/;
// tsconfig/jsconfig are loaded so the M9 App Router pass can resolve `paths` aliases
// (`@/…` imports) — without the file that defines what `@/` maps to, aliased imports are
// invisible to the server→client-leak and server-only-guard cross-file resolution (#380).
const CONFIG_FILE = /^(next\.config\.(js|mjs|cjs|ts)|\.babelrc|\.babelrc\.json|babel\.config\.(js|json|mjs|cjs)|package\.json|tsconfig\.json|jsconfig\.json)$/;
const EXCLUDED_DIR = /^(node_modules|\.next|\.git|dist|build|coverage|out)$/;

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
        files.push({ path, text: readFileSync(full, "utf8") });
      }
    }
  };
  walk(root);
  return files;
}
