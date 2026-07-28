// #1044 — the codebase-size measurement the pricing page sells.
//
// site/app/pricing/page.tsx tells a prospect their size is "measured automatically during the free
// scan" and that the free scan "doubles as an instant, transparent quote". Nothing measured it: the
// operator sized repos by hand, so the quote was neither instant nor auditable, and two clients with
// identically-sized repos could land in different price bands with no reproducible basis.
//
// The definition, written down here because "transparent" is the claim being backed:
//   • COUNTED: non-blank lines of JS/TS application source (.ts/.tsx/.js/.jsx/.mjs/.cjs/.mts/.cts)
//     — the language family Harvey's modules actually analyse. Tests count: they are code the client
//     wrote and M8 assesses. Comments count: they are written and maintained.
//   • NOT COUNTED: everything JSCPD_IGNORE_GLOBS excludes from the M4 duplication scan — node_modules,
//     dist/.next, generated/, *.gen.ts, database.types.ts, types_db.ts, vendor, patches, demo. That
//     list is IMPORTED, not re-declared, so the pricing FAQ's "our dead-code and duplication modules
//     already detect it" is literally true rather than an adjacency argument.
//   • ALSO NOT COUNTED: build output and VCS metadata (build/, coverage/, out/, .turbo/, .git/).
//     Absent from the M4 list because they are not duplication-relevant, but a client must never be
//     billed for a coverage report or a compiled bundle.
//
// Bands mirror site/app/pricing/page.tsx verbatim. They are LINE-COUNT ONLY: the site's "monorepo /
// regulated" route into Enterprise is an operator judgement this tool does not make, and the report
// says so rather than letting a small-LOC regulated app read as a settled Small quote.

import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative, sep } from "node:path";
import { JSCPD_IGNORE_GLOBS } from "../quality-scan.js";

export type SizeBand = "small" | "medium" | "large" | "enterprise";

export interface CodebaseSize {
  loc: number;
  files: number;
  excludedFiles: number; // generated/vendored/build source files deliberately left out of the quote
  band: SizeBand;
  bandLabel: string; // the pricing table's own wording for this band
  definition: string; // how the number was produced — shipped WITH the number, never separately
}

const SOURCE_FILE = /\.(m|c)?[jt]sx?$/;
const BUILD_OUTPUT_DIRS = new Set(["build", "coverage", "out", ".turbo", ".git"]);

// The M4 ignore globs use only `**/` (any depth) and `*` (within a segment), so a small converter is
// enough — and reusing the real list beats maintaining a second, drifting definition of "generated".
const globToRegExp = (glob: string): RegExp => {
  const body = glob
    .split("/")
    .map((seg) => (seg === "**" ? "**" : seg.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, "[^/]*")))
    .join("/")
    .replace(/^\*\*\//, "(?:.*/)?")
    .replace(/\/\*\*$/, "(?:/.*)?");
  return new RegExp(`^${body}$`);
};

const EXCLUDED = JSCPD_IGNORE_GLOBS.map(globToRegExp);

const BANDS: { under: number; band: SizeBand; label: string }[] = [
  { under: 10_000, band: "small", label: "Small · under 10k lines" },
  { under: 50_000, band: "medium", label: "Medium · 10k–50k lines" },
  { under: 150_000, band: "large", label: "Large · 50k–150k lines" },
  { under: Number.POSITIVE_INFINITY, band: "enterprise", label: "Enterprise · 150k+ / monorepo / regulated" },
];

const DEFINITION =
  "Non-blank lines of JS/TS application source (.ts/.tsx/.js/.jsx/.mjs/.cjs), tests included. " +
  "Generated and vendored code is excluded using the same path list the M4 duplication module uses " +
  "(node_modules, dist, .next, generated/, *.gen.ts, database.types.ts, types_db.ts, vendor, patches, " +
  "demo), plus build output (build, coverage, out, .turbo). Bands are line-count only — a monorepo or " +
  "a regulated app is custom-quoted regardless of size, which is an operator judgement, not this " +
  "measurement.";

export function measureCodebaseSize(root: string): CodebaseSize {
  let loc = 0;
  let files = 0;
  let excludedFiles = 0;

  // `excluded` propagates down: once a directory matched a generated/vendored glob, everything under
  // it is counted as excluded rather than re-tested (and rather than silently vanishing — the count
  // is what makes "generated and vendored code doesn't count" a visible fact, not a promise).
  // The #944 dangling-symlink guard, verbatim from mutation-scan's walkRelPaths — a bare
  // `statSync(full).isDirectory()` FOLLOWS the link and throws ENOENT on a dangling one. Committed
  // dangling links are routine (liam's `frontend/apps/app/.env`, dub's EE `LICENSE.md`, cal-diy's
  // `packages/prisma/.env` — all three crashed the 2026-07-28 breadth sweep here). This walker runs
  // near the END of quick-scan, so the throw discarded a completed M1 pass: 118–235 s of semgrep,
  // secrets and dependency work, and every finding it produced, on 3 of 15 wild repos.
  const walk = (dir: string, excluded: boolean): void => {
    for (const e of readdirSync(dir, { withFileTypes: true })) {
      const entry = e.name;
      const full = join(dir, entry);
      if (e.isSymbolicLink() && !existsSync(full)) continue;
      const isDir = e.isDirectory() || (e.isSymbolicLink() && statSync(full).isDirectory());
      if (isDir && BUILD_OUTPUT_DIRS.has(entry)) continue;
      const rel = relative(root, full).split(sep).join("/");
      const skip = excluded || EXCLUDED.some((re) => re.test(rel));
      if (isDir) {
        walk(full, skip);
      } else if (SOURCE_FILE.test(entry)) {
        if (skip) excludedFiles += 1;
        else {
          files += 1;
          loc += readFileSync(full, "utf8").split("\n").filter((line) => line.trim() !== "").length;
        }
      }
    }
  };

  walk(root, false);
  const { band, label } = BANDS.find((b) => loc < b.under)!;
  return { loc, files, excludedFiles, band, bandLabel: label, definition: DEFINITION };
}
