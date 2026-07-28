// pnpm exec tsx src/cli/validate-fs-walk.ts [--list] [--seed-unguarded]
//
// The #1451 gate: no directory walk may call `statSync` directly. It follows symlinks and throws on
// a committed link that does not resolve, and because these walks run near the END of a scan the
// throw discards a COMPLETED pass — MEASURED 2026-07-28, M1 went 336→10, 1625→9 and 1951→0 on three
// of the fifteen #899 breadth targets, with `--findings-out` never written.
//
// --list            prints every call site that routes through src/fs-walk.ts, so the population
//                   this gate judges is visible rather than inferred from a violation count of
//                   zero (#1345). A gate over an empty population is not a gate.
// --seed-unguarded  the negative control: injects the literal regression shape into a real scan
//                   module before auditing it. It MUST exit non-zero.
//
// The gate's own scope is stated in src/fs-walk-guard.ts. The logic runs under `pnpm verify` via
// src/fs-walk-guard.test.ts; this CLI is the human-readable and negative-control face of it.

import {
  BANNED,
  DISCOVERY_ROOTS,
  GUARD_MODULE,
  SAFE_API,
  discoverSourceFiles,
  findBannedStatSites,
  findGuardedSites,
  readSourceFiles,
} from "../fs-walk-guard.js";

const REPO_ROOT = new URL("../../", import.meta.url).pathname;

// Seeded into a REAL scan module rather than a synthetic file, so what the gate is shown to catch is
// the shape that actually shipped twice — a readdir loop that stats each entry to decide whether to
// recurse — sitting where such a walker really lives.
const SEED = {
  file: "src/scan/pg-idor.ts",
  inject: "\nfunction seededWalk(d: string): void {\n  for (const e of readdirSync(d)) if (statSync(join(d, e)).isDirectory()) seededWalk(join(d, e));\n}\n",

};

function main(): void {
  const seed = process.argv.includes("--seed-unguarded");
  const paths = discoverSourceFiles(REPO_ROOT);
  const files = readSourceFiles(REPO_ROOT, paths).map((f) => (seed && f.path === SEED.file ? { ...f, text: f.text + SEED.inject } : f));

  const violations = findBannedStatSites(files);
  const guarded = findGuardedSites(files);

  console.log(`Directory-walk symlink guard (#1451)`);
  console.log(`  files swept:              ${files.length} under ${DISCOVERY_ROOTS.join(", ")}`);
  console.log(`  call sites via ${GUARD_MODULE}: ${guarded.length} across ${new Set(guarded.map((s) => s.file)).size} file(s)`);
  console.log(`  raw ${BANNED.map((b) => `\`${b}\``).join(" / ")} calls:  ${violations.length}`);
  if (seed) console.log(`  (--seed-unguarded: the regression shape injected into ${SEED.file}; the gate must report it below)`);

  if (process.argv.includes("--list")) {
    for (const file of [...new Set(guarded.map((s) => s.file))].sort()) {
      console.log(`\n${file}`);
      for (const s of guarded.filter((g) => g.file === file)) console.log(`  :${s.line}  ${s.snippet}`);
    }
  }

  if (violations.length > 0) {
    console.error(`\n✗ ${violations.length} raw ${BANNED.map((b) => `\`${b}\``).join(" / ")} call(s) outside ${GUARD_MODULE}.`);
    for (const v of violations) console.error(`\n  ${v.file}:${v.line}\n    ${v.snippet}`);
    console.error(
      `\nFix by routing through ${GUARD_MODULE}: ${SAFE_API.join(", ")}.` +
        `\n  readEntriesSafe(dir) is the one to reach for in a walk — it omits an unresolvable link from` +
        `\n  \`entries\` entirely, so a later readFileSync on it cannot throw either, and returns the names it` +
        `\n  skipped in \`dangling\` for whoever is counting. Guarding the site with an existsSync of your own is` +
        `\n  not a fix: it leaves the next walker to remember the same thing, which is how #944's fix was` +
        `\n  undone one day later by #1044's.`,
    );
    process.exit(1);
  }

  console.log(
    `\n✓ no directory walk in ${DISCOVERY_ROOTS.join("/")} calls ${BANNED.map((b) => `\`${b}\``).join(" or ")} directly.` +
      `\n  Bounded, and the bound is the point: this bans a TOKEN, discovery-backed over every source file, so a` +
      `\n  new walker is in scope the day it is written. It does not reason about whether a given call is inside a` +
      `\n  walk. \`lstatSync\` is deliberately allowed (it does not follow the link); fs.promises.stat and` +
      `\n  statfsSync are outside the ban and absent from the tree — see src/fs-walk-guard.ts.`,
  );
}

main();
