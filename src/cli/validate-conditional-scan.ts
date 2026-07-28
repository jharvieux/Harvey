// pnpm exec tsx src/cli/validate-conditional-scan.ts [--list] [--seed-omission]
//
// Gate 4b of the #1320 prevention program (#1330). A scan path that omits a check its sibling path
// runs must emit a counted not-assessed row naming the class it skipped. Silence there is
// indistinguishable from a check that ran and found nothing, which is the inversion the whole
// disclosure-row family exists to prevent.
//
// --list           prints every registered module, its sibling paths and the omissions each one
//                  discloses, so the population the gate judges is visible rather than inferred
//                  from a violation count of zero. The registry is discovery-backed: a module under
//                  src/scan or src/detectors with sibling scan paths and no registry entry FAILS.
// --seed-omission  the negative control: deletes one check call from a registered path's source
//                  before auditing it, producing an omission the registry does not declare. It MUST
//                  exit non-zero. A gate only ever seen passing is indistinguishable from one that
//                  cannot fail (#350/#1065).
//
// The gate's own scope is stated in src/conditional-scan.ts.

import {
  CONDITIONAL_SCANS,
  DISCOVERY_ROOTS,
  auditConditionalScans,
  discoverConditionalScans,
  parseScanPaths,
  readConditionalScan,
  type ConditionalScan,
} from "../conditional-scan.js";

// Removing a check the sibling path still runs is the exact defect: a path quietly stops covering a
// class. Seeding it on the REAL source (rather than on a synthetic file) proves the gate fires on
// the shape it actually guards.
const SEED = { file: "src/scan/supabase.ts", drop: "...checkDangerousExtensions(extensions),\n" };

function seededRead(entry: ConditionalScan): string {
  const text = readConditionalScan(entry);
  if (entry.file !== SEED.file) return text;
  if (!text.includes(SEED.drop)) {
    throw new Error(`--seed-omission cannot find \`${SEED.drop.trim()}\` in ${entry.file}; update the seed to a call the omitting path still makes.`);
  }
  return text.replace(SEED.drop, "");
}

function main(): void {
  const seed = process.argv.includes("--seed-omission");
  const violations = auditConditionalScans(CONDITIONAL_SCANS, seed ? seededRead : readConditionalScan);

  const declaredOmissions = CONDITIONAL_SCANS.flatMap((e) => e.disclosures).flatMap((d) => d.omits);
  console.log("Conditional-scan disclosure (gate 4b, #1330)");
  console.log(`  modules registered:       ${CONDITIONAL_SCANS.length}`);
  console.log(`  sibling scan paths:       ${CONDITIONAL_SCANS.reduce((n, e) => n + e.paths.length, 0)}`);
  console.log(`  omissions disclosed:      ${declaredOmissions.length}`);
  if (seed) console.log(`  (--seed-omission: one check call removed from ${SEED.file}; the gate must report it below)`);

  if (process.argv.includes("--list")) {
    for (const entry of CONDITIONAL_SCANS) {
      console.log(`\n${entry.file}`);
      for (const path of entry.paths) {
        const d = entry.disclosures.find((x) => x.path === path);
        console.log(`  ${path}${d ? `  → ${d.rowId} via ${d.emitter}()` : "  (runs every check)"}`);
        for (const o of d?.omits ?? []) console.log(`      omits ${o.fn} — disclosed as "${o.namedInRow}"`);
      }
      const found = parseScanPaths(readConditionalScan(entry)).map((p) => p.name);
      console.log(`  scan paths found in source: ${found.join(", ")}`);
    }
  }

  const unregistered = discoverConditionalScans().filter((f) => !CONDITIONAL_SCANS.some((e) => e.file === f));
  if (unregistered.length > 0) {
    console.error(
      `\n✗ ${unregistered.length} module(s) under ${DISCOVERY_ROOTS.join(", ")} carry sibling scan paths and are not in` +
        `\n  CONDITIONAL_SCANS: ${unregistered.join(", ")}` +
        `\n  Register each one with its omissions declared, so the checks one path skips are disclosed rather than` +
        `\n  silently absent. An unregistered module is not "no omissions" — it is an unasked question.`,
    );
    process.exit(1);
  }

  if (violations.length > 0) {
    console.error(`\n✗ ${violations.length} conditional-scan omission(s) the deliverable would not mention.`);
    for (const v of violations) console.error(`\n  ${v.file}\n    ${v.detail}`);
    console.error(
      "\nFix by emitting a counted not-assessed row from the omitting path — the SEM-SCOPE-00 / SUP-SCOPE-00 shape:" +
        "\n  name the class that was not checked and why this path cannot check it, and declare the omission in" +
        "\n  CONDITIONAL_SCANS. Dropping the check from the sibling path too is not a fix; it removes the coverage" +
        "\n  instead of the silence.",
    );
    process.exit(1);
  }

  console.log(
    "\n✓ every module with sibling scan paths is registered, and every omission it makes is declared and" +
      "\n  disclosed in a counted row." +
      "\n  Lower bound, not a census — discovery recognises a SHAPE (two top-level `scan*` functions in one" +
      "\n  module) and reads omissions from literal `check*(` calls in each path's own body, so a check reached" +
      "\n  through a helper, and a conditional omission written some other way, are outside it." +
      "\n  See src/conditional-scan.ts.",
  );
}

main();
