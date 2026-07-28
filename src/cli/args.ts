// Shared CLI argument handling for the scan/validate entry points.
//
// WHY THIS EXISTS. Every CLI defined its own two-line `arg()` and NONE validated that the flags it
// was handed were flags it understands. Combined with `arg("--dir") ?? process.cwd()`, an
// unrecognized flag did not fail — it fell through to the current working directory and the tool
// produced a complete, confident, plausible report about THE WRONG TREE.
//
// MEASURED 2026-07-26, which is how this was found: `quick-scan --target targets/calibration
// --findings-out f.json` exited 0 with 650 findings, 188 of them in Harvey's own source
// (`src/cli/**`, `site/**`, `.github/**`, `epic-builder-web/**`) — paths that do not exist under the
// stated target. The correct invocation (`--dir`) returns 462 findings, none outside the target.
// Nothing warned. The flag name was simply wrong: `dry-run.ts` documents `--target`, `run-audit`
// takes the target positionally, and these five take `--dir`.
//
// The damage is not limited to a wasted scan. `validate-calibration --target <dir>` would score
// `process.cwd()` and print a recall figure for a tree nobody asked about — a false capability
// number, which is the exact failure the "measure, don't recall" doctrine exists to prevent.
//
// So: `assertKnownFlags` fails loud on any unrecognized `--flag`, and `targetDir` accepts `--target`
// as an alias for `--dir` rather than punishing a caller for guessing the other CLI's spelling.

/** Value of `flag`, or undefined when absent. */
export function arg(flag: string, argv: string[] = process.argv): string | undefined {
  const i = argv.indexOf(flag);
  return i >= 0 ? argv[i + 1] : undefined;
}

/**
 * Exit non-zero naming any `--flag` this CLI does not accept. Call BEFORE reading any argument, so
 * a typo can never reach a `?? process.cwd()` fallback and silently retarget the run.
 *
 * Values are skipped by position: a token is only checked when it is not consumed as the value of a
 * preceding known flag, so `--out --dir` (a missing value) is reported rather than mistaken for one.
 */
export function assertKnownFlags(known: readonly string[], argv: string[] = process.argv.slice(2)): void {
  const valueless = new Set(["--json", "--real", "--mechanical", "--functions", "--supabase", "--list", "--update-baseline", "--print-pin"]);
  const unknown: string[] = [];
  for (let i = 0; i < argv.length; i++) {
    const token = argv[i];
    if (token === undefined || !token.startsWith("--")) continue;
    if (!known.includes(token)) {
      unknown.push(token);
      continue;
    }
    if (!valueless.has(token)) i++; // consume this flag's value so it is not itself checked
  }
  if (unknown.length === 0) return;
  console.error(
    `Unrecognized ${unknown.length === 1 ? "flag" : "flags"}: ${unknown.join(", ")}\n` +
      `Accepted: ${[...known].sort().join(" ")}\n` +
      `Refusing to run — an ignored flag would silently scan the wrong directory.`,
  );
  process.exit(2);
}

/**
 * The directory to scan. Accepts `--dir` or `--target` (the spelling `dry-run.ts` uses) and falls
 * back to the process cwd. Pass both and it exits rather than picking a winner.
 */
export function targetDir(argv: string[] = process.argv): string {
  const dir = arg("--dir", argv);
  const target = arg("--target", argv);
  if (dir !== undefined && target !== undefined && dir !== target) {
    console.error(`--dir (${dir}) and --target (${target}) disagree; pass one.`);
    process.exit(2);
  }
  return dir ?? target ?? process.cwd();
}
