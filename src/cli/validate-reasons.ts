// pnpm exec tsx src/cli/validate-reasons.ts [--root <path>]... [--revalidate] [--list] [--live | --tier <name>]...
//
// The #1033 gate over recorded reasons. Two passes:
//
//   • STRUCTURAL (always, no commands run) — every reason block is well-formed: it declares whether
//     it is empirical or decisional, carries a MEASURED/TRIED/ASSUMED provenance tag with a date,
//     and — if empirical — carries the command that would falsify it. Fast enough to run in CI and
//     locked by src/recorded-reasons.repo.test.ts so `pnpm verify` enforces it.
//   • --revalidate (runs each empirical falsifier) — a falsifier that now EXITS 0 means the blocker
//     it describes is gone while the text still asserts it. That is a failing row, not a note.
//     Decisional reasons are excluded from this pass entirely; they await a human, not a command.
//
// Also reports subsystem drift for reasons that declare TOUCHES: commits on the referenced paths
// after the reason's date. Advisory — it is a prompt to re-read, not a verdict.

import { spawnSync } from "node:child_process";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  DEFAULT_ROOTS,
  KNOWN_FALSIFIER_TIERS,
  collectReasons,
  reasonKind,
  revalidateReasons,
  subsystemDrift,
  validateRecordedReason,
  type FalsifierResult,
} from "../recorded-reasons.js";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const FALSIFIER_TIMEOUT_MS = 120_000;

function flagValues(flag: string): string[] {
  return process.argv.flatMap((arg, i) => {
    const next = process.argv[i + 1];
    return arg === flag && next ? [next] : [];
  });
}

function runFalsifier(command: string): FalsifierResult {
  const r = spawnSync("sh", ["-c", command], { cwd: REPO_ROOT, encoding: "utf8", timeout: FALSIFIER_TIMEOUT_MS });
  return { code: r.status, output: `${r.stdout ?? ""}${r.stderr ?? ""}` };
}

// End-of-day, not start: a reason recorded on day D is presumed to account for everything that
// landed up to and including D, so only later commits are news. A bare `--since=<date>` is also not
// what it looks like — git resolves it against now and skips same-day commits — so the time is
// explicit here rather than implied.
function commitsSince(paths: string[], since: string): string[] {
  const r = spawnSync("git", ["log", `--since=${since} 23:59:59`, "--format=%h", "--", ...paths], { cwd: REPO_ROOT, encoding: "utf8" });
  return (r.stdout ?? "").split("\n").filter(Boolean);
}

const roots = flagValues("--root");
const reasons = collectReasons(roots.length > 0 ? roots : DEFAULT_ROOTS, REPO_ROOT);
const empirical = reasons.filter((r) => reasonKind(r) === "empirical");
const decisional = reasons.filter((r) => reasonKind(r) === "decisional");

console.log(`Recorded reasons (#1033): ${reasons.length} — ${empirical.length} empirical, ${decisional.length} decisional`);

if (process.argv.includes("--list")) {
  for (const r of reasons) console.log(`  ${r.file}:${r.line}  [${r.fields.KIND ?? "?"}] ${r.fields.REASON?.slice(0, 100) ?? ""}`);
}

let failed = false;

const malformed = reasons.map((r) => ({ r, errors: validateRecordedReason(r) })).filter((x) => x.errors.length > 0);
if (malformed.length > 0) {
  failed = true;
  console.error(`\n✗ ${malformed.length} malformed reason block(s):`);
  for (const { r, errors } of malformed) {
    console.error(`  ${r.file}:${r.line} — ${r.fields.REASON?.slice(0, 90) ?? "(no claim)"}`);
    for (const e of errors) console.error(`      • ${e}`);
  }
} else {
  console.log("✓ every reason block is well-formed (kind declared, provenance dated, empirical reasons carry a falsifier)");
}

for (const row of subsystemDrift(reasons, commitsSince)) {
  console.log(`\nℹ SUBSYSTEM MOVED  ${row.file}:${row.line}\n    ${row.claim.slice(0, 120)}\n    ${row.detail}`);
}

if (process.argv.includes("--revalidate")) {
  // --live enables every registered tier; --tier <name> (repeatable) enables specific ones. An
  // unknown --tier is refused loudly rather than silently enabling nothing.
  const requestedTiers = flagValues("--tier");
  const unknownTiers = requestedTiers.filter((t) => !KNOWN_FALSIFIER_TIERS.has(t));
  if (unknownTiers.length > 0) {
    console.error(`✗ unknown --tier: ${unknownTiers.join(", ")} — known tiers: ${[...KNOWN_FALSIFIER_TIERS].join(", ")}`);
    process.exit(1);
  }
  const availableTiers = process.argv.includes("--live") ? new Set(KNOWN_FALSIFIER_TIERS) : new Set(requestedTiers);

  const rows = revalidateReasons(empirical, runFalsifier, availableTiers);
  const skippedLive = rows.filter((row) => row.status === "SKIPPED-LIVE");
  const broken = rows.filter((row) => row.status === "STALE" || row.status === "UNVERIFIABLE");
  const ran = rows.length - skippedLive.length;
  console.log(`\nRe-validated ${ran} empirical falsifier(s); ${skippedLive.length} live-only skipped; ${decisional.length} decisional reason(s) excluded by kind.`);
  for (const row of skippedLive) {
    console.log(`\nℹ SKIPPED-LIVE  ${row.file}:${row.line}\n    ${row.claim.slice(0, 120)}\n    ${row.detail}`);
  }
  for (const row of broken) {
    failed = true;
    console.error(`\n✗ ${row.status}  ${row.file}:${row.line}\n    ${row.claim.slice(0, 120)}\n    ${row.detail}`);
  }
  if (broken.length === 0 && ran > 0) console.log("✓ every empirical falsifier run still exits non-zero — no reason has outlived its truth");
}

process.exit(failed ? 1 : 0);
