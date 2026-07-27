// pnpm exec tsx src/cli/validate-reasons.ts [--root <path>]... [--revalidate] [--list] [--census]
//                                           [--live | --tier <name>]... [--issues]
//
// The #1033 gate over recorded reasons. Two passes:
//
//   • STRUCTURAL (always, no commands run) — every reason block is well-formed: it declares whether
//     it is empirical or decisional, carries a MEASURED/TRIED/ASSUMED provenance tag with a date,
//     and — if empirical — carries the command that would falsify it. Fast enough to run in CI and
//     locked by src/recorded-reasons.test.ts so `pnpm verify` enforces it.
//   • --revalidate (runs each empirical falsifier) — a falsifier that now EXITS 0 means the blocker
//     it describes is gone while the text still asserts it. That is a failing row, not a note.
//     Decisional reasons are excluded from this pass entirely; they await a human, not a command.
//
// Also reports subsystem drift: commits landing after the reason's date on the paths it declares in
// TOUCHES: plus the paths its FALSIFIER: names that exist in this checkout (#1246). Advisory — it is
// a prompt to re-read, not a verdict.
//
// `--census` lists the claim-shaped prose lines that are NOT inside any reason block; the count is
// printed on every run. Untriaged, not malformed — advisory, and a deliberate lower bound (#1246).
//
// `--issues` folds the open GitHub issues' bodies and comments in as extra surfaces, because
// collectReasons reads files and a blocker recorded in an issue is otherwise gated by nothing. Their
// blocks are held to the same structure; their falsifiers are NOT executed — an issue body is
// attacker-writable input, so running its commands would turn this gate into a remote-execution
// surface. To get a claim re-tested, mirror it into the repo (#920/#921's blocks mirror
// src/scan/sfc-coverage.ts). Needs an authenticated `gh`; it fails loud rather than reporting zero.
//
// A live-tier falsifier names its target as a `<placeholder>` because the target is stood up outside
// the repo. Bind each one in the environment on the run that has the tier — `<crapi-gateway>` reads
// HARVEY_FALSIFIER_CRAPI_GATEWAY — e.g.
//   HARVEY_FALSIFIER_SUPERREDHAT_CLONE=/clones/superredhat pnpm validate-reasons --revalidate --tier secbench
// An unbound placeholder is reported UNVERIFIABLE and the command is not run (#1072).

import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  DEFAULT_ROOTS,
  KNOWN_FALSIFIER_TIERS,
  collectSources,
  issueSources,
  parseRecordedReasons,
  placeholderEnvVar,
  reasonKind,
  revalidateReasons,
  subsystemDrift,
  untriagedClaims,
  validateRecordedReason,
  watchedPaths,
  type FalsifierResult,
  type FetchedIssue,
  type ParsedReason,
  type SourceText,
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

const inRepo = (path: string): boolean => existsSync(resolve(REPO_ROOT, path));
const recordedInIssue = (r: ParsedReason): boolean => r.file.startsWith("issue #");

// Closed issues are out of scope BY DECISION: a blocker on a closed issue no longer steers work, and
// the population is unbounded. Said here rather than left silent — an unstated limit reads as
// coverage (#1246).
function fetchOpenIssues(): SourceText[] {
  const r = spawnSync("gh", ["issue", "list", "--state", "open", "--limit", "300", "--json", "number,body,comments"], { cwd: REPO_ROOT, encoding: "utf8" });
  if (r.status !== 0) {
    console.error(`✗ --issues: \`gh issue list\` failed (exit ${r.status ?? "signal"}) — it needs an authenticated gh. Reporting zero issue-recorded claims here would be the silent pass this gate exists to prevent.\n${(r.stderr ?? "").trim()}`);
    process.exit(1);
  }
  return issueSources(JSON.parse(r.stdout) as FetchedIssue[]);
}

const roots = flagValues("--root");
const sources = collectSources(roots.length > 0 ? roots : DEFAULT_ROOTS, REPO_ROOT);
const fileReasons = sources.flatMap(({ file, text }) => parseRecordedReasons(text, file));

const issues = process.argv.includes("--issues") ? fetchOpenIssues() : [];
const issueReasons = issues.flatMap(({ file, text }) => parseRecordedReasons(text, file, true));

const reasons: ParsedReason[] = [...fileReasons, ...issueReasons];
const empirical = reasons.filter((r) => reasonKind(r) === "empirical");
const decisional = reasons.filter((r) => reasonKind(r) === "decisional");

console.log(`Recorded reasons (#1033): ${reasons.length} — ${empirical.length} empirical, ${decisional.length} decisional`);
if (process.argv.includes("--issues")) console.log(`  including ${issueReasons.length} recorded in ${issues.length} open-issue bodies/comments (closed issues out of scope by decision, #1246)`);

if (process.argv.includes("--list")) {
  for (const r of reasons) console.log(`  ${r.file}:${r.line}  [${r.fields.KIND ?? "?"}] ${r.fields.REASON?.slice(0, 100) ?? ""}`);
}

let failed = false;

const malformed = reasons.map((r) => ({ r, errors: validateRecordedReason(r, inRepo) })).filter((x) => x.errors.length > 0);
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

for (const row of subsystemDrift(reasons, commitsSince, inRepo)) {
  console.log(`\nℹ SUBSYSTEM MOVED  ${row.file}:${row.line}\n    ${row.claim.slice(0, 120)}\n    ${row.detail}`);
}

// The complement of the drift rows above, and the reason they are trustworthy: a reason with no
// watchable path produces no drift row for the same reason a clean repo does. Counted so the two
// cannot be confused (#1246).
const unwatched = empirical.filter((r) => watchedPaths(r, inRepo).length === 0);
console.log(`\nSubsystem drift watches ${empirical.length - unwatched.length}/${empirical.length} empirical reason(s) — the rest name no path that exists here, so silence from them is absence of evidence:`);
for (const r of unwatched) console.log(`  ${r.file}:${r.line} — add TOUCHES: <paths> to put this claim's subsystem under watch`);

// Claim-shaped prose outside any block: untriaged, not malformed. Advisory and a lower bound.
const prose = untriagedClaims([...sources.filter((s) => s.file.endsWith(".md")), ...issues], reasons);
const byRoot = new Map<string, number>();
for (const c of prose) {
  const key = c.file.startsWith("issue #") ? "open issues" : (c.file.split("/")[0] as string);
  byRoot.set(key, (byRoot.get(key) ?? 0) + 1);
}
const breakdown = [...byRoot].sort((a, b) => b[1] - a[1]).slice(0, 6).map(([k, n]) => `${k} ${n}`).join(", ");
console.log(`\nUntriaged claim-shaped prose lines (advisory, LOWER BOUND — a fixed vocabulary, prose only): ${prose.length}${prose.length > 0 ? ` — ${breakdown}` : ""}`);
console.log("  Each is a standing claim outside any REASON block, so nothing re-tests it. --census lists them.");
if (process.argv.includes("--census")) {
  for (const c of prose) console.log(`  ${c.file}:${c.line}  ${c.text.slice(0, 140)}`);
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

  // An issue body is attacker-writable: anyone who can comment can author a FALSIFIER:, so running
  // one would make this gate a remote-execution surface — a scheduled `--issues --revalidate` would
  // execute it with the repo checked out. They are held to the structure above and reported here
  // instead; the way to get a claim re-tested is to mirror the block into the repo (#1246).
  for (const r of empirical.filter(recordedInIssue)) {
    console.log(`\nℹ NOT RE-TESTED  ${r.file}:${r.line}\n    ${r.fields.REASON?.slice(0, 120) ?? ""}\n    recorded outside the repo — its FALSIFIER is not executed, because an issue body is input anyone with comment access can write. Mirror this block into the file it constrains to put it under \`--revalidate\`.`);
  }

  const rows = revalidateReasons(empirical.filter((r) => !recordedInIssue(r)), runFalsifier, availableTiers, (placeholder) => process.env[placeholderEnvVar(placeholder)]);
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
