// #1349 — re-testable measurement for one of the six-gate program's decisional/empirical bounds
// recorded in docs/design/acceptance-conservation.md: `citedScripts` (src/acceptance-conservation.ts)
// only truth-checks a `pnpm <script>` reference when it is BACKTICKED, so an unbackticked-but-real
// reference silently skips the truth check instead of being verified. That narrowing was measured
// 2026-07-27 to cost nothing on 3 `pnpm <script>` references across 2 PRs — every one was already
// backticked. This CLI replays the same parseBody + citedScripts logic over a much larger, live
// population of merged PR bodies, so the claim is re-testable rather than resting on one small
// sample: it prints every `met` line whose evidence mentions `pnpm` OUTSIDE any backtick span AND
// names a real `package.json` script — the exact shape that would mean the narrowing under-serves a
// real case — and exits 0 the moment one exists (the "costs nothing" claim just became false),
// exiting 1 while none has been found (the claim still holds).
//
//   gh pr list --repo jharvieux/Harvey --state merged --limit 200 --json number,body | pnpm exec tsx src/cli/measure-pnpm-evidence.ts
//
// Reads PR data from stdin so this tool stays pure/offline-testable; the falsifier in the registry
// block supplies the live `gh pr list` population.
import { readFileSync } from "node:fs";
import { parseBody } from "../acceptance-conservation.js";

const raw = readFileSync(0, "utf8");
const prs: { number: number; body: string | null }[] = JSON.parse(raw);
const scripts = new Set(Object.keys(JSON.parse(readFileSync(new URL("../../package.json", import.meta.url), "utf8")).scripts));

const BACKTICKED = /`([^`]+)`/g;

let metLines = 0;
let pnpmMentions = 0;
let backtickedPnpm = 0;
const uncaught: { pr: number; line: string }[] = [];

for (const pr of prs) {
  if (!pr.body) continue;
  for (const d of parseBody(pr.body).dispositions) {
    if (d.disposition !== "met") continue;
    metLines++;
    if (!/\bpnpm\b/.test(d.detail)) continue;
    pnpmMentions++;
    const inBacktick = [...d.detail.matchAll(BACKTICKED)].some((m) => /\bpnpm\b/.test(m[1]!));
    if (inBacktick) {
      backtickedPnpm++;
      continue;
    }
    const name = /\bpnpm\s+(?:run\s+)?([\w:-]+)/.exec(d.detail)?.[1];
    if (name && scripts.has(name)) uncaught.push({ pr: pr.number, line: d.detail });
  }
}

console.log(`PRs scanned: ${prs.length}; total met lines: ${metLines}; met lines mentioning pnpm: ${pnpmMentions} (${backtickedPnpm} backticked)`);
if (uncaught.length === 0) {
  console.log("0 unbackticked-but-real pnpm script references found — the narrowing still costs nothing on this population.");
  process.exit(1);
}
console.log(`${uncaught.length} unbackticked pnpm reference(s) name a REAL script — the narrowing now under-serves a real case:`);
for (const u of uncaught) console.log(`  PR #${u.pr}: ${u.line}`);
process.exit(0);
