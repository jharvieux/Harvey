// The acceptance-criteria conservation gate (#1315) and its remainder-liveness half (#1316).
//
//   pnpm exec tsx src/cli/validate-acceptance.ts --pr <number> [--repo <owner/repo>] [--json]
//   pnpm exec tsx src/cli/validate-acceptance.ts --body-file <path> [--json]
//   pnpm exec tsx src/cli/validate-acceptance.ts --selftest
//
// Reads the PR body, finds every closing keyword, and asserts that each acceptance bullet of each
// issue it would close is mapped to `met` (with evidence), `split` (to a live remainder) or
// `relayed` (to a question recorded ON the issue). See src/acceptance-conservation.ts for why.
//
// Exit codes are three-valued ON PURPOSE, because the negative controls have to tell a gate that
// FAILED from a gate that could not RUN:
//   0  passed, or a green no-op (no closing keyword and no `remainder:` line)
//   1  the gate failed — a criterion is unaccounted for, or a remainder is dead
//   2  the gate could not run (no input, `gh` unavailable, a seed that could not be planted)
// A CI negative control that accepted "non-zero" would go green on exit 2, which is the shape
// #1246 found in five recorded falsifiers: an input-redirect error read as "the blocker holds".
//
// --selftest runs the gate over the hermetic scenario in acceptance-conservation.ts: one healthy
// body that must PASS and four seeded violations that must each FAIL. It needs no network and no
// live issue state, so CI can prove the gate can still fail on a PR that closes nothing.
//
// --seed-drop-disposition / --seed-bare-evidence / --seed-remainder <n> plant the same violations
// into a REAL body (--pr / --body-file), mirroring validate-conservation.ts's --seed-* flags.

import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import {
  checkAcceptance,
  formatAcceptance,
  SELFTEST_LOOKUP,
  seedBareEvidence,
  seedDropDisposition,
  seedRemainder,
  selftestCases,
  type IssueRecord,
} from "../acceptance-conservation.js";

const args = process.argv.slice(2);
const flag = (name: string): string | undefined => {
  const i = args.indexOf(name);
  return i === -1 ? undefined : args[i + 1];
};

function die(message: string): never {
  console.error(`✗ ${message}`);
  process.exit(2);
}

if (args.includes("--selftest")) {
  console.log("Acceptance gate self-test — a hermetic scenario, so a green run proves the gate PASSES and CAN FAIL.\n");
  let broken = 0;
  for (const c of selftestCases()) {
    const actual = checkAcceptance(c.body, SELFTEST_LOOKUP).ok ? "pass" : "fail";
    const good = actual === c.expect;
    if (!good) broken++;
    console.log(`  ${good ? "✓" : "✗"} ${c.name} — expected ${c.expect}, got ${actual}`);
  }
  if (broken > 0) {
    console.error(`\n✗ ${broken} self-test case(s) wrong. A gate that cannot fail on a planted violation is not evidence of anything (#350/#1065).`);
    process.exit(1);
  }
  console.log("\n✓ the healthy body passes and every seeded violation fails.");
  process.exit(0);
}

const gh = (ghArgs: string[]): { status: number; stdout: string; stderr: string } => {
  const r = spawnSync("gh", ghArgs, { encoding: "utf8" });
  if (r.error) die(`\`gh ${ghArgs.join(" ")}\` could not be run (${r.error.message}). This gate needs an authenticated gh; reporting a pass here would be the silent omission it exists to prevent.`);
  return { status: r.status ?? 1, stdout: r.stdout ?? "", stderr: r.stderr ?? "" };
};

const repoFlag = flag("--repo");
const repoArgs = repoFlag ? ["--repo", repoFlag] : [];

// `undefined` must mean "does not exist" and nothing else — a fetch that merely failed has to stop
// the run, never quietly become a nonexistent issue that fails the gate for the wrong reason.
const cache = new Map<number, IssueRecord | undefined>();
function lookup(issue: number): IssueRecord | undefined {
  if (cache.has(issue)) return cache.get(issue);
  const r = gh(["issue", "view", String(issue), ...repoArgs, "--json", "number,state,body,comments"]);
  if (r.status !== 0) {
    if (/could not resolve to an? (?:issue|pull request)/i.test(r.stderr)) {
      cache.set(issue, undefined);
      return undefined;
    }
    die(`\`gh issue view ${issue}\` failed (exit ${r.status}): ${r.stderr.trim()}`);
  }
  const raw = JSON.parse(r.stdout) as { number: number; state: string; body: string; comments: { body: string }[] };
  const record: IssueRecord = {
    number: raw.number,
    state: raw.state === "OPEN" ? "OPEN" : "CLOSED",
    body: raw.body ?? "",
    comments: (raw.comments ?? []).map((c) => c.body ?? ""),
  };
  cache.set(issue, record);
  return record;
}

const prFlag = flag("--pr");
const bodyFile = flag("--body-file");
if (!prFlag && !bodyFile) die("nothing to check — pass --pr <number>, --body-file <path>, or --selftest");

let body: string;
let source: string;
if (bodyFile) {
  body = readFileSync(bodyFile, "utf8");
  source = bodyFile;
} else {
  const r = gh(["pr", "view", prFlag!, ...repoArgs, "--json", "body"]);
  if (r.status !== 0) die(`\`gh pr view ${prFlag}\` failed (exit ${r.status}): ${r.stderr.trim()}`);
  body = (JSON.parse(r.stdout) as { body: string }).body ?? "";
  source = `PR #${prFlag}`;
}

const seeded: string[] = [];
try {
  if (args.includes("--seed-drop-disposition")) {
    const s = seedDropDisposition(body);
    body = s.body;
    seeded.push(`dropped the disposition line \`${s.dropped}\` — the bullet it mapped must now read UNMAPPED`);
  }
  if (args.includes("--seed-bare-evidence")) {
    const s = seedBareEvidence(body);
    body = s.body;
    seeded.push(`hollowed \`${s.replaced}\` out to a bare "done" — it must now fail the evidence check`);
  }
  const seedRemainderTarget = flag("--seed-remainder");
  if (args.includes("--seed-remainder")) {
    if (!seedRemainderTarget || !/^\d+$/.test(seedRemainderTarget)) die("--seed-remainder needs an issue number that is CLOSED or nonexistent");
    body = seedRemainder(body, Number(seedRemainderTarget));
    seeded.push(`appended \`remainder: #${seedRemainderTarget}\` — the liveness check must now fail naming which condition`);
  }
} catch (e) {
  die(`${(e as Error).message}. The negative control planted nothing, so a pass below would prove nothing.`);
}

console.log(`Acceptance conservation (#1315/#1316) — ${source}\n`);
for (const s of seeded) console.log(`⚠ SEEDED VIOLATION: ${s}`);
if (seeded.length > 0) console.log("  The gate MUST exit 1 below. Exit 0 means it cannot fail; exit 2 means it could not run.\n");

const report = checkAcceptance(body, lookup, repoFlag);
console.log(args.includes("--json") ? JSON.stringify(report, null, 2) : formatAcceptance(report));
process.exit(report.ok ? 0 : 1);
