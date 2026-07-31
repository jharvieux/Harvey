// pnpm exec tsx src/cli/validate-supervised-declines.ts [--since-days N] [--pr N ...] [--selftest]
//
// #1545. Reads MERGED PR BODIES for the repo's densest false-decline family — "X is a supervised
// path", written in the same grammar as "X is impossible" — and reports every instance carrying no
// relay artifact. Why this is a scheduled scan and not a PR-blocking gate: the decline is prose, the
// prose is often EDITED after the merge, and the check has to read the issue it names as well, so
// there is no moment at merge time when the answer is stable. See src/supervised-declines.ts for
// the rule and for why a filed tracking issue is not a relay.
//
// Exit codes, three-valued like the other gates in this repo:
//   0  no unrelayed decline in the window (or --selftest passed)
//   1  at least one unrelayed decline — named, with the issues it did and did not ask
//   2  could not run (no gh, a bad flag, a fetch that failed)
// A control that accepted "non-zero" would go green on exit 2 (#1246).
//
// --since-days defaults to 1, matching the daily cadence: the scan is over what merged since the
// last run, so a standing backlog of historical instances cannot make it permanently red. The
// historical population is in the issue and in the report's own footer, not in this exit code.

import { spawnSync } from "node:child_process";
import { recordDeclaredNoOp, recordMeasured } from "../ci-liveness.js";
import { findSupervisedDeclines, judgeDecline, ROUTINELY_GRANTED, selftestCases, type IssueLike } from "../supervised-declines.js";

const args = process.argv.slice(2);
const flag = (name: string): string | undefined => {
  const i = args.indexOf(name);
  return i === -1 ? undefined : args[i + 1];
};

function die(message: string): never {
  console.error(`✗ ${message}`);
  process.exit(2);
}

const gh = (ghArgs: string[]): { status: number; stdout: string; stderr: string } => {
  // maxBuffer, because the input IS the prose: 200 PR bodies from this repo overran the 1 MB
  // default and spawnSync returned ENOBUFS (MEASURED 2026-07-31 over a 4-day window). It exited 2
  // rather than 0, which is the three-valued design doing its job — but a scan that cannot read is
  // a scan that must not report a clean window.
  const r = spawnSync("gh", ghArgs, { encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
  if (r.error) die(`\`gh ${ghArgs.join(" ")}\` could not be run (${r.error.message}). Reporting "no unrelayed declines" without having read anything is the silent omission this check exists to find.`);
  return { status: r.status ?? 1, stdout: r.stdout ?? "", stderr: r.stderr ?? "" };
};

if (args.includes("--selftest")) {
  console.log("Supervised-decline scan self-test (#1545) — hermetic, so a green run proves the check FIRES and can stay SILENT.\n");
  let broken = 0;
  for (const c of selftestCases()) {
    const lookup = (n: number): IssueLike | undefined => c.issues.find((i) => i.number === n);
    const verdicts = findSupervisedDeclines(c.body).map((h) => judgeDecline(h, c.body, lookup));
    const actual = verdicts.some((v) => v.relay === "none") ? "flagged" : "clear";
    const good = actual === c.expect;
    if (!good) broken++;
    console.log(`  ${good ? "✓" : "✗"} ${c.name} — expected ${c.expect}, got ${actual}`);
  }
  if (broken > 0) {
    console.error(`\n✗ ${broken} self-test case(s) wrong. A check that cannot fire, or that fires on everything, measures nothing (#350/#1065).`);
    process.exit(1);
  }
  console.log("\n✓ every unrelayed decline is flagged and every relayed one is left alone.");
  recordMeasured("supervised-declines-selftest", selftestCases().length, "hermetic decline/relay cases scored in both directions");
  process.exit(0);
}

const issueCache = new Map<number, IssueLike | undefined>();
function lookupIssue(n: number): IssueLike | undefined {
  if (issueCache.has(n)) return issueCache.get(n);
  const r = gh(["issue", "view", String(n), "--json", "number,body,comments"]);
  // A PR number resolves through `gh issue view` too, which is what we want: a decline that names a
  // PR carrying the operator's own words is as good a relay as one naming an issue.
  const record = r.status === 0
    ? ((): IssueLike => {
        const raw = JSON.parse(r.stdout) as { number: number; body: string; comments: { body: string }[] };
        return { number: raw.number, body: raw.body ?? "", comments: (raw.comments ?? []).map((c) => c.body ?? "") };
      })()
    : undefined;
  issueCache.set(n, record);
  return record;
}

interface Pr {
  number: number;
  title: string;
  body: string;
  mergedAt: string;
}

function prsToScan(): Pr[] {
  const explicit = args.flatMap((a, i) => (a === "--pr" ? [args[i + 1]] : []));
  if (explicit.length > 0) {
    return explicit.map((n) => {
      if (!n || !/^\d+$/.test(n)) die("--pr needs a PR number");
      const r = gh(["pr", "view", n, "--json", "number,title,body,mergedAt"]);
      if (r.status !== 0) die(`\`gh pr view ${n}\` failed (exit ${r.status}): ${r.stderr.trim()}`);
      return JSON.parse(r.stdout) as Pr;
    });
  }
  const days = Number(flag("--since-days") ?? 1);
  if (!Number.isFinite(days) || days <= 0) die("--since-days needs a positive number of days");
  const since = new Date(Date.now() - days * 86_400_000).toISOString().slice(0, 10);
  const r = gh(["pr", "list", "--state", "merged", "--limit", "200", "--search", `merged:>=${since}`, "--json", "number,title,body,mergedAt"]);
  if (r.status !== 0) die(`\`gh pr list\` failed (exit ${r.status}): ${r.stderr.trim()}`);
  return JSON.parse(r.stdout) as Pr[];
}

const prs = prsToScan();
console.log(`Supervised-path declines (#1545) — ${prs.length} merged PR body(ies) read.\n`);

let unrelayed = 0;
let relayed = 0;
let notADecline = 0;
for (const pr of prs) {
  for (const hit of findSupervisedDeclines(pr.body ?? "")) {
    const v = judgeDecline(hit, pr.body ?? "", lookupIssue);
    if (v.relay === "none") {
      unrelayed++;
      console.log(`✗ PR #${pr.number} line ${hit.line} — UNRELAYED DECLINE (${v.detail})`);
      console.log(`    ${hit.text.slice(0, 220)}`);
    } else if (v.relay === "nothing-owed") {
      notADecline++;
      console.log(`ℹ PR #${pr.number} line ${hit.line} — not a decline (${v.detail})`);
    } else {
      relayed++;
      console.log(`✓ PR #${pr.number} line ${hit.line} — relayed (${v.relay}: ${v.detail})`);
    }
  }
}

// A window with no merged PRs is a legitimate nothing-to-read, and it must not leave the same empty
// receipt a run that died before `gh pr list` would leave.
if (prs.length === 0) recordDeclaredNoOp("supervised-declines", "no PR merged in this window, so there was no prose to read");
else recordMeasured("supervised-declines", prs.length, "merged PR body(ies) read for a supervised-path decline");

// Printed on EVERY run, pass or fail: this check's whole purpose is to put the counter-examples
// where the next person writing such a decline will read them.
console.log("\nRoutinely granted — a decline naming one of these is a permission ask, never a capability bound:");
for (const g of ROUTINELY_GRANTED) console.log(`  ${g.path}\n    ${g.evidence}`);
console.log(
  "\nA supervised path stops the EDIT, never the CRITERION: record the question ON THE ISSUE with the exact\n" +
    "wording you propose, and name it in the PR body. A filed tracker is not a relay — PR #1481 filed #1483\n" +
    "and #1483 asks the operator nothing, which is why this check still counts that decline.",
);

// The bound, stated on every run rather than left for a reader to assume it away: this is a
// KEYWORD scan over prose. A decline phrased outside the vocabulary is invisible to it, so the
// count below is a LOWER bound and its silence is not a clean bill of health.
console.log(
  `\nBOUND: ${unrelayed + relayed + notADecline} paragraph(s) matched a supervised-path signal AND a decline verb.` +
    ` A decline phrased outside that vocabulary is not counted here — this is a floor, not a census.`,
);

if (unrelayed > 0) {
  console.error(`\n✗ ${unrelayed} unrelayed supervised-path decline(s) — ${relayed} correctly relayed, ${notADecline} not a decline.`);
  process.exit(1);
}
console.log(`\n✓ no unrelayed supervised-path decline in this window (${relayed} relayed, ${notADecline} not a decline).`);
