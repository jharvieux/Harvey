import { configDefaults, defineConfig } from "vitest/config";
// HEAVY_CLI_TESTS lives in src/ (#1228) so the CI shard assignment can be DERIVED from it rather
// than restated in ci.yml — see the note above the list's use below.
import { HEAVY_CLI_TESTS } from "./src/heavy-cli-tests.js";

// M8 (#72 §M8) added targets/calibration/test-quality/ — a real Stryker mutation-testing
// fixture with its own isolated npm project and, deliberately, one weak test
// (discount.tautological.test.ts, M8-P-TAUTOLOGICAL). Without this exclude, vitest's default
// include glob picks that up as if it were part of this repo's own suite (see eslint.config.mjs,
// which already ignores "targets" for the same reason). The Layer-1 gate for M8 is the recorded
// Stryker-capture assertions in src/mutation-scan.test.ts, not a live re-run of the target's
// own tests here. Extends (not replaces) vitest's own default excludes.
const BASE_EXCLUDE = [
  ...configDefaults.exclude,
  "targets/**",
  "epic-builder-web/**",
  // The marketing site is a separately-DEPLOYED Next.js app, so its page/component code doesn't
  // belong in this suite — but since #1597 (2026-07-30) it is a pnpm WORKSPACE MEMBER, not a
  // separate npm project, and the two constraints this comment used to record are gone:
  //   - "it deploys ALONE from site/ and therefore cannot import shared logic from src/" — FALSE
  //     now. The Vercel project's Root Directory is `site` with the repo root uploaded, and
  //     site/app/supabase-security-checker/page.tsx imports src/supabase-write-probe.ts directly.
  //     The #888 write-probe moved back to src/ for that reason; its gate is src/supabase-write-probe.test.ts.
  //   - "CI installs the repo root's deps but never site/node_modules" — FALSE now. One root
  //     `pnpm install` provisions site/ too, so a test here CAN reach the Next runtime.
  //     site-contract.test.ts still imports nothing from `next` at runtime, but that is now its own
  //     choice (it needs no bundler), not a constraint imposed by what CI installs.
  // So exclude site's build/deps dirs, not the tree.
  "site/node_modules/**",
  "site/.next/**",
  // ".claude/**": agent worktrees are full repo copies (see eslint.config.mjs).
  ".claude/**",
];

// #1120/#1125 — the heavy tail. These files drive real child processes (the tsx CLIs,
// semgrep, the Stryker scaffolding) through SYNCHRONOUS execFileSync, which blocks their vitest
// worker's event loop for the duration of each call. MEASURED 2026-07-26 they are the entire tail
// of the suite: 6s-70s per file depending on machine load, against 1.7s for the next file down.
// #1105 already had to pull an eighth (src/cli/validate-conservation.test.ts) out for the same
// reason; this generalizes that fix instead of repeating it file by file.
//
// Run inside `pnpm verify`'s shared fork pool they land on the machine simultaneously (vitest's
// forks pool defaults to numCpus - 1 workers, and vitest orders the biggest files first), each
// spawning its own multi-core child. A blocked worker cannot service the birpc ack for the
// `onTaskUpdate` it already sent, so once a single blocking call outlasts 60s the run reports
// `[vitest-worker]: Timeout calling "onTaskUpdate"` as an Unhandled Error and exits 1 with ZERO
// failing tests — a red `pnpm verify` that names nothing.
//
// MEASURED 2026-07-26, `pnpm test`, 10-core machine also carrying other agent worktrees. The list
// held SEVEN files that day; #1628 added an eighth, so read the bullets as the measurement that
// settled the split, not as a current census:
//   • unchanged                   — 3 of 5 green (2 RPC-timeout failures, 0 failing tests)
//   • poolOptions.forks.maxForks 4 — 1 of 5 green. TRIED and REJECTED: throttling the pool does not
//     help, because the contention is not only this suite's own — the heavy files still overlap
//     each other and share the machine with whatever else is on it.
//   • these seven excluded        — 6 of 6 green, 45-90s down to ~10s
//   • these seven alone, parallel — 2 of 4 green (this set self-contends even with nothing else)
//   • these seven alone, serial   — 3 of 3 green, ~125s
//
// So the split is BOTH halves: the light suite stops carrying them, and they stop racing each
// other. As configured below: `pnpm verify` 25 of 25 green (15 on 849ef0d, then 10 more after
// rebasing onto de899d7), 12-62s each, zero unhandled errors, load average 23-25 throughout; the
// serialized heavy run 5 of 5 green, 106-175s. The slowest file left in the light suite is 2.8s.
//
// AND A THIRD THING, which only the CI runner exposed — this PR's first `heavy-cli` run failed with
// all 7 files and 83 tests PASSING and one RPC timeout. src/cli/run-audit.test.ts blocked a SINGLE
// uninterrupted window for 62s (a beforeAll doing two full ten-module orchestrator runs back to
// back) on hardware slower than this laptop. Serializing a set does not help a file that outlasts
// the window by itself; that beforeAll now awaits a spawned child instead of blocking on
// execFileSync. **The standing constraint for anything in this list: no single blocking window may
// approach 60s.** The remaining six block ~15s at most, which is why they were left synchronous.
//
// They are NOT dropped — .github/workflows/ci.yml runs them on every code PR in the `heavy-cli`
// job, serialized, with the mechanical binaries actually installed (which the `verify` job
// deliberately does not do, so the skipIf(MECHANICAL_BINARIES_PRESENT) blocks inside three of them
// had never executed in CI at all). That job is in the `verify` gate's needs, so this moves
// required coverage, it does not downgrade it.
//
// REASON: vitest exposes no configuration knob for the worker→main birpc ack window, so a blocking call that outlasts it cannot be waited out — only the load that makes calls that slow can be reduced.
// KIND: empirical
// PROVENANCE: MEASURED 2026-07-26 — vitest 3.2.6 ships `const DEFAULT_TIMEOUT = 6e4` in node_modules/vitest/dist/chunks/index.B521nVV-.js, and the option it would have to be exposed as is absent from the published config types (the same grep finds minForks/maxForks/singleFork, so the search was not the problem).
// FALSIFIER: test -d node_modules/vitest/dist/chunks || exit 127; grep -rq "DEFAULT_TIMEOUT = 6e4" node_modules/vitest/dist/chunks && exit 1 || exit 0
//
// REASON: `dangerouslyIgnoreUnhandledErrors` is not an acceptable fix for this flake even though it would silence it, because it is all-or-nothing and would equally swallow a genuine unhandled rejection thrown by code under test.
// KIND: decisional
// PROVENANCE: TRIED 2026-07-26 — read the branch that sets the exit code (node_modules/vitest/dist/chunks/cli-api.DWGBtMmz.js: `if (errors.length && !this.config.dangerouslyIgnoreUnhandledErrors) process.exitCode = 1`); it takes no predicate, so there is no way to ignore the RPC timeout alone. Not enabled.
// OWNER: Harvey doctrine
// DECISION: CLAUDE.md — "Fail loud": a suite that cannot report an unhandled rejection is a silent omission, which the doctrine ranks as worse than a wrong status.
// The list itself is imported at the top of this file from src/heavy-cli-tests.ts (#1228): the CI
// shard assignment is DERIVED from that one array rather than restated in ci.yml, because a second
// copy would let an eighth heavy file be added here and run in NO shard — passing CI by being
// invisible, which is the silent-omission shape CLAUDE.md ranks worse than a wrong status.

const heavyRun = process.env.HARVEY_HEAVY_CLI_TESTS === "1";

// Say what was left out, in the output, every run — an excluded file produces no row at all, and an
// absent row cannot be argued with (CLAUDE.md's coverage guard). #1105's opt-in block prints the
// same kind of line from inside the test file; these files are excluded before collection, so the
// disclosure has to come from here.
if (!heavyRun) {
  console.warn(
    `⚠ ${HEAVY_CLI_TESTS.length} heavy child-process test files EXCLUDED from this run (#1120): ${HEAVY_CLI_TESTS.join(", ")}\n` +
      `  They block a vitest worker for 6-70s each and starve its RPC channel when run alongside the rest of the suite.\n` +
      `  CI runs them on every code PR (.github/workflows/ci.yml, job \`heavy-cli\`). Locally: HARVEY_HEAVY_CLI_TESTS=1 pnpm exec vitest run`,
  );
}

// #1715 — ONE timeout for the whole suite, with the measurement beside it, instead of a literal
// bolted onto each file that happens to red under load. Before this, four files had picked up an
// ad-hoc `30_000` one incident at a time (#1646) while `src/fs-walk.test.ts` sat in the same class
// with nothing, and the number in vitest's default was never measured against this suite at all.
//
// THE POPULATION, MEASURED (not sampled) on this branch, `pnpm exec vitest run --reporter=json`,
// 5653 tests across 273 light-suite files. Max observed per-test wall time, by fraction of the
// 5000 ms default:
//
//   condition                         >=100%  70-99%  40-69%  20-39%   slowest test
//   near-idle (load avg 1.5-3.7, n=2)      0       2      16      24   4694 ms (94%)
//   contended (12 spinners, peak 30)       0       7      25      15   4640 ms (93%)
//
// The slowest single test on an idle machine is already at 94% of the default, and #1715's own
// capture at load average 81 shows the same files at ~2.2x their idle time (falsifier-exit-codes:
// 2602/2796 ms here, 5597/6091 ms there — the two runs that FAILED in isolation). 4694 ms x 2.2 is
// ~10.3 s, so 5 s is not a budget, it is a coin flip on machine load.
//
// `hookTimeout` moves with it and for the same reason, measured the same way: non-test time per
// file (collection + hooks, an UPPER BOUND on any single hook) peaks at 6443 ms idle and 10512 ms
// contended for src/cli/validate-reasons.test.ts — already past the 10000 ms hookTimeout default —
// with src/scan/rules/semgrep/shared-sources.test.ts at 2518/2950 ms against ~0 ms of test time,
// i.e. essentially one beforeAll.
//
// WHY 30 s and not more: #1120's standing constraint is that no single blocking window may approach
// vitest's hardcoded 60 s worker->main RPC ack. 30 s keeps a runaway test inside that window while
// giving 6.4x headroom over the idle maximum and ~2.9x over the load-81 projection. It costs
// nothing on a green run — a timeout only bounds a test that has already gone wrong.
//
// The uniformity is enforced, not just intended: src/vitest-timeout-budget.test.ts fails on a new
// per-test timeout literal in a light-suite file, and on a backlog row that no longer has one.
const TIMEOUT_MS = 30_000;

export default defineConfig({
  test: {
    testTimeout: TIMEOUT_MS,
    hookTimeout: TIMEOUT_MS,
    exclude: heavyRun ? BASE_EXCLUDE : [...BASE_EXCLUDE, ...HEAVY_CLI_TESTS],
    // One file at a time: measured above, this set flakes on its own RPC channel when its members
    // run concurrently, with nothing else on the machine.
    ...(heavyRun ? { include: HEAVY_CLI_TESTS, poolOptions: { forks: { maxForks: 1 } } } : {}),
  },
});
