// #1288: every SCORED gate must run on a cadence, and the cadence must be checkable.
//
// "Measure, don't recall" is this repo's loudest doctrine, and until #1301 the tools that produce
// the numbers ran only when a human remembered. #1301 put `validate-calibration` inside heavy-cli;
// the other four scored gates still ran nowhere, and four of the five had no package.json script,
// so they were not discoverable at all. A recall regression was invisible until someone happened to
// run the tool by hand.
//
// Wiring them up is a one-time fix that decays. This module is the part that does not: it derives
// the set of scored gates from the filesystem, and asserts for each one that the venue it CLAIMS to
// run in actually invokes it. Delete the calibration step from ci.yml and `pnpm verify` goes red, so
// a cadence removed later fails loud instead of going unremarked the way its absence did.
//
// DISCOVERY-BACKED, not merely enumerated (the #1330 shape): every `src/cli/validate-*.ts` must be
// classified — as a SCORED gate with a cadence, or in NOT_SCORED with the reason it produces no
// score. A new validate-* CLI fails loud rather than joining the repo unexamined. Both directions
// are checked, so a stale registry row fails too.
//
// SCOPE OF THIS GATE, stated so its own silence is not read as coverage. It checks that the venue
// INVOKES the gate — the workflow text names the CLI, or the `verify` chain runs its script. It does
// not check that the invocation is reached: a step behind a false `if:`, or a job whose `needs`
// never resolves, still satisfies it. What it removes is the state #1288 found — a gate wired to
// nothing at all — not every way a wired gate can fail to run.
//
// validate-secbench's "no cadence" reason block used to live here. It was RETIRED on 2026-07-28,
// not edited: the operator authorised the monthly workflow, secbench.yml landed, and the reason's
// own falsifier (`grep -rq 'validate-secbench' .github/workflows/`) now exits 0 — which is the
// registry's definition of STALE. A reason kept past the day its blocker dissolved is the decay this
// repo names as its signature defect, so the row is gone rather than reworded.
//
// validate-connected has no cadence for a DIFFERENT reason, and it is not an empirical one: the gate
// runs fine (measured 2026-07-28 against a live `supabase start` stack — 16 of 20 live rows scored,
// all held, and each of its three B24 detectors gutted in turn exits it 1). What is missing is a CI
// venue, and adding one means editing .github/workflows/, which CLAUDE.md lists as supervised. The
// operator question, with the wording proposed, is recorded on #1491 — a supervised path stops the
// EDIT, never the CRITERION (#1319).
//
// REASON: validate-connected has no CI cadence because standing a Supabase stack up in a workflow is a change to .github/workflows/, which is a supervised path, and no command re-tests whether the operator has approved it
// KIND: decisional
// PROVENANCE: MEASURED 2026-07-28 — the gate itself runs and fails correctly against a live stack; the missing piece is only the venue. `grep -rl "supabase start" .github/workflows/` returns nothing today.
// OWNER: operator (jharvieux)
// DECISION: #1491 — carries the proposed workflow step verbatim for the operator to approve or decline
// TOUCHES: src/cli/validate-connected.ts .github/workflows

// REASON: validate-semantic scores the paid LLM pass against recorded M1.pass.json artifacts, so no cadence can produce its input — the pass itself is an interactive skill run, and the gate exits 1 when nothing is scored
// KIND: empirical
// PROVENANCE: MEASURED 2026-07-28 — `pnpm exec tsx src/cli/validate-semantic.ts --artifacts-dir <empty>` exits 1 with every corpus target NOT SCORED; no M1.pass.json is committed anywhere in this repo. The staleness-alarm half is tracked by #1270.
// FALSIFIER: test -d .github/workflows || exit 127; grep -rq 'validate-semantic' .github/workflows/ && exit 0 || exit 1
// TOUCHES: src/cli/validate-semantic.ts .github/workflows

import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { readNamesSafe } from "./fs-walk.js";

/** Where a gate runs, and the evidence that proves it still does. */
export type Cadence =
  /** Rides inside the required `verify` context and every local `pnpm verify`. */
  | { readonly kind: "verify" }
  /**
   * A named workflow invokes the CLI. Checked against that file's text. `when` is written out
   * rather than assumed: the first three rows all ran on "every PR + daily schedule" and
   * describeCadence hardcoded that phrase, so the monthly SecBench row would have been reported as
   * running daily on every PR — a wrong cadence printed by the gate whose whole job is cadences.
   */
  | { readonly kind: "workflow"; readonly file: string; readonly job: string; readonly when: string }
  /** No cadence. Carries the issue tracking it; the reason lives in this file's header. */
  | { readonly kind: "none"; readonly issue: number };

export interface ScoredGate {
  /** CLI basename without extension — also the discovery key. */
  readonly id: string;
  /** package.json script that runs it, so it is discoverable at all (#1288). */
  readonly script: string;
  /** The number it produces, in the words a reader of a report would use. */
  readonly measures: string;
  readonly cadence: Cadence;
}

export const SCORED_GATES: readonly ScoredGate[] = [
  {
    id: "validate-calibration",
    script: "validate:calibration",
    measures: "M1 mechanical recall/FP against the corpus answer key",
    cadence: { kind: "workflow", file: ".github/workflows/ci.yml", job: "heavy-cli shard 1", when: "every PR + daily schedule" },
  },
  {
    id: "validate-precision",
    script: "validate:precision",
    measures: "M1 tenant-scope / M7 / M8 heuristic corpus precision and recall",
    // Pure TS, no binaries, no network: measured 0.79s on 2026-07-28, so it belongs in the gate
    // that runs on every PR and before every push rather than in the daily heavy job.
    cadence: { kind: "verify" },
  },
  {
    id: "validate-source-recall",
    script: "validate:source-recall",
    measures: "app-layer request→sink source-detector recall (free tier)",
    // Runs the real mechanical scan, so it needs the binaries only heavy-cli installs. Shard 2:
    // shard 1 already carries the calibration gate.
    cadence: { kind: "workflow", file: ".github/workflows/ci.yml", job: "heavy-cli shard 2", when: "every PR + daily schedule" },
  },
  {
    id: "validate-secbench",
    script: "validate:secbench",
    measures: "SecBench.js SCA + library-internal recall over ~600 real npm CVEs",
    // Monthly, and in a workflow of its own, because a scored run has to BUILD its own input: a
    // pinned clone, then one generated package-lock per entry before osv-scanner has anything to
    // read (#879). Measured 2026-07-28 on this machine: clone 3s, 594/600 lockfiles in 39s at
    // concurrency 12, osv 3.4s, score 5.5s. Cheap enough to run, too external to run per-PR — what
    // moves it is OSV's advisory database, which no diff in this repo touches.
    cadence: { kind: "workflow", file: ".github/workflows/secbench.yml", job: "secbench-recall", when: "monthly (1st, 05:00 UTC) + workflow_dispatch" },
  },
  {
    id: "validate-free-recall",
    script: "validate:free-recall",
    measures: "FREE (mechanical, source-only) recall against the five INDEPENDENT answer keys",
    // Monthly, for secbench.yml's reason inverted: its inputs are five third-party repos that
    // change rarely, and what DOES move the number is a Harvey detector — which the PR trigger on
    // the harness covers. MEASURED 2026-07-30 on the authoring machine: five clones in 12s, then
    // 60s to run quick-scan + detect-static over all five and score them. It is the only gate whose
    // answer keys were written by people outside this repo, so a miss here is evidence in a way a
    // miss on our own fixtures is not.
    cadence: { kind: "workflow", file: ".github/workflows/free-recall.yml", job: "free-recall", when: "monthly (2nd, 05:00 UTC) + workflow_dispatch" },
  },
  {
    id: "validate-connected",
    script: "validate:connected",
    measures: "live-tier corpus recall against a running Supabase stack (local / connected / hosted venues)",
    cadence: { kind: "none", issue: 1491 },
  },
  {
    id: "validate-semantic",
    script: "validate:semantic",
    measures: "M1 semantic (paid LLM) recall against the recorded-pass answer key",
    cadence: { kind: "none", issue: 1270 },
  },
];

/**
 * The other `src/cli/validate-*.ts` CLIs, each with the reason it produces no score. Present so
 * discovery is exhaustive: a new validate-* CLI must land in one list or the other.
 */
export const NOT_SCORED: readonly { readonly id: string; readonly why: string }[] = [
  { id: "validate-acceptance", why: "structural — checks a PR against the acceptance criteria of the issues it closes" },
  { id: "validate-alert-paths", why: "structural — checks every CI alert path is dispatch-provable and proven" },
  { id: "validate-conditional-scan", why: "structural — checks a scan path discloses the checks its sibling runs" },
  { id: "validate-conservation", why: "plant-and-assert — a planted finding per module, pass/fail, not a score" },
  { id: "validate-disclosure-venue", why: "structural — checks a rule's recorded bound reaches its own message" },
  { id: "validate-findings", why: "schema validation of a findings file" },
  { id: "validate-fs-walk", why: "structural — bans raw statSync/readdirSync outside src/fs-walk.ts; a violation count, not a recall number" },
  { id: "validate-reasons", why: "structural — checks recorded reasons are well-formed and re-tests their falsifiers" },
  { id: "validate-render-fidelity", why: "structural — checks a finding's own words survive the render seam into report.html (#1435); the standing gate is src/render-fidelity.test.ts inside `pnpm verify`, this CLI points the same check at a real engagement deliverable" },
  { id: "validate-scored-gates", why: "this gate — checks the scored gates above still have a cadence" },
  { id: "validate-test-only-exports", why: "ratchet over exports whose only consumer is their own test" },
];

/** Discovered `validate-*` CLI ids, excluding test files. */
export function discoverValidateClis(cliDir: string): string[] {
  return readNamesSafe(cliDir)
    .filter((f) => f.startsWith("validate-") && f.endsWith(".ts") && !f.endsWith(".test.ts"))
    .map((f) => f.slice(0, -".ts".length))
    .sort();
}

export interface GateInputs {
  /** Discovered ids from discoverValidateClis. */
  readonly discovered: readonly string[];
  /** package.json `scripts`. */
  readonly scripts: Readonly<Record<string, string>>;
  /** Workflow path → file text, for every `.github/workflows/*.yml`. */
  readonly workflows: Readonly<Record<string, string>>;
}

export function checkScoredGates(
  inputs: GateInputs,
  gates: readonly ScoredGate[] = SCORED_GATES,
  notScored: readonly { id: string; why: string }[] = NOT_SCORED,
): string[] {
  const violations: string[] = [];
  const classified = new Set([...gates.map((g) => g.id), ...notScored.map((n) => n.id)]);

  for (const id of inputs.discovered) {
    if (!classified.has(id)) {
      violations.push(
        `${id}: src/cli/${id}.ts is not classified. Add it to SCORED_GATES with a cadence, or to NOT_SCORED with the reason it produces no score — a scored gate that runs nowhere is what #1288 found five of.`,
      );
    }
  }
  const found = new Set(inputs.discovered);
  for (const id of classified) {
    if (!found.has(id)) violations.push(`${id}: registered in src/scored-gates.ts but src/cli/${id}.ts does not exist — stale row.`);
  }

  for (const gate of gates) {
    const cmd = inputs.scripts[gate.script];
    if (cmd === undefined) {
      violations.push(`${gate.id}: no package.json script "${gate.script}" — four of the five scored gates had none, which is why nobody could find them (#1288).`);
    } else if (!cmd.includes(`src/cli/${gate.id}.ts`)) {
      violations.push(`${gate.id}: package.json script "${gate.script}" runs \`${cmd}\`, which does not invoke src/cli/${gate.id}.ts.`);
    }

    if (gate.cadence.kind === "verify") {
      const verify = inputs.scripts["verify"] ?? "";
      if (!verify.split("&&").some((part) => part.trim().endsWith(gate.script))) {
        violations.push(`${gate.id}: declares the \`verify\` cadence but the verify script (\`${verify}\`) does not run \`pnpm ${gate.script}\`.`);
      }
    } else if (gate.cadence.kind === "workflow") {
      const text = inputs.workflows[gate.cadence.file];
      if (text === undefined) {
        violations.push(`${gate.id}: declares cadence in ${gate.cadence.file}, which does not exist.`);
      } else if (!text.includes(`src/cli/${gate.id}.ts`)) {
        violations.push(
          `${gate.id}: declares cadence in ${gate.cadence.file} (${gate.cadence.job}) but that workflow never invokes src/cli/${gate.id}.ts — the cadence was removed, or never landed.`,
        );
      }
    } else if (!(gate.cadence.issue > 0)) {
      violations.push(`${gate.id}: has no cadence and names no tracking issue. An undisclosed gap never appears in a tally.`);
    }
  }

  return violations;
}

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

// #1483 — lives here rather than in validate-scored-gates.ts, where it used to. That CLI runs its
// gate and can `process.exit(1)` at module load, so importing it to reach this loader made one
// gate able to abort another; src/scan/calibration.ts now needs the same venues.
export function loadGateInputs(root = REPO_ROOT): GateInputs {
  const workflowDir = join(root, ".github", "workflows");
  const workflows: Record<string, string> = {};
  for (const f of readNamesSafe(workflowDir).filter((f) => f.endsWith(".yml"))) {
    workflows[`.github/workflows/${f}`] = readFileSync(join(workflowDir, f), "utf8");
  }
  const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8")) as { scripts?: Record<string, string> };
  return {
    discovered: discoverValidateClis(join(root, "src", "cli")),
    scripts: pkg.scripts ?? {},
    workflows,
  };
}

export function describeCadence(cadence: Cadence): string {
  switch (cadence.kind) {
    case "verify":
      return "pnpm verify (required context, every PR + every local push)";
    case "workflow":
      return `${cadence.file} — ${cadence.job} (${cadence.when})`;
    case "none":
      return `NO CADENCE — runs only by hand, tracked by #${cadence.issue}`;
  }
}
