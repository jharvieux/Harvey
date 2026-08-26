// #1422 — A GATE STEP THAT PIPES THROWS ITS GATE'S EXIT CODE AWAY, and nothing in this repo said so
// until a green `reasons-drift` run was found printing three `✗ STALE` rows.
//
// A GitHub Actions `run:` with no `shell:` key is invoked as `bash -e {0}` — the run log prints
// exactly that. It is NOT `bash -eo pipefail {0}`, which is what an explicit `shell: bash` gets. So
// `cmd | tee log` exits with `tee`'s status and the step is green whatever `cmd` said. MEASURED on
// scheduled run 30534660455 (2026-07-30): the `reasons-drift` check step printed
// `✗ STALE src/alert-paths.ts:50`, `✗ STALE docs/design/acceptance-conservation.md:255` and
// `✗ STALE docs/design/m6-simplification-eval.md:79`, exited 0, and the job was green. Every
// scheduled run since 2026-07-28 was green the same way — a gate against decayed claims that had
// itself decayed into a check with no failing direction.
//
// This is the #1426 defect one level up: there, a falsifier's own pipeline lost the first stage's
// exit code; here, the JOB STEP loses the gate's. Same swallow, same silence.
//
// The pipeline discriminator is a SPACED `|`, which is not cosmetic. `case` alternation
// (`docs/*|src/*) relevant=true ;;`) is unspaced everywhere in this repo and is not a pipeline at
// all; measured over .github/workflows on 2026-07-31, the unspaced form matched 6 steps and every
// one was a `case` pattern, while the spaced form matched 14 and every one was a real pipeline. A
// rule that fires on the wrong 6 gets exempted into uselessness, so it reads the form the repo
// actually writes pipelines in.
//
// No exemption list, on the claim ratchet's precedent: `echo … | sha256sum -c -` keeps its exit code
// either way (its first stage is `echo`) and it still got `set -euo pipefail`, because a suppression
// entry is indistinguishable from the silence this exists to remove.
//
// THREE BOUNDS THIS FILE ORIGINALLY CLAIMED PAST, closed 2026-07-31 by an acceptance verifier before
// merge — the same "a bound stated more broadly than what is measured" defect the PR was fixing:
//   • it read only `.github/workflows/*.yml`, never `.github/actions/*/action.yml`, where two real
//     pipelines live;
//   • the pipeline discriminator needs whitespace BEFORE the `|`, so a LINE-CONTINUATION pipeline
//     (`curl … \` / newline / `| tar -xz …`) was invisible once each line was trimmed on its own —
//     which is the exact shape both of those two are written in;
//   • `guarded` was true if `pipefail|PIPESTATUS` appeared ANYWHERE in a multi-command `run:`, so one
//     guarded pipe excused every unguarded sibling in the same step.
// All three are now measured: continuations are joined before matching, both file shapes are read,
// and guarding is tracked as SHELL STATE — `set -o pipefail` covers the commands after it (it is a
// shell option, not a per-command flag), while `PIPESTATUS` only covers its own pipeline and the
// line that reads it. Widening found no live damage: `.github/actions/mechanical-binaries/action.yml`
// already carries `set -euo pipefail` above both pipelines.
//
// The model is line-level, not a shell parser, and it errs toward OVER-reporting so the bound it
// leaves never hides a swallowed exit code: a `|` inside a quoted string or a heredoc reads as a
// pipeline (MEASURED 2026-07-31 — a scratch copy of mechanical-binaries with its guards stripped
// flagged `echo "… $(semgrep --version) | osv-scanner …"` alongside its two real pipelines, and that
// copy is how the widened reach was exercised red-then-green before merge), and `set -o pipefail`
// is tracked as one flat flag rather than per-subshell scope, so a `set`
// inside a `( … )` is credited to the rest of the script. Both directions are visible as a failing
// assertion naming the line, never as silence.

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { parse } from "yaml";
import { readNamesSafe } from "./fs-walk.js";

const GITHUB = join(process.cwd(), ".github");

/** A real shell pipeline, as distinct from `case` alternation — see the header. `||` is not one. */
const PIPELINE = /(?<!\|)\s\|\s(?!\|)/;
/** `set -o pipefail` in any of its spellings. A shell OPTION: it holds for every later command. */
const SETS_PIPEFAIL = /\bset\s+-[^\s;]*\s*(?:-o\s+)?pipefail\b|\bset\s+-o\s+pipefail\b/;

interface PipedStep {
  workflow: string;
  job: string;
  step: string;
  line: string;
}

interface Step {
  name?: string;
  id?: string;
  shell?: string;
  run?: string;
}

/** Backslash-continued lines are ONE command; scoring them apart hides the pipe between them. */
function shellLines(run: string): string[] {
  const joined: string[] = [];
  for (const raw of run.split("\n")) {
    const line = raw.trim();
    const previous = joined.pop();
    if (previous === undefined) joined.push(line);
    else if (previous.endsWith("\\")) joined.push(`${previous.slice(0, -1).trimEnd()} ${line}`);
    else joined.push(previous, line);
  }
  return joined.map((l) => l.trim()).filter((l) => l.length > 0 && !l.startsWith("#"));
}

/** Pipelines in one `run:` whose first stage's exit code is thrown away, scored command by command. */
function unguardedLines(step: Step): string[] {
  // Actions invokes an explicit `shell: bash` as `bash --noprofile --norc -eo pipefail {0}`, so the
  // whole script is covered. A `run:` with no `shell:` key gets `bash -e {0}` and is not.
  if ((step.shell ?? "").startsWith("bash")) return [];
  const lines = shellLines(step.run ?? "");
  const unguarded: string[] = [];
  let pipefail = false;
  lines.forEach((line, i) => {
    if (PIPELINE.test(line)) {
      const readsStatus = /PIPESTATUS/.test(line) || /PIPESTATUS/.test(lines[i + 1] ?? "");
      if (!pipefail && !SETS_PIPEFAIL.test(line) && !readsStatus) unguarded.push(line);
    }
    if (SETS_PIPEFAIL.test(line)) pipefail = true;
  });
  return unguarded;
}

/** Steps of a workflow (`jobs.<id>.steps`) and of a composite action (`runs.steps`) alike. */
function stepGroups(text: string): { group: string; steps: Step[] }[] {
  const doc = parse(text) as {
    jobs?: Record<string, { steps?: Step[] }>;
    runs?: { using?: string; steps?: Step[] };
  };
  const groups = Object.entries(doc?.jobs ?? {}).map(([job, spec]) => ({ group: job, steps: spec?.steps ?? [] }));
  if (doc?.runs?.steps) groups.push({ group: `runs.${doc.runs.using ?? "composite"}`, steps: doc.runs.steps });
  return groups;
}

function unguardedPipedSteps(files: { name: string; text: string }[]): PipedStep[] {
  return files.flatMap(({ name, text }) =>
    stepGroups(text).flatMap(({ group, steps }) =>
      steps.flatMap((step) =>
        typeof step.run !== "string"
          ? []
          : unguardedLines(step).map((line) => ({ workflow: name, job: group, step: step.name ?? step.id ?? "(unnamed)", line })),
      ),
    ),
  );
}

/** Every YAML this repo ships that Actions will execute `run:` blocks from. */
function realWorkflows(): { name: string; text: string }[] {
  const workflows = readNamesSafe(join(GITHUB, "workflows"))
    .filter((f) => f.endsWith(".yml") || f.endsWith(".yaml"))
    .map((name) => ({ name: `workflows/${name}`, text: readFileSync(join(GITHUB, "workflows", name), "utf8") }));
  const actions = readNamesSafe(join(GITHUB, "actions")).flatMap((dir) =>
    readNamesSafe(join(GITHUB, "actions", dir))
      .filter((f) => f === "action.yml" || f === "action.yaml")
      .map((f) => ({ name: `actions/${dir}/${f}`, text: readFileSync(join(GITHUB, "actions", dir, f), "utf8") })),
  );
  return [...workflows, ...actions];
}

describe("a piped CI step keeps its first stage's exit code (#1422)", () => {
  it("keeps the reasons-drift unusable-token control tied to its fail-loud semantic, not a gh subcommand", () => {
    const workflow = realWorkflows().find((file) => file.name === "workflows/reasons-drift.yml");
    const control = stepGroups(workflow?.text ?? "")
      .flatMap(({ steps }) => steps)
      .find((step) => step.name === "Negative control — an --issues fetch with no usable credential must FAIL, not report zero");
    expect(control?.run).toContain("pnpm validate-reasons --issues 2>&1");
    expect(control?.run).toContain("Reporting zero issue-recorded claims here would be the silent pass this gate exists to prevent.");
    expect(control?.run).not.toContain("grep -qF 'gh issue list'");
  });

  it("no workflow or composite-action step pipes a command without pipefail or PIPESTATUS", () => {
    expect(unguardedPipedSteps(realWorkflows()).map((s) => `${s.workflow} / ${s.job} / ${s.step}: ${s.line}`)).toEqual([]);
  });

  // A rule with a population of zero is a guess, not a rule (#1345). If every pipeline were deleted
  // from the workflows the assertion above would pass while proving nothing, so the population is
  // asserted too: this repo really does pipe gate output into `tee`, and those steps really are
  // guarded rather than absent.
  it("the rule has a live population — piped steps exist and are guarded", () => {
    const piped = realWorkflows().filter(({ text }) => /pipefail|PIPESTATUS/.test(text));
    expect(piped.map((w) => w.name)).toContain("workflows/reasons-drift.yml");
    expect(piped.length).toBeGreaterThan(3);
  });

  // The reach the header claims, asserted rather than described: composite actions are read, and the
  // pipelines found there are the line-continuation shape the old trim-then-match could not see.
  it("reads composite actions, and sees their line-continuation pipelines", () => {
    const names = realWorkflows().map((f) => f.name);
    expect(names).toContain("actions/mechanical-binaries/action.yml");

    const action = realWorkflows().find((f) => f.name === "actions/mechanical-binaries/action.yml");
    const continued = stepGroups(action?.text ?? "")
      .flatMap(({ steps }) => steps)
      .flatMap((step) => shellLines(step.run ?? ""))
      .filter((l) => PIPELINE.test(l));
    expect(continued.some((l) => l.startsWith("curl ") && l.includes("| tar -xz"))).toBe(true);
    expect(continued.some((l) => l.startsWith("curl ") && l.includes("| sh -s"))).toBe(true);
  });

  it("fires on an unguarded pipeline inside a composite action", () => {
    const composite = {
      name: "actions/probe/action.yml",
      text: "runs:\n  using: composite\n  steps:\n    - name: fetch\n      shell: sh\n      run: curl -sSfL https://example.test/x.tgz | tar -xz\n",
    };
    expect(unguardedPipedSteps([composite])).toEqual([
      { workflow: "actions/probe/action.yml", job: "runs.composite", step: "fetch", line: "curl -sSfL https://example.test/x.tgz | tar -xz" },
    ]);
  });

  it("sees a pipeline split across a line continuation", () => {
    const continued = {
      name: "probe.yml",
      text: 'jobs:\n  g:\n    steps:\n      - name: fetch\n        run: |\n          curl -sSfL https://example.test/x.tgz \\\n            | tar -xz -C "$HOME/bin"\n',
    };
    expect(unguardedPipedSteps([continued]).map((s) => s.line)).toEqual([
      'curl -sSfL https://example.test/x.tgz | tar -xz -C "$HOME/bin"',
    ]);
  });

  // `PIPESTATUS` guards one pipeline; `set -o pipefail` is a shell option and guards what follows it.
  // Scoring the whole `run:` as one unit conflated the two and let a guarded pipe excuse its siblings.
  it("a guarded pipe does not excuse an unguarded sibling in the same step", () => {
    const siblings = {
      name: "probe.yml",
      text: 'jobs:\n  g:\n    steps:\n      - name: gate\n        run: |\n          pnpm a 2>&1 | tee a.log\n          exit "${PIPESTATUS[0]}"\n          pnpm b 2>&1 | tee b.log\n',
    };
    expect(unguardedPipedSteps([siblings]).map((s) => s.line)).toEqual(["pnpm b 2>&1 | tee b.log"]);

    const optionSet = {
      name: "probe.yml",
      text: "jobs:\n  g:\n    steps:\n      - name: gate\n        run: |\n          set -euo pipefail\n          pnpm a 2>&1 | tee a.log\n          pnpm b 2>&1 | tee b.log\n",
    };
    expect(unguardedPipedSteps([optionSet])).toEqual([]);

    // …and only for what FOLLOWS it: a pipe above the `set` is still unguarded when it runs.
    const setTooLate = {
      name: "probe.yml",
      text: "jobs:\n  g:\n    steps:\n      - name: gate\n        run: |\n          pnpm a 2>&1 | tee a.log\n          set -euo pipefail\n          pnpm b 2>&1 | tee b.log\n",
    };
    expect(unguardedPipedSteps([setTooLate]).map((s) => s.line)).toEqual(["pnpm a 2>&1 | tee a.log"]);
  });

  it("fires on the exact step shape that shipped, and stops firing once it is guarded", () => {
    const broken = { name: "probe.yml", text: "jobs:\n  g:\n    steps:\n      - name: gate\n        run: pnpm validate-reasons --revalidate 2>&1 | tee out.log\n" };
    expect(unguardedPipedSteps([broken])).toEqual([
      { workflow: "probe.yml", job: "g", step: "gate", line: "pnpm validate-reasons --revalidate 2>&1 | tee out.log" },
    ]);

    const fixed = { name: "probe.yml", text: `${broken.text.trimEnd().replace("run: ", "run: |\n          ")}\n          exit "\${PIPESTATUS[0]}"\n` };
    expect(unguardedPipedSteps([fixed])).toEqual([]);
  });

  it("does not fire on `case` alternation, which is not a pipeline", () => {
    const caseStep = { name: "probe.yml", text: "jobs:\n  g:\n    steps:\n      - name: filter\n        run: |\n          case \"$f\" in\n            docs/*|src/*) relevant=true ;;\n          esac\n" };
    expect(unguardedPipedSteps([caseStep])).toEqual([]);
  });
});
