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

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { parse } from "yaml";
import { readNamesSafe } from "./fs-walk.js";

const WORKFLOWS = join(process.cwd(), ".github", "workflows");

/** A real shell pipeline, as distinct from `case` alternation — see the header. `||` is not one. */
const PIPELINE = /(?<!\|)\s\|\s(?!\|)/;

interface PipedStep {
  workflow: string;
  job: string;
  step: string;
  line: string;
}

/**
 * Piped `run:` steps whose first stage's exit code is thrown away. Guarded means the script sets
 * `pipefail`, reads `PIPESTATUS`, or the step declares `shell: bash` (which Actions invokes with
 * `-eo pipefail`).
 */
function unguardedPipedSteps(workflows: { name: string; text: string }[]): PipedStep[] {
  return workflows.flatMap(({ name, text }) => {
    const doc = parse(text) as { jobs?: Record<string, { steps?: { name?: string; id?: string; shell?: string; run?: string }[] }> };
    return Object.entries(doc.jobs ?? {}).flatMap(([job, spec]) =>
      (spec.steps ?? []).flatMap((step) => {
        if (typeof step.run !== "string") return [];
        const guarded = /pipefail|PIPESTATUS/.test(step.run) || (step.shell ?? "").startsWith("bash");
        if (guarded) return [];
        return step.run
          .split("\n")
          .map((l) => l.trim())
          .filter((l) => l.length > 0 && !l.startsWith("#") && PIPELINE.test(l))
          .map((line) => ({ workflow: name, job, step: step.name ?? step.id ?? "(unnamed)", line }));
      }),
    );
  });
}

function realWorkflows(): { name: string; text: string }[] {
  return readNamesSafe(WORKFLOWS)
    .filter((f) => f.endsWith(".yml"))
    .map((name) => ({ name, text: readFileSync(join(WORKFLOWS, name), "utf8") }));
}

describe("a piped CI step keeps its first stage's exit code (#1422)", () => {
  it("no workflow step pipes a command without pipefail or PIPESTATUS", () => {
    expect(unguardedPipedSteps(realWorkflows()).map((s) => `${s.workflow} / ${s.job} / ${s.step}: ${s.line}`)).toEqual([]);
  });

  // A rule with a population of zero is a guess, not a rule (#1345). If every pipeline were deleted
  // from the workflows the assertion above would pass while proving nothing, so the population is
  // asserted too: this repo really does pipe gate output into `tee`, and those steps really are
  // guarded rather than absent.
  it("the rule has a live population — piped steps exist and are guarded", () => {
    const piped = realWorkflows().filter(({ text }) => /pipefail|PIPESTATUS/.test(text));
    expect(piped.map((w) => w.name)).toContain("reasons-drift.yml");
    expect(piped.length).toBeGreaterThan(3);
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
