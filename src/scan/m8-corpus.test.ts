// #1693: this file did not exist. `extraFiles` (#1496) — the mechanism that gives
// multi-tenant-starter a mutation surface at all — shipped with ZERO automated coverage: its write
// loop sat inline in src/cli/corpus-drift.ts's runMutationScan, deleting it turned nothing red in
// `pnpm verify`, and the only thing that would ever have noticed was a monthly job that did not
// score this target either. Both halves are closed here — the write, and the cadence that
// re-measures what it produces.
import { existsSync, mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { EXTERNAL_CORPUS } from "./external-corpus.js";
import { M8_CORPUS_CONFIGS, materializeM8Config, type M8CorpusConfig } from "./m8-corpus.js";
import { buildM8CorpusPlan } from "./m8-corpus-artifacts.js";

const scratch = (): string => mkdtempSync(join(tmpdir(), "harvey-m8-corpus-test-"));

function pullRequestPaths(workflow: string): string[] {
  const block = workflow.match(/pull_request:\n\s+paths:\n((?:\s+- [^\n]+\n)+)/)?.[1] ?? "";
  return [...block.matchAll(/- "([^"]+)"/g)].map((match) => match[1]!);
}

describe("materializeM8Config (#1496/#1693)", () => {
  it("writes every extraFiles entry into the clone, creating the directories it needs", () => {
    const dir = scratch();
    const cfg: M8CorpusConfig = {
      installFlags: [],
      strykerPackages: [],
      config: { testRunner: "vitest" },
      extraFiles: { "vitest.config.ts": "// root-level\n", "test/nested/suite.vitest.test.ts": "// one directory deeper\n" },
    };

    materializeM8Config(dir, cfg);

    expect(readFileSync(join(dir, "vitest.config.ts"), "utf8")).toBe("// root-level\n");
    // The nested key is the load-bearing half: mkdirSync(recursive) is what lets a vendored suite
    // live under test/ in a clone that has no test/ directory of its own.
    expect(readFileSync(join(dir, "test/nested/suite.vitest.test.ts"), "utf8")).toBe("// one directory deeper\n");
  });

  it("writes the Stryker config Stryker actually reads back, as JSON", () => {
    const dir = scratch();
    materializeM8Config(dir, { installFlags: [], strykerPackages: [], config: { testRunner: "vitest", mutate: ["lib/x.ts"] } });
    // JSON, not .mjs, because mutation-scan's warnIfNotPerTest parses this file (M8CorpusConfig's
    // own note) — a shape change here breaks that reader silently.
    expect(JSON.parse(readFileSync(join(dir, "stryker.conf.json"), "utf8"))).toEqual({ testRunner: "vitest", mutate: ["lib/x.ts"] });
  });

  it("leaves a clone untouched but for the config when the target vendors no extra files", () => {
    // The other four scored targets take this path — the loop must be inert for them, not merely
    // harmless-looking.
    const dir = scratch();
    materializeM8Config(dir, { installFlags: [], strykerPackages: [], config: {} });
    expect(existsSync(join(dir, "stryker.conf.json"))).toBe(true);
    expect(existsSync(join(dir, "vitest.config.ts"))).toBe(false);
  });

  it("materializes multi-tenant-starter's real vendored suite — the only entry that uses the field", () => {
    const withExtras = Object.entries(M8_CORPUS_CONFIGS).filter(([, c]) => c.extraFiles !== undefined);
    expect(withExtras.map(([slug]) => slug)).toEqual(["multi-tenant-starter"]);

    const dir = scratch();
    materializeM8Config(dir, withExtras[0]![1]);
    // Stryker's dry run finds the suite through the vendored vitest config, and the mutants it
    // scores come from `mutate`. If either file stops landing, the run scores something other than
    // this target's guards.ts and the monthly job's baseline check is what says so.
    expect(existsSync(join(dir, "vitest.config.ts"))).toBe(true);
    expect(existsSync(join(dir, "test/security-guards.vitest.test.ts"))).toBe(true);
    expect(JSON.parse(readFileSync(join(dir, "stryker.conf.json"), "utf8")).mutate).toEqual(["lib/security/guards.ts"]);
  });

  it("is what src/cli/corpus-drift.ts's mutation run actually calls", () => {
    // A SOURCE assertion, and it is worth saying what that does and does not prove: corpus-drift.ts
    // reads process.argv and runs its whole corpus sweep at module load, so importing it here would
    // execute the sweep rather than let a test watch the call happen. This catches the one-line
    // reversion (dropping the call site while the function and its tests survive), nothing subtler.
    const src = readFileSync(new URL("../cli/corpus-drift.ts", import.meta.url), "utf8");
    expect(src).toContain("materializeM8Config(appDir, cfg)");
  });
});

// #1692/#1693: the cadence half. multi-tenant-starter gained a real MutationBaseline in #1496 and
// the monthly job kept scoring the four targets it scored before — so the new 95.7% was a one-time
// hand measurement that nothing re-checked, which is the same silent shape as having no baseline.
// Nothing structural stops that recurring for the next target, so this is the gate that does.
describe("corpus-m8.yml scores every target that has an M8 config (#1692)", () => {
  const workflow = readFileSync(new URL("../../.github/workflows/corpus-m8.yml", import.meta.url), "utf8");

  it("runs when either production half of the sharded runner changes (#1877 acceptance)", () => {
    expect(pullRequestPaths(workflow)).toEqual(expect.arrayContaining([
      "src/cli/corpus-m8.ts",
      "src/scan/m8-corpus-artifacts.ts",
    ]));

    // Negative control: a step mentions the CLI outside the extracted pull_request.paths block.
    const mentionOnly = 'pull_request:\n  paths:\n    - "docs/**"\njobs:\n  run:\n    steps:\n      - run: pnpm exec tsx src/cli/corpus-m8.ts plan\n';
    expect(pullRequestPaths(mentionOnly)).not.toContain("src/cli/corpus-m8.ts");
  });

  it("derives one target matrix from M8_CORPUS_CONFIGS and consumes each matrix target once", () => {
    expect(workflow.match(/corpus-m8\.ts plan/g)).toHaveLength(1);
    expect(workflow.match(/matrix: \$\{\{ fromJSON\(needs\.plan\.outputs\.matrix\) \}\}/g)).toHaveLength(1);
    expect(workflow.match(/corpus-m8\.ts target --target "\$\{\{ matrix\.target \}\}"/g)).toHaveLength(1);
    expect(buildM8CorpusPlan(EXTERNAL_CORPUS, M8_CORPUS_CONFIGS).configured).toEqual(Object.keys(M8_CORPUS_CONFIGS).sort());
  });

  it("and those configs are exactly the manifest entries corpus-drift will accept for --m8", () => {
    // corpus-drift's --m8 branch scores `target.m8` and fails loudly on a target without one, so a
    // config nobody attached (or an attachment with no config) would make the job fail rather than
    // silently under-score — but it would fail on the FIRST of the month, in a job nobody watches.
    expect(EXTERNAL_CORPUS.filter((t) => t.m8).map((t) => t.slug).sort()).toEqual(Object.keys(M8_CORPUS_CONFIGS).sort());
  });

  it("keeps mutation real, aggregates every shard, and bounds each target below the old 45-minute timeout", () => {
    const targetRunner = readFileSync(new URL("../cli/corpus-m8.ts", import.meta.url), "utf8");
    expect(workflow).toContain("fail-fast: false");
    expect(workflow).toContain("needs: [plan, mutation]");
    expect(workflow).toContain("aggregate --artifacts corpus-m8-artifacts");
    expect(workflow).not.toContain("mode: save");
    const targetJob = workflow.slice(workflow.indexOf("  mutation:"), workflow.indexOf("  aggregate:"));
    expect(targetJob).toContain("timeout-minutes: 20");
    expect(targetRunner).toContain('"--install", "--m8"');
    expect(targetRunner).not.toContain('"--report"');
  });
});
