// #300: the per-target Stryker setup the M8 corpus job (.github/workflows/corpus-m8.yml) needs to
// score the corpus targets that have a real test suite.
//
// WHY THIS IS VENDORED PER TARGET AND NOT GENERATED. src/cli/mutation-scan.ts deliberately does not
// synthesize a Stryker config ("test-runner choice is too client-specific for a generic wrapper"),
// and the corpus proves it right: proposit runs vitest, boxyhq runs jest-via-next/jest. Each also
// needs its own runner plugin package and its own peer-conflict flag. There is no shape a generic
// wrapper could infer here — so the config is data, measured per target, next to the baselines it
// produces.
//
// WHY `mutate` IS SCOPED RATHER THAN WHOLE-REPO. Stryker mutates whatever `mutate` names and then
// runs the suite once per mutant. Pointed at a whole repo, that is thousands of mutants against
// files no test ever touches — hours of CI to measure NoCoverage, which the source-tier modules
// already tell us. Scoping to the files the suite actually covers makes the score mean "how good
// is this suite at what it claims to test", which is M8's question. The cost of the choice is that
// the score is not a whole-repo coverage claim, and the notes below say so.

export interface M8CorpusConfig {
  // Extra packages the target needs before Stryker can run: its own runner plugin, and anything
  // its install refuses without. Installed with --no-save so the target's tree is untouched.
  strykerPackages: string[];
  // npm install flags the target's own dep graph requires. Measured, not defensive.
  installFlags: string[];
  // Written to <target>/stryker.conf.json by the job. JSON (not .mjs) so mutation-scan's
  // warnIfNotPerTest can actually read it back.
  config: Record<string, unknown>;
}

export const M8_CORPUS_CONFIGS: Record<string, M8CorpusConfig> = {
  proposit: {
    // react 19 vs @ai-sdk/react's peer range: npm refuses the install outright without this.
    installFlags: ["--legacy-peer-deps"],
    strykerPackages: ["@stryker-mutator/core@9", "@stryker-mutator/vitest-runner@9"],
    config: {
      testRunner: "vitest",
      coverageAnalysis: "perTest",
      reporters: ["json", "clear-text"],
      // lib/pdf/launch.ts is this repo's ONLY file with real test coverage (its one spec is
      // lib/pdf/__tests__/launch.test.ts).
      mutate: ["lib/pdf/launch.ts"],
    },
  },
  boxyhq: {
    installFlags: ["--legacy-peer-deps"],
    strykerPackages: ["@stryker-mutator/core@9", "@stryker-mutator/jest-runner@9"],
    config: {
      testRunner: "jest",
      coverageAnalysis: "perTest",
      reporters: ["json", "clear-text"],
      // The jest suite's one unit spec (__tests__/lib/server-common.spec.ts) covers this file.
      // #277 expected boxyhq's Playwright E2E specs to block this; they don't — the target's own
      // jest.config.js sets testPathIgnorePatterns: ['<rootDir>/tests/e2e'], so the jest runner
      // never loads them.
      mutate: ["lib/server-common.ts"],
      jest: { configFile: "jest.config.js" },
    },
  },
};
