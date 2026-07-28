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
  // its install refuses without. Installed without persisting the addition to the target's own
  // manifest/lockfile (npm's --no-save natively, pnpm/yarn via src/package-manager.ts's
  // withRestoredManifest — #1268).
  strykerPackages: string[];
  // NPM install flags the target's own dep graph requires. Measured, not defensive. They reach the
  // install ONLY when the target resolves via npm — src/package-manager.ts's npmOnlyFlags withholds
  // them otherwise, because pnpm 11 and yarn exit 1 on an unrecognised option rather than ignoring
  // it (CI run 30362638379: proposit, a pnpm-lockfile repo, failed both installs on
  // `Unknown option: 'legacy-peer-deps'`).
  installFlags: string[];
  // Written to <target[/appPath]>/stryker.conf.json by the job. JSON (not .mjs) so mutation-scan's
  // warnIfNotPerTest can actually read it back.
  config: Record<string, unknown>;
  // #1268: the workspace member that actually carries the test suite, relative to the clone root —
  // undefined scores the clone root itself (proposit/boxyhq, single-package repos). inbox-zero's
  // suite lives at apps/web, not the pnpm-workspace root, so the config, the Stryker package
  // install, and the mutation-scan invocation all need to target that subdirectory.
  appPath?: string;
}

export const M8_CORPUS_CONFIGS: Record<string, M8CorpusConfig> = {
  proposit: {
    // react 19 vs @ai-sdk/react's peer range: npm refuses the install outright without this. Kept
    // even though this repo's own lockfile is pnpm's (so #1284 now resolves it to pnpm, which does
    // not enforce peer ranges and never sees the flag) — the flag records what npm needs here, and
    // an upstream switch back to a package-lock would need it again.
    installFlags: ["--legacy-peer-deps"],
    strykerPackages: ["@stryker-mutator/core@9", "@stryker-mutator/vitest-runner@9"],
    config: {
      testRunner: "vitest",
      coverageAnalysis: "perTest",
      reporters: ["json", "clear-text"],
      // MEASURED 2026-07-28 on the pinned clone: Stryker's default plugin discovery is a
      // `@stryker-mutator/*` glob over a FLAT node_modules, so it resolved the runner under npm and
      // failed to under the pnpm install #1284 now routes this target to (Stryker's own error names
      // zero loaded TestRunner plugins). inbox-zero/rallly name it for the same reason.
      plugins: ["@stryker-mutator/vitest-runner"],
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
  // #1268: MEASURED 2026-07-28 against a real clone (elie222/inbox-zero @ 2b78f2b, apps/web) — a
  // pnpm workspace, unscoreable through the OLD npm-install-only job (external-corpus.ts's M8 entry
  // used to record that not-run reason; `pnpm install` at the root resolves the whole workspace,
  // apps/web included). No installFlags needed: pnpm has no npm-style peer-conflict error class here.
  "inbox-zero": {
    appPath: "apps/web",
    installFlags: [],
    strykerPackages: ["@stryker-mutator/core@9", "@stryker-mutator/vitest-runner@9"],
    config: {
      testRunner: "vitest",
      coverageAnalysis: "perTest",
      reporters: ["json", "clear-text"],
      // #1268: MEASURED — inbox-zero's own pnpm-workspace.yaml sets `enableGlobalVirtualStore:
      // true`, which stores the resolved package graph OUTSIDE the project. Stryker resolves its
      // OWN plugins/typescript via Node's node_modules directory walk relative to wherever ITS OWN
      // file physically lives — under a global virtual store that walk never reaches the project's
      // node_modules at all, so even an explicitly-named plugin (src/mutation-scan.ts's
      // scaffoldStrykerConfig `plugins` fix, #1284) still fails to resolve. corpus-drift.ts's
      // installTargetDeps disables the workspace setting for the disposable clone before installing
      // (never the target's own repo) — this config's `plugins` line only takes effect once that
      // has already put the resolved packages back in the project's own node_modules/.pnpm.
      plugins: ["@stryker-mutator/vitest-runner"],
      // utils/similarity-score.ts: a small, dependency-free pure-logic module (fuzzy-match scoring
      // for detecting duplicate/near-duplicate email drafts) with a real, fast, deterministic spec
      // (utils/similarity-score.test.ts, 55 cases, no network/env/DB) — the same "one well-tested
      // file" scope convention proposit/boxyhq already use, chosen because #894 explicitly wanted
      // inbox-zero's mutation surface measured and a whole-suite run (586 spec files touching a
      // live-service-shaped app) is a materially different, much larger undertaking than this job
      // scores today for any other target.
      mutate: ["utils/similarity-score.ts"],
    },
  },
  // #1268: MEASURED 2026-07-28 against a real clone (lukevella/rallly @ a680798, apps/web) — same
  // pnpm-workspace blocker as inbox-zero (npm install resolved only the 219 root packages), and NO
  // enableGlobalVirtualStore complication here, so the plain pnpm-aware install was the whole fix.
  rallly: {
    appPath: "apps/web",
    installFlags: [],
    strykerPackages: ["@stryker-mutator/core@9", "@stryker-mutator/vitest-runner@9"],
    config: {
      testRunner: "vitest",
      coverageAnalysis: "perTest",
      reporters: ["json", "clear-text"],
      plugins: ["@stryker-mutator/vitest-runner"],
      // src/lib/datetime/utils.ts: normalizeTimeZone/getCalendarDate/etc — pure timezone-handling
      // logic with a fast, deterministic 7-case spec (src/lib/datetime/utils.test.ts), no network/DB.
      mutate: ["src/lib/datetime/utils.ts"],
    },
  },
};
