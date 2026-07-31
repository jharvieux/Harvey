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

import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";

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
  // #1496: files to write into appDir before the Stryker run (materializeM8Config below), keyed by
  // path relative to appDir. Every other target here mutation-scores a suite the clone already
  // ships; this is for a target whose only suite carries a per-mutant Docker cost
  // (multi-tenant-starter, #1436) and needed a NEW, DB-free test file to get any mutation surface
  // at all. The operator ruling on #1496 accepted the trade this implies: a stubbed suite may score
  // differently than the real suite it stands in for, so a target using this field must say so in
  // its baseline note.
  extraFiles?: Record<string, string>;
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
  // #1496: this target's only real suite (test/rls.test.mjs) starts a throwaway Docker Postgres
  // container per invocation, which Stryker's command runner would pay per mutant (#1436's
  // M8_DOCKER_PER_MUTANT). The 2026-07-31 operator ruling on #1496 was to REWORK the suite rather
  // than pay that cost or leave the target unscored: `extraFiles` below vendors a NEW, DB-free unit
  // suite for lib/security/guards.ts (requireAuth/requireTenantAccess/requireTenantAdmin's
  // role-rank comparison), stubbing the two calls that file makes into the DB layer
  // (createServerSupabaseClient's .auth.getUser() and tenants.ts's getUserTenantRole) instead of
  // hitting a real database. MEASURED 2026-07-31 on the pin: 22/23 valid mutants killed (95.7%),
  // reproduced identically across three consecutive runs.
  //
  // COST, RE-MEASURED 2026-07-31 (#1693) because the `~3-6s` first recorded here named no phase and
  // no machine, and a bare second-count is what a future reader will size the monthly job with.
  // Three consecutive runs of the FULL production path — `pnpm corpus-drift --target
  // multi-tenant-starter --install --m8`, i.e. network clone + install + Stryker — on one developer
  // laptop: 17.5s / 10.5s / 9.8s end to end (corpus-drift's own per-target banner: 16s / 9s / 8s;
  // the first run pays a cold npm cache). Stryker's own mutation phase is the small part of that:
  // it reported `Done in 1 second.` on all three, over 23 mutants. A CI runner is slower again, so
  // quote the phase and the machine or re-run the command — not a number from this comment. Either
  // way it is nowhere near the original suite's one-Docker-container-start-per-mutant.
  //
  // See external-corpus.ts's multi-tenant-starter M8 baseline for the accepted trade this implies
  // (a stubbed suite can score differently from the suite it stands in for) and the one surviving
  // mutant's disposition.
  "multi-tenant-starter": {
    installFlags: [],
    strykerPackages: ["@stryker-mutator/core@9", "@stryker-mutator/vitest-runner@9", "vitest@^2"],
    config: {
      testRunner: "vitest",
      coverageAnalysis: "perTest",
      reporters: ["json", "clear-text"],
      plugins: ["@stryker-mutator/vitest-runner"],
      mutate: ["lib/security/guards.ts"],
    },
    extraFiles: {
      "vitest.config.ts": `import { defineConfig } from "vitest/config";
import { resolve } from "node:path";

// #1496: DB-free unit config for the security-guard mutation surface. Scoped to the one new test
// file below so this run never touches test/rls.test.mjs (Docker) or app/**.
export default defineConfig({
  resolve: { alias: { "@": resolve(__dirname, ".") } },
  test: { include: ["test/**/*.vitest.test.ts"] },
});
`,
      "test/security-guards.vitest.test.ts": `// #1496: DB-free unit coverage for lib/security/guards.ts's role-hierarchy authorization logic.
// The target's only other suite (test/rls.test.mjs) needs a live Docker Postgres per invocation,
// which is what made this file not mutation-scoreable at all (#1436's M8_DOCKER_PER_MUTANT). This
// file stubs the two calls guards.ts makes into the DB layer (createServerSupabaseClient's
// .auth.getUser() and tenants.ts's getUserTenantRole) so the mutation surface below never touches
// a real database — it exercises the role-rank comparison and redirect branches directly.
import { afterEach, describe, expect, it, vi } from "vitest";
import { requireAuth, requireTenantAccess, requireTenantAdmin } from "../lib/security/guards";
import { getUserTenantRole } from "../lib/supabase/tenants";
import { createServerSupabaseClient } from "../lib/supabase/server";
import { redirect } from "next/navigation";

vi.mock("../lib/supabase/server", () => ({ createServerSupabaseClient: vi.fn() }));
vi.mock("../lib/supabase/tenants", () => ({ getUserTenantRole: vi.fn() }));
vi.mock("next/navigation", () => ({
  redirect: vi.fn((url: string) => {
    throw new Error("REDIRECT:" + url);
  }),
}));

const USER = { id: "user-1" };

function stubUser(user: { id: string } | null) {
  vi.mocked(createServerSupabaseClient).mockResolvedValue({
    auth: { getUser: async () => ({ data: { user } }) },
  } as never);
}

afterEach(() => {
  vi.clearAllMocks();
});

describe("requireAuth", () => {
  it("returns the user when one is present", async () => {
    stubUser(USER);
    await expect(requireAuth()).resolves.toEqual(USER);
    expect(redirect).not.toHaveBeenCalled();
  });

  it("redirects to /auth/login when no user is present", async () => {
    stubUser(null);
    await expect(requireAuth()).rejects.toThrow("REDIRECT:/auth/login");
    expect(redirect).toHaveBeenCalledWith("/auth/login");
  });
});

describe("requireTenantAccess", () => {
  it("propagates the /auth/login redirect when unauthenticated, before checking role", async () => {
    stubUser(null);
    await expect(requireTenantAccess("tenant-1")).rejects.toThrow("REDIRECT:/auth/login");
    expect(getUserTenantRole).not.toHaveBeenCalled();
  });

  it("redirects to /dashboard when the user is not a member (role is null)", async () => {
    stubUser(USER);
    vi.mocked(getUserTenantRole).mockResolvedValue(null);
    await expect(requireTenantAccess("tenant-1")).rejects.toThrow("REDIRECT:/dashboard");
  });

  it("redirects to /dashboard when the member's role ranks below the minimum", async () => {
    stubUser(USER);
    vi.mocked(getUserTenantRole).mockResolvedValue("member");
    await expect(requireTenantAccess("tenant-1", "admin")).rejects.toThrow("REDIRECT:/dashboard");
  });

  it("allows access at exactly the minimum role rank (boundary)", async () => {
    stubUser(USER);
    vi.mocked(getUserTenantRole).mockResolvedValue("admin");
    await expect(requireTenantAccess("tenant-1", "admin")).resolves.toEqual({ user: USER, role: "admin" });
  });

  it("allows access when the member's role ranks above the minimum", async () => {
    stubUser(USER);
    vi.mocked(getUserTenantRole).mockResolvedValue("owner");
    await expect(requireTenantAccess("tenant-1", "member")).resolves.toEqual({ user: USER, role: "owner" });
  });

  it("defaults the minimum role to 'guest', admitting every real membership rank", async () => {
    stubUser(USER);
    vi.mocked(getUserTenantRole).mockResolvedValue("guest");
    await expect(requireTenantAccess("tenant-1")).resolves.toEqual({ user: USER, role: "guest" });
  });
});

describe("requireTenantAdmin", () => {
  it("rejects a plain member", async () => {
    stubUser(USER);
    vi.mocked(getUserTenantRole).mockResolvedValue("member");
    await expect(requireTenantAdmin("tenant-1")).rejects.toThrow("REDIRECT:/dashboard");
  });

  it("admits an admin", async () => {
    stubUser(USER);
    vi.mocked(getUserTenantRole).mockResolvedValue("admin");
    await expect(requireTenantAdmin("tenant-1")).resolves.toEqual({ user: USER, role: "admin" });
  });

  it("admits an owner", async () => {
    stubUser(USER);
    vi.mocked(getUserTenantRole).mockResolvedValue("owner");
    await expect(requireTenantAdmin("tenant-1")).resolves.toEqual({ user: USER, role: "owner" });
  });
});
`,
    },
  },
};

// #1693: the two writes that turn a disposable clone into something Stryker can run — the vendored
// config, and (for a target using `extraFiles`) the suite that config points at. They belong
// together because dropping either one alone fails SILENTLY in the same direction: a config naming
// a suite nobody wrote finds no tests, and a suite written with no config is never invoked. Both
// used to sit inline in src/cli/corpus-drift.ts's runMutationScan, which reads process.argv and
// runs its whole corpus sweep at module load, so importing it from a test executes the sweep —
// MEASURED 2026-07-31: deleting the `extraFiles` loop there turned nothing red in `pnpm verify`.
// That is the gap this move closes; see m8-corpus.test.ts.
export function materializeM8Config(appDir: string, cfg: M8CorpusConfig): void {
  for (const [rel, content] of Object.entries(cfg.extraFiles ?? {})) {
    const path = join(appDir, rel);
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, content);
  }
  writeFileSync(join(appDir, "stryker.conf.json"), `${JSON.stringify(cfg.config, null, 2)}\n`);
}
