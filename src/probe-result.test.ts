// #1096 invariant (2) — the typed non-empty result. Proves three things, each by seeding the
// violation it is supposed to prevent:
//
//   1. the BAD STATE IS UNREPRESENTABLE — `{ kind: "examined", findings: [] }` with no statement of
//      what was examined does not compile (@ts-expect-error below; `pnpm typecheck` is the assertion
//      — remove the directive and tsc fails the build, which is the test);
//   2. an Examined that examined ZERO units throws rather than reading as a clean scan (#1065's
//      exact shape, in the type system this time);
//   3. the MIGRATION IS DISCLOSED — every module of M1–M10 is in TYPED_PROBES or UNTYPED_PROBES
//      with a reason, so a half-migration cannot be mistaken for a finished one.

import { describe, expect, it } from "vitest";
import { AUDIT_MODULES } from "./audit-coverage.js";
import { type Examined, type ModuleRunner, type NotAssessed, runAudit, toOutcome, TYPED_PROBES, UNTYPED_PROBES } from "./audit-runner.js";
import { AUDIT_RUNNERS } from "./audit-runners.js";

describe("the typed probe result makes the silent-empty state unrepresentable", () => {
  it("does not compile without saying what was examined", () => {
    // @ts-expect-error — "we ran and found nothing" with no unitsExamined/scope is exactly the claim
    // #1062 and #1065 shipped, and it is now a type error. If this line ever starts compiling, the
    // directive itself fails the typecheck and this test's premise is gone.
    const silentlyEmpty: Examined = { kind: "examined", detail: "pnpm detect-static", findings: [] };
    expect(silentlyEmpty).toBeTruthy();
  });

  it("does not compile a not-run reason without provenance and a falsifier", () => {
    // @ts-expect-error — the #1033 contract at the type level: a recorded reason with no provenance
    // tag and no falsifier is unfalsifiable, and four of them were found false in one 2026-07-24
    // sweep. It cannot be written here.
    const untagged: NotAssessed = { kind: "not-assessed", reason: "cannot run offline" };
    expect(untagged).toBeTruthy();
  });

  it("carries the unit count onto the ledger row, so a zero-finding row says what was read", () => {
    const outcome = toOutcome({ kind: "examined", detail: "pnpm detect-static /t", findings: [], unitsExamined: 412, scope: "product source files" });
    expect(outcome.status).toBe("ran");
    expect(outcome.status === "ran" && outcome.detail).toContain("examined 412 product source files");
  });

  it("folds provenance and the falsifier into a not-assessed row's reason", () => {
    const outcome = toOutcome({ kind: "not-assessed", reason: "no stack reachable", provenance: "MEASURED", falsifier: "pnpm exec tsx src/cli/pentest.ts" });
    expect(outcome.status).toBe("requires-live-run");
    expect(outcome.status === "requires-live-run" && outcome.reason).toContain("[MEASURED; falsifier: pnpm exec tsx src/cli/pentest.ts]");
  });

  // SEEDED: a probe claims it examined the target and reports zero units. That is not a clean scan,
  // it is a NotAssessed wearing an Examined's clothes — the #1065 defect, where "loaded 0 product
  // source files" read as a successful pass for nine months.
  it("THROWS on an Examined that examined nothing, rather than letting it read as clean", () => {
    expect(() => toOutcome({ kind: "examined", detail: "pnpm detect-static /empty", findings: [], unitsExamined: 0, scope: "product source files" })).toThrow(/examining nothing is not a clean scan/);
  });
});

describe("the typed-result migration is disclosed, not half-done in silence", () => {
  it("accounts for every module of M1–M10 as typed or explicitly not-yet-typed", () => {
    const covered = [...TYPED_PROBES, ...UNTYPED_PROBES.map((u) => u.module)].sort();
    expect(covered).toEqual([...AUDIT_MODULES].sort());
  });

  // #1109 emptied UNTYPED_PROBES, so this loop no longer runs against anything today. It is kept
  // because the list is the landing slot for an ELEVENTH module's probe: a new module added to
  // AUDIT_MODULES without a typed probe has to be written down with a blocker, not left blank.
  it("gives every un-migrated module a reason naming what blocks it", () => {
    for (const u of UNTYPED_PROBES) expect(u.reason.length).toBeGreaterThan(40);
  });

  // #1109: all ten. This is the assertion that fails the day a probe is reverted to the legacy shape
  // — the registry cross-check below would still pass if the module were moved to UNTYPED_PROBES.
  it("has migrated every module of M1–M10 — no probe is left on the untyped shape", () => {
    expect([...TYPED_PROBES].sort()).toEqual([...AUDIT_MODULES].sort());
    expect(UNTYPED_PROBES).toEqual([]);
  });

  // SEEDED: the hole the migration union opens. `run` accepts both shapes so unmigrated probes keep
  // compiling, which means a helper could silently hand a migrated module's result back in the
  // legacy shape and the compile-time guarantee would read as kept while the runtime one was gone.
  it("FAILS LOUD when a runner declares itself typed and hands back a legacy outcome", () => {
    const registry: ModuleRunner[] = AUDIT_MODULES.map((module) => ({
      module,
      producers: [],
      ...(module === "M9" ? { typed: true as const } : {}),
      run: () => ({ status: "ran" as const, detail: "laundered back to the legacy shape" }),
    }));
    const run = runAudit(registry, { targetDir: "/t", env: { connected: false, dynamic: false, llm: false }, exec: () => ({ ok: true, output: "" }), exists: () => true });
    expect(run.failures.map((f) => `${f.module}: ${f.error}`)).toEqual([
      expect.stringContaining("M9: M9 declares itself migrated (typed: true) but returned 1 legacy ProbeOutcome(s)"),
    ]);
  });

  // The real registry, not a synthetic one: the declared list and the runners must agree, or the
  // runtime check above is watching a module nobody marked.
  it("marks exactly the declared modules as typed in the real registry", () => {
    expect(AUDIT_RUNNERS.filter((r) => r.typed).map((r) => r.module).sort()).toEqual([...TYPED_PROBES].sort());
  });
});
