// #1307 negative control. Every gate in this repo ships one, because a gate only ever seen passing
// is indistinguishable from a gate that cannot fail (#1320).
//
// targets/test-only-export-control/ plants three capabilities reachable only from a test — an
// orphan MODULE, an EXPORT and a TYPE — alongside two controls that must stay silent: an export
// entry.ts calls, and an export used inside its own file plus asserted by the test (the shape every
// detector in src/scan/ has, so a gate that reported it would fire on almost every new detector).

import { execFileSync } from "node:child_process";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const CLI = join(REPO_ROOT, "src", "cli", "validate-test-only-exports.ts");
const FIXTURE = "targets/test-only-export-control";

// One spawn per baseline, shared across the assertions below: each costs ~1.3s and the assertions
// are independent views of the same run.
const runs = new Map<string, { status: number; stdout: string }>();

function run(baseline: string, extra: string[] = []): { status: number; stdout: string } {
  const key = [baseline, ...extra].join(" ");
  const cached = runs.get(key);
  if (cached) return cached;
  let result: { status: number; stdout: string };
  try {
    result = { status: 0, stdout: execFileSync("node_modules/.bin/tsx", [CLI, "--dir", FIXTURE, "--config", "knip.json", "--baseline", baseline, ...extra], { cwd: REPO_ROOT, encoding: "utf8" }) };
  } catch (e) {
    const err = e as { status?: number; stdout?: string };
    result = { status: err.status ?? 1, stdout: err.stdout ?? "" };
  }
  runs.set(key, result);
  return result;
}

describe("test-only-exports gate — negative control (#1307)", () => {
  it("fails on a planted capability whose only referent is a test, and names it", () => {
    const r = run("baseline.empty.json");
    expect(r.status).toBe(1);
    expect(r.stdout).toContain("export src/lib.ts:testOnlyExport");
    expect(r.stdout).toContain("type   src/lib.ts:TestOnlyType");
    // knip reports the orphan as a PATH; the gate has to open it or the capability stays hidden.
    expect(r.stdout).toContain("src/orphan.ts — every export unreachable: neverCalledInProduction, ORPHAN_LIMIT");
    expect(r.stdout).toContain("GATE FAIL — 3 new, 0 stale.");
  });

  it("leaves the production-called and internally-used exports alone", () => {
    const r = run("baseline.empty.json");
    expect(r.stdout).not.toContain("usedInProduction");
    expect(r.stdout).not.toContain("internallyUsed");
  });

  it("passes once the plants are on the baseline, so the failure above was the plant and not the gate", () => {
    const r = run("baseline.json");
    expect(r.status).toBe(0);
    expect(r.stdout).toContain("GATE PASS");
    expect(r.stdout).toContain("3 still on it");
  });

  it("fails when a baseline row has gained a production caller, so the backlog cannot be padded", () => {
    const r = run("baseline.stale.json");
    expect(r.status).toBe(1);
    expect(r.stdout).toContain("export src/lib.ts:usedInProduction");
    expect(r.stdout).toContain("GATE FAIL — 0 new, 1 stale.");
  });

  // #1547. The ruling is "a caller OR a recorded reason" and the gate could only see callers, so a
  // row someone had genuinely triaged printed identically to one nobody had read, and the backlog
  // number could only fall by wiring. Driven through the real CLI rather than the pure function,
  // because the wiring — collectReasons over the analysed directory — is the half with no other
  // failing direction (#1407's class).
  it("separates a baseline row carrying a recorded reason from one that carries none", () => {
    const r = run("baseline.json", ["--list"]);
    expect(r.status).toBe(0);
    expect(r.stdout).toContain("of the 3: 1 carry a recorded reason, 2 still await a caller or a reason");
    expect(r.stdout).toContain("2 untriaged");
    // The planted block names TestOnlyType and nothing else, so the SAME file's other plant and the
    // orphan module must stay unmarked. A file-wide absolution would mark all three.
    expect(r.stdout).toMatch(/type {3}src\/lib\.ts:TestOnlyType {2}\[recorded reason — src\/lib\.ts:\d+\]/);
    expect(r.stdout).toMatch(/export src\/lib\.ts:testOnlyExport\n/);
    expect(r.stdout).toMatch(/file {3}src\/orphan\.ts — every export unreachable: neverCalledInProduction, ORPHAN_LIMIT\n/);
    // #1648: the block names TestOnlyType in its REASON:, which is the only field that counts now —
    // a PROVENANCE: or TOUCHES: mention no longer absolves, and neither does a substring.
  });
  // Every assertion here drives the real CLI in a child process; the comment above says ~1.3s each
  // and MEASURED 2026-07-31 they run 2.9-3.6s, which straddled vitest's old 5s default once the
  // shared worker pool was loaded. #1715 moved the whole light suite to one measured 30s budget in
  // vitest.config.ts, so this file no longer carries its own literal.
});
