// #1426 — A FALSIFIER THAT COULD NOT RUN MUST SAY SO, NOT SAY "THE BLOCKER HOLDS".
//
// `revalidateReasons` maps 127 (and a signal/timeout) to UNVERIFIABLE and every other non-zero to
// "holds". That contract is only safe if the commands themselves reserve 127 for "I could not look",
// and MEASURED 2026-07-31 over the whole population they did not. The population is 34 offline
// empirical falsifiers under `offlineFalsifiers()`'s own filter; 3 are the pure-existence rows
// exempted below, leaving 31 non-existence-test falsifiers of which **19 returned something other
// than 127** when the path they read was absent (22 of 34 counting the exempt three). THREE of the 19
// returned **0** — a lookup that read nothing reporting the blocker GONE. Two are the real defect
// (src/disclosure-venue.ts:77, src/test-only-exports.ts:32); the third, src/alert-paths.ts:50, is a
// NETWORK lookup whose 0 was correct — the self-retiring `gh api` row #1422 discharges. Derivation
// and the re-run recipe: docs/design/recorded-reasons.md.
//
// The two ways it happens, both boring and both silent:
//   • a bare `grep PATTERN FILE` exits **2** when FILE is renamed or deleted, not 1;
//   • a pipeline exits with its LAST stage's code, and `set -o pipefail` is not portable here —
//     `revalidateReasons` runs `spawnSync("sh", …)` and `/bin/sh` on a Linux runner is dash.
//
// Two arms, because neither alone is enough. The STRUCTURAL arm is cheap and total. The EMPIRICAL arm
// actually runs each command with its input absent, which is the only thing that can catch a guard
// that is present but wrong (the #1345 shape: a `grep -q CLOSED` over an API answering lowercase
// `closed` exits 1 in both directions and re-tests nothing).
//
// Two categories are exempt and both are DERIVED from the command, not listed by hand — a hand-kept
// list is the suppression the reason registry refuses everywhere else:
//   • a PURE EXISTENCE TEST (`test -f X`, `ls X`) has no cannot-run state distinct from its answer.
//     The file's absence IS the claim ("no live-captured fixture exists yet").
//   • a NETWORK falsifier reads the world, not the checkout, so an empty cwd reproduces no state it
//     could report on. Those carry their own `command -v curl … || exit 127` guards, which the
//     structural arm still holds them to.

import { execFileSync } from "node:child_process";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { DEFAULT_ROOTS, collectReasons, reasonKind } from "./recorded-reasons.js";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

/** The command's whole body is an existence check, so absence is its answer rather than its failure. */
const PURE_EXISTENCE = /^(?:test\s+-[a-z]\s|ls\s)[^;|&]*$/;
const READS_NETWORK = /\bcurl\b|\bgh\s/;

interface Falsifier {
  at: string;
  command: string;
}

function offlineFalsifiers(): Falsifier[] {
  return collectReasons(DEFAULT_ROOTS, REPO_ROOT).flatMap((r) => {
    const command = r.fields.FALSIFIER;
    if (reasonKind(r) !== "empirical" || !command) return [];
    // A live-tier command names targets nobody stands up here, and its <placeholder>s are not bound
    // on this run — `revalidateReasons` reports both as SKIPPED-LIVE/UNVERIFIABLE without running it.
    if (r.fields["FALSIFIER-TIER"] || /<[a-z][a-z0-9-]*>/.test(command)) return [];
    return [{ at: `${r.file}:${r.line}`, command }];
  });
}

function exitCodeInEmptyDir(command: string): number {
  const dir = mkdtempSync(resolve(tmpdir(), "harvey-falsifier-"));
  try {
    execFileSync("sh", ["-c", command], { cwd: dir, stdio: "ignore", timeout: 60_000 });
    return 0;
  } catch (e) {
    return (e as { status?: number }).status ?? -1;
  }
}

describe("a falsifier that cannot run exits 127, never 'the blocker holds' (#1426)", () => {
  const all = offlineFalsifiers();

  // A rule with a population of zero is a guess (#1345). These counts also stop a future refactor
  // from emptying the two arms below by narrowing what offlineFalsifiers() returns.
  it("has a population to score", () => {
    expect(all.length).toBeGreaterThan(20);
    expect(all.filter((f) => !PURE_EXISTENCE.test(f.command) && !READS_NETWORK.test(f.command)).length).toBeGreaterThan(15);
  });

  it("every non-existence-test falsifier carries an explicit exit-127 branch", () => {
    const unguarded = all.filter((f) => !PURE_EXISTENCE.test(f.command) && !f.command.includes("exit 127"));
    expect(unguarded.map((f) => `${f.at}  ${f.command.slice(0, 100)}`)).toEqual([]);
  });

  // The 30s is not padding, it is the measurement. This arm spawns one `sh -c` per falsifier and its
  // wall time straddles vitest's 5s default: MEASURED 2026-07-31 on `origin/main` with NO local
  // changes, three consecutive runs of this file alone gave 2755ms, then 5597ms FAIL, then 6091ms
  // FAIL. A gate that goes red on scheduling noise is read as noise, which is how a real 127
  // regression would get re-run away. Well inside #1120's standing 60s ceiling for the light suite.
  it("every checkout-reading falsifier exits 127 with its input absent, not 1 or 2", () => {
    const wrong = all
      .filter((f) => !PURE_EXISTENCE.test(f.command) && !READS_NETWORK.test(f.command))
      .map((f) => ({ at: f.at, code: exitCodeInEmptyDir(f.command) }))
      .filter((r) => r.code !== 127);
    expect(wrong).toEqual([]);
  }, 30_000);

  // Both arms have to be able to fail, and on the exact shapes that shipped — a bare grep (exit 2)
  // and an unguarded pipeline whose first stage dies (the last stage's exit 1 wins).
  it("both arms reject the two shapes this issue found", () => {
    const bareGrep = "grep -q HARVEY_CONSERVATION_E2E .github/workflows/ci.yml";
    const pipeline = 'grep -E "^export const SOURCE_FILE" src/detectors/load-sources.ts | grep -Eq "svelte"';
    for (const command of [bareGrep, pipeline]) {
      expect(PURE_EXISTENCE.test(command), `${command} is not an existence test`).toBe(false);
      expect(command.includes("exit 127"), `${command} carries no 127 branch`).toBe(false);
      expect(exitCodeInEmptyDir(command), `${command} does not report cannot-run`).not.toBe(127);
    }
    expect(exitCodeInEmptyDir(bareGrep)).toBe(2);
    expect(exitCodeInEmptyDir(pipeline)).toBe(1);
  });

  // The exemptions are derived, so they need their own control: a rule that exempted everything would
  // pass both arms above while proving nothing.
  it("exempts an existence test and a network lookup, and nothing else", () => {
    expect(PURE_EXISTENCE.test("test -f src/pentest/__fixtures__/postgrest-gotrue-live-responses.json")).toBe(true);
    expect(PURE_EXISTENCE.test("test -f a.json || exit 127; grep -q x a.json")).toBe(false);
    expect(READS_NETWORK.test("command -v curl >/dev/null 2>&1 || exit 127; curl -fsS https://example.test")).toBe(true);
    expect(READS_NETWORK.test("grep -q x src/a.ts")).toBe(false);
  });
});
