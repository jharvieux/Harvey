// This CLI is the executable half of a FALSIFIER, so its exit code IS its contract and the
// dangerous value is the one that looks like an answer. `revalidateReasons` maps 127/null to
// UNVERIFIABLE and every other non-zero to "the blocker still holds", so a `gh` failure that
// reaches this tool as empty stdin must NOT exit 1 — that is a green re-validation which re-tested
// nothing (#1246). All three directions are asserted here because a falsifier nobody has watched
// exit 0 is indistinguishable from one that never could.

import { describe, expect, it } from "vitest";
import { execFileSync } from "node:child_process";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const CLI = "src/cli/measure-pnpm-evidence.ts";

function run(stdin: string): { code: number; out: string } {
  try {
    return { code: 0, out: execFileSync("node_modules/.bin/tsx", [CLI], { cwd: REPO_ROOT, encoding: "utf8", input: stdin, stdio: ["pipe", "pipe", "pipe"] }) };
  } catch (e) {
    const err = e as { status: number; stdout: string; stderr: string };
    return { code: err.status, out: `${err.stdout}${err.stderr}` };
  }
}

const met = (detail: string) => JSON.stringify([{ number: 99001, body: `ACCEPTANCE #1.1 met: ${detail}` }]);

describe("measure-pnpm-evidence exit codes", () => {
  it("exits 0 when the blocker is gone — an unbackticked reference names a real package.json script", () => {
    const { code, out } = run(met("ran pnpm verify green with no backticks on this line"));
    expect(code).toBe(0);
    expect(out).toContain("name a REAL script");
  });

  it("exits 1 when the blocker holds — the only pnpm reference is backticked", () => {
    const { code, out } = run(met("ran `pnpm verify` green"));
    expect(code).toBe(1);
    expect(out).toContain("still costs nothing");
  });

  // The four ways `gh pr list` hands this tool stdin with no population in it. Each must be 127,
  // never 1: exit 1 is the claim "I measured the population and found nothing", which is false.
  it.each([
    ["empty stdin — gh wrote nothing", ""],
    ["garbled stdin — gh errored mid-write", "not json"],
    ["a JSON scalar rather than the expected array", '"nope"'],
    ["an empty population — zero merged PRs to measure", "[]"],
  ])("exits 127, not 1, on %s", (_why, stdin) => {
    const { code, out } = run(stdin);
    expect(code).toBe(127);
    expect(out).toContain("UNVERIFIABLE");
  });
});
