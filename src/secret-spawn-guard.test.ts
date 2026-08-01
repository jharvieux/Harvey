// #1413 crit 1/7 — the argv secret guard must be STRUCTURAL, not opt-in. `assertNoSecretInArgv`
// existed at exactly the hand-wired sites while `sh`'s other callers bypassed it. This meta-test
// requires the modules that hold TARGET-DERIVED secrets to route every spawn through a guard:
// each spawn primitive in them has a guard (`assertArgvClean` / `assertNoSecretInArgv`) within the
// lines just before it, so a new unguarded spawn fails the suite instead of silently shipping.
//
// SCOPE: this covers the four modules that provision or replay with a target's own secrets. The
// broader "every spawn ANYWHERE in src/ routes through the guard" invariant (most of the ~40 other
// spawn sites run a fixed toolchain binary with no secret in scope) is tracked as the #1413
// remainder — see the issue. Add a module here the moment it comes to hold a target secret.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const SECRET_SPAWN_MODULES = [
  "./pentest/live-standup.ts",
  "./pentest/prisma-standup.ts",
  "./pentest/next-auth-session.ts",
  "./scan/supabase-splinter.ts",
];

const SPAWN_PRIMITIVE = /\b(execFileSync|spawnSync|execSync|execFile|spawn)\s*\(/;
const GUARD_CALL = /\b(assertArgvClean|assertNoSecretInArgv)\s*\(/;
// A guard sits within this many source lines above the spawn it protects (the choke-point rail is
// ~2 lines up; the two per-site guards are 1–2 lines up). Chosen so a real guard is found and a
// spawn wired with none is not.
const GUARD_WINDOW = 8;

// Return the 1-based line numbers of spawn primitives that have NO guard call within the preceding
// GUARD_WINDOW non-comment lines. Pure, so the negative controls can feed it synthetic source.
function unguardedSpawnLines(source: string): number[] {
  const lines = source.split("\n");
  const isCode = (l: string): boolean => {
    const t = l.trimStart();
    return t.length > 0 && !t.startsWith("//") && !t.startsWith("*");
  };
  const out: number[] = [];
  for (let i = 0; i < lines.length; i++) {
    if (!isCode(lines[i]!) || !SPAWN_PRIMITIVE.test(lines[i]!)) continue;
    const window = lines.slice(Math.max(0, i - GUARD_WINDOW), i + 1);
    if (!window.some((l) => GUARD_CALL.test(l))) out.push(i + 1);
  }
  return out;
}

describe("the argv secret guard is structural in every secret-handling module (#1413)", () => {
  for (const mod of SECRET_SPAWN_MODULES) {
    it(`${mod}: every spawn primitive is guarded`, () => {
      const source = readFileSync(fileURLToPath(new URL(mod, import.meta.url)), "utf8");
      // Sanity: the module actually spawns and actually guards, so a rename that silences both does
      // not read as a vacuous pass.
      expect(source).toMatch(SPAWN_PRIMITIVE);
      expect(source).toMatch(GUARD_CALL);
      expect(unguardedSpawnLines(source)).toEqual([]);
    });
  }
});

describe("unguardedSpawnLines — the meta-test can fail (#1413 crit 7)", () => {
  it("FLAGS a newly-added unguarded spawn", () => {
    const bad = [
      "function danger(dir: string, secret: string) {",
      "  const out = execFileSync('git', ['-C', dir, 'log', secret]);",
      "  return out;",
      "}",
    ].join("\n");
    expect(unguardedSpawnLines(bad)).toEqual([2]);
  });

  it("does NOT flag a spawn with a guard just above it", () => {
    const good = [
      "function safe(args: string[]) {",
      "  secretRegistry.assertArgvClean('safe', args);",
      "  return execFileSync('git', args);",
      "}",
    ].join("\n");
    expect(unguardedSpawnLines(good)).toEqual([]);
  });

  it("does NOT flag a call routed through the sh wrapper (not a spawn primitive)", () => {
    const routed = ["function f() {", "  return sh('psql', ['-c', 'select 1']);", "}"].join("\n");
    expect(unguardedSpawnLines(routed)).toEqual([]);
  });
});
