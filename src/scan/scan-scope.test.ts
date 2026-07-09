import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { resolveScanScope } from "./scan-scope.js";

const scratches: string[] = [];
afterEach(() => {
  for (const s of scratches.splice(0)) rmSync(s, { recursive: true, force: true });
});

function tmp(prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  scratches.push(dir);
  return dir;
}

describe("resolveScanScope — git repo target", () => {
  it("scopes to git-tracked files, excluding an untracked artifact (N-UNTRACKED-ENV intent)", () => {
    const repo = tmp("harvey-scope-git-");
    execFileSync("git", ["init", "-q", repo]);
    writeFileSync(join(repo, "index.ts"), "export const x = 1;");
    execFileSync("git", ["-C", repo, "add", "index.ts"]);

    // Untracked/gitignored local artifact — the case issue #101 was filed about. Must NOT
    // reach the scoped copy.
    writeFileSync(join(repo, ".env.local"), "SECRET=live-value-should-not-be-scanned");

    const { scanDir, cleanup } = resolveScanScope(repo);
    scratches.push(scanDir);
    try {
      expect(existsSync(join(scanDir, "index.ts"))).toBe(true);
      expect(existsSync(join(scanDir, ".env.local"))).toBe(false);
    } finally {
      cleanup();
    }
  });

  it("keeps a fixture that's force-added despite being gitignored (mirrors B1's committed .env.local)", () => {
    const repo = tmp("harvey-scope-git-forced-");
    execFileSync("git", ["init", "-q", repo]);
    writeFileSync(join(repo, ".gitignore"), ".env.local\n");
    execFileSync("git", ["-C", repo, "add", ".gitignore"]);
    writeFileSync(join(repo, ".env.local"), "FAKE_SECRET=calibration-fixture");
    execFileSync("git", ["-C", repo, "add", "-f", ".env.local"]);

    const { scanDir, cleanup } = resolveScanScope(repo);
    scratches.push(scanDir);
    try {
      expect(existsSync(join(scanDir, ".env.local"))).toBe(true);
      expect(readFileSync(join(scanDir, ".env.local"), "utf8")).toContain("calibration-fixture");
    } finally {
      cleanup();
    }
  });

  it("excludes an untracked worktree-style directory nested inside the repo", () => {
    const repo = tmp("harvey-scope-git-worktree-");
    execFileSync("git", ["init", "-q", repo]);
    writeFileSync(join(repo, "app.ts"), "export const a = 1;");
    execFileSync("git", ["-C", repo, "add", "app.ts"]);
    mkdirSync(join(repo, ".claude", "worktrees", "agent-1"), { recursive: true });
    writeFileSync(join(repo, ".claude", "worktrees", "agent-1", "app.ts"), "export const leak = 'noise';");

    const { scanDir, cleanup } = resolveScanScope(repo);
    scratches.push(scanDir);
    try {
      expect(existsSync(join(scanDir, "app.ts"))).toBe(true);
      expect(existsSync(join(scanDir, ".claude"))).toBe(false);
    } finally {
      cleanup();
    }
  });
});

describe("resolveScanScope — non-git target (zip export fallback)", () => {
  it("applies the hard exclude list (node_modules, .claude, .next, dist, build, coverage)", () => {
    const dir = tmp("harvey-scope-plain-");
    writeFileSync(join(dir, "app.ts"), "export const a = 1;");
    for (const excluded of ["node_modules", ".claude", ".next", "dist", "build", "coverage"]) {
      mkdirSync(join(dir, excluded, "nested"), { recursive: true });
      writeFileSync(join(dir, excluded, "nested", "f.ts"), "noise");
    }

    const { scanDir, cleanup } = resolveScanScope(dir);
    scratches.push(scanDir);
    try {
      expect(existsSync(join(scanDir, "app.ts"))).toBe(true);
      for (const excluded of ["node_modules", ".claude", ".next", "dist", "build", "coverage"]) {
        expect(existsSync(join(scanDir, excluded))).toBe(false);
      }
    } finally {
      cleanup();
    }
  });

  it("does NOT exclude .env files — without git history a zip can carry a legitimately-committed .env", () => {
    const dir = tmp("harvey-scope-plain-env-");
    writeFileSync(join(dir, ".env"), "COMMITTED=value");
    writeFileSync(join(dir, ".env.local"), "ALSO_KEPT=value");

    const { scanDir, cleanup } = resolveScanScope(dir);
    scratches.push(scanDir);
    try {
      expect(existsSync(join(scanDir, ".env"))).toBe(true);
      expect(existsSync(join(scanDir, ".env.local"))).toBe(true);
    } finally {
      cleanup();
    }
  });
});
