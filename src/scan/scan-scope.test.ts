import { execFileSync } from "node:child_process";
import { existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { relativizeScanScope, resolveScanScope } from "./scan-scope.js";

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

  // Measured 2026-07-23 on zenstackhq/zenstack (packages/ide/vscode/res is a tracked symlink to a
  // directory): plain cpSync followed the link, found a directory and threw "Recursive option not
  // enabled", killing the ENTIRE scan of a real repo. The scan must survive it, and must copy the
  // link rather than the tree it points at.
  it("survives a tracked symlink to a directory instead of aborting the whole scan", () => {
    const repo = tmp("harvey-scope-symlink-");
    execFileSync("git", ["init", "-q", repo]);
    mkdirSync(join(repo, "res"));
    writeFileSync(join(repo, "res", "stdlib.txt"), "content");
    writeFileSync(join(repo, "index.ts"), "export const x = 1;");
    symlinkSync("res", join(repo, "link-to-res"));
    execFileSync("git", ["-C", repo, "add", "-A"]);

    const { scanDir, cleanup } = resolveScanScope(repo);
    scratches.push(scanDir);
    try {
      expect(existsSync(join(scanDir, "index.ts"))).toBe(true);
      expect(lstatSync(join(scanDir, "link-to-res")).isSymbolicLink()).toBe(true);
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

describe("relativizeScanScope", () => {
  // The whole point (#285): the same finding scanned twice, under two different mkdtemp roots,
  // must serialize to one identical location — otherwise the committed artifact churns.
  it("collapses two different scratch roots to the same target-relative location", () => {
    const a = relativizeScanScope("/var/folders/vp/T/harvey-scan-scope-JJ0Vim/pages/api/search.js:9");
    const b = relativizeScanScope("/tmp/harvey-scan-scope-Zq91aa/pages/api/search.js:9");
    expect(a).toBe("pages/api/search.js:9");
    expect(b).toBe(a);
  });

  it("strips the scratch root while keeping a [source] prefix and a (pkg) suffix", () => {
    expect(relativizeScanScope("[source] /var/folders/vp/T/harvey-scan-scope-JJ0Vim/.npmrc:4")).toBe("[source] .npmrc:4");
    expect(relativizeScanScope("/var/folders/vp/T/harvey-scan-scope-JJ0Vim/package-lock.json (braces@2.3.2)")).toBe(
      "package-lock.json (braces@2.3.2)",
    );
  });

  it("leaves an already-relative location untouched", () => {
    expect(relativizeScanScope("supabase/migrations/20260708000001_schema.sql:35")).toBe(
      "supabase/migrations/20260708000001_schema.sql:35",
    );
    expect(relativizeScanScope("package.json (next)")).toBe("package.json (next)");
  });
});
