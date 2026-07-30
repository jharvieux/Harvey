// Offline coverage for the corpus-clone-cache safety logic (#1571). No network: `isFreshClone`
// operates on a LOCAL git repo built with plain `git` commands, and `cloneAtPinCached`'s cache-HIT
// path is proven to skip the network entirely by pointing its "repo" at one that does not exist —
// a real fetch attempt would throw, so a clean copy proves the network was never touched.
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { cloneAtPinCached, isFreshClone } from "./corpus-clone.js";

const dirs: string[] = [];
function tmp(prefix: string): string {
  const d = mkdtempSync(join(tmpdir(), prefix));
  dirs.push(d);
  return d;
}
afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

function git(dir: string, ...args: string[]): void {
  execFileSync("git", ["-C", dir, ...args], { stdio: "ignore" });
}

function commitOneFile(dir: string): string {
  git(dir, "init", "-q");
  git(dir, "config", "user.email", "test@example.com");
  git(dir, "config", "user.name", "test");
  writeFileSync(join(dir, "marker.txt"), "pinned content\n");
  git(dir, "add", "marker.txt");
  git(dir, "commit", "-q", "-m", "pin");
  return execFileSync("git", ["-C", dir, "rev-parse", "HEAD"]).toString().trim();
}

describe("isFreshClone", () => {
  it("is true for a clean checkout at the pinned commit", () => {
    const dir = tmp("clone-valid-");
    const sha = commitOneFile(dir);
    expect(isFreshClone(dir, sha)).toBe(true);
  });

  it("is false when HEAD does not match the pinned commit", () => {
    const dir = tmp("clone-stale-");
    commitOneFile(dir);
    expect(isFreshClone(dir, "0".repeat(40))).toBe(false);
  });

  it("is false for a dirty working tree — a partial or corrupted checkout", () => {
    const dir = tmp("clone-dirty-");
    const sha = commitOneFile(dir);
    writeFileSync(join(dir, "marker.txt"), "mutated after checkout\n");
    expect(isFreshClone(dir, sha)).toBe(false);
  });

  it("is false when the directory is not a git repo at all", () => {
    const dir = tmp("clone-missing-");
    expect(isFreshClone(dir, "0".repeat(40))).toBe(false);
  });

  it("is false for a directory that does not exist", () => {
    expect(isFreshClone(join(tmpdir(), "harvey-does-not-exist-xyz"), "0".repeat(40))).toBe(false);
  });
});

describe("cloneAtPinCached", () => {
  it("copies a valid cache entry rather than cloning — no network reached", () => {
    const cacheDir = tmp("cache-root-");
    const repo = "definitely-not-a-real-org/definitely-not-a-real-repo-xyz";
    const cached = join(cacheDir, repo.replace(/\//g, "__"));
    mkdirSync(cached, { recursive: true });
    const sha = commitOneFile(cached);
    const into = tmp("work-");

    // This repo name is invented and resolves to nothing on GitHub, so a network fetch attempt
    // here would throw — a passing test means the valid cache entry was trusted and copied
    // instead.
    expect(() => cloneAtPinCached(repo, sha, into, cacheDir)).not.toThrow();
    expect(readFileSync(join(into, "marker.txt"), "utf8")).toBe("pinned content\n");
  });
});
