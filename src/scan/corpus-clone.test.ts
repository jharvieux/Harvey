// Offline coverage for the corpus-clone-cache safety logic (#1571). No network: `isFreshClone`
// operates on a LOCAL git repo built with plain `git` commands, and `cloneAtPinCached`'s cache-HIT
// path is proven to skip the network entirely by pointing its "repo" at one that does not exist —
// a real fetch attempt would throw, so a clean copy proves the network was never touched.
import { execFileSync, spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, readlinkSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
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

  it("preserves relative symlink targets in the copied checkout", () => {
    const cacheDir = tmp("cache-root-");
    const repo = "definitely-not-a-real-org/definitely-not-a-real-repo-xyz";
    const cached = join(cacheDir, repo.replace(/\//g, "__"));
    mkdirSync(cached, { recursive: true });
    commitOneFile(cached);
    symlinkSync("marker.txt", join(cached, "link.txt"));
    git(cached, "add", "link.txt");
    git(cached, "commit", "-q", "-m", "add relative link");
    const linkedSha = execFileSync("git", ["-C", cached, "rev-parse", "HEAD"]).toString().trim();
    const into = tmp("work-");

    cloneAtPinCached(repo, linkedSha, into, cacheDir);

    expect(readlinkSync(join(into, "link.txt"))).toBe("marker.txt");
    expect(execFileSync("git", ["-C", into, "status", "--porcelain"]).toString()).toBe("");
    expect(isFreshClone(into, linkedSha)).toBe(true);
  });

  it("fails rather than trusting a cached clone when its declared GitHub origin no longer serves the pin", () => {
    const cacheDir = tmp("cache-root-");
    const repo = "definitely-not-a-real-org/definitely-not-a-real-repo-xyz";
    const cached = join(cacheDir, repo.replace(/\//g, "__"));
    mkdirSync(cached, { recursive: true });
    const sha = commitOneFile(cached);
    const into = tmp("work-");

    expect(() => cloneAtPinCached(repo, sha, into, cacheDir, true)).toThrow();
  });
});

// The CI-side half of the same guard, exercised offline. The bug it closes was NOT a failed job
// saving a bad cache (actions/cache@v4 declares post-if: success(), and the poisoning job on
// 2026-07-30 passed) — it was that the key hashes ALL the pins while the saved content is whatever
// that particular job cloned, so corpus-m8's 4-of-14 tree took the 14-target key and corpus-drift's
// complete tree was then refused as a duplicate. The save side must therefore refuse on CONTENT.
const VERIFY_SH = fileURLToPath(new URL("../../.github/actions/corpus-clone-cache/verify-clones.sh", import.meta.url));

function seedCache(repos: string[]): { cacheDir: string; pinFile: string } {
  const cacheDir = tmp("verify-cache-");
  const lines: string[] = [];
  for (const [i, repo] of repos.entries()) {
    const dir = join(cacheDir, repo.replace(/\//g, "__"));
    mkdirSync(dir, { recursive: true });
    lines.push(`slug${i} ${repo}@${commitOneFile(dir)}`);
  }
  const pinFile = join(tmp("verify-pins-"), "corpus-pins.txt");
  writeFileSync(pinFile, `${lines.join("\n")}\n`);
  return { cacheDir, pinFile };
}

function runVerify(cacheDir: string, pinFile: string, mode: "restore" | "save"): { status: number | null; out: string; output: string } {
  const outFile = join(tmp("verify-out-"), "GITHUB_OUTPUT");
  writeFileSync(outFile, "");
  const r = spawnSync("bash", [VERIFY_SH, cacheDir, pinFile, mode], { encoding: "utf8", env: { ...process.env, GITHUB_OUTPUT: outFile } });
  return { status: r.status, out: `${r.stdout}${r.stderr}`, output: readFileSync(outFile, "utf8") };
}

describe("verify-clones.sh — the save side cannot write a partial entry", () => {
  it("saves only when every pinned clone is present", () => {
    const { cacheDir, pinFile } = seedCache(["org/one", "org/two", "org/three"]);
    const r = runVerify(cacheDir, pinFile, "save");
    expect(r.status).toBe(0);
    expect(r.output).toContain("complete=true");
  });

  it("refuses to save the 4-of-14 shape that poisoned the key, naming what is missing", () => {
    const { cacheDir, pinFile } = seedCache(["org/one", "org/two", "org/three"]);
    rmSync(join(cacheDir, "org__three"), { recursive: true, force: true });
    const r = runVerify(cacheDir, pinFile, "save");
    // Exit 0: a subset-scoring job (corpus-m8, or corpus-drift's #1498 narrowed PR path) is
    // behaving correctly and must not be failed — it is just not eligible to write this key.
    expect(r.status).toBe(0);
    expect(r.output).toContain("complete=false");
    expect(r.output).not.toContain("complete=true");
    expect(r.out).toContain("org/three");
  });

  it("refuses to save a clone whose tree was mutated after checkout", () => {
    const { cacheDir, pinFile } = seedCache(["org/one"]);
    writeFileSync(join(cacheDir, "org__one", "marker.txt"), "mutated\n");
    expect(runVerify(cacheDir, pinFile, "save").output).toContain("complete=false");
  });
});

describe("verify-clones.sh — the restore side fails loud on a poisoned hit", () => {
  it("passes a complete restore and reports the count it verified", () => {
    const { cacheDir, pinFile } = seedCache(["org/one", "org/two"]);
    const r = runVerify(cacheDir, pinFile, "restore");
    expect(r.status).toBe(0);
    expect(r.out).toContain("verified 2/2");
  });

  it("fails, and tells the reader what actually recovers — never 're-run'", () => {
    const { cacheDir, pinFile } = seedCache(["org/one", "org/two"]);
    rmSync(join(cacheDir, "org__two"), { recursive: true, force: true });
    const r = runVerify(cacheDir, pinFile, "restore");
    expect(r.status).toBe(1);
    expect(r.out).toContain("poisoned or incomplete for 1 of 2");
    // A key is immutable, so the old advice ("re-run to let the cache rebuild") restored the same
    // bad entry forever. Only deleting the entry or moving the key escapes it.
    expect(r.out).toContain("IMMUTABLE");
    expect(r.out).toContain("gh cache delete");
    expect(r.out).not.toMatch(/[Rr]e-run to let the cache rebuild/);
  });
});
