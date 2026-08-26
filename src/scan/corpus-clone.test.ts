// Offline coverage for the corpus-clone-cache safety logic (#1571). No network: `isFreshClone`
// operates on a LOCAL git repo built with plain `git` commands, and `cloneAtPinCached`'s cache-HIT
// path is proven to skip the network entirely by pointing its "repo" at one that does not exist —
// a real fetch attempt would throw, so a clean copy proves the network was never touched.
import { execFileSync, spawnSync } from "node:child_process";
import { lstatSync, mkdirSync, mkdtempSync, readFileSync, readlinkSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { afterEach, describe, expect, it, vi } from "vitest";
import { readNamesSafe, readRecursiveSafe } from "../fs-walk.js";
import { cloneAtPinCached, isFreshClone } from "./corpus-clone.js";

const dirs: string[] = [];
function tmp(prefix: string): string {
  const d = mkdtempSync(join(tmpdir(), prefix));
  dirs.push(d);
  return d;
}
afterEach(() => {
  vi.unstubAllEnvs();
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

function gitOutput(dir: string, ...args: string[]): string {
  return execFileSync("git", ["-C", dir, ...args], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();
}

function offlineOrigin(): { repo: string; source: string; pin: string; tree: string } {
  vi.stubEnv("GIT_CONFIG_GLOBAL", "/dev/null");
  vi.stubEnv("GIT_CONFIG_NOSYSTEM", "1");
  vi.stubEnv("GIT_ALLOW_PROTOCOL", "file");
  const source = tmp("clone-origin-");
  const repo = "harvey-offline-fixture/corpus-clone";
  const config = [
    [`url.${pathToFileURL(source).href}.insteadOf`, `https://github.com/${repo}`],
    ["fetch.unpackLimit", "1"],
    ["gc.autoDetach", "false"],
    ["maintenance.autoDetach", "false"],
  ];
  vi.stubEnv("GIT_CONFIG_COUNT", String(config.length));
  for (const [index, [key, value]] of config.entries()) {
    vi.stubEnv(`GIT_CONFIG_KEY_${index}`, key);
    vi.stubEnv(`GIT_CONFIG_VALUE_${index}`, value);
  }
  commitOneFile(source);
  symlinkSync("marker.txt", join(source, "link.txt"));
  git(source, "add", "link.txt");
  git(source, "commit", "-q", "-m", "pinned relative link");
  const pin = gitOutput(source, "rev-parse", "HEAD");
  const tree = gitOutput(source, "rev-parse", "HEAD^{tree}");
  writeFileSync(join(source, "marker.txt"), "newer upstream content\n");
  git(source, "commit", "-q", "-am", "advance upstream beyond pin");
  return { repo, source, pin, tree };
}

function gitSnapshot(dir: string): Array<[string, string]> {
  const gitDir = join(dir, ".git");
  return readRecursiveSafe(gitDir).sort()
    .filter((path) => lstatSync(join(gitDir, path)).isFile())
    .map((path) => [path, readFileSync(join(gitDir, path)).toString("base64")]);
}

interface GitTraceEvent {
  event: string;
  argv?: string[];
}

function readGitTrace(path: string): GitTraceEvent[] {
  return readFileSync(path, "utf8").trim().split("\n").map((line) => JSON.parse(line) as GitTraceEvent);
}

function expectNoMaintenance(trace: GitTraceEvent[]): void {
  const maintenance = trace.filter((event) => event.event === "child_start"
    && event.argv?.some((arg) => /(?:^|[\\/])(?:git-)?(?:maintenance|gc|repack)(?:\.exe)?$/.test(arg)));
  expect(maintenance.map((event) => event.argv)).toEqual([]);
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
    const { repo, source, pin } = offlineOrigin();
    const cacheDir = tmp("cache-root-");
    const cached = join(cacheDir, repo.replace(/\//g, "__"));
    cloneAtPinCached(repo, pin, tmp("cache-seed-"), cacheDir);
    // The cached origin still serves the pin; the declared URL now points at an empty repo.
    git(cached, "remote", "set-url", "origin", pathToFileURL(source).href);
    const emptyOrigin = tmp("empty-origin-");
    git(emptyOrigin, "init", "-q");
    vi.stubEnv("GIT_CONFIG_KEY_0", `url.${pathToFileURL(emptyOrigin).href}.insteadOf`);
    const into = tmp("work-");
    const before = gitSnapshot(cached);

    expect(() => cloneAtPinCached(repo, pin, into, cacheDir, true)).toThrow();
    expect(gitSnapshot(cached)).toEqual(before);
  });
});

describe("helper-owned fetch maintenance policy (#1870)", () => {
  it.each(["no-cache", "cold-cache", "warm-cache+verify"] as const)("suppresses maintenance on the %s path", (mode) => {
    const { repo, pin, tree } = offlineOrigin();
    const cacheDir = mode === "no-cache" ? undefined : tmp("fetch-cache-");
    const cached = cacheDir ? join(cacheDir, repo.replace(/\//g, "__")) : undefined;
    if (mode === "warm-cache+verify") {
      cloneAtPinCached(repo, pin, tmp("cache-seed-"), cacheDir);
      // Verification must use the declared URL, not this deliberately unavailable cached origin.
      git(cached!, "remote", "set-url", "origin", pathToFileURL(join(tmp("missing-origin-"), "absent.git")).href);
    }
    const before = mode === "warm-cache+verify" ? gitSnapshot(cached!) : undefined;
    const into = tmp("fetch-work-");
    const traceFile = join(tmp("fetch-trace-"), "git.jsonl");
    vi.stubEnv("GIT_TRACE2_EVENT", traceFile);

    cloneAtPinCached(repo, pin, into, cacheDir, mode !== "no-cache");

    const trace = readGitTrace(traceFile);
    expectNoMaintenance(trace);
    const fetches = trace.filter((event) => event.event === "start" && event.argv?.includes("fetch"))
      .map((event) => event.argv);
    const gitExecutable = expect.stringMatching(/(?:^|[\\/])git(?:\.exe)?$/);
    const initial = [gitExecutable, "-C", cached ?? into, "fetch", "--no-auto-maintenance", "-q", "--depth", "1", "origin", pin];
    const verify = [gitExecutable, "-C", into, "fetch", "--no-auto-maintenance", "-q", "--depth", "1", `https://github.com/${repo}`, pin];
    expect(fetches).toEqual(mode === "no-cache" ? [initial] : mode === "cold-cache" ? [initial, verify] : [verify]);
    expect(gitOutput(into, "rev-parse", "HEAD")).toBe(pin);
    expect(gitOutput(into, "rev-parse", "HEAD^{tree}")).toBe(tree);
    expect(gitOutput(into, "rev-parse", "--is-shallow-repository")).toBe("true");
    expect(gitOutput(into, "rev-list", "HEAD")).toBe(pin);
    expect(gitOutput(into, "status", "--porcelain")).toBe("");
    expect(readFileSync(join(into, "marker.txt"), "utf8")).toBe("pinned content\n");
    expect(readlinkSync(join(into, "link.txt"))).toBe("marker.txt");
    git(into, "fsck", "--full");
    // fetch.unpackLimit=1 exercises normal fetch-created packs independently of maintenance.
    expect(readNamesSafe(join(into, ".git", "objects", "pack")).filter((path) => path.endsWith(".pack")).length).toBeGreaterThan(0);
    if (cached) {
      expect(isFreshClone(cached, pin)).toBe(true);
      expect(gitOutput(cached, "rev-list", "HEAD")).toBe(gitOutput(into, "rev-list", "HEAD"));
      const copiedObjects = gitSnapshot(into).filter(([path]) => path.startsWith("objects/"));
      expect(copiedObjects).toEqual(expect.arrayContaining(gitSnapshot(cached).filter(([path]) => path.startsWith("objects/"))));
      if (before) expect(gitSnapshot(cached)).toEqual(before);
    }
  });

  it.each([false, true])("fails loud for an unavailable pin with cache=%s", (cache) => {
    const { repo, pin } = offlineOrigin();
    const into = tmp("missing-pin-");
    expect(() => cloneAtPinCached(repo, "0".repeat(40), into, cache ? tmp("missing-pin-cache-") : undefined)).toThrow();
    expect(isFreshClone(into, pin)).toBe(false);
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
