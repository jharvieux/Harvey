import { execFile } from "node:child_process";
import { chmod, link, lstat, mkdir, mkdtemp, readFile, readdir, readlink, realpath, rename, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { pathToFileURL } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import { captureSourceSentinel, cleanupDisposableTarget, createDisposableTarget, retainDisposableTarget, type DisposableTarget, verifyRunRoot } from "./disposable-target.js";

const exec = promisify(execFile);
const owned: string[] = [];

afterEach(async () => {
  for (const root of owned.splice(0)) await rm(root, { recursive: true, force: true });
});

async function fixture(): Promise<{ root: string; source: string; scratch: string }> {
  const root = await realpath(await mkdtemp(join(tmpdir(), "harvey-disposable-test-")));
  owned.push(root);
  const source = join(root, "source");
  const scratch = join(root, "scratch");
  await mkdir(source);
  await mkdir(scratch);
  await writeFile(join(source, "package.json"), JSON.stringify({ name: "fixture", version: "1.0.0" }));
  await writeFile(join(source, "source.txt"), "original contents\n");
  return { root, source, scratch };
}

async function ready(source: string, scratch: string): Promise<DisposableTarget> {
  const result = await createDisposableTarget(source, { tempParent: scratch });
  expect(result.status).toBe("ready");
  if (result.status !== "ready") throw new Error(JSON.stringify(result));
  return result.target;
}

async function git(source: string, args: string[]): Promise<void> {
  await exec("git", ["-C", source, ...args], { timeout: 10_000 });
}

describe("disposable source copy", () => {
  it("retains an authentic root while namespace ownership is unresolved and refuses later unconditional deletion", async () => {
    const { source, scratch } = await fixture();
    const target = await ready(source, scratch);
    const retained = await retainDisposableTarget(target, { reasonCode: "owned-workload-unconfirmed", reason: "The fixture has no terminal namespace observation.", falsifier: "Prove the owned workload has terminated before separately remediating the retained root." });
    expect(retained).toMatchObject({ status: "failed", removal: { status: "failed", reasonCode: "owned-workload-unconfirmed" }, source: { status: "passed" } });
    expect((await lstat(target.root)).isDirectory()).toBe(true);
    expect(await cleanupDisposableTarget(target)).toEqual(retained);
    expect((await lstat(target.root)).isDirectory()).toBe(true);
    owned.push(target.root);
  });

  it("copies independent files, excludes artifacts and credential config, and verifies source preservation after physical writes", async () => {
    const { source, scratch } = await fixture();
    for (const dir of ["node_modules", "dist", ".next", ".hg", ".yarn/cache"]) {
      await mkdir(join(source, dir), { recursive: true });
      await writeFile(join(source, dir, "canary"), "do not copy");
    }
    for (const file of [".env", ".env.production", ".npmrc", ".yarnrc.yml"]) await writeFile(join(source, file), "CREDENTIAL_CANARY=never-forward");
    const target = await ready(source, scratch);
    expect(target.copy.excluded).toEqual(expect.arrayContaining(["node_modules", "dist", ".next", ".hg", ".yarn/cache", ".env", ".env.production", ".npmrc", ".yarnrc.yml"]));
    expect(await readdir(target.targetRoot)).not.toContain("node_modules");
    expect((await lstat(join(target.targetRoot, "source.txt"))).ino).not.toBe((await lstat(join(source, "source.txt"))).ino);
    await exec(process.execPath, ["-e", "require('node:fs').writeFileSync('source.txt','changed only in the copy');require('node:fs').writeFileSync('generated.txt','output')"], { cwd: target.targetRoot, timeout: 10_000 });
    expect(await readFile(join(source, "source.txt"), "utf8")).toBe("original contents\n");
    const cleanup = await cleanupDisposableTarget(target);
    expect(cleanup.status).toBe("passed");
    if (!("source" in cleanup)) throw new Error("missing cleanup source receipt");
    expect(cleanup.removal.status).toBe("removed");
    expect(cleanup.source.status).toBe("passed");
    expect(cleanup.durationMs).toBeGreaterThanOrEqual(0);
    await expect(lstat(target.root)).rejects.toMatchObject({ code: "ENOENT" });
  });

  it("rewrites relative and absolute internal links so neither can write through to original source", async () => {
    const { source, scratch } = await fixture();
    await mkdir(join(source, "lib"));
    await writeFile(join(source, "lib", "module.txt"), "source");
    await symlink(join(source, "lib"), join(source, "absolute-lib"));
    await symlink("lib/module.txt", join(source, "relative-file"));
    const target = await ready(source, scratch);
    expect(await readlink(join(target.targetRoot, "absolute-lib"))).toBe("lib");
    expect(await realpath(join(target.targetRoot, "relative-file"))).toBe(join(target.targetRoot, "lib", "module.txt"));
    await writeFile(join(target.targetRoot, "absolute-lib", "module.txt"), "disposable");
    expect(await readFile(join(source, "lib", "module.txt"), "utf8")).toBe("source");
    expect((await cleanupDisposableTarget(target)).status).toBe("passed");
  });

  it.each(["outside", "excluded", "broken"])("refuses a %s source link and cleans its partially created copy", async (kind) => {
    const { root, source, scratch } = await fixture();
    await writeFile(join(root, "outside.txt"), "outside-canary");
    await mkdir(join(source, "node_modules"));
    await writeFile(join(source, "node_modules", "dependency.txt"), "dependency-canary");
    const destination = kind === "outside" ? join(root, "outside.txt") : kind === "excluded" ? join(source, "node_modules", "dependency.txt") : join(source, "missing");
    await symlink(destination, join(source, "unsafe-link"));
    const result = await createDisposableTarget(source, { tempParent: scratch });
    expect(result.status).toBe("not-assessed");
    if (result.status !== "not-assessed") throw new Error("unexpected ready result");
    expect(result.cleanup.status).toBe("passed");
    expect(await readdir(scratch)).toEqual([]);
    expect(await readFile(join(root, "outside.txt"), "utf8")).toBe("outside-canary");
    expect(await readlink(join(source, "unsafe-link"))).toBe(destination);
  });

  it("excludes an original dependency symlink instead of reusing its source installation", async () => {
    const { root, source, scratch } = await fixture();
    const external = join(root, "shared-dependencies");
    await mkdir(external);
    await writeFile(join(external, "unchanged"), "existing installation");
    await symlink(external, join(source, "node_modules"));
    const target = await ready(source, scratch);
    expect(target.copy.excluded).toContain("node_modules");
    await expect(lstat(join(target.targetRoot, "node_modules"))).rejects.toMatchObject({ code: "ENOENT" });
    expect((await cleanupDisposableTarget(target)).status).toBe("passed");
    expect(await readFile(join(external, "unchanged"), "utf8")).toBe("existing installation");
  });

  it("refuses to allocate inside the original source, including a symlinked temporary parent", async () => {
    const { root, source } = await fixture();
    await mkdir(join(source, "scratch"));
    await symlink(join(source, "scratch"), join(root, "scratch-alias"));
    for (const tempParent of [source, join(root, "scratch-alias")]) {
      const result = await createDisposableTarget(source, { tempParent });
      expect(result).toMatchObject({ status: "not-assessed", reasonCode: "temp-inside-source", cleanup: { status: "not-required" } });
    }
    expect(await readdir(join(source, "scratch"))).toEqual([]);
  });

  it("fails source bounds before allocation instead of copying an unbounded tree", async () => {
    const { source, scratch } = await fixture();
    for (const limits of [{ maxEntries: 1 }, { maxBytes: 1 }, { maxDepth: 0 }]) {
      expect(await createDisposableTarget(source, { tempParent: scratch, limits })).toMatchObject({ status: "not-assessed", cleanup: { status: "not-required" } });
    }
    expect(await readdir(scratch)).toEqual([]);
  });
});

describe("spawn-time confinement", () => {
  it("checks cwd realpaths and rejects prefix tricks, absolute paths, and borrowed handles", async () => {
    const { root, source, scratch } = await fixture();
    await mkdir(join(source, "packages", "app"), { recursive: true });
    const target = await ready(source, scratch);
    expect(await verifyRunRoot(target, "packages/app")).toMatchObject({ status: "verified", cwd: join(target.targetRoot, "packages", "app") });
    for (const cwd of [source, target.targetRoot, "../source", "packages/../../source", "packages\\app", "C:\\source", "packages//app", "./packages/app", "packages\0/app"]) {
      expect(await verifyRunRoot(target, cwd)).toMatchObject({ status: "not-assessed", reasonCode: "cwd-escape" });
    }
    expect(await verifyRunRoot({ ...target })).toMatchObject({ status: "not-assessed", reasonCode: "inactive-target" });
    await mkdir(join(root, "source-sibling"));
    await symlink(join(root, "source-sibling"), join(target.targetRoot, "packages", "escape"));
    expect(await verifyRunRoot(target, "packages/escape")).toMatchObject({ status: "not-assessed", reasonCode: "run-link-escape" });
    expect((await cleanupDisposableTarget(target)).status).toBe("passed");
  });

  it("rejects a source link introduced by a prior stage even when the next cwd itself is safe", async () => {
    const { source, scratch } = await fixture();
    const target = await ready(source, scratch);
    await symlink(source, join(target.targetRoot, "back-to-original"));
    expect(await verifyRunRoot(target)).toMatchObject({ status: "not-assessed", reasonCode: "run-link-escape" });
    expect((await cleanupDisposableTarget(target)).status).toBe("passed");
  });

  it("allows hardlinks wholly inside the run root and refuses a hardlink back to source", async () => {
    const { source, scratch } = await fixture();
    const target = await ready(source, scratch);
    await link(join(target.targetRoot, "source.txt"), join(target.targetRoot, "internal-hardlink"));
    expect((await verifyRunRoot(target)).status).toBe("verified");
    await link(join(source, "source.txt"), join(target.targetRoot, "external-hardlink"));
    expect(await verifyRunRoot(target)).toMatchObject({ status: "not-assessed", reasonCode: "run-hardlink-escape" });
    expect((await cleanupDisposableTarget(target)).status).toBe("passed");
  });

  it("rejects a replaced cwd tree even if its replacement is a symlink to the original", async () => {
    const { source, scratch } = await fixture();
    const target = await ready(source, scratch);
    await rename(target.targetRoot, join(target.root, "old-target"));
    await symlink(source, target.targetRoot);
    expect(await verifyRunRoot(target)).toMatchObject({ status: "not-assessed", reasonCode: "directory-escape" });
    expect((await cleanupDisposableTarget(target)).status).toBe("passed");
    expect(await readFile(join(source, "source.txt"), "utf8")).toBe("original contents\n");
  });
});

describe("source and cleanup receipts", () => {
  it.each(["source.txt", "node_modules/dependency.txt"])("makes a physical change to original %s a failed run after cleanup", async (path) => {
    const { source, scratch } = await fixture();
    await mkdir(join(source, "node_modules"));
    await writeFile(join(source, "node_modules", "dependency.txt"), "original dependency");
    const target = await ready(source, scratch);
    await exec(process.execPath, ["-e", "require('node:fs').writeFileSync(process.argv[1], 'forbidden-original-mutation')", join(source, path)], { cwd: target.targetRoot, timeout: 10_000 });
    const cleanup = await cleanupDisposableTarget(target);
    expect(cleanup).toMatchObject({ status: "failed", removal: { status: "removed" }, source: { status: "failed", reasonCode: "source-changed" } });
    await expect(lstat(target.root)).rejects.toMatchObject({ code: "ENOENT" });
  });

  it("retains Git HEAD and status before/after and catches an index-only mutation", async () => {
    const { source, scratch } = await fixture();
    await git(source, ["init", "-q"]);
    await git(source, ["add", "."]);
    await git(source, ["-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "--no-gpg-sign", "-qm", "fixture"]);
    const target = await ready(source, scratch);
    expect(target.sourceBefore.git).toMatchObject({ status: "present", head: expect.stringMatching(/^[a-f0-9]{40}$/) });
    expect(target.copy.excluded).toContain(".git");
    await git(source, ["rm", "--cached", "source.txt"]);
    expect(await cleanupDisposableTarget(target)).toMatchObject({ status: "failed", source: { status: "failed", reasonCode: "source-changed" } });
  });

  it("observes an unborn Git repository without inferring a nonexistent HEAD", async () => {
    const { source } = await fixture();
    await git(source, ["init", "-q"]);
    expect((await captureSourceSentinel(source)).git).toMatchObject({ status: "present", head: null });
  });

  it("neutralizes target-owned Git filters without copying their opaque names into process argv", async () => {
    const { root, source: initialSource } = await fixture();
    const driverName = "HARVEY_SYNTHETIC_FILTER_IDENTITY_7d243e";
    const source = join(root, driverName);
    await rename(initialSource, source);
    await git(source, ["init", "-q"]);
    await writeFile(join(source, ".gitattributes"), `source.txt filter=${driverName}\n`);
    await writeFile(join(source, "filter.cjs"), "const f=require('node:fs');f.writeFileSync('filter-ran','unsafe');process.stdout.write(f.readFileSync(0));");
    await git(source, ["config", `filter.${driverName}.clean`, `${process.execPath} filter.cjs`]);
    await git(source, ["config", `filter.${driverName}.required`, "true"]);
    await git(source, ["add", "."]);
    expect(await readFile(join(source, "filter-ran"), "utf8")).toBe("unsafe");
    await rm(join(source, "filter-ran"));
    await writeFile(join(source, "source.txt"), "original contents\n");
    const log = join(root, "git-argv.jsonl");
    const preload = join(root, "observe-exec.cjs");
    await writeFile(preload, `
const childProcess = require('node:child_process');
const fs = require('node:fs');
const original = childProcess.execFile;
childProcess.execFile = function(file, args, options) {
  if (file === 'git') fs.appendFileSync(process.env.HARVEY_ARGV_LOG, JSON.stringify({
    args, filterOverrides: Object.entries(options.env).filter(([key]) => key.startsWith('GIT_CONFIG_'))
  }) + '\\n');
  return original.apply(this, arguments);
};
childProcess.execFile[require('node:util').promisify.custom] = (...args) => new Promise((resolve, reject) => {
  childProcess.execFile(...args, (error, stdout, stderr) => error ? reject(Object.assign(error, { stdout, stderr })) : resolve({ stdout, stderr }));
});
require('node:module').syncBuiltinESMExports();
`);
    const probe = join(root, "sentinel-probe.mjs");
    await writeFile(probe, `import { captureSourceSentinel } from ${JSON.stringify(pathToFileURL(join(process.cwd(), "src/disposable-target.ts")).href)};\nconsole.log(JSON.stringify((await captureSourceSentinel(process.argv[2])).git));\n`);
    const result = await exec(process.execPath, ["--require", preload, "--import", "tsx", probe, source], {
      timeout: 10_000, env: { PATH: process.env.PATH, HOME: root, HARVEY_ARGV_LOG: log },
    });
    expect(JSON.parse(result.stdout)).toMatchObject({ status: "present", head: null });
    const observations = (await readFile(log, "utf8")).trim().split("\n").map((line) => JSON.parse(line) as { args: string[]; filterOverrides: [string, string][] });
    expect(observations).toHaveLength(4);
    expect(observations.flatMap((observation) => observation.args).join("\n")).not.toContain(driverName);
    const status = observations.find((observation) => observation.args.includes("status"));
    expect(status?.filterOverrides).toEqual(expect.arrayContaining([
      ["GIT_CONFIG_KEY_0", `filter.${driverName}.clean`], ["GIT_CONFIG_VALUE_0", ""],
      ["GIT_CONFIG_KEY_1", `filter.${driverName}.required`], ["GIT_CONFIG_VALUE_1", "false"],
      ["GIT_CONFIG_COUNT", "2"],
    ]));
    await expect(lstat(join(source, "filter-ran"))).rejects.toMatchObject({ code: "ENOENT" });
  });

  it.each([["child_process", true], ["stream", true], ["child_process", false], ["stream", false]] as const)("refuses source observation before copy allocation with startup %s diagnostics and Git=%s", async (diagnostics, hasGit) => {
    const { root, source, scratch } = await fixture();
    const canary = "HARVEY_SYNTHETIC_PRIVATE_FILTER_c88a4d";
    if (hasGit) {
      await git(source, ["init", "-q"]);
      await git(source, ["config", `filter.${canary}.clean`, "cat"]);
    }
    const probe = join(root, "diagnostic-probe.mjs");
    await writeFile(probe, `import { createDisposableTarget } from ${JSON.stringify(pathToFileURL(join(process.cwd(), "src/disposable-target.ts")).href)};\ndelete process.env.NODE_DEBUG;\nconsole.log(JSON.stringify(await createDisposableTarget(process.argv[2], { tempParent: process.argv[3] })));\n`);
    const result = await exec(process.execPath, ["--import", "tsx", probe, source, scratch], {
      timeout: 10_000, env: { PATH: process.env.PATH, HOME: root, NODE_DEBUG: diagnostics },
    });
    expect(JSON.parse(result.stdout)).toMatchObject({ status: "not-assessed", reasonCode: "parent-raw-diagnostics", cleanup: { status: "not-required" } });
    expect(result.stdout + result.stderr).not.toContain(canary);
    expect(await readdir(scratch)).toEqual([]);
  });

  it("returns a failed cleanup receipt for an unrecognized handle without removing the authentic run", async () => {
    const { source, scratch } = await fixture();
    const target = await ready(source, scratch);
    expect(await cleanupDisposableTarget({ ...target })).toMatchObject({ status: "failed", reasonCode: "unrecognized-target" });
    expect((await lstat(target.targetRoot)).isDirectory()).toBe(true);
    expect((await cleanupDisposableTarget(target)).status).toBe("passed");
  });

  it("performs cleanup once after a real child failure and refuses future stage admission", async () => {
    const { source, scratch } = await fixture();
    const target = await ready(source, scratch);
    await expect(exec(process.execPath, ["-e", "process.exit(7)"], { cwd: target.targetRoot, timeout: 10_000 })).rejects.toMatchObject({ code: 7 });
    const first = cleanupDisposableTarget(target);
    const second = cleanupDisposableTarget(target);
    expect(first).toBe(second);
    expect((await first).status).toBe("passed");
    expect(await cleanupDisposableTarget(target)).toBe(await first);
    expect(await verifyRunRoot(target)).toMatchObject({ status: "not-assessed", reasonCode: "inactive-target" });
  });

  it("records physical cleanup failure instead of following a replaced root into source", async () => {
    const { source, scratch } = await fixture();
    const target = await ready(source, scratch);
    const moved = `${target.root}-moved`;
    await rename(target.root, moved);
    await symlink(source, target.root);
    const cleanup = await cleanupDisposableTarget(target);
    expect(cleanup).toMatchObject({ status: "failed", removal: { status: "failed", reasonCode: "directory-escape" }, source: { status: "passed" } });
    expect(await readlink(target.root)).toBe(source);
    expect(await readFile(join(source, "source.txt"), "utf8")).toBe("original contents\n");
    expect(await readdir(moved)).toContain("target");
  });

  it("records removal failure under actual filesystem permissions", async () => {
    if (process.getuid?.() === 0) return;
    const { source, scratch } = await fixture();
    const target = await ready(source, scratch);
    const blocked = join(target.targetRoot, "cannot-remove");
    await mkdir(blocked);
    await writeFile(join(blocked, "child"), "physical cleanup canary");
    await chmod(blocked, 0o500);
    try {
      expect(await cleanupDisposableTarget(target)).toMatchObject({ status: "failed", removal: { status: "failed" }, source: { status: "passed" } });
      expect(await readFile(join(blocked, "child"), "utf8")).toBe("physical cleanup canary");
    } finally { await chmod(blocked, 0o700); }
  });
});
