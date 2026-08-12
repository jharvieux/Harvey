import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { CORPUS_INSTALL_IDENTITY_BOUNDS, buildCorpusScannerCache, dependencyInstallIdentity, observedInstallDigest } from "./corpus-scanner-identity.js";

const decoded = (dir: string): { state: string; observed?: { digest: string } } => JSON.parse(dependencyInstallIdentity(dir)) as { state: string; observed?: { digest: string } };

describe("corpus scanner dependency/install identity (#1871)", () => {
  const dirs: string[] = [];
  afterEach(() => dirs.splice(0).forEach((dir) => rmSync(dir, { recursive: true, force: true })));

  it("keys actual installed package entry bytes as well as manifests and locks", () => {
    const dir = mkdtempSync(join(tmpdir(), "harvey-corpus-install-identity-"));
    dirs.push(dir);
    execFileSync("git", ["init", "-q", dir]);
    writeFileSync(join(dir, "package.json"), "{\"packageManager\":\"pnpm@10.0.0\",\"dependencies\":{\"dependency\":\"1.0.0\"}}\n");
    writeFileSync(join(dir, "pnpm-lock.yaml"), "lockfileVersion: '9.0'\n");
    execFileSync("git", ["-C", dir, "add", "package.json", "pnpm-lock.yaml"]);
    const absent = dependencyInstallIdentity(dir);

    mkdirSync(join(dir, "node_modules", "dependency"), { recursive: true });
    writeFileSync(join(dir, "node_modules", "dependency", "package.json"), "{\"name\":\"dependency\",\"version\":\"1.0.0\",\"main\":\"index.js\"}\n");
    writeFileSync(join(dir, "node_modules", "dependency", "index.js"), "module.exports = 1;\n");
    const installed = dependencyInstallIdentity(dir);
    expect(installed).not.toBe(absent);
    writeFileSync(join(dir, "node_modules", "dependency", "index.js"), "module.exports = 2;\n");
    const changedBytes = dependencyInstallIdentity(dir);
    expect(changedBytes).not.toBe(installed);

    writeFileSync(join(dir, "node_modules", ".modules.yaml"), "layoutVersion: 5\n");
    const prepared = dependencyInstallIdentity(dir);
    expect(prepared).not.toBe(changedBytes);
    writeFileSync(join(dir, "node_modules", ".modules.yaml"), "layoutVersion: 6\n");
    expect(dependencyInstallIdentity(dir)).not.toBe(prepared);

    writeFileSync(join(dir, "pnpm-lock.yaml"), "lockfileVersion: '9.0'\nchanged: true\n");
    expect(dependencyInstallIdentity(dir)).not.toBe(installed);
  });

  it("distinguishes a partial install from a complete installed graph", () => {
    const dir = mkdtempSync(join(tmpdir(), "harvey-corpus-partial-install-"));
    dirs.push(dir);
    execFileSync("git", ["init", "-q", dir]);
    writeFileSync(join(dir, "package.json"), "{\"dependencies\":{\"a\":\"1\",\"b\":\"1\"}}\n");
    execFileSync("git", ["-C", dir, "add", "package.json"]);
    for (const name of ["a", "b"]) {
      if (name === "b") continue;
      mkdirSync(join(dir, "node_modules", name), { recursive: true });
      writeFileSync(join(dir, "node_modules", name, "package.json"), JSON.stringify({ name, version: "1.0.0" }));
    }
    expect(decoded(dir).state).toBe("partial");
    mkdirSync(join(dir, "node_modules", "b"));
    writeFileSync(join(dir, "node_modules", "b", "package.json"), "{\"name\":\"b\",\"version\":\"1.0.0\"}\n");
    expect(decoded(dir).state).toBe("complete");
  });

  it("marks a legitimate no-package target explicitly and lets source-only scanners cache it", () => {
    const dir = mkdtempSync(join(tmpdir(), "harvey-corpus-no-package-"));
    const cacheDir = mkdtempSync(join(tmpdir(), "harvey-corpus-no-package-cache-"));
    dirs.push(dir, cacheDir);
    execFileSync("git", ["init", "-q", dir]);
    writeFileSync(join(dir, "query.sql"), "select 1;\n");
    execFileSync("git", ["-C", dir, "add", "query.sql"]);
    expect(decoded(dir).state).toBe("not-applicable-no-package");
    const sourceCache = buildCorpusScannerCache({
      repoRoot: process.cwd(), cacheDir, mode: "read-write", scanner: "detect-static", targetDir: dir,
      targetRevision: "pin", targetTree: "tree", targetConfig: "root",
    });
    expect(sourceCache.externalInputs).not.toHaveProperty("dependencyInstall");
    const observedCache = buildCorpusScannerCache({
      repoRoot: process.cwd(), cacheDir, mode: "read-write", scanner: "quality-scan", targetDir: dir,
      targetRevision: "pin", targetTree: "tree", targetConfig: "root",
    });
    expect(JSON.parse(observedCache.externalInputs.dependencyInstall ?? "{}")).toMatchObject({
      state: "not-applicable-no-package",
      reason: expect.stringContaining("not an assessed-clean claim"),
    });
  });

  it("includes each tracked workspace manifest's own install state", () => {
    const dir = mkdtempSync(join(tmpdir(), "harvey-corpus-workspace-install-"));
    dirs.push(dir);
    execFileSync("git", ["init", "-q", dir]);
    writeFileSync(join(dir, "package.json"), "{}\n");
    mkdirSync(join(dir, "packages", "app"), { recursive: true });
    writeFileSync(join(dir, "packages", "app", "package.json"), "{}\n");
    execFileSync("git", ["-C", dir, "add", "package.json", "packages/app/package.json"]);
    const before = dependencyInstallIdentity(dir);
    mkdirSync(join(dir, "packages", "app", "node_modules"));
    expect(dependencyInstallIdentity(dir)).not.toBe(before);
  });

  it("canonicalizes workspace aliases to physical installed files before applying the bound", () => {
    const dir = mkdtempSync(join(tmpdir(), "harvey-corpus-install-aliases-"));
    dirs.push(dir);
    mkdirSync(join(dir, "store", "dependency"), { recursive: true });
    writeFileSync(join(dir, "store", "dependency", "index.js"), "export const installed = true;\n");
    mkdirSync(join(dir, "workspace-a", "node_modules"), { recursive: true });
    mkdirSync(join(dir, "workspace-b", "node_modules"), { recursive: true });
    symlinkSync(join(dir, "store", "dependency"), join(dir, "workspace-a", "node_modules", "dependency"), "dir");
    symlinkSync(join(dir, "store", "dependency"), join(dir, "workspace-b", "node_modules", "dependency"), "dir");
    const aliases = ["workspace-a", "workspace-b"].map((workspace) => {
      const logicalPath = join(dir, workspace, "node_modules", "dependency", "index.js");
      return { logicalPath, physicalPath: realpathSync(logicalPath) };
    });
    const forward = observedInstallDigest(dir, aliases, { maxFiles: 1, maxBytes: 1_024 });
    const reverse = observedInstallDigest(dir, [...aliases].reverse(), { maxFiles: 1, maxBytes: 1_024 });
    expect(forward).toEqual(reverse);
    expect(forward.files).toBe(1);
  });

  it("keeps the installed identity deterministic across different checkout roots", () => {
    const roots = ["a", "b"].map((suffix) => mkdtempSync(join(tmpdir(), `harvey-corpus-install-checkout-${suffix}-`)));
    dirs.push(...roots);
    for (const dir of roots) {
      execFileSync("git", ["init", "-q", dir]);
      writeFileSync(join(dir, "package.json"), "{\"dependencies\":{\"dependency\":\"1.0.0\"}}\n");
      execFileSync("git", ["-C", dir, "add", "package.json"]);
      mkdirSync(join(dir, "node_modules", "dependency"), { recursive: true });
      writeFileSync(join(dir, "node_modules", "dependency", "package.json"), "{\"name\":\"dependency\",\"version\":\"1.0.0\",\"main\":\"index.js\"}\n");
      writeFileSync(join(dir, "node_modules", "dependency", "index.js"), "export const installed = true;\n");
    }
    expect(dependencyInstallIdentity(roots[0]!)).toBe(dependencyInstallIdentity(roots[1]!));
  });

  it("fails loud in both directions when the explicit physical population bounds are exceeded", () => {
    const dir = mkdtempSync(join(tmpdir(), "harvey-corpus-install-over-bound-"));
    dirs.push(dir);
    const first = join(dir, "first.js");
    const second = join(dir, "second.js");
    writeFileSync(first, "1234");
    writeFileSync(second, "5678");
    const observations = [first, second].map((logicalPath) => ({ logicalPath, physicalPath: realpathSync(logicalPath) }));
    expect(() => observedInstallDigest(dir, observations, { maxFiles: 1, maxBytes: 1_024 })).toThrow("observed 2 physical files, exceeding the 1-file bound");
    expect(() => observedInstallDigest(dir, observations.slice(0, 1), { maxFiles: 1, maxBytes: 3 })).toThrow("observed 4 physical bytes, exceeding the 3-byte bound");
  });

  it("accepts a representative real-scale physical population without weakening production bounds", () => {
    const dir = mkdtempSync(join(tmpdir(), "harvey-corpus-install-real-scale-"));
    dirs.push(dir);
    const observations: { logicalPath: string; physicalPath: string }[] = [];
    // Pinned Carbon measured 3,685 physical inputs. Use a slightly larger population here so the
    // pass control protects the real scale, while the negative control above owns the ceiling.
    for (let index = 0; index < 3_700; index += 1) {
      const logicalPath = join(dir, `entry-${String(index).padStart(4, "0")}.js`);
      writeFileSync(logicalPath, `export const entry${index} = ${index};\n`);
      observations.push({ logicalPath, physicalPath: realpathSync(logicalPath) });
    }
    // BoxyHQ measured 40,665,455 bytes. One additional 48-MiB installed bundle proves that a
    // legitimate target above the old 32-MiB limit remains within the evidence-based ceiling.
    const bundle = join(dir, "installed-bundle.js");
    writeFileSync(bundle, Buffer.alloc(48 * 1024 * 1024, 0x61));
    observations.push({ logicalPath: bundle, physicalPath: realpathSync(bundle) });
    const result = observedInstallDigest(dir, observations);
    expect(result.files).toBe(3_701);
    expect(result.bytes).toBeGreaterThan(40_665_455);
    expect(result.bytes).toBeLessThan(CORPUS_INSTALL_IDENTITY_BOUNDS.maxBytes);
  });
});
