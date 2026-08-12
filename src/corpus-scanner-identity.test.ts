import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { buildCorpusScannerCache, dependencyInstallIdentity } from "./corpus-scanner-identity.js";

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
});
