import { execFileSync } from "node:child_process";
import { linkSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { CORPUS_INSTALL_IDENTITY_BOUNDS, buildCorpusScannerCache, dependencyInstallIdentity, observedInstallDigest } from "./corpus-scanner-identity.js";

interface DecodedInstallIdentity {
  state: string;
  observed?: { digest: string; files: number; logicalFiles: number; bytes: number };
}

const decoded = (dir: string): DecodedInstallIdentity => JSON.parse(dependencyInstallIdentity(dir)) as DecodedInstallIdentity;

function installedConfigProviderFixture(): string {
  const dir = mkdtempSync(join(tmpdir(), "harvey-corpus-knip-provider-"));
  execFileSync("git", ["init", "-q", dir]);
  writeFileSync(join(dir, "package.json"), '{"name":"knip-provider-falsifier","private":true,"devDependencies":{"knip-config-provider":"1.0.0"}}\n');
  writeFileSync(join(dir, "knip.js"), 'module.exports = require("knip-config-provider");\n');
  mkdirSync(join(dir, "src"));
  writeFileSync(join(dir, "src", "index.ts"), "export const selectedIndex = true;\n");
  writeFileSync(join(dir, "src", "alternate.ts"), "export const selectedAlternate = true;\n");
  const provider = join(dir, "node_modules", "knip-config-provider");
  mkdirSync(join(provider, "settings"), { recursive: true });
  writeFileSync(join(provider, "package.json"), '{"name":"knip-config-provider","version":"1.0.0","main":"index.js"}\n');
  writeFileSync(join(provider, "index.js"), 'module.exports = require("./config.js");\n');
  writeFileSync(join(provider, "config.js"), 'module.exports = { entry: ["src/index.ts"] };\n');
  writeFileSync(join(provider, "settings", "primary.js"), 'module.exports = { entry: ["src/index.ts"] };\n');
  writeFileSync(join(provider, "settings", "alternate.js"), 'module.exports = { entry: ["src/alternate.ts"] };\n');
  execFileSync("git", ["-C", dir, "add", "package.json", "knip.js", "src/index.ts", "src/alternate.ts"]);
  return dir;
}

function qualityScan(dir: string, suffix: string): string {
  const output = join(dir, `findings-${suffix}.json`);
  execFileSync(join(process.cwd(), "node_modules", ".bin", "tsx"), [join(process.cwd(), "src", "cli", "quality-scan.ts"), dir, "--out", output], {
    cwd: process.cwd(),
    stdio: ["ignore", "ignore", "ignore"],
    timeout: 30_000,
  });
  const findings = JSON.parse(readFileSync(output, "utf8")) as { id: string; location: string }[];
  return findings.find((finding) => finding.id === "M5-01")?.location ?? "missing M5-01";
}

describe("corpus scanner dependency/install identity (#1871)", () => {
  const dirs: string[] = [];
  afterEach(() => dirs.splice(0).forEach((dir) => rmSync(dir, { recursive: true, force: true })));

  it("keys actual installed package bytes as well as manifests and locks", () => {
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

  it("invalidates the installed identity when Knip executes a provider config descendant that changes its M5 result", () => {
    const dir = installedConfigProviderFixture();
    dirs.push(dir);
    const config = join(dir, "node_modules", "knip-config-provider", "config.js");
    const beforeIdentity = dependencyInstallIdentity(dir);
    const beforeFinding = qualityScan(dir, "before");
    expect(dependencyInstallIdentity(dir)).toBe(beforeIdentity);

    writeFileSync(config, 'module.exports = { entry: ["src/alternate.ts"] };\n');
    const afterIdentity = dependencyInstallIdentity(dir);
    const afterFinding = qualityScan(dir, "after");

    expect(beforeFinding).toBe("src/alternate.ts");
    expect(afterFinding).toBe("src/index.ts");
    expect(afterIdentity).not.toBe(beforeIdentity);
  });

  it("covers transitive and alternate installed config files even before the provider selects them", () => {
    const dir = installedConfigProviderFixture();
    dirs.push(dir);
    const provider = join(dir, "node_modules", "knip-config-provider");
    writeFileSync(join(provider, "config.js"), 'module.exports = require("./settings/primary.js");\n');
    const before = dependencyInstallIdentity(dir);
    writeFileSync(join(provider, "settings", "primary.js"), 'module.exports = { entry: ["src/alternate.ts"] };\n');
    const transitiveChanged = dependencyInstallIdentity(dir);
    expect(transitiveChanged).not.toBe(before);
    writeFileSync(join(provider, "settings", "alternate.js"), 'module.exports = { entry: ["src/index.ts"] };\n');
    expect(dependencyInstallIdentity(dir)).not.toBe(transitiveChanged);
  });

  it("invalidates when an installed directory symlink is rewired between two already-observed populations", () => {
    const dir = mkdtempSync(join(tmpdir(), "harvey-corpus-install-link-layout-"));
    const external = mkdtempSync(join(tmpdir(), "harvey-corpus-install-link-store-"));
    dirs.push(dir, external);
    execFileSync("git", ["init", "-q", dir]);
    writeFileSync(join(dir, "package.json"), '{"dependencies":{"dependency":"1.0.0"}}\n');
    execFileSync("git", ["-C", dir, "add", "package.json"]);
    const modules = join(dir, "node_modules");
    mkdirSync(modules);
    for (const store of ["store-a", "store-b"]) {
      mkdirSync(join(external, store));
      writeFileSync(join(external, store, "package.json"), JSON.stringify({ name: "dependency", version: store }));
      writeFileSync(join(external, store, "index.js"), `module.exports = ${JSON.stringify(store)};\n`);
      symlinkSync(join(external, store), join(modules, store), "dir");
    }
    symlinkSync(join(external, "store-a"), join(modules, "dependency"), "dir");
    const before = dependencyInstallIdentity(dir);
    rmSync(join(modules, "dependency"));
    symlinkSync(join(external, "store-b"), join(modules, "dependency"), "dir");
    expect(dependencyInstallIdentity(dir)).not.toBe(before);
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
    expect(forward.logicalFiles).toBe(2);
  });

  it("deduplicates hardlinked installed bytes physically while retaining both logical aliases in identity", () => {
    const dir = mkdtempSync(join(tmpdir(), "harvey-corpus-install-hardlinks-"));
    dirs.push(dir);
    const first = join(dir, "first.js");
    const second = join(dir, "second.js");
    writeFileSync(first, "export const installed = true;\n");
    linkSync(first, second);
    const observations = [first, second].map((logicalPath) => ({ logicalPath, physicalPath: realpathSync(logicalPath) }));
    const result = observedInstallDigest(dir, observations, { maxFiles: 1, maxBytes: 1_024 });
    expect(result.files).toBe(1);
    expect(result.logicalFiles).toBe(2);
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
