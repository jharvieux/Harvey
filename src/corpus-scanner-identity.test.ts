import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { dependencyInstallIdentity } from "./corpus-scanner-identity.js";

describe("corpus scanner dependency/install identity (#1871)", () => {
  const dirs: string[] = [];
  afterEach(() => dirs.splice(0).forEach((dir) => rmSync(dir, { recursive: true, force: true })));

  it("keys tracked manifests, locks, and install presence without hashing dependency contents", () => {
    const dir = mkdtempSync(join(tmpdir(), "harvey-corpus-install-identity-"));
    dirs.push(dir);
    execFileSync("git", ["init", "-q", dir]);
    writeFileSync(join(dir, "package.json"), "{\"packageManager\":\"pnpm@10.0.0\"}\n");
    writeFileSync(join(dir, "pnpm-lock.yaml"), "lockfileVersion: '9.0'\n");
    execFileSync("git", ["-C", dir, "add", "package.json", "pnpm-lock.yaml"]);
    const absent = dependencyInstallIdentity(dir);

    mkdirSync(join(dir, "node_modules", "dependency"), { recursive: true });
    writeFileSync(join(dir, "node_modules", "dependency", "index.js"), "module.exports = 1;\n");
    const installed = dependencyInstallIdentity(dir);
    expect(installed).not.toBe(absent);
    writeFileSync(join(dir, "node_modules", "dependency", "index.js"), "module.exports = 2;\n");
    expect(dependencyInstallIdentity(dir)).toBe(installed);

    writeFileSync(join(dir, "pnpm-lock.yaml"), "lockfileVersion: '9.0'\nchanged: true\n");
    expect(dependencyInstallIdentity(dir)).not.toBe(installed);
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
